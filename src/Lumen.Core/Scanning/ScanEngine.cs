using System.Diagnostics;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.Core.Scanning;

/// <summary>
/// Sequential, read-only scan engine. It never writes, moves or deletes files; remediation
/// happens only through the separately confirmed quarantine service.
/// </summary>
public sealed class ScanEngine
{
    private const int MaxErrorSamples = 200;
    private static readonly TimeSpan ProgressInterval = TimeSpan.FromMilliseconds(120);

    private readonly DetectorRegistry _detectorRegistry;
    private readonly IClock _clock;
    private readonly ILog _log;

    public ScanEngine(DetectorRegistry detectorRegistry, IClock clock, ILog log)
    {
        _detectorRegistry = detectorRegistry;
        _clock = clock;
        _log = log;
    }

    public Task<ScanOutcome> ScanAsync(
        ScanRequest request,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken) =>
        Task.Run(() => ScanCore(request, progress, cancellationToken), CancellationToken.None);

    private ScanOutcome ScanCore(
        ScanRequest request,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var started = _clock.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        var errors = new List<ScanError>();
        var detections = new List<ScanDetection>();
        var pending = new List<ScanDetection>();
        var lastProgress = TimeSpan.MinValue;
        var filesScanned = 0L;
        var filesSkipped = 0L;
        var directoriesSkipped = 0L;
        var bytesInspected = 0L;
        var errorCount = 0L;
        var currentFile = string.Empty;
        var cancelled = false;
        var probeReader = new ProbeReader(checked((int)Math.Clamp(request.MaxInspectBytes, 64 * 1024, 16 * 1024 * 1024)));
        var directories = new Stack<(string Directory, int Depth)>();

        void Report(ScanPhase phase, bool force)
        {
            var elapsed = stopwatch.Elapsed;
            if (!force && lastProgress != TimeSpan.MinValue && elapsed - lastProgress < ProgressInterval) return;

            lastProgress = elapsed;
            var batch = pending.ToArray();
            pending.Clear();
            var snapshot = new ScanProgress
            {
                Phase = phase,
                CurrentFile = currentFile,
                FilesScanned = filesScanned,
                FilesSkipped = filesSkipped,
                DirectoriesSkipped = directoriesSkipped,
                ErrorCount = errorCount,
                DetectionCount = detections.Count,
                BytesInspected = bytesInspected,
                Elapsed = elapsed,
                NewDetections = batch
            };

            try
            {
                progress?.Report(snapshot);
            }
            catch (Exception ex)
            {
                _log.Warn("Scan", "A progress handler threw an exception; scanning continues.", ex);
            }
        }

        void AddError(ScanError error)
        {
            errorCount++;
            if (errors.Count < MaxErrorSamples) errors.Add(error);
            _log.Warn("Scan", $"{error.Kind}: {error.Path} ({error.Technical ?? "n/a"})");
        }

        void ScanFile(string path, FileAttributes attributes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            currentFile = path;
            filesScanned++;

            var read = probeReader.Read(path, attributes, cancellationToken);
            if (!read.Success || read.Probe is null)
            {
                AddError(read.Error!);
                Report(ScanPhase.Inspecting, force: false);
                return;
            }

            var probe = read.Probe;
            bytesInspected += probe.Content.Length;

            IReadOnlyList<Finding> findings;
            try
            {
                findings = _detectorRegistry.Inspect(probe, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                AddError(ScanErrors.FromException(path, ex, _clock));
                Report(ScanPhase.Inspecting, force: false);
                return;
            }

            if (findings.Count == 0)
            {
                Report(ScanPhase.Inspecting, force: false);
                return;
            }

            string? hash = null;
            try
            {
                hash = HashUtil.Sha256File(path, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _log.Warn("Scan", $"A finding was recorded but its SHA-256 could not be computed: {path}", ex);
            }

            var detection = new ScanDetection
            {
                FilePath = path,
                SizeBytes = probe.SizeBytes,
                Sha256 = hash,
                Findings = findings,
                DetectedUtc = _clock.UtcNow
            };

            detections.Add(detection);
            pending.Add(detection);
            Report(ScanPhase.Inspecting, force: true);
        }

        void EnumerateDirectory(string directory, int depth)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var info = new DirectoryInfo(directory);
                foreach (var entry in info.EnumerateFileSystemInfos())
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    FileAttributes attributes;
                    try
                    {
                        attributes = entry.Attributes;
                    }
                    catch (Exception ex)
                    {
                        AddError(ScanErrors.FromException(entry.FullName, ex, _clock));
                        continue;
                    }

                    if (entry is DirectoryInfo)
                    {
                        if (PathRules.IsReparsePoint(attributes))
                        {
                            directoriesSkipped++;
                            continue;
                        }

                        if (depth >= request.MaxDepth)
                        {
                            directoriesSkipped++;
                            continue;
                        }

                        if (PathRules.IsExcluded(entry.FullName, request.ExcludedDirectories))
                        {
                            directoriesSkipped++;
                            continue;
                        }

                        directories.Push((entry.FullName, depth + 1));
                        continue;
                    }

                    if (PathRules.IsReparsePoint(attributes))
                    {
                        filesSkipped++;
                        continue;
                    }

                    if (PathRules.IsOfflinePlaceholder(attributes))
                    {
                        filesSkipped++;
                        continue;
                    }

                    ScanFile(entry.FullName, attributes);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                AddError(ScanErrors.FromException(directory, ex, _clock));
            }
        }

        try
        {
            Report(ScanPhase.Enumerating, force: true);

            var roots = NormalizeRoots(request.Roots, AddError);
            if (roots.Count == 0)
            {
                AddError(ScanErrors.Custom(
                    string.Empty,
                    ScanErrorKind.InvalidPath,
                    "No scan locations were available.",
                    _clock));
            }

            foreach (var root in roots)
            {
                cancellationToken.ThrowIfCancellationRequested();

                FileAttributes attributes;
                try
                {
                    attributes = File.GetAttributes(root);
                }
                catch (Exception ex)
                {
                    AddError(ScanErrors.FromException(root, ex, _clock));
                    continue;
                }

                if (Directory.Exists(root))
                {
                    if (PathRules.IsReparsePoint(attributes))
                    {
                        directoriesSkipped++;
                        continue;
                    }

                    directories.Clear();
                    directories.Push((root, 0));
                    while (directories.Count > 0)
                    {
                        var (directory, depth) = directories.Pop();
                        EnumerateDirectory(directory, depth);
                    }
                }
                else if (File.Exists(root))
                {
                    if (PathRules.IsReparsePoint(attributes))
                    {
                        AddError(ScanErrors.Custom(
                            root,
                            ScanErrorKind.ReparsePoint,
                            "Symbolic links and other reparse points are skipped for safety.",
                            _clock));
                        filesSkipped++;
                    }
                    else if (PathRules.IsOfflinePlaceholder(attributes))
                    {
                        AddError(ScanErrors.Custom(
                            root,
                            ScanErrorKind.Offline,
                            "Cloud placeholder files are skipped so scanning does not download them.",
                            _clock));
                        filesSkipped++;
                    }
                    else
                    {
                        ScanFile(root, attributes);
                    }
                }
                else
                {
                    AddError(ScanErrors.Custom(
                        root,
                        ScanErrorKind.NotFound,
                        "The scan location no longer exists.",
                        _clock));
                }
            }
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }
        catch (Exception ex)
        {
            AddError(ScanErrors.FromException(string.Empty, ex, _clock));
        }
        finally
        {
            stopwatch.Stop();
            Report(ScanPhase.Finished, force: true);
        }

        var finished = _clock.UtcNow;
        _log.Info(
            "Scan",
            $"Scan finished. scope={request.Scope} files={filesScanned} detections={detections.Count} errors={errorCount} cancelled={cancelled}");

        return new ScanOutcome
        {
            ScanId = request.ScanId,
            Request = request,
            Detections = detections.ToArray(),
            Errors = errors.ToArray(),
            FilesScanned = filesScanned,
            FilesSkipped = filesSkipped,
            DirectoriesSkipped = directoriesSkipped,
            ErrorCount = errorCount,
            BytesInspected = bytesInspected,
            Cancelled = cancelled,
            StartedUtc = started,
            FinishedUtc = finished
        };
    }

    private static List<string> NormalizeRoots(
        IReadOnlyList<string> rawRoots,
        Action<ScanError> addError)
    {
        var roots = new List<string>();
        foreach (var raw in rawRoots)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            try
            {
                var full = Path.GetFullPath(raw.Trim());
                if (!roots.Contains(full, StringComparer.OrdinalIgnoreCase)) roots.Add(full);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                addError(ScanErrors.FromException(raw, ex));
            }
        }

        var result = new List<string>();
        foreach (var root in roots.OrderBy(path => path.Length))
        {
            if (result.Any(parent => PathRules.IsWithin(root, parent))) continue;
            result.Add(root);
        }

        return result;
    }
}

