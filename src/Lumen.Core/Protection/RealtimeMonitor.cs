using System.Collections.Concurrent;
using System.Threading.Channels;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Protection;

/// <summary>
/// On-access ("real-time") monitoring for a fixed set of user folders. A file-system watcher
/// reports created/changed/renamed files; a single worker re-inspects them with the same
/// detector registry used by on-demand scans. Like ScanEngine, this class never writes, moves
/// or deletes files: it only reports matches through the Detection event, and acting on a
/// match (quarantine) stays the caller's explicitly confirmed decision. It runs only while
/// the app is running; it is not a driver and does not cover system folders.
/// </summary>
public sealed class RealtimeMonitor : IDisposable
{
    private const int MaxPendingPaths = 5000;
    private const int RecentDetectionCap = 512;

    private readonly DetectorRegistry _detectors;
    private readonly IReadOnlyList<string> _roots;
    private readonly IReadOnlyList<string> _excludedDirectories;
    private readonly TimeSpan _settleDelay;
    private readonly TimeSpan _detectionCooldown;
    private readonly IClock _clock;
    private readonly ILog _log;
    private readonly ProbeReader _probeReader;
    private readonly ConcurrentDictionary<string, byte> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentDetections = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly object _gate = new();

    private Channel<string>? _queue;
    private CancellationTokenSource? _cts;
    private Task? _worker;
    private long _filesChecked;
    private long _filesSkipped;
    private long _errorCount;
    private long _detectionCount;
    private long _lastEventTicks;
    private string? _lastDetectionPath;
    private bool _disposed;

    public RealtimeMonitor(
        DetectorRegistry detectors,
        IReadOnlyList<string> roots,
        IReadOnlyList<string> excludedDirectories,
        long maxInspectBytes,
        IClock clock,
        ILog log,
        TimeSpan? settleDelay = null,
        TimeSpan? detectionCooldown = null)
    {
        _detectors = detectors;
        _roots = roots
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Select(NormalizeSafely)
            .Where(root => root is not null)
            .Select(root => root!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        _excludedDirectories = excludedDirectories
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(NormalizeSafely)
            .Where(path => path is not null)
            .Select(path => path!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        MaxInspectBytes = Math.Clamp(maxInspectBytes, 64 * 1024, 16 * 1024 * 1024);
        _probeReader = new ProbeReader(checked((int)MaxInspectBytes));
        _settleDelay = settleDelay ?? TimeSpan.FromMilliseconds(250);
        _detectionCooldown = detectionCooldown ?? TimeSpan.FromMinutes(2);
        _clock = clock;
        _log = log;
    }

    /// <summary>Bounded prefix read per file, matching the on-demand scan limit.</summary>
    public long MaxInspectBytes { get; }

    public IReadOnlyList<string> Roots => _roots;

    public bool IsRunning
    {
        get { lock (_gate) return _worker is { IsCompleted: false }; }
    }

    /// <summary>Raised once per reported match. Handlers run on the worker thread.</summary>
    public event EventHandler<RealtimeDetectionEvent>? Detection;
    /// <summary>
    /// Starts watching the configured roots and inspecting queued files. Safe to call when
    /// already running. Folders that cannot be watched are logged and skipped.
    /// </summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_disposed || _worker is { IsCompleted: false }) return;

            _pending.Clear();
            _queue = Channel.CreateUnbounded<string>(
                new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });
            _cts = new CancellationTokenSource();
            var reader = _queue.Reader;
            var token = _cts.Token;
            _worker = Task.Run(() => WorkerLoopAsync(reader, token), CancellationToken.None);

            foreach (var root in _roots)
            {
                try
                {
                    if (!Directory.Exists(root))
                    {
                        _log.Info("Realtime", "Watch root does not exist: " + root);
                        continue;
                    }

                    var watcher = new FileSystemWatcher(root)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                                       NotifyFilters.Size | NotifyFilters.DirectoryName,
                        EnableRaisingEvents = false
                    };
                    watcher.Created += OnFileSystemEvent;
                    watcher.Changed += OnFileSystemEvent;
                    watcher.Renamed += OnFileSystemRenamed;
                    watcher.Error += OnWatcherError;
                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    _log.Warn("Realtime", "A folder could not be watched: " + root, ex);
                }
            }

            _log.Info("Realtime", $"Real-time protection started. watching={_watchers.Count} roots={_roots.Count}");
        }
    }

    /// <summary>Stops watching and drains the worker. Safe to call when not running.</summary>
    public void Stop()
    {
        Task? worker;
        lock (_gate)
        {
            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Created -= OnFileSystemEvent;
                    watcher.Changed -= OnFileSystemEvent;
                    watcher.Renamed -= OnFileSystemRenamed;
                    watcher.Error -= OnWatcherError;
                    watcher.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Warn("Realtime", "A watcher could not be stopped cleanly.", ex);
                }
            }

            _watchers.Clear();
            _queue?.Writer.TryComplete();
            _cts?.Cancel();
            worker = _worker;
            _worker = null;
            _pending.Clear();
        }

        try
        {
            worker?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException ex)
        {
            _log.Warn("Realtime", "The real-time worker did not stop cleanly.", ex);
        }

        lock (_gate)
        {
            _cts?.Dispose();
            _cts = null;
            _queue = null;
        }

        _log.Info("Realtime", "Real-time protection stopped.");
    }

    /// <summary>
    /// Queues one file for inspection. Excluded paths and duplicates already pending are
    /// ignored. Public so tests (and future callers) can drive inspection without relying
    /// on file-system watcher timing.
    /// </summary>
    public void Enqueue(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        if (_worker is not { IsCompleted: false }) return;

        string full;
        try
        {
            full = PathRules.NormalizeFile(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return;
        }

        if (PathRules.IsExcluded(full, _excludedDirectories)) return;
        if (_pending.Count >= MaxPendingPaths)
        {
            Interlocked.Increment(ref _filesSkipped);
            return;
        }

        if (!_pending.TryAdd(full, 0)) return;

        var queue = _queue;
        if (queue is null || !queue.Writer.TryWrite(full)) _pending.TryRemove(full, out _);
    }

    public RealtimeMonitorStats GetStats()
    {
        lock (_gate)
        {
            return new RealtimeMonitorStats(
                Interlocked.Read(ref _filesChecked),
                Interlocked.Read(ref _filesSkipped),
                Interlocked.Read(ref _errorCount),
                Interlocked.Read(ref _detectionCount),
                _lastEventTicks == 0 ? null : new DateTimeOffset(_lastEventTicks, TimeSpan.Zero),
                _lastDetectionPath,
                IsRunning);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
        }

        Stop();
    }
    private async Task WorkerLoopAsync(ChannelReader<string> reader, CancellationToken token)
    {
        try
        {
            while (await reader.WaitToReadAsync(token).ConfigureAwait(false))
            {
                while (reader.TryRead(out var path))
                {
                    _pending.TryRemove(path, out _);
                    await ProcessAsync(path, token).ConfigureAwait(false);
                    if (token.IsCancellationRequested) return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during Stop/Dispose.
        }
        catch (Exception ex)
        {
            _log.Error("Realtime", "The real-time worker stopped unexpectedly.", ex);
        }
    }

    private async Task ProcessAsync(string path, CancellationToken token)
    {
        try
        {
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(path);
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
                // Created and deleted again before we got to it; nothing to inspect.
                Interlocked.Increment(ref _filesSkipped);
                return;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                Interlocked.Increment(ref _errorCount);
                _log.Warn("Realtime", "File attributes could not be read: " + ex.GetType().Name);
                return;
            }

            if ((attributes & FileAttributes.Directory) != 0)
            {
                Interlocked.Increment(ref _filesSkipped);
                return;
            }

            if (PathRules.IsReparsePoint(attributes) || PathRules.IsOfflinePlaceholder(attributes))
            {
                Interlocked.Increment(ref _filesSkipped);
                return;
            }

            var now = _clock.UtcNow;
            if (_detectionCooldown > TimeSpan.Zero &&
                _recentDetections.TryGetValue(path, out var last) &&
                now - last < _detectionCooldown)
            {
                Interlocked.Increment(ref _filesSkipped);
                return;
            }

            if (_settleDelay > TimeSpan.Zero)
                await Task.Delay(_settleDelay, token).ConfigureAwait(false);

            var read = _probeReader.Read(path, attributes, token);
            if (!read.Success)
            {
                Interlocked.Increment(ref _errorCount);
                if (read.Error is not null)
                    _log.Warn("Realtime", read.Error.Kind + ": " + path);
                return;
            }

            Interlocked.Increment(ref _filesChecked);

            var findings = _detectors.Inspect(read.Probe!, token);
            if (findings.Count == 0) return;

            string? hash = null;
            try
            {
                hash = HashUtil.Sha256File(path, token);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                // The hash is optional context; a locked file must not block the report.
            }

            _recentDetections[path] = now;
            PruneRecentDetections(now);

            Interlocked.Increment(ref _detectionCount);
            lock (_gate)
            {
                _lastDetectionPath = path;
                _lastEventTicks = now.UtcTicks;
            }

            RaiseDetection(new RealtimeDetectionEvent
            {
                FilePath = path,
                SizeBytes = read.Probe!.SizeBytes,
                Sha256 = hash,
                Findings = findings,
                DetectedUtc = now
            });
        }
        catch (OperationCanceledException)
        {
            // Expected during Stop/Dispose.
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _errorCount);
            _log.Warn("Realtime", "Real-time inspection failed.", ex);
        }
    }

    private void PruneRecentDetections(DateTimeOffset now)
    {
        if (_recentDetections.Count <= RecentDetectionCap) return;

        var cutoff = now - _detectionCooldown;
        foreach (var pair in _recentDetections)
        {
            if (pair.Value < cutoff) _recentDetections.TryRemove(pair.Key, out _);
        }
    }

    private void RaiseDetection(RealtimeDetectionEvent detectionEvent)
    {
        var handlers = Detection;
        if (handlers is null) return;

        foreach (var handler in handlers.GetInvocationList())
        {
            try
            {
                ((EventHandler<RealtimeDetectionEvent>)handler)(this, detectionEvent);
            }
            catch (Exception ex)
            {
                // One bad subscriber must not kill monitoring for the rest of the session.
                _log.Warn("Realtime", "A real-time detection handler threw an exception.", ex);
            }
        }
    }

    private void OnFileSystemEvent(object sender, FileSystemEventArgs e) => Enqueue(e.FullPath);

    private void OnFileSystemRenamed(object sender, RenamedEventArgs e) => Enqueue(e.FullPath);

    private void OnWatcherError(object sender, ErrorEventArgs e) =>
        _log.Warn("Realtime", "A folder watcher reported an error; monitoring continues.", e.GetException());

    private static string? NormalizeSafely(string path)
    {
        try
        {
            return PathRules.NormalizeDirectory(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }
}