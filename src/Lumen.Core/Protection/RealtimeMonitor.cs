using System.Collections.Concurrent;
using System.Threading.Channels;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Protection;

/// <summary>
/// On-access ("real-time") monitoring for a configurable set of user folders. A file-system
/// watcher reports created/changed/renamed files; the monitor waits for a file to settle and
/// then re-inspects it with the same detector registry used by on-demand scans.
///
/// This is DETECT-ON-WRITE, NOT BLOCK-ON-WRITE. The monitor observes, it never intercepts:
/// a file can be created, written and executed before the settle delay and the inspection
/// have finished. Lumen is a user-mode watcher, not a driver, and it never covers system
/// folders. It only runs while the application is running.
///
/// Like ScanEngine, this class never writes, moves or deletes files: it only reports matches
/// through the Detection event, and acting on a match (quarantine) stays the caller's
/// explicitly confirmed decision.
/// </summary>
public sealed class RealtimeMonitor : IDisposable
{
    /// <summary>Default number of paths that may wait for inspection at the same time.</summary>
    public const int DefaultMaxPendingPaths = 5000;

    private const int RecentDetectionCap = 512;
    private const int RescanFileCap = 2000;
    private const int MaxLoggedDrops = 5;
    private const int DropLogInterval = 50;

    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(25);
    private static readonly TimeSpan MaxWatcherBackoff = TimeSpan.FromSeconds(30);

    private readonly DetectorRegistry _detectors;
    private readonly IClock _clock;
    private readonly ILog _log;
    private readonly IFileSystemWatcherFactory _watcherFactory;
    private readonly IFileHashProvider _hashProvider;
    private readonly TimeSpan _settleDelay;
    private readonly TimeSpan _detectionCooldown;
    private readonly TimeSpan _watcherRetryDelay;
    private readonly int _maxPendingPaths;

    private readonly object _sessionLock = new();
    private MonitorSession? _session;
    private MonitorConfiguration _configuration;
    private bool _disposed;

    private long _filesChecked;
    private long _filesSkipped;
    private long _errorCount;
    private long _detectionCount;
    private long _droppedPathCount;
    private long _watcherFailureCount;
    private long _loggedDrops;
    private long _lastEventTicks;
    private string? _lastDetectionPath;
    private string? _lastError;

    /// <summary>
    /// Creates a monitor.
    /// </summary>
    /// <param name="detectors">The shared detector registry used for on-demand scans.</param>
    /// <param name="roots">Folders to watch. Roots nested inside another root are dropped so a
    /// folder is never watched twice.</param>
    /// <param name="excludedDirectories">Folders whose entire subtree is skipped.</param>
    /// <param name="maxInspectBytes">Maximum number of leading bytes read per file.</param>
    /// <param name="clock">Clock used for detection timestamps and the detection cooldown.</param>
    /// <param name="log">Diagnostic log. Only paths, sizes and hashes are ever written.</param>
    /// <param name="settleDelay">How long a file must stay unchanged before it is inspected.
    /// The delay never blocks the worker: each path carries its own deadline.</param>
    /// <param name="detectionCooldown">How long a match is not reported twice for the same path.</param>
    /// <param name="watcherFactory">Creates the folder watchers. Inject a fake in tests to
    /// produce watcher failures on demand.</param>
    /// <param name="hashProvider">Computes file digests. Inject a failing implementation to
    /// exercise the "detected but not actionable" path.</param>
    /// <param name="maxPendingPaths">Upper bound on paths waiting for inspection. Paths beyond
    /// the bound are dropped and counted, never silently discarded.</param>
    /// <param name="watcherRetryDelay">Base delay before a failed folder watcher is rebuilt.
    /// The delay doubles with every consecutive failure.</param>
    public RealtimeMonitor(
        DetectorRegistry detectors,
        IReadOnlyList<string> roots,
        IReadOnlyList<string> excludedDirectories,
        long maxInspectBytes,
        IClock clock,
        ILog log,
        TimeSpan? settleDelay = null,
        TimeSpan? detectionCooldown = null,
        IFileSystemWatcherFactory? watcherFactory = null,
        IFileHashProvider? hashProvider = null,
        int maxPendingPaths = DefaultMaxPendingPaths,
        TimeSpan? watcherRetryDelay = null)
    {
        _detectors = detectors;
        _clock = clock;
        _log = log;
        _watcherFactory = watcherFactory ?? new FileSystemWatcherFactory();
        _hashProvider = hashProvider ?? new SystemFileHashProvider();
        _settleDelay = settleDelay ?? TimeSpan.FromMilliseconds(250);
        _detectionCooldown = detectionCooldown ?? TimeSpan.FromMinutes(2);
        _watcherRetryDelay = watcherRetryDelay ?? TimeSpan.FromSeconds(2);
        _maxPendingPaths = Math.Clamp(maxPendingPaths, 16, 1_000_000);

        var exclusions = NormalizeDirectories(excludedDirectories);
        _configuration = new MonitorConfiguration(
            NormalizeRoots(roots, exclusions),
            exclusions,
            ClampInspectBytes(maxInspectBytes),
            CreateProbeReader(maxInspectBytes));
    }

    /// <summary>
    /// The number of leading bytes read per file. The value follows the current configuration
    /// and changes when <see cref="UpdateInspectLimit"/> is called.
    /// </summary>
    public long MaxInspectBytes => Volatile.Read(ref _configuration).MaxInspectBytes;

    /// <summary>The folders currently being watched, after nested duplicates were removed.</summary>
    public IReadOnlyList<string> Roots => Volatile.Read(ref _configuration).Roots;

    /// <summary>The subtree roots that are skipped entirely.</summary>
    public IReadOnlyList<string> ExcludedFolders => Volatile.Read(ref _configuration).ExcludedDirectories;

    /// <summary>True while the worker and the folder watchers are active.</summary>
    public bool IsRunning
    {
        get { lock (_sessionLock) return _session is { Stopping: false }; }
    }

    /// <summary>
    /// How many paths are currently remembered as "recently matched". A deleted file is
    /// removed from this list, so a path can be reported again after it was removed and
    /// created anew.
    /// </summary>
    public int RecentDetectionCount
    {
        get { lock (_sessionLock) return _session?.RecentDetections.Count ?? 0; }
    }

    /// <summary>Raised once per reported match. Handlers run on the worker thread.</summary>
    public event EventHandler<RealtimeDetectionEvent>? Detection;

    /// <summary>
    /// Starts watching the configured roots and inspecting queued files. Safe to call when
    /// already running. Per-session state (recent matches, inspected files) is cleared, so a
    /// restart never inherits a stale cooldown. Folders that cannot be watched are logged and
    /// skipped, and the monitor reports itself as degraded while that is the case.
    /// </summary>
    public void Start()
    {
        MonitorSession session;
        lock (_sessionLock)
        {
            if (_disposed) return;
            if (_session is { Stopping: false }) return;

            var configuration = Volatile.Read(ref _configuration);
            session = new MonitorSession
            {
                Queue = Channel.CreateBounded<string>(
                    new BoundedChannelOptions(_maxPendingPaths)
                    {
                        SingleReader = true,
                        SingleWriter = false,
                        FullMode = BoundedChannelFullMode.Wait
                    }),
                Cts = new CancellationTokenSource(),
                PendingSlots = new SemaphoreSlim(_maxPendingPaths, _maxPendingPaths),
                Cooldown = _detectionCooldown
            };

            foreach (var root in configuration.Roots)
                session.Watchers.Add(new WatcherSlot { Root = root });

            _session = session;

            session.Worker = Task.Run(() => WorkerLoopAsync(session, session.Cts.Token), CancellationToken.None);
            session.Worker.ContinueWith(
                _ =>
                {
                    try { session.Cts.Dispose(); }
                    catch (ObjectDisposedException) { /* already disposed */ }
                },
                TaskScheduler.Default);
        }

        WatcherSlot[] slots;
        int active;
        lock (_sessionLock)
        {
            slots = session.Watchers.ToArray();
            active = CountActiveWatchers(session);
        }

        foreach (var slot in slots) TryCreateWatcher(session, slot);

        _log.Info(
            "Realtime",
            $"Real-time protection started. watching={active} roots={slots.Length}");
    }

    /// <summary>
    /// Stops watching and drains the worker. Safe to call when not running. The call waits
    /// for the worker for a bounded time; prefer <see cref="StopAsync"/> when the caller is
    /// the UI thread, because <see cref="Stop"/> blocks the calling thread while it waits.
    /// </summary>
    public void Stop()
    {
        var session = DetachSession();
        if (session is null) return;

        try
        {
            session.Worker?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException ex)
        {
            _log.Warn("Realtime", "The real-time worker did not stop cleanly.", ex);
        }

        _log.Info("Realtime", "Real-time protection stopped.");
    }

    /// <summary>
    /// Stops watching and awaits the worker. This is the awaitable counterpart of
    /// <see cref="Stop"/> and never blocks the calling thread.
    /// </summary>
    public async Task StopAsync()
    {
        var session = DetachSession();
        if (session is null) return;

        try
        {
            if (session.Worker is not null)
                await session.Worker.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            _log.Warn("Realtime", "The real-time worker did not stop in time.");
        }
        catch (AggregateException ex)
        {
            _log.Warn("Realtime", "The real-time worker did not stop cleanly.", ex);
        }

        _log.Info("Realtime", "Real-time protection stopped.");
    }

    /// <summary>
    /// Replaces the watched folders, the excluded subtrees and (optionally) the inspection
    /// limit while the monitor is running. The watchers are rebuilt so the new folders take
    /// effect immediately; the worker keeps running. This is what the UI calls when the
    /// user changes the real-time settings.
    /// </summary>
    /// <param name="roots">Folders to watch. Nested duplicates are removed automatically.</param>
    /// <param name="excludedDirectories">Folders whose entire subtree is skipped.</param>
    /// <param name="maxInspectBytes">The new inspection limit, or null to keep the current one.</param>
    /// <returns>The outcome of the reconfiguration.</returns>
    public OperationResult Configure(
        IReadOnlyList<string> roots,
        IReadOnlyList<string> excludedDirectories,
        long? maxInspectBytes = null)
    {
        if (_disposed) return OperationResult.Failure("The real-time monitor has been disposed.");

        var current = Volatile.Read(ref _configuration);
        var exclusions = NormalizeDirectories(excludedDirectories);
        var normalizedRoots = NormalizeRoots(roots, exclusions);
        var limit = maxInspectBytes is null ? current.MaxInspectBytes : ClampInspectBytes(maxInspectBytes.Value);
        var configuration = new MonitorConfiguration(normalizedRoots, exclusions, limit, CreateProbeReader(limit));

        var rootsChanged = !normalizedRoots.SequenceEqual(current.Roots, StringComparer.OrdinalIgnoreCase);
        Volatile.Write(ref _configuration, configuration);

        MonitorSession? session;
        lock (_sessionLock) session = _session;
        if (rootsChanged && session is not null) RebuildWatchers(session, normalizedRoots);

        _log.Info(
            "Realtime",
            $"Real-time protection reconfigured. roots={normalizedRoots.Count} excluded={exclusions.Count} inspectBytes={limit}");
        return OperationResult.Success();
    }

    /// <summary>
    /// Changes how many leading bytes are read per file. The change applies to the next file
    /// the worker inspects; no restart is needed.
    /// </summary>
    /// <param name="maxInspectBytes">The new limit. Values outside the supported range are clamped.</param>
    /// <returns>The outcome of the change.</returns>
    public OperationResult UpdateInspectLimit(long maxInspectBytes)
    {
        if (_disposed) return OperationResult.Failure("The real-time monitor has been disposed.");

        var current = Volatile.Read(ref _configuration);
        return Configure(current.Roots, current.ExcludedDirectories, maxInspectBytes);
    }

    /// <summary>
    /// Queues one file for inspection. Excluded paths, directories and duplicates that are
    /// already waiting are ignored. Public so tests (and future callers) can drive inspection
    /// without relying on file-system watcher timing.
    /// </summary>
    public void Enqueue(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;

        MonitorSession? session;
        lock (_sessionLock) session = _session;
        if (session is null || session.Stopping) return;

        var configuration = Volatile.Read(ref _configuration);

        string full;
        try
        {
            full = PathRules.NormalizeFile(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return;
        }

        if (PathRules.IsExcluded(full, configuration.ExcludedDirectories))
        {
            Interlocked.Increment(ref _filesSkipped);
            return;
        }

        // Directories are never inspected. Filtering them here keeps the queue free of
        // work that would be thrown away a moment later.
        try
        {
            if (Directory.Exists(full))
            {
                Interlocked.Increment(ref _filesSkipped);
                return;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // An unreadable path is left to the inspection step, which reports the error.
        }

        Schedule(session, configuration, full);
    }

    /// <summary>Returns a snapshot of the counters and the current coverage.</summary>
    public RealtimeMonitorStats GetStats()
    {
        var configuration = Volatile.Read(ref _configuration);

        MonitorSession? session;
        int watched;
        int queueDepth;
        int pending;
        lock (_sessionLock)
        {
            session = _session;
            watched = session is null ? 0 : CountActiveWatchers(session);
            queueDepth = session is null ? 0 : session.Pending.Count + session.Queue.Reader.Count;
            pending = session?.Pending.Count ?? 0;
        }

        return new RealtimeMonitorStats(
            Interlocked.Read(ref _filesChecked),
            Interlocked.Read(ref _filesSkipped),
            Interlocked.Read(ref _errorCount),
            Interlocked.Read(ref _detectionCount),
            _lastEventTicks == 0 ? null : new DateTimeOffset(_lastEventTicks, TimeSpan.Zero),
            _lastDetectionPath,
            IsRunning)
        {
            WatchedFolderCount = watched,
            ConfiguredFolderCount = configuration.Roots.Count,
            QueueDepth = queueDepth,
            PendingPathCount = pending,
            DroppedPathCount = Interlocked.Read(ref _droppedPathCount),
            WatcherFailureCount = Interlocked.Read(ref _watcherFailureCount),
            LastError = Volatile.Read(ref _lastError),
            IsDegraded = configuration.Roots.Count > 0 && watched < configuration.Roots.Count
        };
    }

    /// <summary>
    /// Builds the folder list the monitor should watch: the standard quick-scan folders plus
    /// the folders the user configured, with nested duplicates removed and fully excluded
    /// folders dropped.
    /// </summary>
    /// <param name="userProfile">The profile whose Desktop, Documents and Downloads folders
    /// are the default watch roots.</param>
    /// <param name="extraWatchFolders">Additional folders the user wants watched.</param>
    /// <param name="excludedFolders">Folders whose subtree is skipped. A root inside one of
    /// them is not watched at all.</param>
    /// <returns>The watch roots, in a stable order, without nested duplicates.</returns>
    public static IReadOnlyList<string> BuildWatchRoots(
        string userProfile,
        IEnumerable<string>? extraWatchFolders = null,
        IEnumerable<string>? excludedFolders = null) =>
        ScanPlanner.RealtimeWatchFolders(userProfile, extraWatchFolders, excludedFolders);

    /// <summary>Stops the monitor and releases the watchers.</summary>
    public void Dispose()
    {
        lock (_sessionLock)
        {
            if (_disposed) return;
            _disposed = true;
        }

        Stop();
    }

    private MonitorSession? DetachSession()
    {
        lock (_sessionLock)
        {
            var session = _session;
            if (session is null) return null;

            _session = null;
            session.Stopping = true;
            foreach (var slot in session.Watchers) DisposeWatcher(slot);
            session.Queue.Writer.TryComplete();
            try
            {
                session.Cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The worker already finished and disposed the token source.
            }

            return session;
        }
    }

    private async Task WorkerLoopAsync(MonitorSession session, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                MoveDuePending(session);
                RecoverWatchers(session);

                while (session.Queue.Reader.TryRead(out var path))
                {
                    if (token.IsCancellationRequested) return;
                    await InspectAsync(session, path, token).ConfigureAwait(false);
                }

                await Task.Delay(PollInterval, token).ConfigureAwait(false);
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

    /// <summary>
    /// Moves paths whose settle deadline has passed into the bounded work queue. The settle
    /// delay never sleeps the worker: a path that keeps being written simply has its
    /// deadline pushed forward until it stops changing.
    /// </summary>
    private void MoveDuePending(MonitorSession session)
    {
        if (session.Pending.Count == 0) return;

        var now = DateTime.UtcNow;
        foreach (var key in session.Pending.Keys)
        {
            if (!session.Pending.TryGetValue(key, out var entry)) continue;
            if (entry.DueUtc > now) continue;
            if (!session.Pending.TryRemove(key, out _)) continue;

            session.PendingSlots.Release();

            if (!session.Queue.Writer.TryWrite(key))
            {
                // The queue is full. This is a real miss and it is reported as one.
                CountDrop(key);
            }
        }
    }

    /// <summary>
    /// Rebuilds watchers whose root vanished or whose watcher failed. The rebuild uses a
    /// backoff that grows with every consecutive failure.
    /// </summary>
    private void RecoverWatchers(MonitorSession session)
    {
        if (!session.HasFailedWatcher) return;

        WatcherSlot[] slots;
        lock (_sessionLock) slots = session.Watchers.ToArray();

        foreach (var slot in slots)
        {
            if (slot.Watcher is not null) continue;
            if (slot.NextAttemptUtc > DateTime.UtcNow) continue;
            TryCreateWatcher(session, slot);
        }
    }

    private void RebuildWatchers(MonitorSession session, IReadOnlyList<string> roots)
    {
        lock (_sessionLock)
        {
            foreach (var slot in session.Watchers) DisposeWatcher(slot);
            session.Watchers.Clear();

            foreach (var root in roots) session.Watchers.Add(new WatcherSlot { Root = root });
            foreach (var slot in session.Watchers.ToArray()) TryCreateWatcher(session, slot);
        }
    }

    private bool TryCreateWatcher(MonitorSession session, WatcherSlot slot)
    {
        try
        {
            if (!Directory.Exists(slot.Root))
            {
                // The folder does not exist (yet). Try again later instead of pretending
                // the folder is covered.
                session.HasFailedWatcher = true;
                slot.Failures++;
                slot.NextAttemptUtc = DateTime.UtcNow + _watcherRetryDelay;
                _log.Info("Realtime", "Watch root does not exist: " + DisplayText.SanitizePath(slot.Root));
                return false;
            }

            var watcher = _watcherFactory.Create(slot.Root);
            watcher.Created += OnWatcherCreated;
            watcher.Changed += OnWatcherChanged;
            watcher.Deleted += OnWatcherDeleted;
            watcher.Renamed += OnWatcherRenamed;
            watcher.Error += OnWatcherError;

            slot.Watcher = watcher;
            watcher.Enable();
            session.HasFailedWatcher = session.Watchers.Any(candidate => candidate.Watcher is null);

            if (slot.Failures > 0)
            {
                // The watcher was rebuilt after a failure. Files that changed while the
                // folder was uncovered are re-inspected so nothing is silently missed.
                _log.Info("Realtime", "A folder watcher was rebuilt: " + DisplayText.SanitizePath(slot.Root));
                RescanRoot(session, slot.Root);
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            slot.Failures++;
            slot.NextAttemptUtc = DateTime.UtcNow + BackoffFor(slot.Failures);
            session.HasFailedWatcher = true;
            Interlocked.Increment(ref _watcherFailureCount);
            SetLastError("A folder could not be watched: " + DisplayText.SanitizePath(slot.Root));
            _log.Warn("Realtime", "A folder could not be watched: " + DisplayText.SanitizePath(slot.Root), ex);
            return false;
        }
    }

    private void RescanRoot(MonitorSession session, string root)
    {
        var configuration = Volatile.Read(ref _configuration);
        var count = 0;
        try
        {
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                if (count++ >= RescanFileCap)
                {
                    _log.Warn("Realtime", "A recovered folder was only partially re-scanned: " + DisplayText.SanitizePath(root));
                    break;
                }

                if (PathRules.IsExcluded(file, configuration.ExcludedDirectories)) continue;
                Schedule(session, configuration, file);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Warn("Realtime", "A recovered folder could not be re-scanned: " + DisplayText.SanitizePath(root), ex);
        }
    }

    private void Schedule(MonitorSession session, MonitorConfiguration configuration, string path)
    {
        var now = DateTime.UtcNow;
        var signal = TryReadSignal(path);
        var due = now + _settleDelay;

        if (session.Pending.TryGetValue(path, out var existing))
        {
            // The file is being written again: push the deadline out instead of inspecting
            // a half-written file.
            session.Pending[path] = existing with { DueUtc = due, Signal = signal ?? existing.Signal };
            return;
        }

        if (!session.PendingSlots.Wait(0))
        {
            CountDrop(path);
            return;
        }

        if (session.Pending.TryAdd(path, new PendingFile(due, signal))) return;

        // Another thread queued the same path first; give the permit back and let the
        // existing entry carry the new deadline.
        session.PendingSlots.Release();
        if (session.Pending.TryGetValue(path, out var current))
            session.Pending[path] = current with { DueUtc = due, Signal = signal ?? current.Signal };
    }

    private async Task InspectAsync(MonitorSession session, string path, CancellationToken token)
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

            var signal = TryReadSignal(path);
            if (signal is not null &&
                session.Inspected.TryGetValue(path, out var previous) &&
                previous == signal.Value)
            {
                // Already inspected and nothing changed since. A file that is written over
                // and over does not have to be re-read and re-hashed every time.
                Interlocked.Increment(ref _filesSkipped);
                return;
            }

            var now = _clock.UtcNow;
            if (_detectionCooldown > TimeSpan.Zero &&
                session.RecentDetections.TryGetValue(path, out var last) &&
                now - last < _detectionCooldown)
            {
                Interlocked.Increment(ref _filesSkipped);
                return;
            }

            var configuration = Volatile.Read(ref _configuration);
            var read = configuration.ProbeReader.Read(path, attributes, token);
            if (!read.Success)
            {
                Interlocked.Increment(ref _errorCount);
                if (read.Error is not null)
                    _log.Warn("Realtime", read.Error.Kind + ": " + DisplayText.SanitizePath(path));
                return;
            }

            Interlocked.Increment(ref _filesChecked);
            if (signal is not null) session.Inspected[path] = signal.Value;

            var findings = _detectors.Inspect(read.Probe!, token);
            if (findings.Count == 0) return;

            var hash = _hashProvider.TryComputeSha256(path, token);

            session.RecentDetections[path] = now;
            PruneRecentDetections(session, now);

            Interlocked.Increment(ref _detectionCount);
            lock (_sessionLock)
            {
                _lastDetectionPath = path;
                _lastEventTicks = now.UtcTicks;
            }

            RaiseDetection(new RealtimeDetectionEvent
            {
                FilePath = path,
                SizeBytes = read.Probe!.SizeBytes,
                Sha256 = hash.Sha256,
                Sha256Error = hash.Error,
                IsActionable = hash.Success,
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

    private static void PruneRecentDetections(MonitorSession session, DateTimeOffset now)
    {
        if (session.RecentDetections.Count <= RecentDetectionCap) return;

        var cutoff = now - session.Cooldown;
        foreach (var pair in session.RecentDetections)
        {
            if (pair.Value < cutoff) session.RecentDetections.TryRemove(pair.Key, out _);
        }

        if (session.RecentDetections.Count <= RecentDetectionCap) return;

        // Deterministic pruning: the oldest entries go first, ties broken by path, so the
        // map never grows without bound and always drops the same entries.
        var excess = session.RecentDetections.Count - RecentDetectionCap;
        var oldest = session.RecentDetections
            .OrderBy(pair => pair.Value)
            .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(excess)
            .ToArray();

        foreach (var pair in oldest) session.RecentDetections.TryRemove(pair.Key, out _);
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

    private void OnWatcherCreated(object? sender, FileSystemEventArgs e) =>
        HandleWatcherEvent(sender, e.ChangeType, e.FullPath);

    private void OnWatcherChanged(object? sender, FileSystemEventArgs e) =>
        HandleWatcherEvent(sender, e.ChangeType, e.FullPath);

    private void OnWatcherRenamed(object? sender, RenamedEventArgs e) =>
        HandleWatcherEvent(sender, e.ChangeType, e.FullPath);

    private void OnWatcherDeleted(object? sender, FileSystemEventArgs e) =>
        HandleWatcherEvent(sender, e.ChangeType, e.FullPath);

    private void HandleWatcherEvent(object? sender, WatcherChangeTypes changeType, string fullPath)
    {
        MonitorSession? session;
        lock (_sessionLock)
        {
            session = _session;
            if (session is null || session.Stopping) return;

            // Events from a watcher that has already been replaced are stale; ignoring them
            // keeps a dead watcher from resurrecting work.
            var known = false;
            foreach (var slot in session.Watchers)
            {
                if (ReferenceEquals(slot.Watcher, sender))
                {
                    known = true;
                    break;
                }
            }

            if (!known) return;
        }

        if (changeType == WatcherChangeTypes.Deleted)
        {
            Forget(session, fullPath);
            return;
        }

        Enqueue(fullPath);
    }

    private void OnWatcherError(object? sender, ErrorEventArgs e)
    {
        WatcherSlot? slot = null;
        lock (_sessionLock)
        {
            var session = _session;
            if (session is null) return;

            foreach (var candidate in session.Watchers)
            {
                if (ReferenceEquals(candidate.Watcher, sender))
                {
                    slot = candidate;
                    break;
                }
            }

            if (slot is null) return;

            slot.Failures++;
            slot.NextAttemptUtc = DateTime.UtcNow + BackoffFor(slot.Failures);
            DisposeWatcher(slot);
            session.HasFailedWatcher = true;
        }

        Interlocked.Increment(ref _watcherFailureCount);

        var reason = e.GetException();
        var message = "A folder watcher failed: " + DisplayText.SanitizePath(slot!.Root) +
                      (reason is null ? string.Empty : " (" + reason.GetType().Name + ")");
        SetLastError(message);
        _log.Warn("Realtime", message + ". The watcher will be rebuilt and the folder re-scanned.");
    }

    /// <summary>
    /// Forgets everything the monitor remembers about a path. A deleted file must not stay
    /// in the recent-match map, otherwise the cooldown would suppress a file that is created
    /// again later.
    /// </summary>
    private void Forget(MonitorSession session, string path)
    {
        string full;
        try
        {
            full = PathRules.NormalizeFile(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return;
        }

        if (session.Pending.TryRemove(full, out _)) session.PendingSlots.Release();
        session.RecentDetections.TryRemove(full, out _);
        session.Inspected.TryRemove(full, out _);
    }

    private static int CountActiveWatchers(MonitorSession session)
    {
        var count = 0;
        foreach (var slot in session.Watchers)
        {
            if (slot.Watcher is not null) count++;
        }

        return count;
    }

    private void DisposeWatcher(WatcherSlot slot)
    {
        var watcher = slot.Watcher;
        slot.Watcher = null;
        if (watcher is null) return;

        try
        {
            watcher.Created -= OnWatcherCreated;
            watcher.Changed -= OnWatcherChanged;
            watcher.Deleted -= OnWatcherDeleted;
            watcher.Renamed -= OnWatcherRenamed;
            watcher.Error -= OnWatcherError;
            watcher.Disable();
            watcher.Dispose();
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // The watcher is being thrown away; a failure to close it changes nothing.
        }
    }

    private TimeSpan BackoffFor(int failures)
    {
        var exponent = Math.Clamp(failures - 1, 0, 5);
        var ticks = _watcherRetryDelay.Ticks * (1L << exponent);
        return TimeSpan.FromTicks(Math.Min(ticks, MaxWatcherBackoff.Ticks));
    }

    private void CountDrop(string path)
    {
        var total = Interlocked.Increment(ref _droppedPathCount);
        var logged = Interlocked.Increment(ref _loggedDrops);
        if (logged <= MaxLoggedDrops || logged % DropLogInterval == 0)
        {
            _log.Warn(
                "Realtime",
                "The real-time queue is full; a file was not inspected: " + DisplayText.SanitizePath(path) +
                $" (dropped={total})");
        }

        SetLastError("The real-time queue is full; some files were not inspected.");
    }

    private void SetLastError(string message) => Volatile.Write(ref _lastError, DisplayText.Sanitize(message));

    private static FileSignal? TryReadSignal(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return null;
            if ((info.Attributes & FileAttributes.Directory) != 0) return null;
            return new FileSignal(info.LastWriteTimeUtc, info.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // The file may not exist yet, or may be locked. The inspection step decides.
            return null;
        }
    }

    private static ProbeReader CreateProbeReader(long maxInspectBytes) =>
        new(checked((int)ClampInspectBytes(maxInspectBytes)));

    private static long ClampInspectBytes(long maxInspectBytes) =>
        Math.Clamp(maxInspectBytes, 64 * 1024, 16 * 1024 * 1024);

    private static IReadOnlyList<string> NormalizeDirectories(IEnumerable<string>? directories)
    {
        if (directories is null) return [];

        var result = new List<string>();
        foreach (var directory in directories)
        {
            if (string.IsNullOrWhiteSpace(directory)) continue;
            try
            {
                var full = PathRules.NormalizeDirectory(directory);
                if (!result.Contains(full, StringComparer.OrdinalIgnoreCase)) result.Add(full);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // A malformed rule is ignored rather than breaking monitoring.
            }
        }

        return result;
    }

    private static IReadOnlyList<string> NormalizeRoots(
        IEnumerable<string>? roots,
        IReadOnlyList<string> excludedDirectories)
    {
        if (roots is null) return [];

        var normalized = new List<string>();
        foreach (var root in roots)
        {
            if (string.IsNullOrWhiteSpace(root)) continue;
            try
            {
                var full = PathRules.NormalizeDirectory(root);
                if (!normalized.Contains(full, StringComparer.OrdinalIgnoreCase)) normalized.Add(full);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // A malformed root is ignored rather than breaking monitoring.
            }
        }

        // A root that lies inside an excluded subtree is not watched at all.
        normalized = normalized
            .Where(root => !PathRules.IsExcluded(root, excludedDirectories))
            .ToList();

        // Remove roots nested inside another root so no folder is watched twice.
        var result = new List<string>();
        foreach (var root in normalized.OrderBy(path => path.Length))
        {
            var nested = false;
            foreach (var parent in result)
            {
                if (!PathRules.IsWithin(root, parent)) continue;
                nested = true;
                break;
            }

            if (!nested) result.Add(root);
        }

        return result;
    }

    private sealed record MonitorConfiguration(
        IReadOnlyList<string> Roots,
        IReadOnlyList<string> ExcludedDirectories,
        long MaxInspectBytes,
        ProbeReader ProbeReader);

    private sealed record PendingFile(DateTime DueUtc, FileSignal? Signal);

    private readonly record struct FileSignal(DateTime LastWriteUtc, long Length);

    private sealed class WatcherSlot
    {
        public required string Root { get; init; }
        public IFileSystemWatcher? Watcher { get; set; }
        public int Failures { get; set; }
        public DateTime NextAttemptUtc { get; set; }
    }

    private sealed class MonitorSession
    {
        public required Channel<string> Queue { get; init; }
        public required CancellationTokenSource Cts { get; init; }
        public required SemaphoreSlim PendingSlots { get; init; }
        public Task? Worker { get; set; }
        public bool Stopping { get; set; }
        public volatile bool HasFailedWatcher;
        public TimeSpan Cooldown { get; init; } = TimeSpan.FromMinutes(2);
        public ConcurrentDictionary<string, PendingFile> Pending { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<string, DateTimeOffset> RecentDetections { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<string, FileSignal> Inspected { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<WatcherSlot> Watchers { get; } = [];
    }
}
