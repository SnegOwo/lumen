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
/// To keep the answer short, the monitor keeps a small pool of workers: several files are
/// inspected at the same time, so a burst of ten downloads does not turn into ten
/// inspections in a row. The settle delay is spent OUTSIDE the workers. A path that is
/// still being written waits for its own deadline and never occupies a worker, and a file
/// that keeps changing is re-armed (its deadline moves out) instead of being queued again.
///
/// Like ScanEngine, this class never writes, moves or deletes files: it only reports matches
/// through the Detection event, and acting on a match (quarantine) stays the caller's
/// explicitly confirmed decision.
/// </summary>
public sealed class RealtimeMonitor : IDisposable
{
    /// <summary>Default number of paths that may wait for inspection at the same time.</summary>
    public const int DefaultMaxPendingPaths = 5000;

    /// <summary>
    /// Default number of files that are inspected at the same time. Three workers keep the
    /// monitor responsive on a busy folder without burning a whole processor on a download
    /// that is still in progress.
    /// </summary>
    public const int DefaultWorkerCount = 3;

    /// <summary>Smallest number of workers the monitor accepts.</summary>
    public const int MinWorkerCount = 1;

    /// <summary>
    /// Largest number of workers the monitor accepts. More workers only help while the disk
    /// is not the bottleneck; the upper bound keeps a busy machine usable.
    /// </summary>
    public const int MaxWorkerCount = 8;

    /// <summary>
    /// Default settle delay: how long a file has to stay unchanged before it is inspected.
    /// The delay is short on purpose. A file that is still changing is re-armed rather than
    /// being inspected half-written, so a longer delay buys very little.
    /// </summary>
    public static readonly TimeSpan DefaultSettleDelay = TimeSpan.FromMilliseconds(150);

    private const int RecentDetectionCap = 512;
    private const int RescanFileCap = 2000;
    private const int MaxLoggedDrops = 5;
    private const int DropLogInterval = 50;

    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan MaxWatcherBackoff = TimeSpan.FromSeconds(30);

    private readonly DetectorRegistry _detectors;
    private readonly IClock _clock;
    private readonly ILog _log;
    private readonly IFileSystemWatcherFactory _watcherFactory;
    private readonly IFileHashProvider _hashProvider;
    private readonly TimeSpan _detectionCooldown;
    private readonly TimeSpan _watcherRetryDelay;
    private readonly int _maxPendingPaths;

    // The settle delay and the worker count can change while the monitor runs, so they are
    // read and written atomically instead of being frozen in a readonly field.
    private long _settleDelayTicks;
    private int _workerCount;

    // Aggressive mode is a flag, not a behaviour of its own: the behaviour comes from the
    // watch roots and from the settle delay and worker count that go with it. The flag is
    // kept so the interface can say what the monitor is running with.
    private volatile bool _aggressiveMode;

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
    private int _liveWorkers;
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
    /// The delay never blocks a worker: each path carries its own deadline and a path that
    /// keeps changing is re-armed instead of occupying the queue.</param>
    /// <param name="detectionCooldown">How long a match is not reported twice for the same path.</param>
    /// <param name="watcherFactory">Creates the folder watchers. Inject a fake in tests to
    /// produce watcher failures on demand.</param>
    /// <param name="hashProvider">Computes file digests. Inject a failing implementation to
    /// exercise the "detected but not actionable" path.</param>
    /// <param name="maxPendingPaths">Upper bound on paths waiting for inspection. Paths beyond
    /// the bound are dropped and counted, never silently discarded.</param>
    /// <param name="watcherRetryDelay">Base delay before a failed folder watcher is rebuilt.
    /// The delay doubles with every consecutive failure.</param>
    /// <param name="workerCount">How many files may be inspected at the same time. Values
    /// outside <see cref="MinWorkerCount"/>..<see cref="MaxWorkerCount"/> are clamped.</param>
    /// <param name="aggressiveMode">
    /// True when the monitor runs in aggressive mode. The flag itself changes nothing:
    /// the aggressive watch roots and the faster settings come from
    /// <see cref="ResolveConfiguration"/>, and this only records which mode the monitor
    /// was told about, so the interface can say so honestly.
    /// </param>
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
        TimeSpan? watcherRetryDelay = null,
        int workerCount = DefaultWorkerCount,
        bool aggressiveMode = false)
    {
        _detectors = detectors;
        _clock = clock;
        _log = log;
        _watcherFactory = watcherFactory ?? new FileSystemWatcherFactory();
        _hashProvider = hashProvider ?? new SystemFileHashProvider();
        Volatile.Write(ref _settleDelayTicks, (settleDelay ?? DefaultSettleDelay).Ticks);
        _detectionCooldown = detectionCooldown ?? TimeSpan.FromMinutes(2);
        _watcherRetryDelay = watcherRetryDelay ?? TimeSpan.FromSeconds(2);
        _maxPendingPaths = Math.Clamp(maxPendingPaths, 16, 1_000_000);
        Volatile.Write(ref _workerCount, Math.Clamp(workerCount, MinWorkerCount, MaxWorkerCount));
        _aggressiveMode = aggressiveMode;

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

    /// <summary>
    /// How long a file must stay unchanged before it is inspected. The delay is spent outside
    /// the workers, so a settling file never slows down the files behind it.
    /// </summary>
    public TimeSpan SettleDelay => TimeSpan.FromTicks(Volatile.Read(ref _settleDelayTicks));

    /// <summary>
    /// How many files may be inspected at the same time. More workers mean a shorter answer
    /// when several files arrive together; they also mean more disk reads at the same time.
    /// </summary>
    public int WorkerCount => Volatile.Read(ref _workerCount);

    /// <summary>
    /// True when the monitor was told to run in aggressive mode.
    ///
    /// <para>
    /// The flag is a label, not a behaviour: the aggressive watch roots, the zero settle
    /// delay and the larger worker pool come from <see cref="ResolveConfiguration"/>. The
    /// interface shows this flag so it can tell the user that aggressive mode is on and
    /// that it costs more CPU and covers more folders.
    /// </para>
    /// </summary>
    public bool AggressiveMode => _aggressiveMode;

    /// <summary>True while the workers and the folder watchers are active.</summary>
    public bool IsRunning
    {
        get { lock (_sessionLock) return _session is { Stopping: false }; }
    }

    /// <summary>
    /// How many of the monitor's background threads are alive right now: the workers plus
    /// the scheduler that hands the ready paths to them. The value is zero while the
    /// monitor is stopped, which is how a caller can tell that nothing is left running in
    /// the background.
    /// </summary>
    public int ActiveWorkerCount => Volatile.Read(ref _liveWorkers);

    /// <summary>
    /// How many paths are currently remembered as "recently matched". A deleted file is
    /// removed from this list, so a path can be reported again after it was removed and
    /// created anew.
    /// </summary>
    public int RecentDetectionCount
    {
        get { lock (_sessionLock) return _session?.RecentDetections.Count ?? 0; }
    }

    /// <summary>
    /// Raised once per reported match. Handlers run on the worker that found the match, so a
    /// slow handler holds up that one worker and not the whole monitor.
    /// </summary>
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
            session = new MonitorSession(
                WorkerLoop,
                () => Interlocked.Increment(ref _liveWorkers),
                () => Interlocked.Decrement(ref _liveWorkers))
            {
                // Several workers read from the same channel. The channel is only a hand-off
                // point: the pending ledger decides whether a path is still due, so a path
                // that was re-armed while it waited is never inspected twice.
                Queue = Channel.CreateBounded<string>(
                    new BoundedChannelOptions(_maxPendingPaths)
                    {
                        SingleReader = false,
                        SingleWriter = false,
                        FullMode = BoundedChannelFullMode.Wait
                    }),
                Cts = new CancellationTokenSource(),
                Pending = new PendingLedger(_maxPendingPaths),
                Cooldown = _detectionCooldown
            };

            foreach (var root in configuration.Roots)
                session.Watchers.Add(new WatcherSlot { Root = root });

            _session = session;

            // One scheduler moves the paths whose settle deadline has passed into the ready
            // queue. It is separate from the workers on purpose: a busy worker must never
            // delay a file that is already due.
            session.WorkerStarted();
            session.AddTask(Task.Factory.StartNew(
                () => SchedulerLoop(session, session.Cts.Token),
                CancellationToken.None,
                TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
                TaskScheduler.Default));

            // The workers are the ones that read the files. The count follows the current
            // setting, so a caller may change it while the monitor runs.
            session.StartWorkers(WorkerCount);
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
            $"Real-time protection started. watching={active} roots={slots.Length} " +
            $"workers={WorkerCount} settleMs={SettleDelay.TotalMilliseconds:0}");
    }

    /// <summary>
    /// Stops watching and drains the workers. Safe to call when not running. The call waits
    /// for the workers for a bounded time; prefer <see cref="StopAsync"/> when the caller is
    /// the UI thread, because <see cref="Stop"/> blocks the calling thread while it waits.
    /// </summary>
    public void Stop()
    {
        var session = DetachSession();
        if (session is null) return;

        try
        {
            if (session.WaitForCompletion(TimeSpan.FromSeconds(2)))
                session.Dispose();
        }
        catch (AggregateException ex)
        {
            _log.Warn("Realtime", "The real-time workers did not stop cleanly.", ex);
        }

        _log.Info("Realtime", "Real-time protection stopped.");
    }

    /// <summary>
    /// Stops watching and awaits the workers. This is the awaitable counterpart of
    /// <see cref="Stop"/> and never blocks the calling thread.
    /// </summary>
    public async Task StopAsync()
    {
        var session = DetachSession();
        if (session is null) return;

        try
        {
            if (await session.WaitForCompletionAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false))
                session.Dispose();
        }
        catch (TimeoutException)
        {
            _log.Warn("Realtime", "The real-time workers did not stop in time.");
        }
        catch (AggregateException ex)
        {
            _log.Warn("Realtime", "The real-time workers did not stop cleanly.", ex);
        }

        _log.Info("Realtime", "Real-time protection stopped.");
    }

    /// <summary>
    /// Replaces the watched folders, the excluded subtrees and (optionally) the inspection
    /// limit, the settle delay and the worker count while the monitor is running. The
    /// watchers are rebuilt so the new folders take effect immediately; the workers keep
    /// running. This is what the UI calls when the user changes the real-time settings.
    /// </summary>
    /// <param name="roots">Folders to watch. Nested duplicates are removed automatically.</param>
    /// <param name="excludedDirectories">Folders whose entire subtree is skipped.</param>
    /// <param name="maxInspectBytes">The new inspection limit, or null to keep the current one.</param>
    /// <param name="settleDelay">The new settle delay, or null to keep the current one. The
    /// new delay applies to the files that are queued from now on; a file that is already
    /// waiting keeps the deadline it has.</param>
    /// <param name="workerCount">The new number of workers, or null to keep the current one.
    /// Workers that are no longer needed finish the file they are reading and then stop.</param>
    /// <param name="aggressiveMode">
    /// True or false to record the mode the monitor runs in, or null to keep the current
    /// one. The flag itself changes nothing: the watch roots, the settle delay and the
    /// worker count are what aggressive mode really means.
    /// </param>
    /// <returns>The outcome of the reconfiguration.</returns>
    public OperationResult Configure(
        IReadOnlyList<string> roots,
        IReadOnlyList<string> excludedDirectories,
        long? maxInspectBytes = null,
        TimeSpan? settleDelay = null,
        int? workerCount = null,
        bool? aggressiveMode = null)
    {
        if (_disposed) return OperationResult.Failure("The real-time monitor has been disposed.");

        var current = Volatile.Read(ref _configuration);
        var exclusions = NormalizeDirectories(excludedDirectories);
        var normalizedRoots = NormalizeRoots(roots, exclusions);
        var limit = maxInspectBytes is null ? current.MaxInspectBytes : ClampInspectBytes(maxInspectBytes.Value);
        var configuration = new MonitorConfiguration(normalizedRoots, exclusions, limit, CreateProbeReader(limit));

        var rootsChanged = !normalizedRoots.SequenceEqual(current.Roots, StringComparer.OrdinalIgnoreCase);
        Volatile.Write(ref _configuration, configuration);

        if (settleDelay is not null) Volatile.Write(ref _settleDelayTicks, settleDelay.Value.Ticks);

        MonitorSession? session;
        lock (_sessionLock) session = _session;
        if (rootsChanged && session is not null) RebuildWatchers(session, normalizedRoots);

        if (workerCount is not null)
        {
            var workers = Math.Clamp(workerCount.Value, MinWorkerCount, MaxWorkerCount);
            Volatile.Write(ref _workerCount, workers);
            session?.AdjustWorkers(workers);
        }

        if (aggressiveMode is not null) _aggressiveMode = aggressiveMode.Value;

        _log.Info(
            "Realtime",
            $"Real-time protection reconfigured. roots={normalizedRoots.Count} excluded={exclusions.Count} " +
            $"inspectBytes={limit} workers={WorkerCount} settleMs={SettleDelay.TotalMilliseconds:0}");
        return OperationResult.Success();
    }

    /// <summary>
    /// Changes how many leading bytes are read per file. The change applies to the next file
    /// a worker inspects; no restart is needed.
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

        Schedule(session, full);
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
            queueDepth = session is null ? 0 : session.Pending.QueueDepth;
            pending = session?.Pending.WaitingCount ?? 0;
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
            IsAggressiveMode = AggressiveMode,
            QueueDepth = queueDepth,
            PendingPathCount = pending,
            DroppedPathCount = Interlocked.Read(ref _droppedPathCount),
            WatcherFailureCount = Interlocked.Read(ref _watcherFailureCount),
            WorkerCount = WorkerCount,
            ActiveWorkerCount = ActiveWorkerCount,
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

    /// <summary>
    /// Builds the AGGRESSIVE watch list: the standard watch roots plus the folders a
    /// dropper uses — the Downloads folder, the per-user Startup folder and the
    /// per-user temporary folder — minus everything inside an excluded subtree, with
    /// nested folders removed so no folder is watched twice.
    ///
    /// <para>
    /// This costs more than the standard list: more folders mean more file-system events
    /// and more files to inspect. The interface shows how many folders are watched, so
    /// the user is never surprised by the bill.
    /// </para>
    /// </summary>
    /// <param name="userProfile">The profile whose dropper locations are added.</param>
    /// <param name="extraWatchFolders">Additional folders the user wants watched.</param>
    /// <param name="excludedFolders">
    /// Folders whose subtree is skipped. A root inside one of them is not watched at
    /// all, and the dropper locations are skipped the same way.
    /// </param>
    /// <returns>The watch roots, in a stable order, without nested duplicates.</returns>
    public static IReadOnlyList<string> AggressiveWatchRoots(
        string userProfile,
        IEnumerable<string>? extraWatchFolders = null,
        IEnumerable<string>? excludedFolders = null) =>
        AggressiveWatchList.Build(userProfile, extraWatchFolders, excludedFolders);

    /// <summary>
    /// Turns the user's settings into the configuration the monitor runs with.
    ///
    /// <para>
    /// Aggressive mode watches more folders, stops waiting (the settle delay goes to
    /// zero) and uses more workers. Everything else stays exactly as it is, and nothing
    /// about the settings makes the monitor delete anything: what happens to a match is
    /// decided by <see cref="RealtimeResponsePolicy"/>, and only after the user asked
    /// for it.
    /// </para>
    ///
    /// <para>
    /// The application and the tests both go through this method, so there is exactly
    /// one answer to "what does aggressive mode actually do".
    /// </para>
    /// </summary>
    /// <param name="settings">The user's settings. They are normalized first.</param>
    /// <param name="userProfile">The profile whose folders are watched.</param>
    /// <param name="additionalExcludedFolders">
    /// Folders to skip on top of the ones in the settings. The application passes
    /// Lumen's own data folder here, so Lumen never watches itself.
    /// </param>
    /// <returns>The effective configuration.</returns>
    public static RealtimeConfiguration ResolveConfiguration(
        AppSettings settings,
        string userProfile,
        IEnumerable<string>? additionalExcludedFolders = null) =>
        RealtimeConfigurationResolver.Resolve(settings, userProfile, additionalExcludedFolders);

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
                // The workers already finished and disposed the token source.
            }

            return session;
        }
    }

    /// <summary>
    /// Moves the paths whose settle deadline has passed into the ready queue. This runs on
    /// its own thread, so a worker that is busy with a large file cannot hold up a file that
    /// is already due. A path that keeps being written is re-armed: its deadline moves out
    /// and it never reaches the queue.
    /// </summary>
    private void SchedulerLoop(MonitorSession session, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var due = session.Pending.TakeDue(DateTime.UtcNow);
                foreach (var path in due)
                {
                    if (session.Queue.Writer.TryWrite(path)) continue;

                    // The ready queue is full. The path stays pending and is tried again
                    // shortly, so the file waits a little longer instead of being lost.
                    session.Pending.RevertToWaiting(path);
                    LogReadyQueueFull();
                    break;
                }

                // A folder watcher that failed is rebuilt here, so a broken watcher is
                // repaired even while every worker is busy.
                RecoverWatchers(session);

                // Wait for a new path, or for the next poll if nothing arrives.
                session.WaitForWork(PollInterval);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during Stop/Dispose.
        }
        catch (Exception ex)
        {
            _log.Error("Realtime", "The real-time scheduler stopped unexpectedly.", ex);
        }
        finally
        {
            session.WorkerFinished();
        }
    }

    /// <summary>
    /// Reads ready paths and inspects them. Several workers run this loop at the same time;
    /// the pending ledger guarantees that one path is never inspected twice at once.
    /// </summary>
    private void WorkerLoop(MonitorSession session, CancellationTokenSource workerCts)
    {
        var token = workerCts.Token;
        try
        {
            while (!token.IsCancellationRequested)
            {
                string path;
                try
                {
                    if (!session.Queue.Reader.WaitToReadAsync(token).AsTask().GetAwaiter().GetResult()) break;
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ChannelClosedException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                if (!session.Queue.Reader.TryRead(out path!)) continue;

                // The ledger is the single source of truth. A path that was re-armed while
                // it waited is not due yet, and a path that is already being inspected by
                // another worker is not picked up a second time.
                if (!session.Pending.TryBeginInspect(path)) continue;

                try
                {
                    Inspect(session, path, token);
                }
                finally
                {
                    session.Pending.EndInspect(path);
                }
            }
        }
        catch (Exception ex)
        {
            _log.Error("Realtime", "A real-time worker stopped unexpectedly.", ex);
        }
        finally
        {
            session.WorkerFinished();
            try
            {
                workerCts.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // The session was disposed first.
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
                Schedule(session, file);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Warn("Realtime", "A recovered folder could not be re-scanned: " + DisplayText.SanitizePath(root), ex);
        }
    }

    /// <summary>
    /// Remembers a path and gives it a deadline. The path is not inspected yet: the
    /// scheduler moves it into the ready queue when the deadline has passed. A path that is
    /// already known is re-armed, which means its deadline moves out instead of the path
    /// being queued a second time.
    /// </summary>
    private void Schedule(MonitorSession session, string path)
    {
        var now = DateTime.UtcNow;
        var signal = TryReadSignal(path);
        var due = now + SettleDelay;

        var outcome = session.Pending.Schedule(path, due, signal);
        if (outcome == ScheduleOutcome.Dropped)
        {
            // The monitor is already holding as many paths as it is allowed to. The file is
            // not inspected, and the miss is reported instead of being hidden.
            CountDrop(path);
            return;
        }

        // Wake the scheduler so a file that is due right now does not wait for the next poll.
        session.Wake();
    }

    private void Inspect(MonitorSession session, string path, CancellationToken token)
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
                // and over does not have to be re-read and re-hashed every time. The map is
                // shared by every worker, so the suppression works the same way in a pool.
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

            // The digest is only computed when there is something to report. Hashing a large
            // file is the most expensive step in the whole pipeline, and a clean file must
            // not pay for it. The digest is the one of the WHOLE file, because that is the
            // one the quarantine service recomputes; a digest of the inspected prefix would
            // not match it and would block an automatic quarantine.
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

        session.Pending.Forget(full);
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

    private void LogReadyQueueFull()
    {
        var logged = Interlocked.Increment(ref _loggedDrops);
        if (logged <= MaxLoggedDrops || logged % DropLogInterval == 0)
        {
            _log.Warn(
                "Realtime",
                "The real-time ready queue is full; a file had to wait a little longer.");
        }
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

    private readonly record struct FileSignal(DateTime LastWriteUtc, long Length);

    private sealed class WatcherSlot
    {
        public required string Root { get; init; }
        public IFileSystemWatcher? Watcher { get; set; }
        public int Failures { get; set; }
        public DateTime NextAttemptUtc { get; set; }
    }

    /// <summary>
    /// One inspection worker. The worker owns its own cancellation source, so it can be
    /// taken out of the pool while the monitor keeps running.
    /// </summary>
    private sealed class InspectionWorker
    {
        public InspectionWorker(Task task, CancellationTokenSource cts)
        {
            Task = task;
            Cts = cts;
        }

        public Task Task { get; }

        public CancellationTokenSource Cts { get; }

        /// <summary>Asks the worker to stop after the file it is reading.</summary>
        public void Stop()
        {
            try
            {
                Cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The worker already stopped and released its source.
            }
        }
    }

    private sealed class MonitorSession : IDisposable
    {
        private readonly SemaphoreSlim _wakeup = new(0, 1);
        private readonly Action<MonitorSession, CancellationTokenSource> _workerLoop;
        private readonly Action _onWorkerFinished;
        private readonly Action _onWorkerStarted;
        private readonly object _workerGate = new();
        private readonly object _taskGate = new();
        private readonly List<InspectionWorker> _workers = [];

        public MonitorSession(
            Action<MonitorSession, CancellationTokenSource> workerLoop,
            Action onWorkerStarted,
            Action onWorkerFinished)
        {
            _workerLoop = workerLoop;
            _onWorkerStarted = onWorkerStarted;
            _onWorkerFinished = onWorkerFinished;
        }

        public required Channel<string> Queue { get; init; }
        public required CancellationTokenSource Cts { get; init; }
        public required PendingLedger Pending { get; init; }

        /// <summary>The scheduler and the workers. All of them stop when the session ends.</summary>
        public List<Task> Tasks { get; } = [];

        /// <summary>Adds a background thread to the session, so it can be waited for.</summary>
        public void AddTask(Task task)
        {
            lock (_taskGate) Tasks.Add(task);
        }

        /// <summary>A copy of the background threads, safe to iterate while one is added.</summary>
        public Task[] SnapshotTasks()
        {
            lock (_taskGate) return Tasks.ToArray();
        }

        public bool Stopping { get; set; }
        public volatile bool HasFailedWatcher;
        public TimeSpan Cooldown { get; init; } = TimeSpan.FromMinutes(2);
        public ConcurrentDictionary<string, DateTimeOffset> RecentDetections { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<string, FileSignal> Inspected { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<WatcherSlot> Watchers { get; } = [];

        /// <summary>
        /// Wakes the scheduler so a path that is due right now does not wait for the next
        /// poll. Only one wake-up is ever kept pending.
        /// </summary>
        public void Wake()
        {
            try
            {
                _wakeup.Release();
            }
            catch (SemaphoreFullException)
            {
                // A wake-up is already pending; the scheduler will pick the work up.
            }
            catch (ObjectDisposedException)
            {
                // The session is shutting down.
            }
        }

        /// <summary>Waits for new work or for the given timeout to pass.</summary>
        public void WaitForWork(TimeSpan timeout)
        {
            try
            {
                _wakeup.Wait(timeout);
            }
            catch (ObjectDisposedException)
            {
                // The session is shutting down.
            }
        }

        /// <summary>Called by a background thread when it leaves the session.</summary>
        public void WorkerFinished() => _onWorkerFinished();

        /// <summary>Called when a background thread of this session is started.</summary>
        public void WorkerStarted() => _onWorkerStarted();

        /// <summary>
        /// Starts the inspection workers. The count is the number of files that may be read
        /// at the same time.
        /// </summary>
        public void StartWorkers(int count)
        {
            lock (_workerGate)
            {
                while (_workers.Count < count) _workers.Add(CreateWorker());
            }
        }

        /// <summary>
        /// Changes the number of inspection workers while the monitor runs. Workers that are
        /// not needed any more finish the file they are reading and then stop; the files
        /// that are still queued are picked up by the workers that remain.
        /// </summary>
        public void AdjustWorkers(int count)
        {
            lock (_workerGate)
            {
                // Workers that already stopped are dropped from the list.
                _workers.RemoveAll(worker => worker.Task.IsCompleted);

                while (_workers.Count > count)
                {
                    var worker = _workers[^1];
                    _workers.RemoveAt(_workers.Count - 1);
                    worker.Stop();
                }

                while (_workers.Count < count) _workers.Add(CreateWorker());
            }
        }

        private InspectionWorker CreateWorker()
        {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(Cts.Token);
            WorkerStarted();
            var task = Task.Factory.StartNew(
                () => _workerLoop(this, cts),
                CancellationToken.None,
                TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
                TaskScheduler.Default);
            AddTask(task);
            return new InspectionWorker(task, cts);
        }

        /// <summary>Waits for every background thread of the session to finish.</summary>
        public bool WaitForCompletion(TimeSpan timeout)
        {
            var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
            foreach (var task in SnapshotTasks())
            {
                var remaining = deadline - Environment.TickCount64;
                if (remaining <= 0) return false;
                if (!task.Wait(TimeSpan.FromMilliseconds(remaining))) return false;
            }

            return true;
        }

        /// <summary>Awaits every background thread of the session to finish.</summary>
        public async Task<bool> WaitForCompletionAsync(TimeSpan timeout)
        {
            var all = Task.WhenAll(SnapshotTasks());
            await all.WaitAsync(timeout).ConfigureAwait(false);
            return true;
        }

        /// <summary>Releases the session's resources once every thread has stopped.</summary>
        public void Dispose()
        {
            try
            {
                _wakeup.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Already disposed.
            }

            try
            {
                Cts.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Already disposed.
            }
        }
    }

    /// <summary>What happened when a path was handed to the pending ledger.</summary>
    private enum ScheduleOutcome
    {
        /// <summary>The path was added and now waits for its deadline.</summary>
        Added,

        /// <summary>
        /// The path was already known. Its deadline moved out, which re-arms it instead of
        /// queueing it a second time.
        /// </summary>
        ReArmed,

        /// <summary>The monitor is holding as many paths as it is allowed to.</summary>
        Dropped
    }

    /// <summary>
    /// The state of a path the monitor still has to deal with. It is the single source of
    /// truth for the queue: a path moves from Waiting (it is still settling) to Ready (its
    /// deadline has passed) to Inspecting (a worker is reading it), and a path that changes
    /// while it is being inspected is re-armed instead of being inspected a second time at
    /// the same time.
    /// </summary>
    private sealed class PendingLedger
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, PendingFile> _items = new(StringComparer.OrdinalIgnoreCase);
        private readonly int _limit;

        public PendingLedger(int limit) => _limit = limit;

        /// <summary>How many paths the monitor still has to deal with.</summary>
        public int QueueDepth
        {
            get { lock (_gate) return _items.Count; }
        }

        /// <summary>How many paths are still waiting for their settle deadline.</summary>
        public int WaitingCount
        {
            get
            {
                lock (_gate)
                {
                    var count = 0;
                    foreach (var entry in _items.Values)
                    {
                        if (entry.State == PendingState.Waiting) count++;
                    }

                    return count;
                }
            }
        }

        /// <summary>
        /// Adds a path or re-arms a known one. Re-arming pushes the deadline out, so a file
        /// that keeps being written is inspected once, when it finally stops changing.
        /// </summary>
        public ScheduleOutcome Schedule(string path, DateTime dueUtc, FileSignal? signal)
        {
            lock (_gate)
            {
                if (_items.TryGetValue(path, out var entry))
                {
                    if (entry.State == PendingState.Inspecting)
                    {
                        // The file changed while a worker was reading it. The worker is not
                        // allowed to start a second inspection at the same time, so the path
                        // is remembered and inspected again after the current one is done.
                        _items[path] = entry with { DueUtc = dueUtc, Signal = signal ?? entry.Signal, ReArmed = true };
                    }
                    else
                    {
                        // The path is waiting or already ready. Both cases simply get a new
                        // deadline; a ready path goes back to waiting so the stale hand-off
                        // in the channel is ignored.
                        _items[path] = entry with
                        {
                            DueUtc = dueUtc,
                            Signal = signal ?? entry.Signal,
                            State = PendingState.Waiting,
                            ReArmed = false
                        };
                    }

                    return ScheduleOutcome.ReArmed;
                }

                if (_items.Count >= _limit) return ScheduleOutcome.Dropped;

                _items[path] = new PendingFile(dueUtc, signal, PendingState.Waiting, ReArmed: false);
                return ScheduleOutcome.Added;
            }
        }

        /// <summary>
        /// Moves the paths whose deadline has passed to Ready and returns them, so the
        /// scheduler can hand them to the workers.
        /// </summary>
        public List<string> TakeDue(DateTime now)
        {
            lock (_gate)
            {
                var due = new List<string>();
                foreach (var pair in _items)
                {
                    if (pair.Value.State == PendingState.Waiting && pair.Value.DueUtc <= now)
                        due.Add(pair.Key);
                }

                foreach (var key in due)
                {
                    var entry = _items[key];
                    _items[key] = entry with { State = PendingState.Ready };
                }

                return due;
            }
        }

        /// <summary>
        /// Puts a path back into the waiting state. It is used when the ready queue is full:
        /// the file waits a little longer instead of being lost.
        /// </summary>
        public void RevertToWaiting(string path)
        {
            lock (_gate)
            {
                if (_items.TryGetValue(path, out var entry) && entry.State == PendingState.Ready)
                    _items[path] = entry with { State = PendingState.Waiting };
            }
        }

        /// <summary>
        /// Claims a path for inspection. Only one worker can win this for a given path, which
        /// is what keeps a file from being inspected twice at the same time.
        /// </summary>
        public bool TryBeginInspect(string path)
        {
            lock (_gate)
            {
                if (!_items.TryGetValue(path, out var entry)) return false;
                if (entry.State != PendingState.Ready) return false;

                _items[path] = entry with { State = PendingState.Inspecting, ReArmed = false };
                return true;
            }
        }

        /// <summary>
        /// Releases a path after the inspection. A path that was re-armed while it was being
        /// inspected stays in the ledger, because the file changed and has to be looked at
        /// again once it stops changing.
        /// </summary>
        public void EndInspect(string path)
        {
            lock (_gate)
            {
                if (!_items.TryGetValue(path, out var entry)) return;
                if (entry.State != PendingState.Inspecting) return;

                if (entry.ReArmed)
                    _items[path] = entry with { State = PendingState.Waiting, ReArmed = false };
                else
                    _items.Remove(path);
            }
        }

        /// <summary>Removes a path completely, for example because the file was deleted.</summary>
        public void Forget(string path)
        {
            lock (_gate) _items.Remove(path);
        }
    }

    private enum PendingState
    {
        /// <summary>The file is still settling. It waits for its deadline outside the workers.</summary>
        Waiting,

        /// <summary>The deadline has passed and the path is on its way to a worker.</summary>
        Ready,

        /// <summary>A worker is inspecting the path right now.</summary>
        Inspecting
    }

    private sealed record PendingFile(
        DateTime DueUtc,
        FileSignal? Signal,
        PendingState State,
        bool ReArmed);
}
