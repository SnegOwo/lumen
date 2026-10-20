using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Protection;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

/// <summary>
/// Tests for the on-access protection subsystem: configuration, watcher recovery, queue
/// behaviour and the honesty of the reported state. Everything here works on temporary
/// folders and injected fakes; the real user profile is never touched.
/// </summary>
public sealed class RealtimeProtectionTests
{
    [Fact]
    public async Task Changing_the_watch_configuration_changes_the_watched_roots()
    {
        using var temp = new TempDirectory();
        var first = temp.CreateDirectory("first");
        var second = temp.CreateDirectory("second");
        var factory = new FakeWatcherFactory();

        using var monitor = CreateMonitor(DetectorRegistry.CreateDefault(), first, watcherFactory: factory);
        monitor.Start();
        await WaitUntilAsync(() => factory.LatestEnabled is not null);

        Assert.Equal([first], monitor.Roots);
        Assert.Equal(1, monitor.GetStats().WatchedFolderCount);

        monitor.Configure([first, second], []);

        Assert.Equal(2, monitor.Roots.Count);
        Assert.Contains(second, monitor.Roots);
        await WaitUntilAsync(() => factory.Created.Any(watcher => watcher.Root == second && watcher.Enabled));
        Assert.Equal(2, monitor.GetStats().WatchedFolderCount);
    }

    [Fact]
    public void BuildWatchRoots_removes_nested_duplicates_and_excluded_roots()
    {
        using var temp = new TempDirectory();
        var parent = temp.CreateDirectory("parent");
        var child = temp.CreateDirectory("parent/child");
        var excluded = temp.CreateDirectory("excluded");

        var roots = RealtimeMonitor.BuildWatchRoots(temp.Root, [parent, child, excluded], [excluded]);

        Assert.Contains(parent, roots);
        Assert.DoesNotContain(child, roots);
        Assert.DoesNotContain(excluded, roots);
        Assert.Equal(roots.Count, roots.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public async Task Inspect_limit_change_is_applied_to_the_next_inspection()
    {
        using var temp = new TempDirectory();
        var before = temp.FileBytes("before.bin", new byte[200 * 1024]);
        var detector = new RecordingDetector("rt.probe", _ => false);
        var registry = new DetectorRegistry([detector]);

        using var monitor = CreateMonitor(registry, temp.Root);
        monitor.Start();

        monitor.Enqueue(before);
        await WaitUntilAsync(() => detector.Probes.Count >= 1);

        Assert.False(detector.Probes[0].ContentTruncated);
        Assert.Equal(200 * 1024, detector.Probes[0].Content.Length);

        monitor.UpdateInspectLimit(64 * 1024);
        Assert.Equal(64 * 1024, monitor.MaxInspectBytes);

        var after = temp.FileBytes("after.bin", new byte[200 * 1024]);
        monitor.Enqueue(after);
        await WaitUntilAsync(() => detector.Probes.Count >= 2);

        Assert.True(detector.Probes[1].ContentTruncated);
        Assert.Equal(64 * 1024, detector.Probes[1].Content.Length);
    }

    [Fact]
    public async Task Watcher_error_is_counted_and_the_monitor_reports_a_degraded_state()
    {
        using var temp = new TempDirectory();
        var factory = new FakeWatcherFactory();
        var log = new FakeLog();

        using var monitor = CreateMonitor(
            DetectorRegistry.CreateDefault(),
            temp.Root,
            watcherFactory: factory,
            watcherRetryDelay: TimeSpan.FromMinutes(5),
            log: log);
        monitor.Start();
        await WaitUntilAsync(() => factory.LatestEnabled is not null);

        factory.LatestEnabled!.RaiseError(new IOException("the share went away"));

        await WaitUntilAsync(() => monitor.GetStats().WatcherFailureCount >= 1);

        var stats = monitor.GetStats();
        Assert.Equal(1, stats.WatcherFailureCount);
        Assert.True(stats.IsDegraded);
        Assert.Equal(0, stats.WatchedFolderCount);
        Assert.Equal(1, stats.ConfiguredFolderCount);
        Assert.NotNull(stats.LastError);
        Assert.Contains(log.Lines, line => line.StartsWith("WARN|Realtime|") && line.Contains("watcher failed"));
    }

    [Fact]
    public async Task Watcher_is_recreated_after_an_error()
    {
        using var temp = new TempDirectory();
        var factory = new FakeWatcherFactory();

        using var monitor = CreateMonitor(
            DetectorRegistry.CreateDefault(),
            temp.Root,
            watcherFactory: factory,
            watcherRetryDelay: TimeSpan.FromMilliseconds(50));
        monitor.Start();
        await WaitUntilAsync(() => factory.LatestEnabled is not null);

        factory.LatestEnabled!.RaiseError();
        await WaitUntilAsync(() => factory.Created.Count >= 2);

        Assert.True(factory.Latest!.Enabled);
        await WaitUntilAsync(() => monitor.GetStats().WatchedFolderCount == 1);
        Assert.False(monitor.GetStats().IsDegraded);
    }

    [Fact]
    public async Task Delete_event_clears_the_recent_detection_map()
    {
        using var temp = new TempDirectory();
        var flagged = temp.File("bad.dll", "flag content");
        var registry = new DetectorRegistry([new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")]);
        var factory = new FakeWatcherFactory();

        using var monitor = CreateMonitor(registry, temp.Root, watcherFactory: factory);
        monitor.Start();
        await WaitUntilAsync(() => factory.LatestEnabled is not null);

        monitor.Enqueue(flagged);
        await WaitUntilAsync(() => monitor.GetStats().DetectionCount == 1);
        Assert.Equal(1, monitor.RecentDetectionCount);

        factory.LatestEnabled!.RaiseDeleted(flagged);
        await WaitUntilAsync(() => monitor.RecentDetectionCount == 0);

        // The path may be reported again once it exists again.
        monitor.Enqueue(flagged);
        await WaitUntilAsync(() => monitor.GetStats().DetectionCount == 2);
    }

    [Fact]
    public async Task Queue_overflow_is_counted_and_logged_instead_of_silently_dropped()
    {
        using var temp = new TempDirectory();
        var log = new FakeLog();

        using var monitor = new RealtimeMonitor(
            DetectorRegistry.CreateDefault(),
            [temp.Root],
            [],
            maxInspectBytes: 1024 * 1024,
            new FakeClock(),
            log,
            settleDelay: TimeSpan.FromMinutes(5),
            detectionCooldown: TimeSpan.FromMinutes(2),
            maxPendingPaths: 16);
        monitor.Start();

        for (var index = 0; index < 128; index++)
            monitor.Enqueue(Path.Combine(temp.Root, "file" + index + ".txt"));

        await WaitUntilAsync(() => monitor.GetStats().DroppedPathCount > 0);

        var stats = monitor.GetStats();
        Assert.True(stats.DroppedPathCount > 0);
        Assert.True(stats.PendingPathCount <= 16);
        Assert.Contains(log.Lines, line => line.StartsWith("WARN|Realtime|") && line.Contains("queue is full"));
    }

    [Fact]
    public void Enqueue_after_stop_is_a_no_op_and_does_not_throw()
    {
        using var temp = new TempDirectory();
        var file = temp.File("a.txt", "x");

        using var monitor = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root);
        monitor.Start();
        monitor.Stop();

        monitor.Enqueue(file);
        monitor.Enqueue(null);
        monitor.Enqueue("   ");

        Assert.Equal(0, monitor.GetStats().FilesChecked);
        Assert.False(monitor.GetStats().IsRunning);
    }

    [Fact]
    public async Task Enqueue_while_the_monitor_stops_never_throws()
    {
        using var temp = new TempDirectory();
        var file = temp.File("a.txt", "x");

        using var monitor = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root);
        monitor.Start();

        var stop = Task.Run(() => monitor.Stop());
        var enqueue = Task.Run(() =>
        {
            for (var index = 0; index < 500; index++) monitor.Enqueue(file);
        });

        await Task.WhenAll(stop, enqueue);

        Assert.False(monitor.GetStats().IsRunning);
    }

    [Fact]
    public async Task Detection_without_a_hash_is_reported_as_not_actionable()
    {
        using var temp = new TempDirectory();
        var flagged = temp.File("bad.dll", "flag content");
        var registry = new DetectorRegistry([new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")]);

        using var monitor = CreateMonitor(
            registry,
            temp.Root,
            hashProvider: new FailingHashProvider("The file is in use and could not be hashed."));

        var raised = new TaskCompletionSource<RealtimeDetectionEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        monitor.Detection += (_, e) => raised.TrySetResult(e);
        monitor.Start();

        monitor.Enqueue(flagged);
        var detection = await raised.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Null(detection.Sha256);
        Assert.False(detection.IsActionable);
        Assert.NotNull(detection.Sha256Error);
        Assert.Equal(1, monitor.GetStats().DetectionCount);
    }

    [Fact]
    public async Task Detection_with_a_hash_is_reported_as_actionable()
    {
        using var temp = new TempDirectory();
        var flagged = temp.File("bad.dll", "flag content");
        var registry = new DetectorRegistry([new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")]);

        using var monitor = CreateMonitor(registry, temp.Root);

        var raised = new TaskCompletionSource<RealtimeDetectionEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        monitor.Detection += (_, e) => raised.TrySetResult(e);
        monitor.Start();

        monitor.Enqueue(flagged);
        var detection = await raised.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.NotNull(detection.Sha256);
        Assert.True(detection.IsActionable);
        Assert.Null(detection.Sha256Error);
    }

    [Fact]
    public async Task File_written_repeatedly_is_inspected_once_it_settles()
    {
        using var temp = new TempDirectory();
        var file = temp.File("loop.txt", "payload");
        var registry = new DetectorRegistry([new FakeDetector("rt.flag", probe => probe.FileName == "loop.txt")]);
        var factory = new FakeWatcherFactory();

        using var monitor = CreateMonitor(
            registry,
            temp.Root,
            watcherFactory: factory,
            settleDelay: TimeSpan.FromMilliseconds(400));
        monitor.Start();
        await WaitUntilAsync(() => factory.LatestEnabled is not null);

        for (var index = 0; index < 5; index++) factory.LatestEnabled!.RaiseChanged(file);

        await WaitUntilAsync(() => monitor.GetStats().FilesChecked >= 1);
        await Task.Delay(800);

        Assert.Equal(1, monitor.GetStats().FilesChecked);
    }

    [Fact]
    public async Task Directories_are_never_inspected()
    {
        using var temp = new TempDirectory();
        var directory = temp.CreateDirectory("subfolder");

        using var monitor = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root);
        monitor.Start();

        monitor.Enqueue(directory);
        await Task.Delay(400);

        var stats = monitor.GetStats();
        Assert.Equal(0, stats.FilesChecked);
        Assert.Equal(0, stats.DetectionCount);
        Assert.True(stats.FilesSkipped >= 1);
    }

    [Fact]
    public async Task Restart_clears_the_stale_detection_state()
    {
        using var temp = new TempDirectory();
        var flagged = temp.File("bad.dll", "flag content");
        var registry = new DetectorRegistry([new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")]);

        using var monitor = CreateMonitor(registry, temp.Root);
        monitor.Start();

        monitor.Enqueue(flagged);
        await WaitUntilAsync(() => monitor.GetStats().DetectionCount == 1);
        Assert.Equal(1, monitor.RecentDetectionCount);

        monitor.Stop();
        monitor.Start();

        Assert.Equal(0, monitor.RecentDetectionCount);
    }

    private static RealtimeMonitor CreateMonitor(
        DetectorRegistry registry,
        string root,
        IReadOnlyList<string>? excludedDirectories = null,
        IFileSystemWatcherFactory? watcherFactory = null,
        IFileHashProvider? hashProvider = null,
        TimeSpan? settleDelay = null,
        TimeSpan? watcherRetryDelay = null,
        ILog? log = null) =>
        new(
            registry,
            [root],
            excludedDirectories ?? [],
            maxInspectBytes: 1024 * 1024,
            new FakeClock(),
            log ?? new FakeLog(),
            settleDelay: settleDelay ?? TimeSpan.Zero,
            detectionCooldown: TimeSpan.FromMinutes(2),
            watcherFactory: watcherFactory,
            hashProvider: hashProvider,
            watcherRetryDelay: watcherRetryDelay);

    private static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 10000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (condition()) return;
            await Task.Delay(25);
        }

        Assert.Fail($"Condition was not met within {timeoutMs} ms.");
    }
}
