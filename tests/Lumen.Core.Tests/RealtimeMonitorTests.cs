using Lumen.Core.Detection;
using Lumen.Core.Protection;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

public sealed class RealtimeMonitorTests
{
    [Fact]
    public async Task Enqueued_match_raises_detection_with_hash_and_findings()
    {
        using var temp = new TempDirectory();
        var flagged = temp.File("bad.dll", "flag content");
        var registry = new DetectorRegistry(
        [
            new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")
        ]);

        using var monitor = CreateMonitor(registry, temp.Root);
        var raised = new TaskCompletionSource<RealtimeDetectionEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        monitor.Detection += (_, e) => raised.TrySetResult(e);
        monitor.Start();

        monitor.Enqueue(flagged);
        var detection = await raised.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(flagged, detection.FilePath);
        Assert.Equal("bad.dll", detection.FileName);
        Assert.Equal("rt.flag", detection.Findings[0].RuleId);
        Assert.NotNull(detection.Sha256);
        Assert.Equal(64, detection.Sha256!.Length);

        var stats = monitor.GetStats();
        Assert.True(stats.FilesChecked >= 1);
        Assert.Equal(1, stats.DetectionCount);
        Assert.True(stats.IsRunning);
        Assert.Equal(flagged, stats.LastDetectionPath);
    }

    [Fact]
    public async Task Clean_file_is_checked_without_raising_detection()
    {
        using var temp = new TempDirectory();
        var clean = temp.File("notes.txt", "just a shopping list");
        var registry = new DetectorRegistry(
        [
            new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")
        ]);

        using var monitor = CreateMonitor(registry, temp.Root);
        var raised = 0;
        monitor.Detection += (_, _) => Interlocked.Increment(ref raised);
        monitor.Start();

        monitor.Enqueue(clean);
        await WaitUntilAsync(() => monitor.GetStats().FilesChecked >= 1);

        Assert.Equal(0, raised);
        Assert.Equal(0, monitor.GetStats().DetectionCount);
        Assert.Null(monitor.GetStats().LastDetectionPath);
    }

    [Fact]
    public async Task Excluded_directory_is_never_inspected()
    {
        using var temp = new TempDirectory();
        var watched = temp.CreateDirectory("watched");
        var excluded = temp.CreateDirectory("excluded");
        var flaggedInExcluded = Path.Combine(excluded, "bad.dll");
        File.WriteAllText(flaggedInExcluded, "flag content");

        var registry = new DetectorRegistry(
        [
            new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")
        ]);

        using var monitor = CreateMonitor(registry, watched, excludedDirectories: [excluded]);
        monitor.Start();

        monitor.Enqueue(flaggedInExcluded);
        await Task.Delay(250);

        var stats = monitor.GetStats();
        Assert.Equal(0, stats.FilesChecked);
        Assert.Equal(0, stats.DetectionCount);
    }

    [Fact]
    public async Task Duplicate_path_within_cooldown_is_reported_once()
    {
        using var temp = new TempDirectory();
        var flagged = temp.File("bad.dll", "flag content");
        var registry = new DetectorRegistry(
        [
            new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")
        ]);

        using var monitor = CreateMonitor(registry, temp.Root);
        var raised = 0;
        monitor.Detection += (_, _) => Interlocked.Increment(ref raised);
        monitor.Start();

        monitor.Enqueue(flagged);
        await WaitUntilAsync(() => monitor.GetStats().DetectionCount >= 1);

        monitor.Enqueue(flagged);
        monitor.Enqueue(flagged);
        await Task.Delay(250);

        Assert.Equal(1, raised);
        Assert.Equal(1, monitor.GetStats().DetectionCount);
    }

    [Fact]
    public async Task Deleted_file_is_skipped_without_error()
    {
        using var temp = new TempDirectory();
        var ghost = Path.Combine(temp.Root, "ghost.txt");

        using var monitor = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root);
        monitor.Start();

        monitor.Enqueue(ghost);
        await Task.Delay(250);

        var stats = monitor.GetStats();
        Assert.Equal(0, stats.FilesChecked);
        Assert.Equal(0, stats.ErrorCount);
        Assert.True(stats.FilesSkipped >= 1);
    }

    [Fact]
    public async Task Stop_prevents_further_inspections_and_start_is_idempotent()
    {
        using var temp = new TempDirectory();
        var flagged = temp.File("bad.dll", "flag content");
        var registry = new DetectorRegistry(
        [
            new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")
        ]);

        using var monitor = CreateMonitor(registry, temp.Root);
        monitor.Start();
        monitor.Start(); // second start must be a no-op

        monitor.Enqueue(flagged);
        await WaitUntilAsync(() => monitor.GetStats().DetectionCount >= 1);

        monitor.Stop();
        Assert.False(monitor.GetStats().IsRunning);

        var checkedBefore = monitor.GetStats().FilesChecked;
        monitor.Enqueue(flagged);
        await Task.Delay(250);
        Assert.Equal(checkedBefore, monitor.GetStats().FilesChecked);
    }

    [Fact]
    public void Enqueue_before_start_is_ignored()
    {
        using var temp = new TempDirectory();
        var file = temp.File("a.txt", "x");

        using var monitor = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root);
        monitor.Enqueue(file);

        Assert.Equal(0, monitor.GetStats().FilesChecked);
        Assert.False(monitor.GetStats().IsRunning);
    }

    [Fact]
    public void Dispose_stops_monitor_safely()
    {
        using var temp = new TempDirectory();
        var monitor = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root);
        monitor.Start();
        Assert.True(monitor.IsRunning);

        monitor.Dispose();
        Assert.False(monitor.IsRunning);
    }

    [Fact]
    public async Task Filesystem_watcher_detects_new_file_end_to_end()
    {
        using var temp = new TempDirectory();
        var registry = new DetectorRegistry(
        [
            new FakeDetector("rt.flag", probe => probe.FileName == "dropper.exe")
        ]);

        using var monitor = CreateMonitor(registry, temp.Root);
        var raised = new TaskCompletionSource<RealtimeDetectionEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        monitor.Detection += (_, e) => raised.TrySetResult(e);
        monitor.Start();

        // Written after Start so the watcher, not Enqueue, delivers it.
        temp.File("dropper.exe", "payload");

        var detection = await raised.Task.WaitAsync(TimeSpan.FromSeconds(15));
        Assert.Equal("dropper.exe", detection.FileName);
    }

    private static RealtimeMonitor CreateMonitor(
        DetectorRegistry registry,
        string root,
        IReadOnlyList<string>? excludedDirectories = null) =>
        new(
            registry,
            [root],
            excludedDirectories ?? [],
            maxInspectBytes: 1024 * 1024,
            new FakeClock(),
            new FakeLog(),
            settleDelay: TimeSpan.Zero,
            detectionCooldown: TimeSpan.FromMinutes(2));

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