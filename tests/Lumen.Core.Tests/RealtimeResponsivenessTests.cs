using System.Diagnostics;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

/// <summary>
/// Tests for how quickly the real-time monitor answers. They use temporary folders and
/// injected fakes only; the real user profile, the real processes and the real registry are
/// never touched.
///
/// The timings are measured as ratios and with gates rather than as absolute limits, so a
/// slow or busy machine does not turn a working monitor into a failing test.
/// </summary>
public sealed class RealtimeResponsivenessTests
{
    [Fact]
    public async Task Four_files_are_inspected_at_the_same_time_instead_of_one_after_the_other()
    {
        using var temp = new TempDirectory();
        var files = new[] { "a.bin", "b.bin", "c.bin", "d.bin" }
            .Select(name => temp.File(name, "content of " + name))
            .ToArray();

        const int perFileDelayMs = 200;

        // The baseline: a single worker has to do the four inspections one after the other.
        long sequentialMs;
        var sequentialDetector = new ResponsivenessDetector(_ => Thread.Sleep(perFileDelayMs));
        using (var sequential = CreateMonitor(
                   new DetectorRegistry([sequentialDetector]),
                   temp.Root,
                   workerCount: 1))
        {
            sequential.Start();
            var start = Stopwatch.StartNew();
            foreach (var file in files) sequential.Enqueue(file);
            await WaitUntilAsync(() => sequentialDetector.CompletedInspections >= files.Length);
            sequentialMs = start.ElapsedMilliseconds;
        }

        // The same work with four workers. Every inspection waits until all four are open,
        // so the gate can only open when the workers really run in parallel.
        var gate = new CountdownEvent(files.Length);
        var allQueued = new ManualResetEventSlim(false);
        var parallelDetector = new ResponsivenessDetector(_ =>
        {
            allQueued.Wait(TimeSpan.FromSeconds(10));
            gate.Signal();
            gate.Wait(TimeSpan.FromSeconds(10));
            Thread.Sleep(perFileDelayMs);
        });

        using var parallel = CreateMonitor(
            new DetectorRegistry([parallelDetector]),
            temp.Root,
            workerCount: 4);
        parallel.Start();

        var parallelStart = Stopwatch.StartNew();
        foreach (var file in files) parallel.Enqueue(file);
        allQueued.Set();
        await WaitUntilAsync(() => parallelDetector.CompletedInspections >= files.Length);
        var parallelMs = parallelStart.ElapsedMilliseconds;

        // The gate only opens when all four inspections are open at the same time.
        Assert.Equal(0, gate.CurrentCount);
        Assert.Equal(files.Length, parallelDetector.MaxConcurrentInspections);
        Assert.True(
            parallelMs < sequentialMs * 0.7,
            $"Four workers took {parallelMs} ms while one worker took {sequentialMs} ms. " +
            "The inspections did not run in parallel.");
    }

    [Fact]
    public void The_worker_count_is_configurable_and_the_default_is_the_documented_one()
    {
        using var temp = new TempDirectory();

        using var byDefault = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root);
        Assert.Equal(3, RealtimeMonitor.DefaultWorkerCount);
        Assert.Equal(RealtimeMonitor.DefaultWorkerCount, byDefault.WorkerCount);
        Assert.Equal(RealtimeMonitor.DefaultWorkerCount, byDefault.GetStats().WorkerCount);

        using var configured = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root, workerCount: 6);
        Assert.Equal(6, configured.WorkerCount);

        // Values outside the supported range are clamped instead of being refused.
        using var tooMany = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root, workerCount: 99);
        Assert.Equal(RealtimeMonitor.MaxWorkerCount, tooMany.WorkerCount);

        using var tooFew = CreateMonitor(DetectorRegistry.CreateDefault(), temp.Root, workerCount: 0);
        Assert.Equal(RealtimeMonitor.MinWorkerCount, tooFew.WorkerCount);
    }

    [Fact]
    public async Task A_file_that_is_still_settling_does_not_occupy_a_worker()
    {
        using var temp = new TempDirectory();
        var busy = temp.File("busy.txt", "still being written");
        var ready = temp.File("ready.txt", "written once and done");

        var detector = new ResponsivenessDetector();
        using var monitor = CreateMonitor(
            new DetectorRegistry([detector]),
            temp.Root,
            settleDelay: TimeSpan.FromMilliseconds(300),
            workerCount: 1);
        monitor.Start();

        monitor.Enqueue(busy);
        monitor.Enqueue(ready);

        // The busy file is written over and over. Its deadline moves out every time, so it
        // never becomes due, and it must not hold up the file that is already finished.
        var rearm = Task.Run(async () =>
        {
            for (var index = 0; index < 12; index++)
            {
                await Task.Delay(60);
                monitor.Enqueue(busy);
            }
        });

        await WaitUntilAsync(() => monitor.GetStats().FilesChecked >= 1);

        var inspected = detector.InspectedPaths;
        Assert.Contains(ready, inspected);
        Assert.DoesNotContain(busy, inspected);

        await rearm;
    }

    [Fact]
    public async Task The_settle_delay_is_configurable_and_a_delay_of_zero_means_no_waiting()
    {
        using var temp = new TempDirectory();
        var file = temp.File("quick.txt", "content");

        var registry = new DetectorRegistry([new FakeDetector("rt.flag", _ => false)]);

        // A delay of zero: the file is inspected as soon as it is queued.
        using var instant = CreateMonitor(registry, temp.Root, settleDelay: TimeSpan.Zero);
        instant.Start();
        var instantStart = Stopwatch.StartNew();
        instant.Enqueue(file);
        await WaitUntilAsync(() => instant.GetStats().FilesChecked >= 1);
        var instantMs = instantStart.ElapsedMilliseconds;

        // A delay of 400 ms: the inspection cannot happen before the deadline.
        using var patient = CreateMonitor(registry, temp.Root, settleDelay: TimeSpan.FromMilliseconds(400));
        patient.Start();
        var patientStart = Stopwatch.StartNew();
        patient.Enqueue(file);
        await WaitUntilAsync(() => patient.GetStats().FilesChecked >= 1);
        var patientMs = patientStart.ElapsedMilliseconds;

        Assert.Equal(TimeSpan.Zero, instant.SettleDelay);
        Assert.Equal(TimeSpan.FromMilliseconds(400), patient.SettleDelay);
        Assert.True(patientMs >= 350, $"The settle delay was not honoured ({patientMs} ms).");
        Assert.True(
            instantMs < patientMs * 0.5,
            $"A delay of zero took {instantMs} ms while a delay of 400 ms took {patientMs} ms.");
    }

    [Fact]
    public async Task Stop_stops_every_worker_and_leaves_nothing_running()
    {
        using var temp = new TempDirectory();
        var file = temp.File("a.txt", "content");

        var detector = new ResponsivenessDetector();
        using var monitor = CreateMonitor(new DetectorRegistry([detector]), temp.Root, workerCount: 4);
        monitor.Start();

        monitor.Enqueue(file);
        await WaitUntilAsync(() => monitor.GetStats().FilesChecked >= 1);
        Assert.True(
            monitor.ActiveWorkerCount >= 4,
            "The workers have to be running while the monitor is running.");

        monitor.Stop();

        Assert.False(monitor.IsRunning);
        Assert.Equal(0, monitor.ActiveWorkerCount);
        Assert.Equal(0, monitor.GetStats().ActiveWorkerCount);

        // Nothing runs behind the caller's back: a file that is queued after the stop is
        // never inspected.
        var checkedBefore = monitor.GetStats().FilesChecked;
        monitor.Enqueue(file);
        await Task.Delay(300);
        Assert.Equal(checkedBefore, monitor.GetStats().FilesChecked);
    }

    [Fact]
    public async Task The_same_path_is_never_inspected_twice_at_the_same_time()
    {
        using var temp = new TempDirectory();
        var file = temp.File("same.txt", "content");

        var detector = new ResponsivenessDetector();
        using var monitor = CreateMonitor(new DetectorRegistry([detector]), temp.Root, workerCount: 4);
        monitor.Start();

        for (var index = 0; index < 40; index++) monitor.Enqueue(file);

        await WaitUntilAsync(() => detector.Inspections >= 1);
        await Task.Delay(500);

        // The file may be inspected again, but never at the same time as itself.
        Assert.Equal(1, detector.MaxConcurrentInspectionsPerPath);
    }

    [Fact]
    public async Task The_counters_stay_correct_with_several_workers()
    {
        using var temp = new TempDirectory();
        var badOne = temp.File("one/bad.dll", "flagged content");
        var badTwo = temp.File("two/bad.dll", "flagged content");
        var goodOne = temp.File("one/notes.txt", "harmless content");
        var goodTwo = temp.File("two/notes.txt", "harmless content");

        var registry = new DetectorRegistry(
        [
            new FakeDetector("rt.flag", probe => probe.FileName == "bad.dll")
        ]);

        using var monitor = CreateMonitor(registry, temp.Root, workerCount: 4);
        monitor.Start();

        monitor.Enqueue(badOne);
        monitor.Enqueue(badTwo);
        monitor.Enqueue(goodOne);
        monitor.Enqueue(goodTwo);

        await WaitUntilAsync(() => monitor.GetStats().DetectionCount >= 2);
        await Task.Delay(300);

        var stats = monitor.GetStats();
        Assert.Equal(4, stats.FilesChecked);
        Assert.Equal(2, stats.DetectionCount);
        Assert.Equal(0, stats.ErrorCount);
        Assert.Equal(0, stats.DroppedPathCount);
    }

    [Fact]
    public async Task The_unchanged_file_suppression_still_works_with_several_workers()
    {
        using var temp = new TempDirectory();
        var file = temp.File("same.txt", "content");

        var detector = new ResponsivenessDetector();
        using var monitor = CreateMonitor(new DetectorRegistry([detector]), temp.Root, workerCount: 3);
        monitor.Start();

        monitor.Enqueue(file);
        await WaitUntilAsync(() => detector.Inspections >= 1);

        // The file did not change, so the second pass must not read it again.
        monitor.Enqueue(file);
        await WaitUntilAsync(() => monitor.GetStats().FilesSkipped >= 1);
        await Task.Delay(300);

        Assert.Equal(1, detector.Inspections);
        Assert.Equal(1, monitor.GetStats().FilesChecked);
    }

    [Fact]
    public async Task The_worker_count_and_the_settle_delay_can_be_changed_while_the_monitor_runs()
    {
        using var temp = new TempDirectory();
        var file = temp.File("a.txt", "content");

        using var monitor = CreateMonitor(
            new DetectorRegistry([new FakeDetector("rt.flag", _ => false)]),
            temp.Root,
            workerCount: 2);
        monitor.Start();

        var result = monitor.Configure([temp.Root], [], null, TimeSpan.FromMilliseconds(50), 5);
        Assert.True(result.Ok);
        Assert.Equal(5, monitor.WorkerCount);
        Assert.Equal(TimeSpan.FromMilliseconds(50), monitor.SettleDelay);

        monitor.Enqueue(file);
        await WaitUntilAsync(() => monitor.GetStats().FilesChecked >= 1);

        // Fewer workers: the ones that are not needed any more stop, and the monitor keeps
        // working with the workers that are left.
        monitor.Configure([temp.Root], [], null, null, 1);
        Assert.Equal(1, monitor.WorkerCount);

        var second = temp.File("b.txt", "content");
        monitor.Enqueue(second);
        await WaitUntilAsync(() => monitor.GetStats().FilesChecked >= 2);
    }

    private static RealtimeMonitor CreateMonitor(
        DetectorRegistry registry,
        string root,
        TimeSpan? settleDelay = null,
        int? workerCount = null) =>
        new(
            registry,
            [root],
            [],
            maxInspectBytes: 1024 * 1024,
            new FakeClock(),
            new FakeLog(),
            settleDelay: settleDelay ?? TimeSpan.Zero,
            detectionCooldown: TimeSpan.FromMinutes(2),
            watcherFactory: new FakeWatcherFactory(),
            workerCount: workerCount ?? RealtimeMonitor.DefaultWorkerCount);

    private static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 10000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (condition()) return;
            await Task.Delay(10);
        }

        Assert.Fail($"Condition was not met within {timeoutMs} ms.");
    }
}

/// <summary>
/// A detector that measures how the monitor schedules its work. It records how many
/// inspections were open at the same time, for the whole monitor and for each single file,
/// and it can hold an inspection open so a test can see whether the workers really work in
/// parallel. It never finds anything; the tests that need a match use their own detector.
/// </summary>
internal sealed class ResponsivenessDetector : IScanDetector
{
    private readonly object _gate = new();
    private readonly Dictionary<string, int> _perPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _paths = [];
    private int _active;
    private int _maxActive;
    private int _maxPerPath;
    private int _completed;

    public ResponsivenessDetector(Action<FileProbe>? duringInspection = null) =>
        DuringInspection = duringInspection;

    public string Id => "rt.instrumented";
    public string Name => "Instrumented detector";
    public string Description => "Measures how the real-time monitor schedules its work.";
    public FindingCategory Category => FindingCategory.Heuristic;
    public Confidence Confidence => Confidence.Medium;

    /// <summary>Runs while the inspection is open. Used to hold an inspection open.</summary>
    public Action<FileProbe>? DuringInspection { get; }

    /// <summary>The largest number of inspections that were open at the same time.</summary>
    public int MaxConcurrentInspections
    {
        get { lock (_gate) return _maxActive; }
    }

    /// <summary>
    /// The largest number of inspections of ONE file that were open at the same time. The
    /// value must stay at one: a file is never inspected twice at once.
    /// </summary>
    public int MaxConcurrentInspectionsPerPath
    {
        get { lock (_gate) return _maxPerPath; }
    }

    /// <summary>How many inspections ran.</summary>
    public int Inspections
    {
        get { lock (_gate) return _paths.Count; }
    }

    /// <summary>How many inspections ran to the end.</summary>
    public int CompletedInspections
    {
        get { lock (_gate) return _completed; }
    }

    /// <summary>The files that were inspected, in the order the inspections started.</summary>
    public IReadOnlyList<string> InspectedPaths
    {
        get { lock (_gate) return _paths.ToArray(); }
    }

    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        Enter(probe.Path);
        try
        {
            DuringInspection?.Invoke(probe);
            return [];
        }
        finally
        {
            Exit(probe.Path);
        }
    }

    private void Enter(string path)
    {
        lock (_gate)
        {
            _active++;
            if (_active > _maxActive) _maxActive = _active;

            _perPath.TryGetValue(path, out var current);
            current++;
            _perPath[path] = current;
            if (current > _maxPerPath) _maxPerPath = current;

            _paths.Add(path);
        }
    }

    private void Exit(string path)
    {
        lock (_gate)
        {
            _active--;
            _completed++;
            if (_perPath.TryGetValue(path, out var current)) _perPath[path] = current - 1;
        }
    }
}
