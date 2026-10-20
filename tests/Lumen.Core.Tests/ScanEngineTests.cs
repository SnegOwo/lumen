using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;
using Xunit.Abstractions;

namespace Lumen.Core.Tests;

public sealed class ScanEngineTests
{
    private readonly ITestOutputHelper _output;

    public ScanEngineTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task Scans_files_reports_detection_and_computes_hash()
    {
        using var temp = new TempDirectory();
        temp.File("a.txt", "hello");
        var flagged = temp.File("sub/b.txt", "flag content");
        var registry = new DetectorRegistry(
        [
            new FakeDetector("test.flag", probe => probe.FileName == "b.txt")
        ]);
        var progress = new CollectingProgress();
        var engine = CreateEngine(registry);

        var outcome = await engine.ScanAsync(TestData.Request(temp.Root), progress, CancellationToken.None);

        Assert.False(outcome.Cancelled);
        Assert.Equal(2, outcome.FilesScanned);
        Assert.Single(outcome.Detections);
        var detection = outcome.Detections[0];
        Assert.Equal("b.txt", detection.FileName);
        Assert.Equal("test.flag", detection.Findings[0].RuleId);
        Assert.Equal(HashUtil.Sha256File(flagged, CancellationToken.None), detection.Sha256);
        Assert.Contains(progress.Reports, report => report.Phase == ScanPhase.Finished);
        Assert.Contains(progress.Reports.SelectMany(report => report.NewDetections),
            item => item.FileName == "b.txt");
    }

    [Fact]
    public async Task Cancellation_stops_scan_without_throwing()
    {
        using var temp = new TempDirectory();
        for (var index = 0; index < 20; index++) temp.File($"file-{index}.txt", "x");

        using var cts = new CancellationTokenSource();
        var registry = new DetectorRegistry([new CancellingDetector(cts)]);
        var engine = CreateEngine(registry);

        var outcome = await engine.ScanAsync(TestData.Request(temp.Root), null, cts.Token);

        Assert.True(outcome.Cancelled);
        Assert.Equal(1, outcome.FilesScanned);
        Assert.Empty(outcome.Detections);
    }

    [Fact]
    public async Task Pre_cancelled_token_returns_cancelled_outcome()
    {
        using var temp = new TempDirectory();
        temp.File("a.txt", "x");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var outcome = await CreateEngine().ScanAsync(TestData.Request(temp.Root), null, cts.Token);

        Assert.True(outcome.Cancelled);
        Assert.Equal(0, outcome.FilesScanned);
    }

    [Fact]
    public async Task Missing_root_is_reported_and_does_not_throw()
    {
        using var temp = new TempDirectory();
        var missing = Path.Combine(temp.Root, "does-not-exist");
        var outcome = await CreateEngine().ScanAsync(TestData.Request(missing), null, CancellationToken.None);

        Assert.False(outcome.Cancelled);
        Assert.True(outcome.ErrorCount >= 1);
        Assert.Contains(outcome.Errors, error => error.Kind == ScanErrorKind.NotFound);
    }

    [Fact]
    public async Task Locked_file_is_reported_and_scan_continues()
    {
        using var temp = new TempDirectory();
        temp.File("good.txt", "ok");
        var locked = temp.File("locked.txt", "in use");

        using var hold = new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None);
        var outcome = await CreateEngine().ScanAsync(TestData.Request(temp.Root), null, CancellationToken.None);

        Assert.True(outcome.FilesScanned >= 2);
        Assert.Contains(outcome.Errors,
            error => error.Kind is ScanErrorKind.InUse or ScanErrorKind.Io);
        Assert.DoesNotContain(outcome.Detections, item => item.FileName == "good.txt");
    }

    [Fact]
    public async Task Large_file_content_is_truncated_at_the_configured_limit()
    {
        using var temp = new TempDirectory();
        temp.FileBytes("large.bin", new byte[200_000]);
        FileProbe? seen = null;
        var registry = new DetectorRegistry(
        [
            new FakeDetector("test.probe", probe =>
            {
                seen = probe;
                return false;
            })
        ]);

        var request = TestData.Request(temp.Root) with { MaxInspectBytes = 64 * 1024 };
        var outcome = await CreateEngine(registry).ScanAsync(request, null, CancellationToken.None);

        Assert.Equal(1, outcome.FilesScanned);
        Assert.NotNull(seen);
        Assert.True(seen!.ContentTruncated);
        Assert.Equal(64 * 1024, seen.Content.Length);
    }

    [Fact]
    public async Task Scans_paths_longer_than_max_path()
    {
        using var temp = new TempDirectory();
        var directory = temp.Root;
        for (var index = 0; index < 6; index++)
        {
            directory = Path.Combine(directory, new string('a', 55) + index);
            Directory.CreateDirectory(directory);
        }

        var path = Path.Combine(directory, "long-path.txt");
        File.WriteAllText(path, "x");
        if (path.Length <= 260)
        {
            _output.WriteLine("Path was not long enough on this system; test not meaningful.");
            return;
        }

        var outcome = await CreateEngine().ScanAsync(TestData.Request(temp.Root), null, CancellationToken.None);

        Assert.Equal(1, outcome.FilesScanned);
        Assert.Equal(0, outcome.ErrorCount);
    }

    [Fact]
    public async Task Offline_placeholder_is_skipped()
    {
        using var temp = new TempDirectory();
        var path = temp.File("cloud.txt", "placeholder");
        try
        {
            File.SetAttributes(path, FileAttributes.Offline);
        }
        catch (Exception ex)
        {
            _output.WriteLine("Could not set the offline attribute: " + ex.GetType().Name);
            return;
        }

        if (!File.GetAttributes(path).HasFlag(FileAttributes.Offline))
        {
            _output.WriteLine("The filesystem ignored the offline attribute; test not meaningful.");
            return;
        }

        var outcome = await CreateEngine().ScanAsync(TestData.Request(temp.Root), null, CancellationToken.None);

        Assert.Equal(0, outcome.FilesScanned);
        Assert.Equal(1, outcome.FilesSkipped);
    }

    [Fact]
    public async Task Single_file_scope_scans_only_that_file()
    {
        using var temp = new TempDirectory();
        var file = temp.File("one.txt", "x");
        temp.File("two.txt", "y");
        var request = TestData.Request(file) with { Scope = ScanScopeKind.File, Description = "file" };

        var outcome = await CreateEngine().ScanAsync(request, null, CancellationToken.None);

        Assert.Equal(1, outcome.FilesScanned);
        Assert.Equal(0, outcome.ErrorCount);
    }

    [Fact]
    public async Task Excluded_directory_subtree_is_not_scanned()
    {
        using var temp = new TempDirectory();
        var excluded = temp.CreateDirectory("cache");
        File.WriteAllText(Path.Combine(excluded, "ignored.txt"), "x");
        temp.File("kept.txt", "x");
        var request = TestData.Request(temp.Root) with { ExcludedDirectories = [excluded] };

        var outcome = await CreateEngine().ScanAsync(request, null, CancellationToken.None);

        Assert.Equal(1, outcome.FilesScanned);
        Assert.True(outcome.DirectoriesSkipped >= 1);
    }

    private static ScanEngine CreateEngine(DetectorRegistry? registry = null) =>
        new(registry ?? DetectorRegistry.CreateDefault(), new FakeClock(), new FakeLog());

    private sealed class CancellingDetector(CancellationTokenSource cts) : Abstractions.IScanDetector
    {
        private int _seen;

        public string Id => "test.cancel";
        public string Name => "cancel";
        public string Description => "cancel";
        public FindingCategory Category => FindingCategory.Heuristic;
        public Confidence Confidence => Confidence.Low;

        public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _seen) == 1) cts.Cancel();
            return [];
        }
    }
}

