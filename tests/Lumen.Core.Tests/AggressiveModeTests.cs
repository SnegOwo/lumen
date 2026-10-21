using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Tests;

/// <summary>
/// Tests for the AGGRESSIVE mode behaviour: what Lumen watches, how fast it reacts and
/// how it answers a match.
///
/// <para>
/// Every test here works on a temporary folder. Nothing touches the real user profile,
/// the real Lumen data folder, real processes, the registry or scheduled tasks.
/// </para>
/// </summary>
public sealed class AggressiveModeTests
{
    // ------------------------------------------------------------------
    // The watch list
    // ------------------------------------------------------------------

    [Fact]
    public void Aggressive_watch_list_covers_downloads_startup_and_temp()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);

        var roots = RealtimeMonitor.AggressiveWatchRoots(profile);

        Assert.Contains(roots, root => IsSame(root, Path.Combine(profile, "Downloads")));
        Assert.Contains(roots, root => IsSame(root, AggressiveWatchList.StartupFolder(profile)));
        Assert.Contains(roots, root => IsSame(root, AggressiveWatchList.TempFolder(profile)));
    }

    [Fact]
    public void Aggressive_watch_list_contains_the_standard_roots_as_well()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);

        var standard = RealtimeMonitor.BuildWatchRoots(profile);
        var aggressive = RealtimeMonitor.AggressiveWatchRoots(profile);

        foreach (var root in standard)
            Assert.Contains(aggressive, candidate => IsSame(candidate, root));
    }

    [Fact]
    public void Aggressive_watch_list_does_not_contain_an_excluded_folder()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var excluded = Path.Combine(profile, "Downloads");

        var roots = RealtimeMonitor.AggressiveWatchRoots(profile, excludedFolders: [excluded]);

        Assert.DoesNotContain(roots, root => PathRules.IsWithin(root, excluded));
        Assert.Contains(roots, root => IsSame(root, AggressiveWatchList.StartupFolder(profile)));
    }

    [Fact]
    public void Aggressive_watch_list_does_not_contain_a_folder_inside_an_excluded_subtree()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var excluded = Path.Combine(profile, "AppData", "Roaming");
        var startup = AggressiveWatchList.StartupFolder(profile);

        var roots = RealtimeMonitor.AggressiveWatchRoots(profile, excludedFolders: [excluded]);

        // The Startup folder lives inside AppData\Roaming, so excluding that subtree
        // must take it out as well. Containment, not a string prefix.
        Assert.DoesNotContain(roots, root => PathRules.IsWithin(root, excluded));
        Assert.DoesNotContain(roots, root => IsSame(root, startup));
        Assert.Contains(roots, root => IsSame(root, AggressiveWatchList.TempFolder(profile)));
    }

    [Fact]
    public void Aggressive_watch_list_removes_nested_folders_so_nothing_is_watched_twice()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var nested = Path.Combine(profile, "Downloads", "Incoming");

        var roots = RealtimeMonitor.AggressiveWatchRoots(profile, extraWatchFolders: [nested]);

        Assert.DoesNotContain(roots, root => IsSame(root, nested));
        Assert.Contains(roots, root => IsSame(root, Path.Combine(profile, "Downloads")));
        Assert.Equal(roots.Count, roots.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Aggressive_watch_list_collapses_a_profile_root_onto_itself()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);

        // The user added the whole profile. Every dropper location is inside it, so the
        // watch list must be the profile alone: nothing is watched twice.
        var roots = RealtimeMonitor.AggressiveWatchRoots(profile, extraWatchFolders: [profile]);

        Assert.Single(roots);
        Assert.True(IsSame(roots[0], profile));
    }

    // ------------------------------------------------------------------
    // The configuration
    // ------------------------------------------------------------------

    [Fact]
    public void Aggressive_configuration_stops_waiting_and_uses_more_workers()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var settings = new AppSettings
        {
            AggressiveMode = true,
            RealtimeSettleDelayMs = 150,
            RealtimeWorkerCount = 3
        };

        var configuration = RealtimeMonitor.ResolveConfiguration(settings, profile);

        Assert.Equal(TimeSpan.Zero, configuration.SettleDelay);
        Assert.True(
            configuration.WorkerCount > settings.RealtimeWorkerCount,
            "Aggressive mode must use more workers than the standard count.");
        Assert.True(configuration.AggressiveMode);
        Assert.Contains(
            configuration.WatchRoots,
            root => IsSame(root, AggressiveWatchList.StartupFolder(profile)));
        Assert.Contains(
            configuration.WatchRoots,
            root => IsSame(root, AggressiveWatchList.TempFolder(profile)));
    }

    [Fact]
    public void Standard_configuration_keeps_the_slow_settle_delay_and_the_small_worker_pool()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var settings = new AppSettings
        {
            AggressiveMode = false,
            RealtimeSettleDelayMs = 150,
            RealtimeWorkerCount = 3
        };

        var configuration = RealtimeMonitor.ResolveConfiguration(settings, profile);

        Assert.Equal(TimeSpan.FromMilliseconds(150), configuration.SettleDelay);
        Assert.Equal(3, configuration.WorkerCount);
        Assert.False(configuration.AggressiveMode);
    }

    /// <summary>
    /// The standard watch list covers the dropper locations too.
    ///
    /// A file dropped in the Startup folder is run at every logon, and a file unpacked
    /// into the temporary folder is exactly the kind of thing nobody looks at by hand.
    /// Watching those two costs a folder watch and nothing else: the cost of aggressive
    /// mode is the extra detection rules and the eagerness, not the number of folders.
    /// </summary>
    [Fact]
    public void Standard_configuration_also_watches_the_startup_and_temporary_folders()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var settings = new AppSettings
        {
            AggressiveMode = false,
            RealtimeSettleDelayMs = 150,
            RealtimeWorkerCount = 3
        };

        var configuration = RealtimeMonitor.ResolveConfiguration(settings, profile);

        Assert.Equal(
            AggressiveWatchList.BuildStandard(profile, settings.RealtimeWatchFolders, []),
            configuration.WatchRoots);

        Assert.Contains(
            configuration.WatchRoots,
            root => IsSame(root, AggressiveWatchList.StartupFolder(profile)));
        Assert.Contains(
            configuration.WatchRoots,
            root => IsSame(root, AggressiveWatchList.TempFolder(profile)));
    }

    [Fact]
    public void Standard_configuration_keeps_the_users_settle_delay_and_worker_count()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var settings = new AppSettings
        {
            AggressiveMode = false,
            RealtimeSettleDelayMs = 400,
            RealtimeWorkerCount = 5
        };

        var configuration = RealtimeMonitor.ResolveConfiguration(settings, profile);

        Assert.Equal(TimeSpan.FromMilliseconds(400), configuration.SettleDelay);
        Assert.Equal(5, configuration.WorkerCount);
    }

    [Fact]
    public void Aggressive_configuration_still_honours_the_excluded_folders()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var excluded = Path.Combine(profile, "AppData", "Local", "Temp");
        var settings = new AppSettings
        {
            AggressiveMode = true,
            RealtimeExcludedFolders = [excluded]
        };

        var configuration = RealtimeMonitor.ResolveConfiguration(settings, profile);

        Assert.DoesNotContain(configuration.WatchRoots, root => PathRules.IsWithin(root, excluded));
        Assert.Contains(configuration.ExcludedFolders, folder => IsSame(folder, excluded));
    }

    // ------------------------------------------------------------------
    // The response policy
    // ------------------------------------------------------------------

    [Fact]
    public void Policy_announces_a_high_confidence_finding()
    {
        var decision = RealtimeResponsePolicy.Decide([Finding(Confidence.High)]);

        Assert.Equal(RealtimeResponseLevel.Loud, decision.Level);
        Assert.True(decision.ShouldAlert);
        Assert.True(decision.ShouldNotify);
        Assert.False(decision.ShouldQuarantine);
        Assert.False(string.IsNullOrWhiteSpace(decision.Reason));
    }

    [Fact]
    public void Policy_announces_a_definitive_finding()
    {
        var decision = RealtimeResponsePolicy.Decide([Finding(Confidence.Definitive)]);

        Assert.Equal(RealtimeResponseLevel.Loud, decision.Level);
        Assert.True(decision.ShouldAlert);
    }

    [Fact]
    public void Policy_announces_a_test_signature()
    {
        var decision = RealtimeResponsePolicy.Decide(
            [Finding(Confidence.Medium, FindingCategory.TestSignature)]);

        Assert.Equal(RealtimeResponseLevel.Loud, decision.Level);
        Assert.True(decision.ShouldAlert);
    }

    [Fact]
    public void Policy_notifies_quietly_for_a_medium_finding()
    {
        var decision = RealtimeResponsePolicy.Decide([Finding(Confidence.Medium)]);

        Assert.Equal(RealtimeResponseLevel.Quiet, decision.Level);
        Assert.False(decision.ShouldAlert);
        Assert.True(decision.ShouldNotify);
        Assert.False(decision.ShouldQuarantine);
    }

    [Fact]
    public void Policy_only_lists_a_low_finding()
    {
        var decision = RealtimeResponsePolicy.Decide([Finding(Confidence.Low)]);

        Assert.Equal(RealtimeResponseLevel.ListOnly, decision.Level);
        Assert.False(decision.ShouldAlert);
        Assert.False(decision.ShouldNotify);
        Assert.False(decision.ShouldQuarantine);
    }

    [Fact]
    public void Policy_uses_the_strongest_finding_when_several_match()
    {
        var findings = new[]
        {
            Finding(Confidence.Low, ruleId: "weak"),
            Finding(Confidence.Medium, ruleId: "medium"),
            Finding(Confidence.High, ruleId: "strong")
        };

        var decision = RealtimeResponsePolicy.Decide(findings);

        Assert.Equal(RealtimeResponseLevel.Loud, decision.Level);
        Assert.Equal(Confidence.High, decision.StrongestConfidence);
        Assert.Contains("strong", decision.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Policy_uses_the_strongest_finding_even_when_the_weak_one_comes_first()
    {
        var findings = new[]
        {
            Finding(Confidence.High, ruleId: "strong"),
            Finding(Confidence.Low, ruleId: "weak")
        };

        var decision = RealtimeResponsePolicy.Decide(findings);

        Assert.Equal(RealtimeResponseLevel.Loud, decision.Level);
        Assert.Equal(Confidence.High, decision.StrongestConfidence);
    }

    [Fact]
    public void Policy_only_lists_a_detection_without_findings()
    {
        var decision = RealtimeResponsePolicy.Decide([]);

        Assert.Equal(RealtimeResponseLevel.ListOnly, decision.Level);
        Assert.False(decision.ShouldAlert);
        Assert.False(decision.ShouldNotify);
        Assert.False(decision.ShouldQuarantine);
        Assert.Equal(Confidence.Low, decision.StrongestConfidence);
    }

    [Fact]
    public void Policy_only_lists_a_detection_with_a_null_finding_list()
    {
        var decision = RealtimeResponsePolicy.Decide(null);

        Assert.Equal(RealtimeResponseLevel.ListOnly, decision.Level);
        Assert.False(decision.ShouldAlert);
    }

    [Fact]
    public void Policy_quarantines_a_strong_match_only_when_the_user_asked_for_it()
    {
        var strong = Finding(Confidence.High);
        var medium = Finding(Confidence.Medium);

        var asked = RealtimeResponsePolicy.Decide([strong], autoQuarantineRequested: true);
        var notAsked = RealtimeResponsePolicy.Decide([strong]);
        var weakMatch = RealtimeResponsePolicy.Decide([medium], autoQuarantineRequested: true);

        Assert.True(asked.ShouldQuarantine);
        Assert.Equal(RealtimeResponseLevel.Loud, asked.Level);
        Assert.False(notAsked.ShouldQuarantine);
        Assert.False(weakMatch.ShouldQuarantine);
    }

    [Fact]
    public void Policy_never_asks_for_a_deletion()
    {
        var decision = RealtimeResponsePolicy.Decide(
            [Finding(Confidence.Definitive)],
            autoQuarantineRequested: true);

        // The decision is about alerting and quarantining. There is no member that
        // removes a file, and the monitor never deletes anything either.
        var members = typeof(RealtimeResponseDecision)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();

        Assert.DoesNotContain(members, name => name.Contains("Delete", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(members, name => name.Contains("Remove", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(members, name => name.Contains("Destroy", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(members, name => name.Contains("Wipe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("ShouldQuarantine", members);
    }

    // ------------------------------------------------------------------
    // The monitor itself
    // ------------------------------------------------------------------

    [Fact]
    public async Task Aggressive_configuration_is_visible_in_the_monitor_and_its_stats()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var settings = new AppSettings { AggressiveMode = true, RealtimeWorkerCount = 3 };
        var configuration = RealtimeMonitor.ResolveConfiguration(settings, profile);
        var watchers = new FakeWatcherFactory();

        using var monitor = new RealtimeMonitor(
            DetectorRegistry.CreateDefault(),
            configuration.WatchRoots,
            configuration.ExcludedFolders,
            configuration.MaxInspectBytes,
            new FakeClock(),
            new FakeLog(),
            settleDelay: configuration.SettleDelay,
            workerCount: configuration.WorkerCount,
            watcherFactory: watchers,
            aggressiveMode: configuration.AggressiveMode);

        monitor.Start();
        await WaitUntilAsync(() => watchers.Created.Count >= configuration.WatchRoots.Count);

        Assert.Equal(TimeSpan.Zero, monitor.SettleDelay);
        Assert.Equal(configuration.WorkerCount, monitor.WorkerCount);
        Assert.True(monitor.AggressiveMode);

        var stats = monitor.GetStats();
        Assert.True(stats.IsAggressiveMode);
        Assert.Equal(configuration.WatchRoots.Count, stats.ConfiguredFolderCount);
        Assert.Equal(configuration.WatchRoots.Count, stats.WatchedFolderCount);
    }

    [Fact]
    public async Task The_same_folder_is_never_watched_twice()
    {
        using var temp = new TempDirectory();
        var profile = CreateProfile(temp);
        var roots = RealtimeMonitor.AggressiveWatchRoots(profile);
        var watchers = new FakeWatcherFactory();

        using var monitor = new RealtimeMonitor(
            DetectorRegistry.CreateDefault(),
            roots,
            [],
            maxInspectBytes: 1024 * 1024,
            new FakeClock(),
            new FakeLog(),
            settleDelay: TimeSpan.Zero,
            watcherFactory: watchers);

        monitor.Start();
        await WaitUntilAsync(() => watchers.Created.Count >= roots.Count);

        Assert.Equal(roots.Count, watchers.Created.Count);
        Assert.Equal(
            roots.Count,
            roots.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(
            watchers.Created.Count,
            watchers.Created.Select(watcher => watcher.Root).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public async Task The_same_file_is_never_inspected_twice_at_the_same_time()
    {
        using var temp = new TempDirectory();
        var sample = temp.File("sample.bin", "content");
        var detector = new BlockingDetector(TimeSpan.FromMilliseconds(150));
        var registry = new DetectorRegistry([detector]);

        using var monitor = new RealtimeMonitor(
            registry,
            [temp.Root],
            [],
            maxInspectBytes: 1024 * 1024,
            new FakeClock(),
            new FakeLog(),
            settleDelay: TimeSpan.Zero,
            workerCount: 4);

        monitor.Start();

        // The same path arrives again and again, as it would when a download is still
        // being written. The pending ledger must never let two workers read it at once.
        for (var attempt = 0; attempt < 6; attempt++)
        {
            monitor.Enqueue(sample);
            await Task.Delay(40);
        }

        await WaitUntilAsync(() => detector.Inspections >= 1);

        Assert.Equal(1, detector.MaxConcurrent);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// Builds a fake user profile with the folders the aggressive mode cares about.
    /// The path is a temporary folder, so the real profile is never read or watched.
    /// </summary>
    private static string CreateProfile(TempDirectory temp)
    {
        temp.CreateDirectory(Path.Combine("profile", "Desktop"));
        temp.CreateDirectory(Path.Combine("profile", "Documents"));
        temp.CreateDirectory(Path.Combine("profile", "Downloads"));
        temp.CreateDirectory(Path.Combine("profile", "AppData", "Local", "Temp"));
        temp.CreateDirectory(Path.Combine(
            "profile",
            "AppData",
            "Roaming",
            "Microsoft",
            "Windows",
            "Start Menu",
            "Programs",
            "Startup"));

        return Path.Combine(temp.Root, "profile");
    }

    private static bool IsSame(string left, string right) =>
        string.Equals(
            PathRules.NormalizeDirectory(left),
            PathRules.NormalizeDirectory(right),
            StringComparison.OrdinalIgnoreCase);

    private static Finding Finding(
        Confidence confidence,
        FindingCategory category = FindingCategory.Heuristic,
        string ruleId = "test.rule") =>
        new()
        {
            RuleId = ruleId,
            Title = "Test rule " + ruleId,
            Category = category,
            Confidence = confidence,
            Summary = "Test summary",
            Detail = "Test detail",
            Advice = "Test advice"
        };

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

    /// <summary>
    /// A detector that holds the inspection open for a while and remembers how many
    /// inspections ran at the same time. It is how the tests observe that the monitor
    /// never reads one file twice at once.
    /// </summary>
    private sealed class BlockingDetector : IScanDetector
    {
        private readonly TimeSpan _hold;
        private readonly object _gate = new();
        private int _current;
        private int _max;
        private int _inspections;

        public BlockingDetector(TimeSpan hold) => _hold = hold;

        public string Id => "aggressive.blocking";
        public string Name => "Blocking detector";
        public string Description => "Test detector that holds the inspection open";
        public FindingCategory Category => FindingCategory.Heuristic;
        public Confidence Confidence => Confidence.Medium;

        public int Inspections => Volatile.Read(ref _inspections);

        public int MaxConcurrent
        {
            get { lock (_gate) return _max; }
        }

        public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
        {
            lock (_gate)
            {
                _current++;
                _inspections++;
                if (_current > _max) _max = _current;
            }

            try
            {
                Thread.Sleep(_hold);
            }
            finally
            {
                lock (_gate) _current--;
            }

            return [];
        }
    }
}
