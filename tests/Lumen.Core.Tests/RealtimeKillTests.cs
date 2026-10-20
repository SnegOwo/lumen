using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Remediation;

namespace Lumen.Core.Tests;

/// <summary>
/// Test double for the running processes of the machine. It never touches a real
/// process: it only remembers what it was asked to do, so a test can assert on it.
///
/// The double mimics the real adapter: a process is reported only when its executable
/// path or its loaded module path IS the file that was asked about. A process that
/// merely lives in the same folder is not reported.
/// </summary>
internal sealed class FakeKillProcessTerminator : IProcessTerminator
{
    private readonly List<ProcessMatch> _matches = [];

    /// <summary>Every process id the service asked to stop, in order.</summary>
    public List<int> TerminatedPids { get; } = [];

    /// <summary>Process ids Windows is supposed to deny access to.</summary>
    public HashSet<int> DeniedPids { get; } = [];

    /// <summary>Process ids that have already exited when the service looks at them.</summary>
    public HashSet<int> ExitedPids { get; } = [];

    /// <summary>
    /// When true the double reports every match, even one that does not point at the
    /// file. It stands in for an adapter that reports too much.
    /// </summary>
    public bool ReportEveryMatch { get; set; }

    /// <summary>How often the service asked for the process list.</summary>
    public int FindCallCount { get; private set; }

    /// <summary>How often the service asked for a single process.</summary>
    public int GetCallCount { get; private set; }

    /// <summary>Adds a process that uses the given file.</summary>
    public FakeKillProcessTerminator AddProcess(
        string name,
        string? executablePath,
        int pid,
        bool isSystemProcess = false,
        bool isSigned = false,
        ProcessMatchKind matchKind = ProcessMatchKind.ExecutablePath,
        string? matchedPath = null)
    {
        var process = new ProcessInfo
        {
            Pid = pid,
            Name = name,
            ExecutablePath = executablePath,
            IsSystemProcess = isSystemProcess,
            IsSigned = isSigned
        };

        _matches.Add(new ProcessMatch
        {
            Process = process,
            MatchKind = matchKind,
            MatchedPath = matchedPath ?? executablePath ?? name
        });

        return this;
    }

    /// <summary>
    /// Makes the process look different now than it did when it was found. This is how
    /// a test proves that the protection is checked again at the moment of the action.
    /// </summary>
    public FakeKillProcessTerminator SetCurrentState(int pid, ProcessInfo process)
    {
        CurrentState[pid] = process;
        return this;
    }

    private Dictionary<int, ProcessInfo> CurrentState { get; } = [];

    public Task<IReadOnlyList<ProcessMatch>> FindByFilePathAsync(string filePath, CancellationToken cancellationToken)
    {
        FindCallCount++;

        var found = ReportEveryMatch
            ? _matches.ToArray()
            : _matches.Where(match => Matches(match, filePath)).ToArray();

        return Task.FromResult<IReadOnlyList<ProcessMatch>>(found);
    }

    public Task<ProcessInfo?> GetAsync(int pid, CancellationToken cancellationToken)
    {
        GetCallCount++;

        if (ExitedPids.Contains(pid)) return Task.FromResult<ProcessInfo?>(null);
        if (CurrentState.TryGetValue(pid, out var current)) return Task.FromResult<ProcessInfo?>(current);

        var process = _matches
            .Select(match => match.Process)
            .FirstOrDefault(candidate => candidate.Pid == pid);

        return Task.FromResult(process);
    }

    public Task<ProcessTerminationResult> TerminateAsync(int pid, CancellationToken cancellationToken)
    {
        TerminatedPids.Add(pid);

        if (DeniedPids.Contains(pid))
        {
            return Task.FromResult(new ProcessTerminationResult
            {
                Terminated = false,
                Outcome = ProcessTerminationOutcome.AccessDenied,
                Message = "Windows denied access. Lumen does not elevate its privileges."
            });
        }

        return Task.FromResult(new ProcessTerminationResult
        {
            Terminated = true,
            Outcome = ProcessTerminationOutcome.Terminated,
            Message = "The process was stopped."
        });
    }

    private static bool Matches(ProcessMatch match, string filePath)
    {
        var target = Normalize(filePath);
        if (target is null) return false;

        return SamePath(match.MatchedPath, target) || SamePath(match.Process.ExecutablePath, target);
    }

    private static bool SamePath(string? left, string target)
    {
        if (string.IsNullOrWhiteSpace(left)) return false;
        var full = Normalize(left);
        return full is not null && string.Equals(full, target, StringComparison.OrdinalIgnoreCase);
    }

    private static string? Normalize(string path)
    {
        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }
}

/// <summary>
/// Bundles the real-time kill service with its test doubles so each test reads as one
/// short story.
/// </summary>
internal sealed class RealtimeKillHarness
{
    public RealtimeKillHarness(bool autoKillEnabled = true, bool remediationEnabled = true)
    {
        Service = new RealtimeKillService(
            Processes,
            Journal,
            Clock,
            Log,
            autoKillEnabled,
            remediationEnabled);
    }

    public FakeKillProcessTerminator Processes { get; } = new();
    public FakeAuditJournal Journal { get; } = new();
    public FakeClock Clock { get; } = new();
    public FakeLog Log { get; } = new();
    public RealtimeKillService Service { get; }

    /// <summary>Builds the detection the real-time monitor would have produced.</summary>
    public RealtimeDetectionEvent Detection(string path, bool withFinding = true) => new()
    {
        FilePath = path,
        SizeBytes = 128,
        Sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
        IsActionable = true,
        Findings = withFinding
            ?
            [
                new Finding
                {
                    RuleId = "test-rule",
                    Title = "Test finding",
                    Category = FindingCategory.Heuristic,
                    Confidence = Confidence.High,
                    Summary = "Test summary",
                    Detail = "Test detail",
                    Advice = "Test advice"
                }
            ]
            : [],
        DetectedUtc = Clock.UtcNow
    };
}

public sealed class RealtimeKillTests
{
    [Fact]
    public async Task With_the_feature_off_nothing_is_stopped_and_nothing_is_journalled()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness(autoKillEnabled: false);
        harness.Processes.AddProcess("evil.exe", file, 4242);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Equal(RealtimeKillStatus.Disabled, result.Status);
        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Empty(harness.Journal.Entries);

        // Lumen does not even look at the running processes when the feature is off.
        Assert.Equal(0, harness.Processes.FindCallCount);
    }

    [Fact]
    public async Task With_the_remediation_master_switch_off_nothing_is_stopped()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness(autoKillEnabled: true, remediationEnabled: false);
        harness.Processes.AddProcess("evil.exe", file, 4242);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Equal(RealtimeKillStatus.Disabled, result.Status);
        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Empty(harness.Journal.Entries);
    }

    [Fact]
    public async Task A_process_whose_executable_is_the_flagged_file_is_stopped()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("evil.exe", file, 4242);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Equal(RealtimeKillStatus.Stopped, result.Status);
        Assert.Equal(new[] { 4242 }, harness.Processes.TerminatedPids);
        Assert.Equal(1, result.StoppedCount);

        var entry = Assert.Single(result.Processes);
        Assert.Equal(4242, entry.Pid);
        Assert.Equal("evil.exe", entry.Name);
        Assert.True(entry.Stopped);
        Assert.Equal(ProcessMatchKind.ExecutablePath, entry.MatchKind);
    }

    [Fact]
    public async Task A_process_whose_loaded_module_is_the_flagged_file_is_stopped()
    {
        using var temp = new TempDirectory();
        var file = temp.File("payload.dll", "malicious content");
        var host = Path.Combine(temp.Root, "host.exe");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess(
            "host.exe",
            host,
            5150,
            matchKind: ProcessMatchKind.LoadedModule,
            matchedPath: file);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Equal(RealtimeKillStatus.Stopped, result.Status);
        Assert.Equal(new[] { 5150 }, harness.Processes.TerminatedPids);

        var entry = Assert.Single(result.Processes);
        Assert.Equal(ProcessMatchKind.LoadedModule, entry.MatchKind);
        Assert.True(entry.Stopped);
    }

    [Fact]
    public async Task A_process_that_merely_lives_in_the_same_folder_is_not_stopped()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var neighbour = temp.File("notepad.exe", "harmless content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("notepad.exe", neighbour, 4243);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Equal(RealtimeKillStatus.NothingToStop, result.Status);
        Assert.Empty(result.Processes);
    }

    [Fact]
    public async Task A_match_that_does_not_point_at_the_flagged_file_is_refused()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var neighbour = temp.File("notepad.exe", "harmless content");

        var harness = new RealtimeKillHarness();

        // The adapter reports too much: the process only lives in the same folder.
        harness.Processes.ReportEveryMatch = true;
        harness.Processes.AddProcess("notepad.exe", neighbour, 4243);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Empty(harness.Processes.TerminatedPids);

        var entry = Assert.Single(result.Processes);
        Assert.Equal(RealtimeKillProcessOutcome.NotUsingFile, entry.Outcome);
        Assert.Equal(RealtimeKillStatus.Refused, result.Status);
        Assert.Equal(1, result.RefusedCount);
    }

    [Fact]
    public async Task A_protected_process_is_refused_and_the_refusal_is_journalled()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess(
            "lsass",
            @"C:\Windows\System32\lsass.exe",
            500,
            matchKind: ProcessMatchKind.LoadedModule,
            matchedPath: file);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Equal(RealtimeKillStatus.Refused, result.Status);

        var entry = Assert.Single(result.Processes);
        Assert.Equal(RealtimeKillProcessOutcome.RefusedProtected, entry.Outcome);
        Assert.False(entry.Stopped);

        var journalled = Assert.Single(
            harness.Journal.Entries,
            item => item.Kind == AuditEventKind.StepRefused);

        Assert.Contains("pid 500", journalled.Detail);
        Assert.Equal(RemediationStepKind.TerminateProcess, journalled.StepKind);
    }

    [Fact]
    public async Task A_process_running_from_a_system_critical_location_is_refused()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess(
            "systemhost.exe",
            @"C:\Windows\System32\systemhost.exe",
            700,
            matchKind: ProcessMatchKind.LoadedModule,
            matchedPath: file);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Empty(harness.Processes.TerminatedPids);

        var entry = Assert.Single(result.Processes);
        Assert.Equal(RealtimeKillProcessOutcome.RefusedSystemLocation, entry.Outcome);
        Assert.Equal(RealtimeKillStatus.Refused, result.Status);

        Assert.Contains(
            harness.Journal.Entries,
            item => item.Kind == AuditEventKind.StepRefused && item.Detail!.Contains("pid 700"));
    }

    [Fact]
    public async Task The_protection_is_checked_again_at_the_moment_of_the_action()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("evil.exe", file, 4242);

        // The process looked ordinary when it was found, and is protected by the time
        // Lumen goes to stop it.
        harness.Processes.SetCurrentState(4242, new ProcessInfo
        {
            Pid = 4242,
            Name = "evil.exe",
            ExecutablePath = @"C:\Windows\System32\evil.exe",
            IsSystemProcess = true
        });

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Equal(1, harness.Processes.GetCallCount);

        var entry = Assert.Single(result.Processes);
        Assert.Equal(RealtimeKillProcessOutcome.RefusedProtected, entry.Outcome);
        Assert.Equal(RealtimeKillStatus.Refused, result.Status);

        Assert.Contains(
            harness.Journal.Entries,
            item => item.Kind == AuditEventKind.StepRefused && item.Detail!.Contains("pid 4242"));
    }

    [Fact]
    public async Task The_flagged_file_is_neither_deleted_nor_quarantined()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("evil.exe", file, 4242);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Equal(RealtimeKillStatus.Stopped, result.Status);
        Assert.True(File.Exists(file));

        // The kill service has no file-removing seam at all: the journal must not
        // mention a removal either.
        Assert.DoesNotContain(
            harness.Journal.Entries,
            entry => entry.StepKind == RemediationStepKind.RemoveFile);
    }

    [Fact]
    public async Task A_second_flag_for_the_same_file_does_not_stop_anything_twice()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("evil.exe", file, 4242);

        var first = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);
        var second = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Equal(RealtimeKillStatus.Stopped, first.Status);
        Assert.Equal(new[] { 4242 }, harness.Processes.TerminatedPids);
        Assert.Equal(RealtimeKillStatus.AlreadyHandled, second.Status);
        Assert.Empty(second.Processes);
    }

    [Fact]
    public async Task A_file_that_no_longer_exists_is_handled_without_throwing()
    {
        using var temp = new TempDirectory();
        var gone = Path.Combine(temp.Root, "already-deleted.exe");

        var harness = new RealtimeKillHarness();

        var result = await harness.Service.KillAsync(harness.Detection(gone), CancellationToken.None);

        Assert.Equal(RealtimeKillStatus.NothingToStop, result.Status);
        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.False(File.Exists(gone));
    }

    [Fact]
    public async Task Every_action_and_every_refusal_appears_in_the_audit_journal()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("evil.exe", file, 4242);
        harness.Processes.AddProcess(
            "lsass",
            @"C:\Windows\System32\lsass.exe",
            500,
            matchKind: ProcessMatchKind.LoadedModule,
            matchedPath: file);
        harness.Processes.AddProcess("gone.exe", file, 4244);
        harness.Processes.ExitedPids.Add(4244);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Equal(RealtimeKillStatus.Stopped, result.Status);
        Assert.Equal(new[] { 4242 }, harness.Processes.TerminatedPids);

        // The stop, the refusal and the process that had already exited are all on
        // record, and each line names the process it is about.
        Assert.Contains(harness.Journal.Entries, entry =>
            entry.Kind == AuditEventKind.StepExecuted && entry.Detail!.Contains("pid 4242"));
        Assert.Contains(harness.Journal.Entries, entry =>
            entry.Kind == AuditEventKind.StepRefused && entry.Detail!.Contains("pid 500"));
        Assert.Contains(harness.Journal.Entries, entry =>
            entry.Kind == AuditEventKind.StepSkipped && entry.Detail!.Contains("pid 4244"));

        // The run itself is on record as well.
        Assert.Contains(harness.Journal.Entries, entry => entry.Kind == AuditEventKind.PlanCreated);
        Assert.Contains(harness.Journal.Entries, entry => entry.Kind == AuditEventKind.PlanCompleted);

        // Every line belongs to this run, and the run is recognisable as a real-time
        // kill rather than a plan the user reviewed.
        Assert.All(
            harness.Journal.Entries,
            entry => Assert.StartsWith(RealtimeKillService.RunIdPrefix, entry.PlanId));
    }

    [Fact]
    public async Task A_process_that_windows_protects_is_reported_and_not_thrown()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("evil.exe", file, 4242);
        harness.Processes.DeniedPids.Add(4242);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        // The process is still running. That is a normal outcome, not a failure.
        Assert.Equal(RealtimeKillStatus.Refused, result.Status);
        Assert.DoesNotContain(result.Processes, process => process.Stopped);

        var entry = Assert.Single(result.Processes);
        Assert.Equal(RealtimeKillProcessOutcome.Denied, entry.Outcome);
        Assert.Contains("denied", entry.Reason, StringComparison.OrdinalIgnoreCase);

        Assert.Contains(
            harness.Journal.Entries,
            item => item.Kind == AuditEventKind.StepRefused && item.Detail!.Contains("pid 4242"));
    }

    [Fact]
    public async Task Nothing_is_stopped_when_the_audit_journal_cannot_be_written()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Journal.FailOnAppend = true;
        harness.Processes.AddProcess("evil.exe", file, 4242);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Equal(RealtimeKillStatus.Refused, result.Status);
        Assert.Contains("journal", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Lumen_never_stops_itself()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("lumen.exe", file, Environment.ProcessId);

        var result = await harness.Service.KillAsync(harness.Detection(file), CancellationToken.None);

        Assert.Empty(harness.Processes.TerminatedPids);

        var entry = Assert.Single(result.Processes);
        Assert.Equal(RealtimeKillProcessOutcome.RefusedSelf, entry.Outcome);
    }

    [Fact]
    public async Task A_detection_without_a_finding_is_refused()
    {
        using var temp = new TempDirectory();
        var file = temp.File("maybe.exe", "unknown content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("maybe.exe", file, 4242);

        var result = await harness.Service.KillAsync(
            harness.Detection(file, withFinding: false),
            CancellationToken.None);

        // Nothing is stopped because nothing was flagged. Lumen never decides on its
        // own that a process looks suspicious.
        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Equal(RealtimeKillStatus.Refused, result.Status);
    }

    [Fact]
    public async Task Only_the_processes_the_caller_approves_are_stopped()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var other = temp.File("other.exe", "malicious content");

        var harness = new RealtimeKillHarness();
        harness.Processes.AddProcess("evil.exe", file, 4242);
        harness.Processes.AddProcess(
            "other.exe",
            other,
            4243,
            matchKind: ProcessMatchKind.LoadedModule,
            matchedPath: file);

        var request = new RealtimeKillRequest
        {
            FilePath = file,
            Findings =
            [
                new Finding
                {
                    RuleId = "test-rule",
                    Title = "Test finding",
                    Category = FindingCategory.Heuristic,
                    Confidence = Confidence.High,
                    Summary = "Test summary",
                    Detail = "Test detail",
                    Advice = "Test advice"
                }
            ]
        };

        var result = await harness.Service.KillAsync(request, [4242], CancellationToken.None);

        Assert.Equal(new[] { 4242 }, harness.Processes.TerminatedPids);
        Assert.Contains(result.Processes, process => process.Pid == 4243 && process.Outcome == RealtimeKillProcessOutcome.NotApproved);
    }
}
