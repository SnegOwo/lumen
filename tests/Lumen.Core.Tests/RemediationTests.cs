using Lumen.Core.Models;
using Lumen.Core.Remediation;
using Lumen.Core.Util;

namespace Lumen.Core.Tests;

public sealed class RemediationTests
{
    private const string OtherHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public async Task Plan_produces_a_preview_and_changes_nothing_until_the_user_confirms()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var hash = HashUtil.Sha256File(file, CancellationToken.None);

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, hash);
        harness.Processes.AddProcess("evil.exe", file, 4242);
        harness.Persistence.Entries.Add(RemediationHarness.RunEntry("Evil", file));

        var plan = await harness.Engine.PlanAsync(harness.Target(file, hash), CancellationToken.None);

        Assert.Equal(RemediationStatus.Planned, plan.Status);
        Assert.Equal(3, plan.Steps.Count);
        Assert.All(plan.Steps, step => Assert.Equal(RemediationStepStatus.Pending, step.Status));

        // Nothing at all has happened yet: no process stopped, no entry removed, no file deleted.
        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Empty(harness.Persistence.RemovedEntries);
        Assert.Empty(harness.Remover.RemovedPaths);
        Assert.True(File.Exists(file));

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStatus.Executed, result.Status);
        Assert.Equal(new[] { 4242 }, harness.Processes.TerminatedPids);
        Assert.Single(harness.Persistence.RemovedEntries);
        Assert.Single(harness.Remover.RemovedPaths);
    }

    [Fact]
    public async Task Dry_run_leaves_the_machine_untouched()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var hash = HashUtil.Sha256File(file, CancellationToken.None);

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, hash);
        harness.Processes.AddProcess("evil.exe", file, 1111);
        harness.Persistence.Entries.Add(RemediationHarness.RunEntry("Evil", file));

        var plan = await harness.Engine.PlanAsync(harness.Target(file, hash), CancellationToken.None);

        Assert.NotEmpty(plan.Steps);
        Assert.Equal(0, harness.Remover.RemoveCallCount);
        Assert.Equal(0, harness.Persistence.RemoveCallCount);
        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.True(File.Exists(file));

        // The journal only holds the preview, not an execution.
        Assert.All(
            harness.Journal.Entries,
            entry => Assert.True(
                entry.Kind is AuditEventKind.PlanCreated or AuditEventKind.StepPlanned,
                $"Unexpected journal entry {entry.Kind}."));
    }

    [Fact]
    public async Task Protected_processes_never_appear_in_a_plan()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, OtherHash);
        harness.Processes.AddProcess("lsass", @"C:\Windows\System32\lsass.exe", 500);
        harness.Processes.AddProcess("wininit", @"C:\Windows\System32\wininit.exe", 501);
        harness.Processes.AddProcess("evil.exe", file, 600);

        var plan = await harness.Engine.PlanAsync(harness.Target(file, OtherHash), CancellationToken.None);

        var terminate = plan.Steps.Where(step => step.Kind == RemediationStepKind.TerminateProcess).ToArray();
        Assert.Single(terminate);
        Assert.Equal(600, terminate[0].ProcessId);
    }

    [Fact]
    public async Task A_terminate_request_for_a_protected_process_is_refused()
    {
        var harness = new RemediationHarness();
        harness.Processes.AddProcess("lsass", @"C:\Windows\System32\lsass.exe", 500);

        var step = new RemediationStep
        {
            Id = "step-1",
            Kind = RemediationStepKind.TerminateProcess,
            Description = "Terminate pid 500 (lsass)",
            ProcessId = 500,
            ProcessName = "lsass",
            Status = RemediationStepStatus.Pending
        };

        var plan = new RemediationPlan
        {
            Id = "plan-1",
            CreatedUtc = harness.Clock.UtcNow,
            Target = harness.Target(@"C:\Users\tester\evil.exe", OtherHash),
            Steps = [step]
        };

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStatus.Refused, result.Status);
        Assert.Equal(RemediationStepStatus.Refused, Assert.Single(result.Steps).Status);
        Assert.Empty(harness.Processes.TerminatedPids);
    }

    [Fact]
    public async Task A_process_running_from_the_windows_folder_is_treated_as_protected()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, OtherHash);
        harness.Processes.AddProcess("systemhost.exe", @"C:\Windows\System32\systemhost.exe", 700);

        var plan = await harness.Engine.PlanAsync(harness.Target(file, OtherHash), CancellationToken.None);

        Assert.DoesNotContain(plan.Steps, step => step.Kind == RemediationStepKind.TerminateProcess);

        Assert.True(ProtectedProcesses.IsProtectedLocation(@"C:\Windows\System32\thing.exe"));
        Assert.True(ProtectedProcesses.IsProtectedLocation(@"C:\Program Files\Vendor\App\app.exe"));
        Assert.False(ProtectedProcesses.IsProtectedLocation(@"C:\Users\tester\Windows\notes.txt"));
    }

    [Fact]
    public async Task A_system_critical_path_is_refused_and_is_never_deleted()
    {
        var systemPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "evil.exe");

        var harness = new RemediationHarness();
        harness.Hasher.Set(systemPath, OtherHash);

        var plan = await harness.Engine.PlanAsync(harness.Target(systemPath, OtherHash), CancellationToken.None);

        var step = Assert.Single(plan.Steps);
        Assert.Equal(RemediationStepKind.RemoveFile, step.Kind);
        Assert.Equal(RemediationStepStatus.Refused, step.Status);

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStepStatus.Refused, Assert.Single(result.Steps).Status);
        Assert.Empty(harness.Remover.RemovedPaths);
    }

    [Fact]
    public async Task Every_executed_action_is_written_to_the_audit_journal()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var hash = HashUtil.Sha256File(file, CancellationToken.None);

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, hash);
        harness.Processes.AddProcess("evil.exe", file, 4242);
        harness.Persistence.Entries.Add(RemediationHarness.RunEntry("Evil", file));

        var plan = await harness.Engine.PlanAsync(harness.Target(file, hash), CancellationToken.None);
        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStatus.Executed, result.Status);

        var executed = harness.Journal.Entries
            .Where(entry => entry.Kind == AuditEventKind.StepExecuted)
            .ToArray();

        Assert.Equal(3, executed.Length);
        Assert.Contains(executed, entry => entry.StepKind == RemediationStepKind.TerminateProcess);
        Assert.Contains(executed, entry => entry.StepKind == RemediationStepKind.RemovePersistence);
        Assert.Contains(executed, entry => entry.StepKind == RemediationStepKind.RemoveFile);

        var fileEntry = executed.Single(entry => entry.StepKind == RemediationStepKind.RemoveFile);
        Assert.Equal(hash, fileEntry.Sha256);
        Assert.Equal("vaultitem000000000000000000000000", fileEntry.QuarantineItemId);
        Assert.Equal(plan.Id, fileEntry.PlanId);

        // The vault copy is always pointed at, so a wrong removal can be reported.
        Assert.All(
            harness.Journal.Entries,
            entry => Assert.Equal(plan.Id, entry.PlanId));
    }

    [Fact]
    public async Task A_failure_in_the_middle_stops_the_steps_that_follow()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var hash = HashUtil.Sha256File(file, CancellationToken.None);

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, hash);
        harness.Processes.AddProcess("evil.exe", file, 800);
        harness.Processes.FailTerminationPids.Add(800);
        harness.Persistence.Entries.Add(RemediationHarness.RunEntry("Evil", file));

        var plan = await harness.Engine.PlanAsync(harness.Target(file, hash), CancellationToken.None);
        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStatus.Failed, result.Status);
        Assert.Equal(RemediationStepStatus.Failed, result.Steps[0].Status);
        Assert.Equal(RemediationStepStatus.Skipped, result.Steps[1].Status);
        Assert.Equal(RemediationStepStatus.Skipped, result.Steps[2].Status);

        // The steps after the failure were not attempted.
        Assert.Empty(harness.Persistence.RemovedEntries);
        Assert.Empty(harness.Remover.RemovedPaths);

        Assert.Contains(harness.Journal.Entries, entry => entry.Kind == AuditEventKind.StepFailed);
        Assert.Contains(harness.Journal.Entries, entry => entry.Kind == AuditEventKind.StepSkipped);
    }

    [Fact]
    public async Task The_engine_refuses_to_plan_or_execute_when_remediation_is_disabled()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var hash = HashUtil.Sha256File(file, CancellationToken.None);

        var harness = new RemediationHarness(remediationEnabled: false);
        harness.Hasher.Set(file, hash);
        harness.Processes.AddProcess("evil.exe", file, 900);

        var plan = await harness.Engine.PlanAsync(harness.Target(file, hash), CancellationToken.None);

        Assert.Equal(RemediationStatus.Refused, plan.Status);
        Assert.Empty(plan.Steps);

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStatus.Refused, result.Status);
        Assert.Empty(harness.Processes.TerminatedPids);
        Assert.Empty(harness.Remover.RemovedPaths);
        Assert.Empty(harness.Persistence.RemovedEntries);
    }

    [Fact]
    public async Task Removing_a_persistence_entry_stores_enough_to_restore_it()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RemediationHarness();
        var entry = RemediationHarness.RunEntry("EvilUpdater", file);
        harness.Persistence.Entries.Add(entry);

        var plan = await harness.Engine.PlanAsync(
            harness.Target(file, OtherHash),
            new RemediationOptions { TerminateProcesses = false, RemoveFile = false, RemovePersistence = true },
            CancellationToken.None);

        var step = Assert.Single(plan.Steps);
        Assert.Equal(RemediationStepKind.RemovePersistence, step.Kind);

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);
        Assert.Equal(RemediationStatus.Executed, result.Status);
        Assert.Equal(entry, Assert.Single(harness.Persistence.RemovedEntries));

        var journalEntry = Assert.Single(
            harness.Journal.Entries,
            item => item.Kind == AuditEventKind.StepExecuted &&
                    item.StepKind == RemediationStepKind.RemovePersistence);

        var restore = Assert.IsType<PersistenceRestoreData>(journalEntry.RestoreData);
        Assert.Equal("EvilUpdater", restore.RegistryValueName);
        Assert.Equal(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", restore.RegistryKeyPath);
        Assert.Equal(file, restore.RegistryValueData);
        Assert.Equal("REG_SZ", restore.RegistryValueKind);
        Assert.True(restore.CanRestore);
    }

    [Fact]
    public async Task A_persistence_entry_without_restore_data_is_left_alone()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RemediationHarness();
        harness.Persistence.Entries.Add(RemediationHarness.RunEntry("Evil", file, canRestore: false));

        var plan = await harness.Engine.PlanAsync(
            harness.Target(file, OtherHash),
            new RemediationOptions { TerminateProcesses = false, RemoveFile = false, RemovePersistence = true },
            CancellationToken.None);

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStatus.Refused, result.Status);
        Assert.Equal(RemediationStepStatus.Refused, Assert.Single(result.Steps).Status);
        Assert.Empty(harness.Persistence.RemovedEntries);
    }

    [Fact]
    public async Task The_file_removal_step_refuses_when_the_hash_does_not_match()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var hash = HashUtil.Sha256File(file, CancellationToken.None);

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, hash);

        var plan = await harness.Engine.PlanAsync(harness.Target(file, OtherHash), CancellationToken.None);

        var step = plan.Steps.Single(candidate => candidate.Kind == RemediationStepKind.RemoveFile);
        Assert.Equal(RemediationStepStatus.Refused, step.Status);

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStepStatus.Refused, result.Steps[0].Status);
        Assert.Empty(harness.Remover.RemovedPaths);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task The_file_removal_step_refuses_when_the_file_changes_after_the_plan()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var hash = HashUtil.Sha256File(file, CancellationToken.None);

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, hash);

        var plan = await harness.Engine.PlanAsync(harness.Target(file, hash), CancellationToken.None);

        // The file changes between planning and confirming.
        harness.Hasher.Set(file, OtherHash);

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStatus.Refused, result.Status);
        Assert.Empty(harness.Remover.RemovedPaths);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task A_file_that_was_never_verified_is_not_removed()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, OtherHash);

        var plan = await harness.Engine.PlanAsync(
            harness.Target(file, sha256: null),
            new RemediationOptions { TerminateProcesses = false, RemovePersistence = false },
            CancellationToken.None);

        var result = await harness.Engine.ExecuteAsync(plan, CancellationToken.None);

        Assert.Equal(RemediationStepStatus.Refused, Assert.Single(result.Steps).Status);
        Assert.Empty(harness.Remover.RemovedPaths);
    }

    [Fact]
    public async Task Only_the_steps_the_user_selects_are_run()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");
        var hash = HashUtil.Sha256File(file, CancellationToken.None);

        var harness = new RemediationHarness();
        harness.Hasher.Set(file, hash);
        harness.Processes.AddProcess("evil.exe", file, 4242);

        var plan = await harness.Engine.PlanAsync(harness.Target(file, hash), CancellationToken.None);

        var terminate = plan.Steps.Single(step => step.Kind == RemediationStepKind.TerminateProcess);
        var result = await harness.Engine.ExecuteAsync(plan, [terminate.Id], CancellationToken.None);

        Assert.Equal(RemediationStatus.Executed, result.Status);
        Assert.Equal(new[] { 4242 }, harness.Processes.TerminatedPids);
        Assert.Empty(harness.Remover.RemovedPaths);

        var fileStep = result.Steps.Single(step => step.Kind == RemediationStepKind.RemoveFile);
        Assert.Equal(RemediationStepStatus.Skipped, fileStep.Status);
    }

    [Fact]
    public void A_persistence_entry_that_points_elsewhere_is_not_offered()
    {
        var entry = RemediationHarness.RunEntry("Notepad", @"C:\Windows\System32\notepad.exe");

        Assert.False(PersistenceMatcher.PointsAt(entry, @"C:\Users\tester\evil.exe"));
        Assert.True(PersistenceMatcher.PointsAt(entry, @"C:\Windows\System32\notepad.exe"));
        Assert.False(PersistenceMatcher.PointsAt(entry, null));
    }

    [Fact]
    public async Task The_journal_file_is_append_only_and_survives_a_restart()
    {
        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Root, "journal", "remediation-journal.jsonl");
        var clock = new FakeClock();
        var log = new FakeLog();

        var journal = new FileAuditJournal(path, clock, log);
        await journal.AppendAsync(
            new AuditEntry
            {
                TimestampUtc = clock.UtcNow,
                Kind = AuditEventKind.PlanCreated,
                PlanId = "plan-1",
                Target = @"C:\Users\tester\evil.exe"
            },
            CancellationToken.None);

        var reopened = new FileAuditJournal(path, clock, log);
        await reopened.AppendAsync(
            new AuditEntry
            {
                TimestampUtc = clock.UtcNow,
                Kind = AuditEventKind.PlanCompleted,
                PlanId = "plan-1",
                Target = @"C:\Users\tester\evil.exe"
            },
            CancellationToken.None);

        var entries = await reopened.ReadAsync(CancellationToken.None);

        Assert.Equal(2, entries.Count);
        Assert.Equal(AuditEventKind.PlanCreated, entries[0].Kind);
        Assert.Equal(AuditEventKind.PlanCompleted, entries[1].Kind);
        Assert.Equal("plan-1", entries[0].PlanId);
    }

    [Fact]
    public async Task A_plan_is_not_produced_when_the_journal_cannot_be_written()
    {
        using var temp = new TempDirectory();
        var file = temp.File("evil.exe", "malicious content");

        var harness = new RemediationHarness();
        harness.Journal.FailOnAppend = true;
        harness.Hasher.Set(file, OtherHash);

        var plan = await harness.Engine.PlanAsync(harness.Target(file, OtherHash), CancellationToken.None);

        Assert.Equal(RemediationStatus.Refused, plan.Status);
        Assert.Empty(plan.Steps);
        Assert.Empty(harness.Remover.RemovedPaths);
    }
}
