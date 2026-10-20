using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.Core.Remediation;

/// <summary>
/// Decides what should happen to a detected file and reports what happened.
///
/// The engine is pure orchestration: it never touches the operating system itself. It
/// reads the world through <see cref="IProcessTerminator"/>, <see cref="IPersistenceEnumerator"/>,
/// <see cref="IFileHasher"/> and <see cref="IFileRemover"/>, and records what it decided
/// and what it did in an <see cref="IAuditJournal"/>.
///
/// The contract with the caller is deliberately narrow and deliberately dull:
///
/// <list type="bullet">
/// <item>Planning changes nothing. <see cref="PlanAsync"/> only produces a preview.</item>
/// <item>Nothing runs without an explicit call to <see cref="ExecuteAsync"/>, and only the
/// steps the caller selects are run. There is no "clean everything" path.</item>
/// <item>System-critical files are never removed and protected processes are never
/// stopped. Both rules are checked again at execution time, not only when planning.</item>
/// <item>The engine fails closed. When a step fails, the remaining steps are not
/// attempted, the quarantine copy is kept, and the result names exactly which steps ran
/// and which did not.</item>
/// <item>Nothing is ever run elevated. Lumen writes only to the user's own registry hive
/// and never installs a service, a driver or a scheduled task of its own.</item>
/// </list>
/// </summary>
public sealed class RemediationEngine
{
    private readonly IProcessTerminator _processes;
    private readonly IPersistenceEnumerator _persistence;
    private readonly IFileRemover _files;
    private readonly IFileHasher _hasher;
    private readonly IAuditJournal _journal;
    private readonly IClock _clock;
    private readonly ILog _log;

    /// <summary>
    /// Creates the engine. The remediation master switch starts in the state it is given;
    /// while it is off the engine refuses to plan and refuses to execute, which keeps
    /// Lumen's detect-and-quarantine-only behaviour intact.
    /// </summary>
    public RemediationEngine(
        IProcessTerminator processes,
        IPersistenceEnumerator persistence,
        IFileRemover files,
        IFileHasher hasher,
        IAuditJournal journal,
        IClock clock,
        ILog log,
        bool remediationEnabled = false)
    {
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));
        _persistence = persistence ?? throw new ArgumentNullException(nameof(persistence));
        _files = files ?? throw new ArgumentNullException(nameof(files));
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _log = log ?? throw new ArgumentNullException(nameof(log));

        RemediationEnabled = remediationEnabled;
    }

    /// <summary>
    /// The master switch for the whole remediation feature. It mirrors
    /// <c>AppSettings.RemediationEnabled</c>: while it is off, the engine refuses to
    /// plan and refuses to execute, and Lumen only detects and quarantines.
    /// </summary>
    public bool RemediationEnabled { get; set; }

    /// <summary>
    /// The process names that are never terminated. This list is hardcoded in the product
    /// on purpose: it must not be changeable by a settings file or a registry value.
    /// </summary>
    public static IReadOnlyList<string> ProtectedProcessNames => ProtectedProcesses.ProtectedNames;

    /// <summary>
    /// Decides whether a process is one Lumen refuses to stop, either because of its name,
    /// because the operating system calls it a system process, or because it runs from the
    /// Windows or Program Files folders.
    /// </summary>
    public static bool IsProtectedProcess(ProcessInfo process) => ProtectedProcesses.IsProtected(process);

    /// <summary>
    /// Lists the running processes that use the given file, including the ones Lumen will
    /// refuse to stop. The caller shows these to the user; the engine filters out the
    /// protected ones when it builds a plan. Nothing is changed by this call.
    /// </summary>
    public async Task<IReadOnlyList<ProcessMatch>> FindProcessesAsync(string filePath, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return [];

        try
        {
            return await _processes.FindByFilePathAsync(filePath, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The running processes that use the file could not be listed.", ex);
            return [];
        }
    }

    /// <summary>
    /// Builds a preview of what could be done about the detected file. Nothing is changed
    /// by this call: it only reads the world and returns the steps for the user to review.
    /// When the master switch is off, the plan comes back refused and empty.
    /// </summary>
    public Task<RemediationPlan> PlanAsync(RemediationTarget target, CancellationToken cancellationToken) =>
        PlanAsync(target, new RemediationOptions(), cancellationToken);

    /// <summary>
    /// Builds a preview of what could be done about the detected file, limited to the kinds
    /// of action the caller asked for. Nothing is changed by this call.
    /// </summary>
    public async Task<RemediationPlan> PlanAsync(
        RemediationTarget target,
        RemediationOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(options);

        var planId = NewId();
        var createdUtc = _clock.UtcNow;

        if (!RemediationEnabled)
        {
            _log.Warn("Remediation", "Remediation is turned off; nothing was planned.");
            return new RemediationPlan
            {
                Id = planId,
                CreatedUtc = createdUtc,
                Target = target,
                Steps = [],
                Status = RemediationStatus.Refused,
                Message = "Remediation is turned off in Lumen's settings, so nothing was planned."
            };
        }

        string fullPath;
        try
        {
            fullPath = PathRules.NormalizeFile(target.FilePath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            _log.Warn("Remediation", "The file path of the target is not valid.");
            return new RemediationPlan
            {
                Id = planId,
                CreatedUtc = createdUtc,
                Target = target,
                Steps = [],
                Status = RemediationStatus.Refused,
                Message = "That file path is not valid on this system."
            };
        }

        var normalized = target with { FilePath = fullPath };
        var steps = new List<RemediationStep>();
        var notes = new List<string>();

        if (options.TerminateProcesses)
        {
            foreach (var step in await PlanProcessStepsAsync(fullPath, notes, cancellationToken).ConfigureAwait(false))
            {
                steps.Add(step);
            }
        }

        if (options.RemovePersistence)
        {
            foreach (var step in await PlanPersistenceStepsAsync(fullPath, notes, cancellationToken).ConfigureAwait(false))
            {
                steps.Add(step);
            }
        }

        if (options.RemoveFile)
        {
            steps.Add(await PlanFileStepAsync(normalized, notes, cancellationToken).ConfigureAwait(false));
        }

        var plan = new RemediationPlan
        {
            Id = planId,
            CreatedUtc = createdUtc,
            Target = normalized,
            Steps = steps,
            Status = RemediationStatus.Planned,
            Message = notes.Count == 0
                ? $"{steps.Count} step(s) are ready for review. Nothing has been changed yet."
                : string.Join(" ", notes)
        };

        var recorded = await RecordPlanAsync(plan, cancellationToken).ConfigureAwait(false);
        if (!recorded) return plan with
        {
            Status = RemediationStatus.Refused,
            Steps = [],
            Message = "The audit journal could not be written, so no plan was produced. Nothing was changed."
        };

        return plan;
    }

    /// <summary>
    /// Runs every step of the plan. This call is the confirmation: the caller must only
    /// make it after the user has seen the plan. When the master switch is off, nothing
    /// runs.
    /// </summary>
    public Task<RemediationResult> ExecuteAsync(RemediationPlan plan, CancellationToken cancellationToken) =>
        ExecuteAsync(plan, plan.Steps.Select(step => step.Id).ToArray(), cancellationToken);

    /// <summary>
    /// Runs only the steps whose ids the caller selected. This is the preferred way to
    /// call the engine, because every destructive action is then individually confirmed.
    /// A step that fails stops the run: the steps after it are not attempted.
    /// </summary>
    public async Task<RemediationResult> ExecuteAsync(
        RemediationPlan plan,
        IReadOnlyCollection<string> stepIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(stepIds);

        if (!RemediationEnabled)
        {
            _log.Warn("Remediation", "Remediation is turned off; nothing was executed.");
            return new RemediationResult
            {
                PlanId = plan.Id,
                Status = RemediationStatus.Refused,
                Steps = plan.Steps,
                Message = "Remediation is turned off in Lumen's settings, so nothing was changed.",
                QuarantineItemId = plan.Target.QuarantineItemId
            };
        }

        if (plan.Status == RemediationStatus.Refused)
        {
            return new RemediationResult
            {
                PlanId = plan.Id,
                Status = RemediationStatus.Refused,
                Steps = plan.Steps,
                Message = plan.Message ?? "The plan was refused, so nothing was changed.",
                QuarantineItemId = plan.Target.QuarantineItemId
            };
        }

        var selected = new HashSet<string>(stepIds, StringComparer.OrdinalIgnoreCase);
        var outcomes = new List<RemediationStep>(plan.Steps.Count);
        var cancelled = false;
        var abortReason = (string?)null;

        foreach (var step in plan.Steps)
        {
            if (cancelled)
            {
                outcomes.Add(step with
                {
                    Status = RemediationStepStatus.Skipped,
                    Outcome = "The run was cancelled before this step was attempted."
                });
                continue;
            }

            if (abortReason is not null)
            {
                outcomes.Add(step with
                {
                    Status = RemediationStepStatus.Skipped,
                    Outcome = "Not attempted because an earlier step failed."
                });
                await RecordStepAsync(plan, step, RemediationStepStatus.Skipped, "Not attempted because an earlier step failed.").ConfigureAwait(false);
                continue;
            }

            if (!selected.Contains(step.Id))
            {
                outcomes.Add(step with
                {
                    Status = RemediationStepStatus.Skipped,
                    Outcome = "Not selected for this run."
                });
                await RecordStepAsync(plan, step, RemediationStepStatus.Skipped, "Not selected for this run.").ConfigureAwait(false);
                continue;
            }

            if (step.Status == RemediationStepStatus.Refused)
            {
                var reason = step.Outcome ?? "This step was refused.";
                outcomes.Add(step with { Status = RemediationStepStatus.Refused, Outcome = reason });
                await RecordStepAsync(plan, step, RemediationStepStatus.Refused, reason).ConfigureAwait(false);
                continue;
            }

            RemediationStep outcome;
            try
            {
                outcome = await ExecuteStepAsync(plan, step, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
                outcomes.Add(step with
                {
                    Status = RemediationStepStatus.Skipped,
                    Outcome = "The run was cancelled before this step was attempted."
                });
                continue;
            }

            outcomes.Add(outcome);

            var auditKind = outcome.Status switch
            {
                RemediationStepStatus.Succeeded => AuditEventKind.StepExecuted,
                RemediationStepStatus.Refused => AuditEventKind.StepRefused,
                RemediationStepStatus.Failed => AuditEventKind.StepFailed,
                _ => AuditEventKind.StepSkipped
            };

            await RecordStepAsync(plan, outcome, outcome.Status, outcome.Outcome ?? string.Empty, auditKind).ConfigureAwait(false);

            if (outcome.Status == RemediationStepStatus.Failed)
            {
                abortReason = outcome.Outcome ?? "The step failed.";
            }
        }

        var status = Summarize(outcomes, cancelled);
        var message = SummarizeMessage(outcomes, status, abortReason);

        await RecordCompletionAsync(plan, status, message, cancellationToken).ConfigureAwait(false);

        return new RemediationResult
        {
            PlanId = plan.Id,
            Status = status,
            Steps = outcomes,
            Message = message,
            QuarantineItemId = plan.Target.QuarantineItemId
        };
    }

    private async Task<IReadOnlyList<RemediationStep>> PlanProcessStepsAsync(
        string fullPath,
        List<string> notes,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<ProcessMatch> matches;
        try
        {
            matches = await _processes.FindByFilePathAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The running processes that use the file could not be listed.", ex);
            notes.Add("The processes that use the file could not be listed, so no process will be stopped.");
            return [];
        }

        var steps = new List<RemediationStep>();
        foreach (var match in matches)
        {
            if (ProtectedProcesses.IsProtected(match.Process))
            {
                _log.Warn(
                    "Remediation",
                    $"Process {DisplayText.Sanitize(match.Process.Name)} (pid {match.Process.Pid}) is protected and is never stopped.");
                continue;
            }

            steps.Add(new RemediationStep
            {
                Id = NewId(),
                Kind = RemediationStepKind.TerminateProcess,
                Description = $"Terminate pid {match.Process.Pid} ({DisplayText.Sanitize(match.Process.Name)})",
                Status = RemediationStepStatus.Pending,
                TargetPath = match.Process.ExecutablePath,
                ProcessId = match.Process.Pid,
                ProcessName = match.Process.Name,
                ProcessIsSigned = match.Process.IsSigned,
                Sha256 = null,
                QuarantineItemId = null
            });
        }

        if (steps.Count == 0 && matches.Count > 0)
        {
            notes.Add("The processes that use the file are protected, so none of them can be stopped.");
        }

        return steps;
    }

    private async Task<IReadOnlyList<RemediationStep>> PlanPersistenceStepsAsync(
        string fullPath,
        List<string> notes,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<PersistenceEntry> entries;
        try
        {
            entries = await _persistence.EnumerateAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The autostart entries that point at the file could not be listed.", ex);
            notes.Add("The autostart entries could not be listed, so nothing was removed.");
            return [];
        }

        var steps = new List<RemediationStep>();
        foreach (var entry in entries)
        {
            if (entry is null) continue;
            if (!PersistenceMatcher.PointsAt(entry, fullPath)) continue;

            steps.Add(new RemediationStep
            {
                Id = NewId(),
                Kind = RemediationStepKind.RemovePersistence,
                Description = DescribePersistence(entry),
                Status = RemediationStepStatus.Pending,
                TargetPath = entry.TargetPath,
                PersistenceEntry = entry,
                QuarantineItemId = null
            });
        }

        return steps;
    }

    private async Task<RemediationStep> PlanFileStepAsync(
        RemediationTarget target,
        List<string> notes,
        CancellationToken cancellationToken)
    {
        var step = new RemediationStep
        {
            Id = NewId(),
            Kind = RemediationStepKind.RemoveFile,
            Description = $"Delete {DisplayText.SanitizePath(target.FilePath)}",
            Status = RemediationStepStatus.Pending,
            TargetPath = target.FilePath,
            Sha256 = target.Sha256,
            SizeBytes = target.SizeBytes,
            QuarantineItemId = target.QuarantineItemId
        };

        if (PathRules.IsSystemCritical(target.FilePath))
        {
            _log.Warn("Remediation", "A system-critical path was offered for removal and was refused.");
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "Lumen never removes files from system folders."
            };
        }

        var hash = await HashAsync(target.FilePath, cancellationToken).ConfigureAwait(false);
        if (!hash.Success)
        {
            if (hash.Outcome == FileHashOutcome.NotFound)
            {
                return step with
                {
                    Status = RemediationStepStatus.Skipped,
                    Outcome = "The file no longer exists."
                };
            }

            notes.Add("The file could not be read, so it will not be removed.");
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = hash.Error ?? "The file could not be read, so it will not be removed."
            };
        }

        if (string.IsNullOrWhiteSpace(target.Sha256) && !target.AllowChangedFile)
        {
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "The file was never verified, so Lumen will not remove it."
            };
        }

        if (!target.AllowChangedFile && !HashEquals(target.Sha256, hash.Sha256))
        {
            _log.Warn("Remediation", "The file changed since it was scanned; removal was refused.");
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "The file changed since it was scanned, so Lumen will not remove it."
            };
        }

        return step with { SizeBytes = hash.SizeBytes ?? target.SizeBytes };
    }

    private async Task<RemediationStep> ExecuteStepAsync(
        RemediationPlan plan,
        RemediationStep step,
        CancellationToken cancellationToken)
    {
        return step.Kind switch
        {
            RemediationStepKind.TerminateProcess => await ExecuteTerminateAsync(step, cancellationToken).ConfigureAwait(false),
            RemediationStepKind.RemovePersistence => await ExecuteRemovePersistenceAsync(step, cancellationToken).ConfigureAwait(false),
            RemediationStepKind.RemoveFile => await ExecuteRemoveFileAsync(plan, step, cancellationToken).ConfigureAwait(false),
            _ => step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "This step is not a known action."
            }
        };
    }

    private async Task<RemediationStep> ExecuteTerminateAsync(RemediationStep step, CancellationToken cancellationToken)
    {
        if (step.ProcessId is null)
        {
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "The step does not name a process."
            };
        }

        var pid = step.ProcessId.Value;

        // Re-check at the moment of execution: the world may have changed since planning.
        ProcessInfo? info;
        try
        {
            info = await _processes.GetAsync(pid, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The process could not be read before it was stopped.", ex);
            return step with
            {
                Status = RemediationStepStatus.Failed,
                Outcome = "The process could not be checked, so it was not stopped."
            };
        }

        if (info is null)
        {
            return step with
            {
                Status = RemediationStepStatus.Skipped,
                Outcome = "The process had already exited."
            };
        }

        if (ProtectedProcesses.IsProtected(info))
        {
            _log.Warn("Remediation", $"Process {DisplayText.Sanitize(info.Name)} (pid {pid}) is protected and was not stopped.");
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "This process is protected and Lumen never stops it."
            };
        }

        ProcessTerminationResult result;
        try
        {
            result = await _processes.TerminateAsync(pid, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The process could not be stopped.", ex);
            return step with
            {
                Status = RemediationStepStatus.Failed,
                Outcome = "The process could not be stopped."
            };
        }

        return result.Terminated
            ? step with
            {
                Status = RemediationStepStatus.Succeeded,
                Outcome = result.Message
            }
            : step with
            {
                Status = RemediationStepStatus.Failed,
                Outcome = result.Message
            };
    }

    private async Task<RemediationStep> ExecuteRemovePersistenceAsync(RemediationStep step, CancellationToken cancellationToken)
    {
        var entry = step.PersistenceEntry;
        if (entry is null)
        {
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "The step does not name an autostart entry."
            };
        }

        if (!entry.RestoreData.CanRestore)
        {
            _log.Warn("Remediation", "An autostart entry without restore data was refused.");
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "Lumen did not capture enough of this entry to put it back, so it was left alone."
            };
        }

        PersistenceRemovalResult result;
        try
        {
            result = await _persistence.RemoveAsync(entry, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The autostart entry could not be removed.", ex);
            return step with
            {
                Status = RemediationStepStatus.Failed,
                Outcome = "The autostart entry could not be removed."
            };
        }

        return result.Removed
            ? step with
            {
                Status = RemediationStepStatus.Succeeded,
                Outcome = result.Message
            }
            : step with
            {
                Status = RemediationStepStatus.Failed,
                Outcome = result.Message
            };
    }

    private async Task<RemediationStep> ExecuteRemoveFileAsync(
        RemediationPlan plan,
        RemediationStep step,
        CancellationToken cancellationToken)
    {
        var path = step.TargetPath ?? plan.Target.FilePath;

        if (PathRules.IsSystemCritical(path))
        {
            _log.Warn("Remediation", "A removal from a system-critical path was refused.");
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "Lumen never removes files from system folders."
            };
        }

        var expected = string.IsNullOrWhiteSpace(plan.Target.Sha256) ? step.Sha256 : plan.Target.Sha256;
        var hash = await HashAsync(path, cancellationToken).ConfigureAwait(false);
        if (!hash.Success)
        {
            if (hash.Outcome == FileHashOutcome.NotFound)
            {
                return step with
                {
                    Status = RemediationStepStatus.Skipped,
                    Outcome = "The file no longer exists."
                };
            }

            return step with
            {
                Status = RemediationStepStatus.Failed,
                Outcome = hash.Error ?? "The file could not be read, so it was not removed."
            };
        }

        if (string.IsNullOrWhiteSpace(expected) && !plan.Target.AllowChangedFile)
        {
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "The file was never verified, so Lumen will not remove it."
            };
        }

        if (!plan.Target.AllowChangedFile && !HashEquals(expected, hash.Sha256))
        {
            _log.Warn("Remediation", "The file changed since it was scanned; the removal was refused.");
            return step with
            {
                Status = RemediationStepStatus.Refused,
                Outcome = "The file changed since it was scanned, so Lumen will not remove it."
            };
        }

        FileRemovalResult result;
        try
        {
            result = await _files.RemoveAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The file could not be removed.", ex);
            return step with
            {
                Status = RemediationStepStatus.Failed,
                Outcome = "The file could not be removed."
            };
        }

        if (!result.Removed)
        {
            return step with
            {
                Status = RemediationStepStatus.Failed,
                Outcome = result.Message
            };
        }

        return step with
        {
            Status = RemediationStepStatus.Succeeded,
            Outcome = result.Message,
            Sha256 = hash.Sha256 ?? expected,
            SizeBytes = hash.SizeBytes ?? step.SizeBytes
        };
    }

    private async Task<FileHashResult> HashAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await _hasher.GetSha256Async(path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The file could not be hashed.", ex);
            return new FileHashResult
            {
                Outcome = FileHashOutcome.Failed,
                Error = "The file could not be read, so Lumen did not change it."
            };
        }
    }

    private async Task<bool> RecordPlanAsync(RemediationPlan plan, CancellationToken cancellationToken)
    {
        try
        {
            await _journal.AppendAsync(
                new AuditEntry
                {
                    TimestampUtc = _clock.UtcNow,
                    Kind = AuditEventKind.PlanCreated,
                    PlanId = plan.Id,
                    Target = DisplayText.SanitizePath(plan.Target.FilePath),
                    Detail = DisplayText.Sanitize(plan.Target.FindingTitle),
                    Sha256 = plan.Target.Sha256,
                    SizeBytes = plan.Target.SizeBytes,
                    QuarantineItemId = plan.Target.QuarantineItemId
                },
                cancellationToken).ConfigureAwait(false);

            foreach (var step in plan.Steps)
            {
                await _journal.AppendAsync(
                    new AuditEntry
                    {
                        TimestampUtc = _clock.UtcNow,
                        Kind = AuditEventKind.StepPlanned,
                        PlanId = plan.Id,
                        StepId = step.Id,
                        StepKind = step.Kind,
                        Target = DisplayText.SanitizePath(step.TargetPath ?? string.Empty),
                        Detail = DisplayText.Sanitize(step.Description),
                        Status = step.Status,
                        Sha256 = step.Sha256,
                        SizeBytes = step.SizeBytes,
                        QuarantineItemId = step.QuarantineItemId ?? plan.Target.QuarantineItemId
                    },
                    cancellationToken).ConfigureAwait(false);
            }

            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("Remediation", "The plan could not be written to the audit journal.", ex);
            return false;
        }
    }

    private async Task RecordStepAsync(
        RemediationPlan plan,
        RemediationStep step,
        RemediationStepStatus status,
        string detail,
        AuditEventKind? kind = null)
    {
        var auditKind = kind ?? status switch
        {
            RemediationStepStatus.Succeeded => AuditEventKind.StepExecuted,
            RemediationStepStatus.Refused => AuditEventKind.StepRefused,
            RemediationStepStatus.Failed => AuditEventKind.StepFailed,
            _ => AuditEventKind.StepSkipped
        };

        try
        {
            await _journal.AppendAsync(
                new AuditEntry
                {
                    TimestampUtc = _clock.UtcNow,
                    Kind = auditKind,
                    PlanId = plan.Id,
                    StepId = step.Id,
                    StepKind = step.Kind,
                    Target = DisplayText.SanitizePath(step.TargetPath ?? string.Empty),
                    Detail = DisplayText.Sanitize(detail),
                    Status = status,
                    Sha256 = step.Sha256 ?? plan.Target.Sha256,
                    SizeBytes = step.SizeBytes ?? plan.Target.SizeBytes,
                    QuarantineItemId = step.QuarantineItemId ?? plan.Target.QuarantineItemId,
                    RestoreData = step.PersistenceEntry?.RestoreData
                },
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Error("Remediation", "A remediation step could not be written to the audit journal.", ex);
        }
    }

    private async Task RecordCompletionAsync(
        RemediationPlan plan,
        RemediationStatus status,
        string message,
        CancellationToken cancellationToken)
    {
        try
        {
            await _journal.AppendAsync(
                new AuditEntry
                {
                    TimestampUtc = _clock.UtcNow,
                    Kind = AuditEventKind.PlanCompleted,
                    PlanId = plan.Id,
                    Target = DisplayText.SanitizePath(plan.Target.FilePath),
                    Detail = DisplayText.Sanitize(message),
                    Status = null,
                    Sha256 = plan.Target.Sha256,
                    SizeBytes = plan.Target.SizeBytes,
                    QuarantineItemId = plan.Target.QuarantineItemId
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Error("Remediation", "The end of the run could not be written to the audit journal.", ex);
        }
    }

    private static RemediationStatus Summarize(IReadOnlyList<RemediationStep> outcomes, bool cancelled)
    {
        if (cancelled) return RemediationStatus.Cancelled;
        if (outcomes.Count == 0) return RemediationStatus.Refused;

        var succeeded = outcomes.Count(step => step.Status == RemediationStepStatus.Succeeded);
        var failed = outcomes.Count(step => step.Status == RemediationStepStatus.Failed);
        var refused = outcomes.Count(step => step.Status == RemediationStepStatus.Refused);

        if (failed > 0 && succeeded > 0) return RemediationStatus.PartiallyExecuted;
        if (failed > 0) return RemediationStatus.Failed;
        if (succeeded == 0 && refused > 0) return RemediationStatus.Refused;
        return RemediationStatus.Executed;
    }

    private static string SummarizeMessage(
        IReadOnlyList<RemediationStep> outcomes,
        RemediationStatus status,
        string? abortReason)
    {
        var succeeded = outcomes.Count(step => step.Status == RemediationStepStatus.Succeeded);
        var failed = outcomes.Count(step => step.Status == RemediationStepStatus.Failed);
        var refused = outcomes.Count(step => step.Status == RemediationStepStatus.Refused);
        var skipped = outcomes.Count(step => step.Status == RemediationStepStatus.Skipped);

        if (status == RemediationStatus.Cancelled)
            return "The run was cancelled. The steps that had already finished were kept.";

        if (outcomes.Count == 0)
            return "Nothing was selected to run, so nothing was changed.";

        var parts = new List<string> { $"{succeeded} step(s) completed." };
        if (failed > 0) parts.Add($"{failed} step(s) failed and the rest were not attempted.");
        if (refused > 0) parts.Add($"{refused} step(s) were refused.");
        if (skipped > 0) parts.Add($"{skipped} step(s) were skipped.");

        if (!string.IsNullOrWhiteSpace(abortReason))
        {
            parts.Add($"Stopped after: {DisplayText.Sanitize(abortReason)}");
        }

        return string.Join(" ", parts);
    }

    private static string DescribePersistence(PersistenceEntry entry)
    {
        var name = DisplayText.Sanitize(entry.Name);
        var location = DisplayText.Sanitize(entry.Location);

        return entry.Kind switch
        {
            PersistenceEntryKind.RegistryRunValue =>
                $"Remove Run key {location}\\{name}".TrimEnd('\\'),
            PersistenceEntryKind.RegistryRunOnceValue =>
                $"Remove RunOnce key {location}\\{name}".TrimEnd('\\'),
            PersistenceEntryKind.StartupFolderItem =>
                $"Remove Startup item {name}",
            PersistenceEntryKind.ScheduledTask =>
                $"Remove scheduled task {location}".Trim(),
            PersistenceEntryKind.Service =>
                $"Remove service {name}",
            _ => $"Remove autostart entry {name}"
        };
    }

    private static bool HashEquals(string? left, string? right) =>
        !string.IsNullOrWhiteSpace(left) &&
        !string.IsNullOrWhiteSpace(right) &&
        string.Equals(left.Trim(), right.Trim(), StringComparison.OrdinalIgnoreCase);

    private static string NewId() => Guid.NewGuid().ToString("N");
}
