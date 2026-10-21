using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Util;

namespace Lumen.Core.Remediation;

/// <summary>
/// Stops the processes that are using a file the real-time monitor just flagged.
///
/// This is a separate path from <see cref="RemediationEngine"/> on purpose. The engine
/// is interactive: it builds a plan, the user reads it and confirms. A real-time kill
/// cannot wait for a click, so it is a small service that does one thing and reports
/// what it did. It keeps every safety rail the engine has:
///
/// <list type="bullet">
/// <item>It refuses to do anything at all while the feature is turned off. With the
/// feature off, no process is listed, no process is stopped and nothing at all is
/// written to the audit journal.</item>
/// <item>It only ever acts on a finding the real-time monitor actually produced. The
/// request carries the findings; Lumen never decides on its own that something looks
/// suspicious.</item>
/// <item>It never stops a protected or system process, and it never stops a process that
/// runs from a system folder. Those checks are repeated at the moment of the action,
/// not only when the process was found.</item>
/// <item>It never stops Lumen itself, and it never stops a process it cannot place.</item>
/// <item>It writes every action and every refusal to the audit journal. If the run
/// cannot be written down, nothing is stopped: an action nobody can report on is an
/// action that does not happen.</item>
/// <item>It never deletes and never quarantines anything. Stopping the process is the
/// whole job; removing the file stays a separate, confirmed action.</item>
/// <item>Nothing runs elevated. A process Lumen is not allowed to stop is left running
/// and the reason is reported.</item>
/// </list>
///
/// The service reads the operating system through <see cref="IProcessTerminator"/> and
/// never touches a file, a registry key or a scheduled task itself.
/// </summary>
public sealed class RealtimeKillService
{
    /// <summary>
    /// The prefix used for the audit id of a real-time kill run. It tells a reader of
    /// the journal that these entries come from the real-time path and not from a
    /// remediation plan the user reviewed.
    /// </summary>
    public const string RunIdPrefix = "rtkill-";

    /// <summary>
    /// How long a file is remembered as already handled. The same file is often flagged
    /// twice in a row: a file that is written, executed and rewritten. Lumen must not
    /// stop the same processes twice for the same file.
    /// </summary>
    public static readonly TimeSpan DefaultRepeatWindow = TimeSpan.FromMinutes(2);

    private const int MaxRememberedFiles = 512;

    private readonly IProcessTerminator _processes;
    private readonly IAuditJournal _journal;
    private readonly IClock _clock;
    private readonly ILog _log;
    private readonly TimeSpan _repeatWindow;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> _handledFiles = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Creates the service. Both switches start in the state they are given; while they
    /// are off the service refuses every request, which keeps Lumen's detect-and-report
    /// behaviour intact.
    /// </summary>
    /// <param name="processes">Reads the running processes that use the flagged file.</param>
    /// <param name="journal">Records every action and every refusal.</param>
    /// <param name="clock">Clock used for the journal and for the repeat window.</param>
    /// <param name="log">Diagnostic log. Only paths, process names and outcomes are written.</param>
    /// <param name="autoKillEnabled">Mirrors <c>AppSettings.RealtimeAutoKill</c>.</param>
    /// <param name="remediationEnabled">
    /// Mirrors <c>AppSettings.RemediationEnabled</c>. Stopping a process is a
    /// remediation action, so the remediation master switch has to be on as well.
    /// </param>
    /// <param name="repeatWindow">
    /// How long a file is remembered as already handled. Defaults to
    /// <see cref="DefaultRepeatWindow"/>.
    /// </param>
    public RealtimeKillService(
        IProcessTerminator processes,
        IAuditJournal journal,
        IClock clock,
        ILog log,
        bool autoKillEnabled = false,
        bool remediationEnabled = false,
        TimeSpan? repeatWindow = null)
    {
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _log = log ?? throw new ArgumentNullException(nameof(log));

        AutoKillEnabled = autoKillEnabled;
        RemediationEnabled = remediationEnabled;
        _repeatWindow = repeatWindow ?? DefaultRepeatWindow;
    }

    /// <summary>
    /// The switch for the real-time kill feature. It mirrors
    /// <c>AppSettings.RealtimeAutoKill</c>: while it is off the service refuses every
    /// request and the machine is left exactly as it was.
    /// </summary>
    public bool AutoKillEnabled { get; set; }

    /// <summary>
    /// The master switch for remediation. Stopping a running process is a remediation
    /// action, so the real-time kill needs this switch as well as
    /// <see cref="AutoKillEnabled"/>.
    /// </summary>
    public bool RemediationEnabled { get; set; }

    /// <summary>
    /// Handles a real-time detection: finds the processes that use the flagged file and
    /// stops the ones that may be stopped. The result reports exactly what happened.
    ///
    /// This is the call the real-time detection handler makes. It never throws for an
    /// ordinary situation: a missing file, a process that has already exited, a process
    /// that cannot be stopped and a protected process are all reported, not thrown.
    /// </summary>
    /// <param name="detection">The detection the real-time monitor produced.</param>
    /// <param name="cancellationToken">Cancels the run.</param>
    /// <returns>What was stopped, what was refused and why.</returns>
    public async Task<RealtimeKillResult> KillAsync(
        RealtimeDetectionEvent detection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(detection);

        var request = new RealtimeKillRequest
        {
            FilePath = detection.FilePath,
            Findings = detection.Findings ?? [],
            Sha256 = detection.Sha256,
            SizeBytes = detection.SizeBytes,
            DetectedUtc = detection.DetectedUtc
        };

        return await KillAsync(request, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Handles a real-time detection with an explicit list of approved processes. When
    /// the list is null, every process that passes every safety check is stopped, which
    /// is what the real-time path does: the user has already said yes by turning the
    /// feature on.
    /// </summary>
    /// <param name="request">The flagged file and the findings that produced it.</param>
    /// <param name="approvedProcessIds">
    /// The process ids the caller approves. Null means "every process that passes every
    /// safety check".
    /// </param>
    /// <param name="cancellationToken">Cancels the run.</param>
    /// <param name="userConfirmed">
    /// True when the user confirmed this specific action by hand, for example by
    /// pressing a button in the alert window. The automatic switch is not needed then,
    /// because the confirmation IS the consent. The remediation master switch is still
    /// required, and every other safety rule still applies unchanged.
    /// </param>
    /// <returns>What was stopped, what was refused and why.</returns>
    public async Task<RealtimeKillResult> KillAsync(
        RealtimeKillRequest request,
        IReadOnlyCollection<int>? approvedProcessIds,
        CancellationToken cancellationToken,
        bool userConfirmed = false)
    {
        ArgumentNullException.ThrowIfNull(request);

        // The switch is checked before anything else: with the feature off, Lumen does
        // not even look at the running processes, and the journal stays untouched.
        if (!RemediationEnabled || (!AutoKillEnabled && !userConfirmed))
        {
            // Turning the feature off is the normal state, not a problem to report: the
            // log stays quiet so a caller that asks anyway does not fill it up.
            _log.Info("RealtimeKill", "The real-time kill feature is turned off; nothing was stopped.");
            var now = _clock.UtcNow;
            return new RealtimeKillResult
            {
                FilePath = request.FilePath,
                Status = RealtimeKillStatus.Disabled,
                Processes = [],
                Message = "The real-time kill feature is turned off in Lumen's settings, so nothing was stopped.",
                StartedUtc = now,
                CompletedUtc = now
            };
        }

        // A kill is only ever the consequence of a finding. Without one there is nothing
        // to act on, however suspicious the path may look.
        if (request.Findings.Count == 0)
        {
            _log.Warn("RealtimeKill", "A real-time request without a finding was refused.");
            return await RefuseRunAsync(
                request,
                request.FilePath,
                "The detection did not carry a finding, so nothing was stopped.").ConfigureAwait(false);
        }

        string target;
        try
        {
            target = PathRules.NormalizeFile(request.FilePath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            _log.Warn("RealtimeKill", "The path of the flagged file is not valid.");
            return await RefuseRunAsync(
                request,
                request.FilePath,
                "That file path is not valid on this system, so nothing was stopped.").ConfigureAwait(false);
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsRecentlyHandled(target))
            {
                _log.Info("RealtimeKill", "The file was already handled; it was not handled twice.");
                return await SkipRunAsync(
                    request,
                    target,
                    "This file was already handled a moment ago, so no process was stopped a second time.").ConfigureAwait(false);
            }

            return await RunAsync(request, target, approvedProcessIds, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Lists the processes that are using a file, without stopping anything.
    ///
    /// The interface uses this to tell the user "two programs are running this
    /// file" before they decide what to do. Listing a process is a read, so it is
    /// allowed even when the automatic kill is turned off.
    /// </summary>
    /// <param name="filePath">The file to look for.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>The processes whose executable or loaded module is that file.</returns>
    public async Task<IReadOnlyList<ProcessMatch>> FindAsync(
        string filePath,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return [];

        try
        {
            var target = PathRules.NormalizeFile(filePath);
            return await _processes.FindByFilePathAsync(target, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            _log.Warn("RealtimeKill", "The path of the flagged file is not valid.");
            return [];
        }
    }

    /// <summary>
    /// Runs the kill for one flagged file. The caller holds the gate, so two runs never
    /// overlap and the same file is never handled twice at the same time.
    /// </summary>
    private async Task<RealtimeKillResult> RunAsync(
        RealtimeKillRequest request,
        string target,
        IReadOnlyCollection<int>? approvedProcessIds,
        CancellationToken cancellationToken)
    {
        var runId = RunIdPrefix + Guid.NewGuid().ToString("N");
        var startedUtc = _clock.UtcNow;

        // The run is written down before anything is done. If it cannot be written,
        // nothing is stopped: an action nobody can report on is an action that does
        // not happen.
        if (!await RecordRunStartedAsync(runId, request, target, startedUtc).ConfigureAwait(false))
        {
            return new RealtimeKillResult
            {
                FilePath = target,
                Status = RealtimeKillStatus.Refused,
                Processes = [],
                Message = "The audit journal could not be written, so nothing was stopped.",
                StartedUtc = startedUtc,
                CompletedUtc = _clock.UtcNow
            };
        }

        IReadOnlyList<ProcessMatch>? matches;
        try
        {
            matches = await _processes.FindByFilePathAsync(target, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("RealtimeKill", "The processes that use the file could not be listed.", ex);
            var failure = "The processes that use the file could not be listed, so nothing was stopped.";
            await RecordRunFinishedAsync(runId, request, target, failure).ConfigureAwait(false);
            return new RealtimeKillResult
            {
                FilePath = target,
                Status = RealtimeKillStatus.Failed,
                Processes = [],
                Message = failure,
                StartedUtc = startedUtc,
                CompletedUtc = _clock.UtcNow
            };
        }

        var outcomes = new List<RealtimeKillProcessResult>();
        var seen = new HashSet<int>();
        var stoppedSomething = false;

        foreach (var candidate in matches ?? [])
        {
            if (candidate is null) continue;

            var match = candidate;
            var pid = match.Process?.Pid ?? 0;
            if (pid <= 0) continue;

            // One process can be reported more than once: once as the executable and
            // once as a loaded module. It is considered once.
            if (!seen.Add(pid)) continue;

            var outcome = await ConsiderProcessAsync(
                runId,
                request,
                target,
                match,
                approvedProcessIds,
                cancellationToken).ConfigureAwait(false);

            outcomes.Add(outcome);
            if (outcome.Stopped) stoppedSomething = true;
        }

        // The file is remembered only when something was actually stopped. A run that
        // found nothing to stop must not block a later run that would find something.
        if (stoppedSomething) RememberHandled(target);

        var status = Summarize(outcomes);
        var message = SummarizeMessage(outcomes, status);

        await RecordRunFinishedAsync(runId, request, target, message).ConfigureAwait(false);

        return new RealtimeKillResult
        {
            FilePath = target,
            Status = status,
            Processes = outcomes,
            Message = message,
            StartedUtc = startedUtc,
            CompletedUtc = _clock.UtcNow
        };
    }

    /// <summary>
    /// Decides what happens to one process that was found using the flagged file, and
    /// does it. Every path through this method either stops the process or leaves it
    /// running with a reason, and every one of them is written to the journal.
    /// </summary>
    private async Task<RealtimeKillProcessResult> ConsiderProcessAsync(
        string runId,
        RealtimeKillRequest request,
        string target,
        ProcessMatch match,
        IReadOnlyCollection<int>? approvedProcessIds,
        CancellationToken cancellationToken)
    {
        var found = match.Process!;
        var pid = found.Pid;

        // The adapter decides what "using the file" means. The service checks again,
        // because a process that merely lives in the same folder is not using the file
        // and must never be stopped because of it.
        if (!PointsAtFile(match, target))
        {
            return await RefuseProcessAsync(
                runId,
                request,
                target,
                found,
                match,
                RealtimeKillProcessOutcome.NotUsingFile,
                "The process does not actually use the flagged file.").ConfigureAwait(false);
        }

        if (approvedProcessIds is not null && !approvedProcessIds.Contains(pid))
        {
            return await RefuseProcessAsync(
                runId,
                request,
                target,
                found,
                match,
                RealtimeKillProcessOutcome.NotApproved,
                "The caller did not approve stopping this process.").ConfigureAwait(false);
        }

        // The world may have changed since the process was found, so the facts are read
        // again here, at the moment of the action.
        ProcessInfo? current;
        try
        {
            current = await _processes.GetAsync(pid, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("RealtimeKill", "The process could not be read before it was stopped.", ex);
            return await RefuseProcessAsync(
                runId,
                request,
                target,
                found,
                match,
                RealtimeKillProcessOutcome.Failed,
                "The process could not be checked, so it was not stopped.").ConfigureAwait(false);
        }

        if (current is null)
        {
            return await RefuseProcessAsync(
                runId,
                request,
                target,
                found,
                match,
                RealtimeKillProcessOutcome.AlreadyExited,
                "The process had already exited.").ConfigureAwait(false);
        }

        // Lumen never stops itself.
        if (current.Pid == Environment.ProcessId)
        {
            return await RefuseProcessAsync(
                runId,
                request,
                target,
                current,
                match,
                RealtimeKillProcessOutcome.RefusedSelf,
                "That process is Lumen itself, and Lumen never stops itself.").ConfigureAwait(false);
        }

        // A protected process is never stopped. The list is hardcoded in the product
        // and cannot be weakened by a settings file.
        if (current.IsSystemProcess || ProtectedProcesses.IsProtectedName(current.Name))
        {
            _log.Warn(
                "RealtimeKill",
                $"Process {DisplayText.Sanitize(current.Name)} (pid {current.Pid}) is protected and was not stopped.");

            return await RefuseProcessAsync(
                runId,
                request,
                target,
                current,
                match,
                RealtimeKillProcessOutcome.RefusedProtected,
                "This process is protected and Lumen never stops it.").ConfigureAwait(false);
        }

        // A process Lumen cannot place is a process Lumen does not stop: it could be
        // running from a system folder, and Lumen would not know.
        if (string.IsNullOrWhiteSpace(current.ExecutablePath))
        {
            return await RefuseProcessAsync(
                runId,
                request,
                target,
                current,
                match,
                RealtimeKillProcessOutcome.RefusedUnknownPath,
                "Lumen could not read where this process runs from, so it was not stopped.").ConfigureAwait(false);
        }

        // A process that runs from a system folder is never stopped, even when its file
        // was flagged.
        if (ProtectedProcesses.IsProtectedLocation(current.ExecutablePath) ||
            PathRules.IsSystemCritical(current.ExecutablePath))
        {
            _log.Warn(
                "RealtimeKill",
                $"Process {DisplayText.Sanitize(current.Name)} (pid {current.Pid}) runs from a system folder and was not stopped.");

            return await RefuseProcessAsync(
                runId,
                request,
                target,
                current,
                match,
                RealtimeKillProcessOutcome.RefusedSystemLocation,
                "This process runs from a system folder, so Lumen never stops it.").ConfigureAwait(false);
        }

        ProcessTerminationResult termination;
        try
        {
            termination = await _processes.TerminateAsync(pid, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("RealtimeKill", "The process could not be stopped.", ex);
            return await RefuseProcessAsync(
                runId,
                request,
                target,
                current,
                match,
                RealtimeKillProcessOutcome.Failed,
                "The process could not be stopped.").ConfigureAwait(false);
        }

        if (termination.Terminated)
        {
            _log.Info(
                "RealtimeKill",
                $"Stopped {DisplayText.Sanitize(current.Name)} (pid {current.Pid}) because it was using a flagged file.");

            return await RecordProcessAsync(
                runId,
                request,
                target,
                current,
                match,
                RealtimeKillProcessOutcome.Stopped,
                termination.Message ?? "The process was stopped.").ConfigureAwait(false);
        }

        // Not being allowed to stop a process is a normal outcome, not an error. It is
        // reported plainly: the process is still running and Lumen says so.
        var outcome = termination.Outcome switch
        {
            ProcessTerminationOutcome.AccessDenied => RealtimeKillProcessOutcome.Denied,
            ProcessTerminationOutcome.NotFound => RealtimeKillProcessOutcome.AlreadyExited,
            _ => RealtimeKillProcessOutcome.Failed
        };

        return await RecordProcessAsync(
            runId,
            request,
            target,
            current,
            match,
            outcome,
            termination.Message ?? "The process could not be stopped.").ConfigureAwait(false);
    }

    /// <summary>
    /// Records a process that was left running. The reason is written to the journal,
    /// because a refusal that nobody can read is not a refusal the user can trust.
    /// </summary>
    private async Task<RealtimeKillProcessResult> RefuseProcessAsync(
        string runId,
        RealtimeKillRequest request,
        string target,
        ProcessInfo process,
        ProcessMatch match,
        RealtimeKillProcessOutcome outcome,
        string reason)
    {
        var result = new RealtimeKillProcessResult
        {
            Pid = process.Pid,
            Name = process.Name,
            Outcome = outcome,
            Reason = reason,
            ExecutablePath = process.ExecutablePath,
            MatchKind = match.MatchKind,
            IsSigned = process.IsSigned
        };

        await AppendProcessEntryAsync(runId, request, target, result).ConfigureAwait(false);
        return result;
    }

    /// <summary>
    /// Writes one process entry to the journal and returns the result that describes
    /// it. A journal that cannot be written is logged and the run continues: the
    /// process has already been dealt with, and hiding that would be worse than a
    /// missing line.
    /// </summary>
    private async Task<RealtimeKillProcessResult> RecordProcessAsync(
        string runId,
        RealtimeKillRequest request,
        string target,
        ProcessInfo process,
        ProcessMatch match,
        RealtimeKillProcessOutcome outcome,
        string reason)
    {
        var result = new RealtimeKillProcessResult
        {
            Pid = process.Pid,
            Name = process.Name,
            Outcome = outcome,
            Reason = reason,
            ExecutablePath = process.ExecutablePath,
            MatchKind = match.MatchKind,
            IsSigned = process.IsSigned
        };

        await AppendProcessEntryAsync(runId, request, target, result).ConfigureAwait(false);
        return result;
    }

    /// <summary>
    /// Appends one process entry to the audit journal. Every action and every refusal
    /// goes through here.
    /// </summary>
    private async Task AppendProcessEntryAsync(
        string runId,
        RealtimeKillRequest request,
        string target,
        RealtimeKillProcessResult result)
    {
        var kind = result.Outcome switch
        {
            RealtimeKillProcessOutcome.Stopped => AuditEventKind.StepExecuted,
            RealtimeKillProcessOutcome.Failed => AuditEventKind.StepFailed,
            RealtimeKillProcessOutcome.AlreadyExited => AuditEventKind.StepSkipped,
            RealtimeKillProcessOutcome.NotApproved => AuditEventKind.StepSkipped,
            _ => AuditEventKind.StepRefused
        };

        var status = result.Outcome switch
        {
            RealtimeKillProcessOutcome.Stopped => RemediationStepStatus.Succeeded,
            RealtimeKillProcessOutcome.Failed => RemediationStepStatus.Failed,
            RealtimeKillProcessOutcome.AlreadyExited => RemediationStepStatus.Skipped,
            RealtimeKillProcessOutcome.NotApproved => RemediationStepStatus.Skipped,
            _ => RemediationStepStatus.Refused
        };

        var detail = $"pid {result.Pid} ({DisplayText.Sanitize(result.Name)}): {DisplayText.Sanitize(result.Reason)}";

        await AppendEntryAsync(
            runId,
            request,
            target,
            kind,
            status,
            detail,
            $"{runId}:{result.Pid}").ConfigureAwait(false);
    }

    /// <summary>
    /// Appends one entry to the audit journal. A journal that cannot be written is
    /// logged rather than thrown: the caller decides whether that is fatal.
    /// </summary>
    private async Task AppendEntryAsync(
        string runId,
        RealtimeKillRequest request,
        string target,
        AuditEventKind kind,
        RemediationStepStatus status,
        string detail,
        string? stepId)
    {
        try
        {
            await _journal.AppendAsync(
                new AuditEntry
                {
                    TimestampUtc = _clock.UtcNow,
                    Kind = kind,
                    PlanId = runId,
                    StepId = stepId,
                    StepKind = RemediationStepKind.TerminateProcess,
                    Target = DisplayText.SanitizePath(target),
                    Detail = DisplayText.Sanitize(detail),
                    Status = status,
                    Sha256 = request.Sha256,
                    SizeBytes = request.SizeBytes
                },
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Error("RealtimeKill", "A real-time kill entry could not be written to the audit journal.", ex);
        }
    }

    /// <summary>
    /// Writes the start of the run. Returns false when the journal could not be
    /// written, in which case the caller stops nothing.
    /// </summary>
    private async Task<bool> RecordRunStartedAsync(
        string runId,
        RealtimeKillRequest request,
        string target,
        DateTimeOffset startedUtc)
    {
        try
        {
            await _journal.AppendAsync(
                new AuditEntry
                {
                    TimestampUtc = startedUtc,
                    Kind = AuditEventKind.PlanCreated,
                    PlanId = runId,
                    Target = DisplayText.SanitizePath(target),
                    Detail = "The real-time monitor flagged this file; Lumen looked for the processes that use it.",
                    Sha256 = request.Sha256,
                    SizeBytes = request.SizeBytes
                },
                CancellationToken.None).ConfigureAwait(false);

            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Error("RealtimeKill", "The real-time kill could not be written to the audit journal.", ex);
            return false;
        }
    }

    /// <summary>
    /// Writes the end of the run, with the honest summary of what happened.
    /// </summary>
    private async Task RecordRunFinishedAsync(
        string runId,
        RealtimeKillRequest request,
        string target,
        string message)
    {
        try
        {
            await _journal.AppendAsync(
                new AuditEntry
                {
                    TimestampUtc = _clock.UtcNow,
                    Kind = AuditEventKind.PlanCompleted,
                    PlanId = runId,
                    Target = DisplayText.SanitizePath(target),
                    Detail = DisplayText.Sanitize(message),
                    Sha256 = request.Sha256,
                    SizeBytes = request.SizeBytes
                },
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Error("RealtimeKill", "The end of the real-time kill could not be written to the audit journal.", ex);
        }
    }

    /// <summary>
    /// Refuses a run before it starts, for example because the request carried no
    /// finding. The refusal is journalled: it is part of the account of what Lumen did.
    /// </summary>
    private async Task<RealtimeKillResult> RefuseRunAsync(
        RealtimeKillRequest request,
        string target,
        string message)
    {
        var runId = RunIdPrefix + Guid.NewGuid().ToString("N");

        await AppendEntryAsync(
            runId,
            request,
            target,
            AuditEventKind.StepRefused,
            RemediationStepStatus.Refused,
            message,
            null).ConfigureAwait(false);

        return new RealtimeKillResult
        {
            FilePath = target,
            Status = RealtimeKillStatus.Refused,
            Processes = [],
            Message = message,
            StartedUtc = _clock.UtcNow,
            CompletedUtc = _clock.UtcNow
        };
    }

    /// <summary>
    /// Skips a run because the same file was handled a moment ago. The skip is
    /// journalled, so the journal shows that Lumen saw the second flag and did nothing.
    /// </summary>
    private async Task<RealtimeKillResult> SkipRunAsync(
        RealtimeKillRequest request,
        string target,
        string message)
    {
        var runId = RunIdPrefix + Guid.NewGuid().ToString("N");

        await AppendEntryAsync(
            runId,
            request,
            target,
            AuditEventKind.StepSkipped,
            RemediationStepStatus.Skipped,
            message,
            null).ConfigureAwait(false);

        return new RealtimeKillResult
        {
            FilePath = target,
            Status = RealtimeKillStatus.AlreadyHandled,
            Processes = [],
            Message = message,
            StartedUtc = _clock.UtcNow,
            CompletedUtc = _clock.UtcNow
        };
    }

    /// <summary>
    /// True when the file was handled recently enough that handling it again would stop
    /// the same processes a second time.
    /// </summary>
    private bool IsRecentlyHandled(string target)
    {
        if (!_handledFiles.TryGetValue(target, out var handledUtc)) return false;

        if (_clock.UtcNow - handledUtc > _repeatWindow)
        {
            _handledFiles.Remove(target);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Remembers that a file was handled, so the same flag does not stop the same
    /// processes twice. The list is bounded and the oldest entries are dropped first.
    /// </summary>
    private void RememberHandled(string target)
    {
        _handledFiles[target] = _clock.UtcNow;

        if (_handledFiles.Count <= MaxRememberedFiles) return;

        var oldest = _handledFiles
            .OrderBy(pair => pair.Value)
            .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(_handledFiles.Count - MaxRememberedFiles)
            .Select(pair => pair.Key)
            .ToArray();

        foreach (var key in oldest) _handledFiles.Remove(key);
    }

    /// <summary>
    /// True when the match really points at the flagged file: either the process runs
    /// from it, or the flagged file is loaded into it. A process that merely lives in
    /// the same folder does not qualify.
    /// </summary>
    private static bool PointsAtFile(ProcessMatch match, string target) =>
        SamePath(match.Process?.ExecutablePath, target) || SamePath(match.MatchedPath, target);

    /// <summary>
    /// Compares two paths the way Windows does: normalized, case-insensitive. A path
    /// that cannot be normalized is compared as it was written.
    /// </summary>
    private static bool SamePath(string? left, string right)
    {
        if (string.IsNullOrWhiteSpace(left)) return false;

        try
        {
            return string.Equals(
                PathRules.NormalizeFile(left),
                PathRules.NormalizeFile(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Equals(left.Trim(), right.Trim(), StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Summarizes the run from the outcomes of the individual processes.
    /// </summary>
    private static RealtimeKillStatus Summarize(IReadOnlyList<RealtimeKillProcessResult> outcomes)
    {
        if (outcomes.Count == 0) return RealtimeKillStatus.NothingToStop;

        var stopped = outcomes.Count(outcome => outcome.Stopped);
        var failed = outcomes.Count(outcome => outcome.Outcome == RealtimeKillProcessOutcome.Failed);
        var refused = outcomes.Count(outcome => outcome.Refused);

        if (stopped > 0 && failed > 0) return RealtimeKillStatus.PartiallyStopped;
        if (stopped > 0) return RealtimeKillStatus.Stopped;
        if (failed > 0) return RealtimeKillStatus.Failed;
        if (refused > 0) return RealtimeKillStatus.Refused;
        return RealtimeKillStatus.NothingToStop;
    }

    /// <summary>
    /// Writes the summary the user sees. It never claims more than happened.
    /// </summary>
    private static string SummarizeMessage(
        IReadOnlyList<RealtimeKillProcessResult> outcomes,
        RealtimeKillStatus status)
    {
        if (outcomes.Count == 0)
        {
            return "No running process was using the flagged file, so nothing was stopped.";
        }

        var stopped = outcomes.Count(outcome => outcome.Stopped);
        var refused = outcomes.Count(outcome => outcome.Refused);
        var failed = outcomes.Count(outcome => outcome.Outcome == RealtimeKillProcessOutcome.Failed);
        var skipped = outcomes.Count(outcome =>
            outcome.Outcome is RealtimeKillProcessOutcome.AlreadyExited);

        var parts = new List<string>
        {
            stopped == 0 ? "No process was stopped." : $"{stopped} process(es) were stopped."
        };

        if (refused > 0) parts.Add($"{refused} were refused.");
        if (failed > 0) parts.Add($"{failed} could not be stopped.");
        if (skipped > 0) parts.Add($"{skipped} had already exited.");

        return string.Join(" ", parts);
    }
}
