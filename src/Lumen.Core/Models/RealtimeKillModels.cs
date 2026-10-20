namespace Lumen.Core.Models;

/// <summary>
/// Why a real-time kill run ended the way it did. The status is a summary of what
/// actually happened to the processes that were using the flagged file; it never claims
/// more than was done.
/// </summary>
public enum RealtimeKillStatus
{
    /// <summary>
    /// The feature is turned off. Nothing was looked at, nothing was stopped and
    /// nothing was written to the audit journal.
    /// </summary>
    Disabled,

    /// <summary>
    /// No running process was using the flagged file, so there was nothing to stop.
    /// </summary>
    NothingToStop,

    /// <summary>
    /// At least one process was stopped and no attempt failed.
    /// </summary>
    Stopped,

    /// <summary>
    /// At least one process was stopped and at least one attempt failed.
    /// </summary>
    PartiallyStopped,

    /// <summary>
    /// Nothing was stopped. Every candidate was refused: it was protected, it ran from
    /// a system folder, Lumen could not read where it ran from, or the caller did not
    /// approve stopping it. A refusal is a normal outcome, not an error.
    /// </summary>
    Refused,

    /// <summary>
    /// Nothing was stopped because something went wrong while trying. The reason is
    /// in the message.
    /// </summary>
    Failed,

    /// <summary>
    /// The same file was flagged again shortly after it was handled. Lumen did not stop
    /// anything a second time.
    /// </summary>
    AlreadyHandled
}

/// <summary>
/// What happened to one process that was using the flagged file. Every value other than
/// <see cref="Stopped"/> means the process was left running, and each one says why.
/// </summary>
public enum RealtimeKillProcessOutcome
{
    /// <summary>The process was stopped.</summary>
    Stopped,

    /// <summary>
    /// The process is protected: the operating system calls it a system process, or its
    /// image name is on the hardcoded protected list. Lumen never stops such a process.
    /// </summary>
    RefusedProtected,

    /// <summary>
    /// The process runs from a system folder such as Windows or Program Files. Lumen
    /// never stops a process that lives there.
    /// </summary>
    RefusedSystemLocation,

    /// <summary>
    /// Lumen could not read where the process runs from, so it could not rule out a
    /// system-critical location. Lumen stops nothing it cannot place.
    /// </summary>
    RefusedUnknownPath,

    /// <summary>
    /// The process is Lumen itself. Lumen never stops itself.
    /// </summary>
    RefusedSelf,

    /// <summary>
    /// The caller did not approve stopping this particular process.
    /// </summary>
    NotApproved,

    /// <summary>
    /// The match does not actually point at the flagged file. A process that merely
    /// lives in the same folder is not using the file.
    /// </summary>
    NotUsingFile,

    /// <summary>
    /// The process had already exited when Lumen went to stop it.
    /// </summary>
    AlreadyExited,

    /// <summary>
    /// Windows denied access, for example because the process belongs to another user.
    /// Lumen does not elevate its privileges to get around this.
    /// </summary>
    Denied,

    /// <summary>
    /// The attempt failed. The reason is in the result.
    /// </summary>
    Failed
}

/// <summary>
/// What happened to one process while a flagged file was being handled. The record is
/// descriptive only: it reports an outcome that already happened.
/// </summary>
public sealed record RealtimeKillProcessResult
{
    /// <summary>The process id of the process that was considered.</summary>
    public required int Pid { get; init; }

    /// <summary>The image name of the process, for example "evil.exe".</summary>
    public required string Name { get; init; }

    /// <summary>What happened to the process.</summary>
    public required RealtimeKillProcessOutcome Outcome { get; init; }

    /// <summary>
    /// Why the process was or was not stopped, in plain language. It is never empty for
    /// an outcome other than <see cref="RealtimeKillProcessOutcome.Stopped"/>.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>The path of the running executable, when it could be read.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Why the process was linked to the flagged file.</summary>
    public ProcessMatchKind MatchKind { get; init; }

    /// <summary>Whether that process carried a digital signature, for display.</summary>
    public bool IsSigned { get; init; }

    /// <summary>True only when the process was actually stopped.</summary>
    public bool Stopped => Outcome == RealtimeKillProcessOutcome.Stopped;

    /// <summary>
    /// True when Lumen left the process alone on purpose, or when the operating system
    /// would not let it stop the process. A refusal is a normal outcome: Lumen says what
    /// it did not do and why.
    /// </summary>
    public bool Refused => Outcome is RealtimeKillProcessOutcome.RefusedProtected
        or RealtimeKillProcessOutcome.RefusedSystemLocation
        or RealtimeKillProcessOutcome.RefusedUnknownPath
        or RealtimeKillProcessOutcome.RefusedSelf
        or RealtimeKillProcessOutcome.NotApproved
        or RealtimeKillProcessOutcome.NotUsingFile
        or RealtimeKillProcessOutcome.Denied;
}

/// <summary>
/// The request that starts a real-time kill run. It carries the facts the real-time
/// monitor produced, so Lumen never has to decide on its own that a file is suspicious.
///
/// The request is the only thing that can authorise a kill: there is no path in Lumen
/// that stops a process because it looked odd.
/// </summary>
public sealed record RealtimeKillRequest
{
    /// <summary>
    /// The full path of the file the real-time monitor flagged.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// The findings the real-time monitor produced for that file. A request without a
    /// finding is refused: Lumen stops processes because a file was flagged, never
    /// because a process looked suspicious.
    /// </summary>
    public IReadOnlyList<Finding> Findings { get; init; } = [];

    /// <summary>
    /// The digest of the flagged file, when the monitor could compute it. It is recorded
    /// in the audit journal so the run can be traced back to the file. It is NOT a
    /// precondition for stopping a process: a file that cannot be hashed is often a
    /// file that is in use by the very process that has to be stopped.
    /// </summary>
    public string? Sha256 { get; init; }

    /// <summary>The size of the flagged file in bytes, when it is known.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>When the real-time monitor made the finding.</summary>
    public DateTimeOffset DetectedUtc { get; init; }
}

/// <summary>
/// The outcome of a real-time kill run. It reports exactly what was stopped, what was
/// left alone and why, so the user is never told more than actually happened.
///
/// A real-time kill never deletes or quarantines anything. Stopping the process is the
/// whole job; removing the file stays a separate, confirmed action.
/// </summary>
public sealed record RealtimeKillResult
{
    /// <summary>The file the run was about.</summary>
    public required string FilePath { get; init; }

    /// <summary>The overall outcome of the run.</summary>
    public required RealtimeKillStatus Status { get; init; }

    /// <summary>
    /// Every process that was considered, with its own outcome. A process that was
    /// never considered does not appear here.
    /// </summary>
    public required IReadOnlyList<RealtimeKillProcessResult> Processes { get; init; }

    /// <summary>A short summary that is safe to show to the user.</summary>
    public required string Message { get; init; }

    /// <summary>When the run started.</summary>
    public DateTimeOffset StartedUtc { get; init; }

    /// <summary>When the run finished.</summary>
    public DateTimeOffset CompletedUtc { get; init; }

    /// <summary>How many processes were actually stopped.</summary>
    public int StoppedCount => Processes.Count(process => process.Stopped);

    /// <summary>How many processes Lumen left alone on purpose.</summary>
    public int RefusedCount => Processes.Count(process => process.Refused);

    /// <summary>True only when at least one process was actually stopped.</summary>
    public bool StoppedAnything => StoppedCount > 0;
}
