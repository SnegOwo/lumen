namespace Lumen.Core.Models;

/// <summary>
/// How a running process was linked to a detected file. The operating-system adapter
/// reports the link; the remediation engine only uses it to build a preview the user
/// can review. Lumen never infers this on its own.
/// </summary>
public enum ProcessMatchKind
{
    /// <summary>The process was started from the detected file.</summary>
    ExecutablePath,

    /// <summary>The detected file was loaded as a module inside the running process.</summary>
    LoadedModule
}

/// <summary>
/// The facts Lumen knows about a running process. Everything here is descriptive only:
/// the process is never touched unless the user confirms a plan step.
/// </summary>
public sealed record ProcessInfo
{
    /// <summary>The operating-system process id.</summary>
    public required int Pid { get; init; }

    /// <summary>The process image name, for example "evil.exe".</summary>
    public required string Name { get; init; }

    /// <summary>Full path of the running executable, when it could be read.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>
    /// True when the operating system reports the process as a system or critical
    /// process. Such a process is never terminated by Lumen.
    /// </summary>
    public bool IsSystemProcess { get; init; }

    /// <summary>True when the executable carries a valid digital signature.</summary>
    public bool IsSigned { get; init; }
}

/// <summary>
/// A running process that was linked to the detected file, plus the reason for the link.
/// </summary>
public sealed record ProcessMatch
{
    /// <summary>The process the match refers to.</summary>
    public required ProcessInfo Process { get; init; }

    /// <summary>Why the process was linked to the detected file.</summary>
    public required ProcessMatchKind MatchKind { get; init; }

    /// <summary>The executable or module path that matched the detected file.</summary>
    public required string MatchedPath { get; init; }
}

/// <summary>
/// The kind of autostart entry Lumen found. Each kind is removed through a different
/// mechanism, and each carries the data needed to put it back.
/// </summary>
public enum PersistenceEntryKind
{
    /// <summary>A value under a Run key in the user's own registry hive.</summary>
    RegistryRunValue,

    /// <summary>A value under a RunOnce key in the user's own registry hive.</summary>
    RegistryRunOnceValue,

    /// <summary>An item in a Startup folder.</summary>
    StartupFolderItem,

    /// <summary>A Windows scheduled task.</summary>
    ScheduledTask,

    /// <summary>An installed service.</summary>
    Service
}

/// <summary>
/// Everything that is needed to put a removed autostart entry back. The engine stores this
/// in the audit journal before anything is removed, so a wrong removal can be reported
/// and undone by hand. Nothing here is ever executed: it is data only.
/// </summary>
public sealed record PersistenceRestoreData
{
    /// <summary>The registry key path, for example HKCU\Software\...\Run.</summary>
    public string? RegistryKeyPath { get; init; }

    /// <summary>The registry value name inside <see cref="RegistryKeyPath"/>.</summary>
    public string? RegistryValueName { get; init; }

    /// <summary>The registry value data exactly as it was read.</summary>
    public string? RegistryValueData { get; init; }

    /// <summary>The registry value kind, for example REG_SZ or REG_EXPAND_SZ.</summary>
    public string? RegistryValueKind { get; init; }

    /// <summary>The full path of the Startup-folder item.</summary>
    public string? StartupItemPath { get; init; }

    /// <summary>The full path of the scheduled task, for example \Vendor\EvilTask.</summary>
    public string? ScheduledTaskPath { get; init; }

    /// <summary>The exported task XML, captured before the task was removed.</summary>
    public string? ScheduledTaskXml { get; init; }

    /// <summary>The service name, without the ".exe" extension.</summary>
    public string? ServiceName { get; init; }

    /// <summary>The service display name.</summary>
    public string? ServiceDisplayName { get; init; }

    /// <summary>The service image path, exactly as it was read.</summary>
    public string? ServiceImagePath { get; init; }

    /// <summary>
    /// True when the captured data is complete enough for a human to recreate the entry.
    /// Lumen does not restore entries itself; it only records what would be needed.
    /// </summary>
    public bool CanRestore { get; init; }
}

/// <summary>
/// One autostart entry that points at the detected file.
/// </summary>
public sealed record PersistenceEntry
{
    /// <summary>The kind of autostart entry.</summary>
    public required PersistenceEntryKind Kind { get; init; }

    /// <summary>A short display name for the entry, for example the registry value name.</summary>
    public required string Name { get; init; }

    /// <summary>The path the entry points at, as reported by the operating system.</summary>
    public required string TargetPath { get; init; }

    /// <summary>Where the entry lives, for example a registry key path or a task path.</summary>
    public string? Location { get; init; }

    /// <summary>The data captured for restoring the entry later.</summary>
    public PersistenceRestoreData RestoreData { get; init; } = new();
}

/// <summary>Why a permanent file removal succeeded or failed.</summary>
public enum FileRemovalOutcome
{
    /// <summary>The file was permanently removed.</summary>
    Removed,

    /// <summary>The file did not exist.</summary>
    NotFound,

    /// <summary>Windows denied access. Lumen does not bypass permissions.</summary>
    AccessDenied,

    /// <summary>The file is in use by another program.</summary>
    InUse,

    /// <summary>The path is a folder, not a file.</summary>
    PathIsDirectory,

    /// <summary>The path is system-critical and is never removed.</summary>
    SystemCritical,

    /// <summary>The removal was refused for any other reason.</summary>
    Failed
}

/// <summary>The outcome of a permanent file removal.</summary>
public sealed record FileRemovalResult
{
    /// <summary>True only when the file was actually removed.</summary>
    public bool Removed { get; init; }

    /// <summary>Why the removal succeeded or failed.</summary>
    public FileRemovalOutcome Outcome { get; init; }

    /// <summary>A short message that is safe to show to the user.</summary>
    public string Message { get; init; } = string.Empty;
}

/// <summary>Why a process termination succeeded or failed.</summary>
public enum ProcessTerminationOutcome
{
    /// <summary>The process was terminated.</summary>
    Terminated,

    /// <summary>The process was no longer running.</summary>
    NotFound,

    /// <summary>Windows denied access.</summary>
    AccessDenied,

    /// <summary>The process could not be stopped.</summary>
    Failed
}

/// <summary>The outcome of a process termination.</summary>
public sealed record ProcessTerminationResult
{
    /// <summary>True only when the process was actually terminated.</summary>
    public bool Terminated { get; init; }

    /// <summary>Why the termination succeeded or failed.</summary>
    public ProcessTerminationOutcome Outcome { get; init; }

    /// <summary>A short message that is safe to show to the user.</summary>
    public string Message { get; init; } = string.Empty;
}

/// <summary>Why an autostart entry removal succeeded or failed.</summary>
public enum PersistenceRemovalOutcome
{
    /// <summary>The entry was removed.</summary>
    Removed,

    /// <summary>The entry was no longer present.</summary>
    NotFound,

    /// <summary>Windows denied access.</summary>
    AccessDenied,

    /// <summary>The entry was not removed because not enough was captured to restore it.</summary>
    NotReversible,

    /// <summary>The entry could not be removed.</summary>
    Failed
}

/// <summary>The outcome of an autostart entry removal.</summary>
public sealed record PersistenceRemovalResult
{
    /// <summary>True only when the entry was actually removed.</summary>
    public bool Removed { get; init; }

    /// <summary>Why the removal succeeded or failed.</summary>
    public PersistenceRemovalOutcome Outcome { get; init; }

    /// <summary>A short message that is safe to show to the user.</summary>
    public string Message { get; init; } = string.Empty;
}

/// <summary>Why a file hash could or could not be read.</summary>
public enum FileHashOutcome
{
    /// <summary>The file was read and hashed.</summary>
    Hashed,

    /// <summary>The file did not exist.</summary>
    NotFound,

    /// <summary>Windows denied access.</summary>
    AccessDenied,

    /// <summary>The file could not be hashed.</summary>
    Failed
}

/// <summary>
/// The result of hashing a file. Only the hash and the size are reported; Lumen never
/// reads or stores file contents anywhere else.
/// </summary>
public sealed record FileHashResult
{
    /// <summary>Why the hash could or could not be computed.</summary>
    public FileHashOutcome Outcome { get; init; }

    /// <summary>The lower-case SHA-256 of the file, when it was read.</summary>
    public string? Sha256 { get; init; }

    /// <summary>The size of the file in bytes, when it was read.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>A short message describing a failure.</summary>
    public string? Error { get; init; }

    /// <summary>True only when a hash was actually computed.</summary>
    public bool Success => Outcome == FileHashOutcome.Hashed;
}

/// <summary>The kinds of remediation action Lumen can plan.</summary>
public enum RemediationStepKind
{
    /// <summary>Stop a running process that uses the detected file.</summary>
    TerminateProcess,

    /// <summary>Permanently delete the detected file.</summary>
    RemoveFile,

    /// <summary>Remove an autostart entry that points at the detected file.</summary>
    RemovePersistence
}

/// <summary>The state of a single step in a remediation plan.</summary>
public enum RemediationStepStatus
{
    /// <summary>The step is planned and has not been run.</summary>
    Pending,

    /// <summary>The step ran and did what it promised.</summary>
    Succeeded,

    /// <summary>The step ran and failed. Later steps are not attempted.</summary>
    Failed,

    /// <summary>The step was not run, for example because the user did not select it.</summary>
    Skipped,

    /// <summary>The step was refused. Nothing was changed.</summary>
    Refused
}

/// <summary>The overall state of a remediation run.</summary>
public enum RemediationStatus
{
    /// <summary>A plan was produced; nothing has been executed.</summary>
    Planned,

    /// <summary>Every selected step completed.</summary>
    Executed,

    /// <summary>Some steps completed and at least one failed.</summary>
    PartiallyExecuted,

    /// <summary>No step completed and at least one failed.</summary>
    Failed,

    /// <summary>Nothing was executed because the request was refused.</summary>
    Refused,

    /// <summary>The run was cancelled by the user.</summary>
    Cancelled
}

/// <summary>
/// The file Lumen wants to clean up, together with the facts that were verified when it
/// was detected. The engine never re-reads the file's contents; it only checks the hash
/// against what is stored here.
/// </summary>
public sealed record RemediationTarget
{
    /// <summary>The full path of the detected file.</summary>
    public required string FilePath { get; init; }

    /// <summary>The SHA-256 that was recorded when the file was scanned.</summary>
    public string? Sha256 { get; init; }

    /// <summary>The size of the file in bytes, when it was recorded.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>The title of the finding that produced this target.</summary>
    public required string FindingTitle { get; init; }

    /// <summary>Extra detail about the finding, shown next to the plan.</summary>
    public string? FindingDetail { get; init; }

    /// <summary>
    /// The quarantine vault item that holds an encrypted copy of this file, when there is
    /// one. The audit journal records it so a wrong removal can be pointed back at the
    /// vault copy.
    /// </summary>
    public string? QuarantineItemId { get; init; }

    /// <summary>
    /// Set only when the user has explicitly accepted that the file changed since the
    /// scan. Without it, a changed file is never removed.
    /// </summary>
    public bool AllowChangedFile { get; init; }
}

/// <summary>
/// Which kinds of action a plan should contain. Planning never changes anything, so the
/// defaults only decide what the preview shows; the user still confirms each step.
/// </summary>
public sealed record RemediationOptions
{
    /// <summary>Offer to stop processes that use the detected file.</summary>
    public bool TerminateProcesses { get; init; } = true;

    /// <summary>Offer to permanently delete the detected file.</summary>
    public bool RemoveFile { get; init; } = true;

    /// <summary>Offer to remove autostart entries that point at the detected file.</summary>
    public bool RemovePersistence { get; init; } = true;
}

/// <summary>
/// One step of a remediation plan. A step describes exactly what would happen; it is
/// executed only when the user confirms it, and it reports its own outcome afterwards.
/// </summary>
public sealed record RemediationStep
{
    /// <summary>A stable id for this step, used to select it for execution.</summary>
    public required string Id { get; init; }

    /// <summary>The kind of action this step performs.</summary>
    public required RemediationStepKind Kind { get; init; }

    /// <summary>A short, sanitized description of what the step does.</summary>
    public required string Description { get; init; }

    /// <summary>The current state of the step.</summary>
    public RemediationStepStatus Status { get; init; } = RemediationStepStatus.Pending;

    /// <summary>The path the step acts on, when the step acts on a path.</summary>
    public string? TargetPath { get; init; }

    /// <summary>The process id the step acts on, when the step stops a process.</summary>
    public int? ProcessId { get; init; }

    /// <summary>The process name the step acts on, for display.</summary>
    public string? ProcessName { get; init; }

    /// <summary>Whether that process carried a digital signature, for display.</summary>
    public bool? ProcessIsSigned { get; init; }

    /// <summary>The autostart entry the step removes, when the step removes one.</summary>
    public PersistenceEntry? PersistenceEntry { get; init; }

    /// <summary>The SHA-256 the step expects the file to have.</summary>
    public string? Sha256 { get; init; }

    /// <summary>The size of the file in bytes, when it is known.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>The quarantine vault item that holds a copy of the file, when there is one.</summary>
    public string? QuarantineItemId { get; init; }

    /// <summary>The outcome message, filled in once the step has run.</summary>
    public string? Outcome { get; init; }
}

/// <summary>
/// A reviewed, ordered list of steps. A plan is a promise of what would happen; it does
/// not do anything by itself.
/// </summary>
public sealed record RemediationPlan
{
    /// <summary>The id of the plan. Every audit entry refers back to it.</summary>
    public required string Id { get; init; }

    /// <summary>When the plan was created.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>The file the plan is about.</summary>
    public required RemediationTarget Target { get; init; }

    /// <summary>The steps, in the order they would run.</summary>
    public required IReadOnlyList<RemediationStep> Steps { get; init; }

    /// <summary>The state of the plan itself.</summary>
    public RemediationStatus Status { get; init; } = RemediationStatus.Planned;

    /// <summary>A short message describing the state of the plan.</summary>
    public string? Message { get; init; }
}

/// <summary>
/// The result of running a plan. It reports exactly which steps ran, which did not, and
/// why, so the user is never told more than actually happened.
/// </summary>
public sealed record RemediationResult
{
    /// <summary>The id of the plan that was run.</summary>
    public required string PlanId { get; init; }

    /// <summary>The overall outcome.</summary>
    public required RemediationStatus Status { get; init; }

    /// <summary>Every step with its own outcome.</summary>
    public required IReadOnlyList<RemediationStep> Steps { get; init; }

    /// <summary>A short summary that is safe to show to the user.</summary>
    public required string Message { get; init; }

    /// <summary>
    /// The quarantine vault item that holds an encrypted copy of the file, when there is
    /// one. Lumen keeps the vault copy whatever happens, so a wrong removal can be undone
    /// with the existing quarantine restore.
    /// </summary>
    public string? QuarantineItemId { get; init; }
}

/// <summary>The kind of event recorded in the audit journal.</summary>
public enum AuditEventKind
{
    /// <summary>A plan was produced. Nothing was changed.</summary>
    PlanCreated,

    /// <summary>A single step was added to a plan.</summary>
    StepPlanned,

    /// <summary>A step ran and completed.</summary>
    StepExecuted,

    /// <summary>A step was refused and nothing was changed.</summary>
    StepRefused,

    /// <summary>A step ran and failed.</summary>
    StepFailed,

    /// <summary>A step was not attempted.</summary>
    StepSkipped,

    /// <summary>The run finished.</summary>
    PlanCompleted
}

/// <summary>
/// One line of the audit journal. The journal records what was planned and what was done,
/// with enough detail to report a removal later and to point back at the vault copy.
/// File contents are never recorded.
/// </summary>
public sealed record AuditEntry
{
    /// <summary>When the event happened.</summary>
    public required DateTimeOffset TimestampUtc { get; init; }

    /// <summary>The kind of event.</summary>
    public required AuditEventKind Kind { get; init; }

    /// <summary>The plan the event belongs to.</summary>
    public required string PlanId { get; init; }

    /// <summary>The step the event belongs to, when it belongs to one.</summary>
    public string? StepId { get; init; }

    /// <summary>The kind of the step, when the event belongs to one.</summary>
    public RemediationStepKind? StepKind { get; init; }

    /// <summary>The path or process the event is about.</summary>
    public required string Target { get; init; }

    /// <summary>A short description of the event.</summary>
    public string? Detail { get; init; }

    /// <summary>The step outcome, when the event belongs to a step.</summary>
    public RemediationStepStatus? Status { get; init; }

    /// <summary>The SHA-256 of the file the event is about.</summary>
    public string? Sha256 { get; init; }

    /// <summary>The size of the file the event is about.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>The quarantine vault item that holds a copy of the file, when there is one.</summary>
    public string? QuarantineItemId { get; init; }

    /// <summary>
    /// The captured data needed to put a removed autostart entry back. It is written
    /// before the entry is removed, never after.
    /// </summary>
    public PersistenceRestoreData? RestoreData { get; init; }
}
