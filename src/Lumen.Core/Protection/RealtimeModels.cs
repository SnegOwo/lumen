using Lumen.Core.Models;

namespace Lumen.Core.Protection;

/// <summary>
/// Raised once per reported real-time match. Like on-demand scans, the monitor is read-only:
/// acting on a match (quarantine) stays the caller's explicitly confirmed decision.
/// </summary>
public sealed record RealtimeDetectionEvent
{
    public required string FilePath { get; init; }
    public required long SizeBytes { get; init; }

    /// <summary>
    /// The digest of the file, or null when the file could not be hashed. A null digest does
    /// not mean "clean"; it means the file was in use or unreadable at that moment.
    /// </summary>
    public string? Sha256 { get; init; }

    /// <summary>
    /// Why the digest is missing, in plain language. Null when the hash succeeded.
    /// </summary>
    public string? Sha256Error { get; init; }

    /// <summary>
    /// True when the detection can be acted on safely right now: a digest is available, so
    /// the caller can pass <see cref="Sha256"/> as the expected-hash guard and the file
    /// cannot be swapped between the detection and the quarantine. A detection that is not
    /// actionable must still be shown to the user; it simply must not be quarantined
    /// automatically.
    /// </summary>
    public bool IsActionable { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }
    public required DateTimeOffset DetectedUtc { get; init; }

    public string FileName => Path.GetFileName(FilePath);
    public Finding? PrimaryFinding => Findings.Count > 0 ? Findings[0] : null;
}

/// <summary>Point-in-time snapshot of the monitor's counters for status displays.</summary>
public sealed record RealtimeMonitorStats(
    long FilesChecked,
    long FilesSkipped,
    long ErrorCount,
    long DetectionCount,
    DateTimeOffset? LastEventUtc,
    string? LastDetectionPath,
    bool IsRunning)
{
    /// <summary>
    /// How many of the configured folders are covered by a live watcher right now. A number
    /// lower than <see cref="ConfiguredFolderCount"/> means part of the protection is not
    /// currently working, and the UI must say so instead of claiming full coverage.
    /// </summary>
    public int WatchedFolderCount { get; init; }

    /// <summary>How many folders the monitor was asked to watch.</summary>
    public int ConfiguredFolderCount { get; init; }

    /// <summary>Paths waiting to be inspected, plus paths already handed to the worker.</summary>
    public int QueueDepth { get; init; }

    /// <summary>Paths that were waiting to be inspected but had to be dropped.</summary>
    public int PendingPathCount { get; init; }

    /// <summary>
    /// How many paths were dropped because the queue was full. A non-zero value means files
    /// may exist that were never inspected; this is reported, never hidden.
    /// </summary>
    public long DroppedPathCount { get; init; }

    /// <summary>How many times a folder watcher failed and had to be rebuilt.</summary>
    public long WatcherFailureCount { get; init; }

    /// <summary>The most recent watcher or inspection error, in plain language.</summary>
    public string? LastError { get; init; }

    /// <summary>
    /// True when the monitor is not covering everything it was asked to cover. The UI should
    /// show "watching N of M folders" rather than "protection active" in that case.
    /// </summary>
    public bool IsDegraded { get; init; }
}
