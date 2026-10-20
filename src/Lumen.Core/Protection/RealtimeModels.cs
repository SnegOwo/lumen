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
    /// The digest of the WHOLE file, or null when the file could not be hashed. A null digest
    /// does not mean "clean"; it means the file was in use or unreadable at that moment.
    ///
    /// This is the digest of the complete file, not of the inspected prefix, because the
    /// quarantine service recomputes the digest of the complete file and compares the two.
    /// It is only computed when there is something to report, since hashing a large file is
    /// the most expensive step of the whole inspection.
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

    /// <summary>
    /// True when the monitor runs in aggressive mode.
    ///
    /// <para>
    /// Aggressive mode watches more folders and inspects more eagerly, so it uses more
    /// CPU. The interface shows this together with
    /// <see cref="WatchedFolderCount"/>, so the cost is visible instead of surprising.
    /// </para>
    /// </summary>
    public bool IsAggressiveMode { get; init; }

    /// <summary>
    /// How many paths the monitor is still dealing with: the paths that are waiting for their
    /// settle deadline, the paths that are ready to be inspected and the paths a worker is
    /// reading right now. A number above zero means the monitor is busy, and the UI can say
    /// so instead of pretending that everything was answered already.
    /// </summary>
    public int QueueDepth { get; init; }

    /// <summary>
    /// How many paths are still waiting for their settle deadline. These paths do not occupy
    /// a worker: they wait outside the inspection stage until the file stops changing.
    /// </summary>
    public int PendingPathCount { get; init; }

    /// <summary>How many files the monitor may inspect at the same time.</summary>
    public int WorkerCount { get; init; }

    /// <summary>
    /// How many of the monitor's background threads are alive right now: the workers plus
    /// the scheduler that hands the ready paths to them. The value is zero while the
    /// monitor is stopped, which shows that nothing is left running in the background.
    /// </summary>
    public int ActiveWorkerCount { get; init; }

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
