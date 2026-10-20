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
    public string? Sha256 { get; init; }
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
    bool IsRunning);