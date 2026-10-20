using Lumen.Core.Models;

namespace Lumen.Core.Models;

public sealed record QuarantineRequest
{
    public required string FilePath { get; init; }
    public required string FindingTitle { get; init; }
    public required FindingCategory Category { get; init; }
    public required string FindingDetail { get; init; }
    public string? ExpectedSha256 { get; init; }
    public string? SourceScanId { get; init; }
    public DateTimeOffset? DetectedUtc { get; init; }

    /// <summary>
    /// Set only after the user has explicitly confirmed that the file changed since the
    /// scan. Without this flag the service refuses to quarantine changed content.
    /// </summary>
    public bool AllowChangedFile { get; init; }
}

public sealed record QuarantineItem
{
    public required string Id { get; init; }
    public required string OriginalPath { get; init; }
    public required string Sha256 { get; init; }
    public required long SizeBytes { get; init; }
    public required DateTimeOffset DetectedUtc { get; init; }
    public required DateTimeOffset QuarantinedUtc { get; init; }
    public required string FindingTitle { get; init; }
    public required FindingCategory Category { get; init; }
    public required string FindingDetail { get; init; }
    public string? SourceScanId { get; init; }
    public required string VaultFileName { get; init; }
    public required string ProtectedKey { get; init; }
    public required string ProtectedMacKey { get; init; }
    public required string Mac { get; init; }
    public required string Iv { get; init; }

    /// <summary>Non-fatal note, for example that the original could not be removed.</summary>
    public string? Note { get; init; }

    public string FileName => Path.GetFileName(OriginalPath);
}

public enum QuarantineStatus
{
    Quarantined,
    QuarantinedOriginalRetained,
    ChangedSinceScan,
    NotFound,
    AccessDenied,
    Failed,
    Cancelled
}

public sealed record QuarantineResult(
    QuarantineStatus Status,
    QuarantineItem? Item,
    string Message,
    bool OriginalRemoved);

public sealed record RestoreRequest
{
    public required string Id { get; init; }
    public bool Overwrite { get; init; }

    /// <summary>Null restores to the original path; otherwise a file path to restore to.</summary>
    public string? DestinationPath { get; init; }
}

public enum RestoreStatus
{
    Restored,
    NotFound,
    TargetExists,
    DestinationMissing,
    Corrupt,
    Failed,
    Cancelled
}

public sealed record RestoreResult(
    RestoreStatus Status,
    string? RestoredPath,
    string Message);

public sealed record DeleteResult(
    bool Deleted,
    string Message);
