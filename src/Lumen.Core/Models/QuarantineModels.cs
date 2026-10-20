using System.Text.Json.Serialization;
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

    /// <summary>
    /// Metadata captured from the original file so that a restore can put it back the way
    /// the user remembers it. Absent in manifests written by older versions of Lumen, which
    /// simply means "keep whatever timestamps the restored file gets".
    /// </summary>
    public QuarantinedFileMetadata? Metadata { get; init; }

    /// <summary>
    /// The file name of the original path. Derived on demand so it cannot go stale in the
    /// manifest file on disk.
    /// </summary>
    [JsonIgnore]
    public string FileName => Path.GetFileName(OriginalPath);
}

/// <summary>
/// The small amount of file metadata Lumen preserves across a quarantine so that a
/// restore does not silently change a file. Access control lists are deliberately not
/// captured: Lumen never manages permissions.
/// </summary>
public sealed record QuarantinedFileMetadata
{
    /// <summary>Windows file attributes such as ReadOnly, Hidden or System.</summary>
    public FileAttributes Attributes { get; init; }

    /// <summary>Last write time of the original file, in UTC.</summary>
    public DateTimeOffset LastWriteTimeUtc { get; init; }

    /// <summary>Creation time of the original file, in UTC.</summary>
    public DateTimeOffset CreationTimeUtc { get; init; }
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
    Cancelled,

    /// <summary>
    /// The requested destination is inside a protected system location. Lumen does not
    /// write to those folders, so the file was not restored.
    /// </summary>
    DestinationProtected
}

public sealed record RestoreResult(
    RestoreStatus Status,
    string? RestoredPath,
    string Message);

public sealed record DeleteResult(
    bool Deleted,
    string Message);
