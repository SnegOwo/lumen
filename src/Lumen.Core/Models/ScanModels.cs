namespace Lumen.Core.Models;

/// <summary>
/// Describes a single on-demand scan. Requests are pure data so they can be built and
/// tested without touching the UI.
/// </summary>
public sealed record ScanRequest
{
    public required ScanScopeKind Scope { get; init; }

    /// <summary>Files and folders to scan. Files and directories may be mixed.</summary>
    public required IReadOnlyList<string> Roots { get; init; }

    /// <summary>Short, human-readable description stored in history.</summary>
    public required string Description { get; init; }

    /// <summary>Directories whose entire subtree is skipped (cache and system folders).</summary>
    public IReadOnlyList<string> ExcludedDirectories { get; init; } = [];

    /// <summary>Maximum number of leading bytes read from each file for content checks.</summary>
    public long MaxInspectBytes { get; init; } = 1024 * 1024;

    /// <summary>Directory nesting limit, a guard against pathological trees.</summary>
    public int MaxDepth { get; init; } = 64;

    public string ScanId { get; init; } = Guid.NewGuid().ToString("N");
}

public sealed record Finding
{
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required FindingCategory Category { get; init; }
    public required Confidence Confidence { get; init; }

    /// <summary>Plain-language explanation of what was observed.</summary>
    public required string Summary { get; init; }

    /// <summary>Why the rule fired, without reproducing file contents.</summary>
    public required string Detail { get; init; }

    /// <summary>Safe next step for the user. Never an instruction to upload files.</summary>
    public required string Advice { get; init; }
}

public sealed record ScanDetection
{
    public required string FilePath { get; init; }
    public required long SizeBytes { get; init; }
    public string? Sha256 { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required DateTimeOffset DetectedUtc { get; init; }

    public string FileName => Path.GetFileName(FilePath);
    public int FindingCount => Findings.Count;
    public Finding? PrimaryFinding => Findings.Count > 0 ? Findings[0] : null;
}

public sealed record ScanError
{
    public required string Path { get; init; }
    public required ScanErrorKind Kind { get; init; }
    public required string Message { get; init; }
    public required DateTimeOffset OccurredUtc { get; init; }

    /// <summary>Exception type name only. Never includes file contents.</summary>
    public string? Technical { get; init; }
}

public sealed record ScanProgress
{
    public ScanPhase Phase { get; init; } = ScanPhase.Enumerating;
    public string CurrentFile { get; init; } = string.Empty;
    public long FilesScanned { get; init; }
    public long FilesSkipped { get; init; }
    public long DirectoriesSkipped { get; init; }
    public long ErrorCount { get; init; }
    public long DetectionCount { get; init; }
    public long BytesInspected { get; init; }
    public TimeSpan Elapsed { get; init; }
    public IReadOnlyList<ScanDetection> NewDetections { get; init; } = [];
}

public sealed record ScanOutcome
{
    public required string ScanId { get; init; }
    public required ScanRequest Request { get; init; }
    public required IReadOnlyList<ScanDetection> Detections { get; init; }
    public required IReadOnlyList<ScanError> Errors { get; init; }
    public required long FilesScanned { get; init; }
    public required long FilesSkipped { get; init; }
    public required long DirectoriesSkipped { get; init; }
    public required long ErrorCount { get; init; }
    public required long BytesInspected { get; init; }
    public required bool Cancelled { get; init; }
    public required DateTimeOffset StartedUtc { get; init; }
    public required DateTimeOffset FinishedUtc { get; init; }

    public TimeSpan Duration => FinishedUtc - StartedUtc;
    public bool HasFindings => Detections.Count > 0;
}

public sealed record DetectionRuleSummary(
    string Id,
    string Name,
    string Description,
    FindingCategory Category,
    Confidence Confidence);

public sealed record OperationResult(bool Ok, string? Message = null)
{
    public static OperationResult Success() => new(true);
    public static OperationResult Failure(string message) => new(false, message);
}
