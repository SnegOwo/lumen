using System.Text.Json.Serialization;
using Lumen.Core.Models;

namespace Lumen.Core.Models;

public sealed record ScanHistoryEntry
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset StartedUtc { get; init; }
    public DateTimeOffset FinishedUtc { get; init; }
    public ScanScopeKind Scope { get; init; }
    public string ScopeDescription { get; init; } = string.Empty;
    public IReadOnlyList<string> Roots { get; init; } = [];
    public long FilesScanned { get; init; }
    public long FilesSkipped { get; init; }
    public long ErrorCount { get; init; }
    public long DetectionCount { get; init; }
    public bool Cancelled { get; init; }

    /// <summary>A few error samples for the history details pane. Capped by the engine.</summary>
    public IReadOnlyList<ScanError> Errors { get; init; } = [];

    /// <summary>How long the scan took. Derived on demand so it cannot go stale on disk.</summary>
    [JsonIgnore]
    public TimeSpan Duration => FinishedUtc - StartedUtc;

    /// <summary>Short status line for the history list. Derived on demand.</summary>
    [JsonIgnore]
    public string StatusText => Cancelled
        ? "Cancelled"
        : ErrorCount > 0
            ? "Completed with errors"
            : "Completed";
}

public sealed class HistoryFile
{
    public int SchemaVersion { get; set; } = 1;
    public List<ScanHistoryEntry> Entries { get; set; } = [];
}
