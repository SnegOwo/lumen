using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Abstractions;

/// <summary>
/// A detector inspects already-read file metadata/content. Detectors perform no I/O so
/// they can be unit tested with synthetic in-memory probes.
/// </summary>
public interface IScanDetector
{
    string Id { get; }
    string Name { get; }
    string Description { get; }
    FindingCategory Category { get; }
    Confidence Confidence { get; }

    IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken);
}
