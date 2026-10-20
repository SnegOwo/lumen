using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// Runs the configured detectors over one probe. Detectors are pure and UI-independent so
/// the detection layer can be tested without a desktop session.
/// </summary>
public sealed class DetectorRegistry
{
    private readonly IReadOnlyList<IScanDetector> _detectors;

    public DetectorRegistry(IEnumerable<IScanDetector> detectors)
    {
        _detectors = detectors.ToArray();
    }

    public IReadOnlyList<IScanDetector> Detectors => _detectors;

    public static DetectorRegistry CreateDefault() =>
        new(
        [
            new EicarTestDetector(),
            new ScriptPatternDetector(),
            new FilenameHeuristicDetector()
        ]);

    public IReadOnlyList<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var detector in _detectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var finding in detector.Inspect(probe, cancellationToken))
            {
                if (seen.Add(finding.RuleId)) findings.Add(finding);
            }
        }

        return findings;
    }
}
