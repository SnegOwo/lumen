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
    private readonly RiskScorer _riskScorer;

    /// <summary>
    /// Creates a registry over the supplied detectors.
    /// </summary>
    /// <param name="detectors">The detectors to run, in order.</param>
    /// <param name="riskScorer">The scorer used to combine findings. The built-in scorer is used when none is supplied.</param>
    public DetectorRegistry(IEnumerable<IScanDetector> detectors, RiskScorer? riskScorer = null)
    {
        _detectors = detectors.ToArray();
        _riskScorer = riskScorer ?? new RiskScorer();
    }

    /// <summary>The detectors this registry runs.</summary>
    public IReadOnlyList<IScanDetector> Detectors => _detectors;

    /// <summary>The scorer used to combine findings into a risk score with a breakdown.</summary>
    public RiskScorer RiskScorer => _riskScorer;

    /// <summary>
    /// Creates the registry Lumen uses by default. The signature rules come from the set
    /// embedded in the assembly, so no file is read while a scan is running.
    /// </summary>
    public static DetectorRegistry CreateDefault() => CreateDefault(SignatureEngine.CreateEmbedded());

    /// <summary>
    /// Creates the registry with a caller supplied signature engine. A caller that wants to
    /// use a rule file from disk builds the engine first and passes it in.
    /// </summary>
    /// <param name="signatureEngine">The signature engine to use, or null for the embedded one.</param>
    /// <param name="locations">
    /// Decides which folders count as places a user can freely write to and run from. The
    /// folders of the current machine are used when this is left out.
    /// </param>
    public static DetectorRegistry CreateDefault(SignatureEngine? signatureEngine, ISuspiciousLocation? locations = null) =>
        new(
        [
            new EicarTestDetector(),
            new ScriptPatternDetector(),
            new FilenameHeuristicDetector(),
            signatureEngine ?? SignatureEngine.CreateEmbedded(),
            new PortableExecutableDetector(SystemClock.Instance, locations ?? new DefaultSuspiciousLocation()),
            new ScriptThreatDetector(),
            new OfficeMacroDetector(),
            new PdfDetector(),
            new ArchiveDetector(),
            new ShortcutDetector(),
            new HashReputationDetector(),
            new EntropyDetector()
        ]);

    /// <summary>
    /// Runs every detector over a probe and returns the findings, one per rule.
    /// </summary>
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

    /// <summary>
    /// Combines findings into a risk score together with the breakdown that produced it.
    /// </summary>
    public RiskAssessment Assess(IReadOnlyList<Finding> findings) => _riskScorer.Evaluate(findings);
}
