using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Aggressive;
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
    private readonly CombinationSignalScorer _combinationScorer;

    /// <summary>
    /// Creates a registry over the supplied detectors.
    /// </summary>
    /// <param name="detectors">The detectors to run, in order.</param>
    /// <param name="riskScorer">The scorer used to combine findings. The built-in scorer is used when none is supplied.</param>
    /// <param name="combinationScorer">
    /// The scorer that turns several weak signals into one finding. It is only used when
    /// the registry holds an aggressive detector.
    /// </param>
    public DetectorRegistry(
        IEnumerable<IScanDetector> detectors,
        RiskScorer? riskScorer = null,
        CombinationSignalScorer? combinationScorer = null)
    {
        _detectors = detectors.ToArray();
        _riskScorer = riskScorer ?? new RiskScorer();
        _combinationScorer = combinationScorer ?? new CombinationSignalScorer();
    }

    /// <summary>The detectors this registry runs.</summary>
    public IReadOnlyList<IScanDetector> Detectors => _detectors;

    /// <summary>
    /// True when the registry holds at least one detector of the AGGRESSIVE tier. The
    /// combination finding is only produced in that case, because it belongs to the same
    /// tier as the rules it summarises.
    /// </summary>
    public bool IncludeAggressive => _detectors.Any(detector => detector is IAggressiveDetector);

    /// <summary>The detectors of the AGGRESSIVE tier that this registry runs.</summary>
    public IReadOnlyList<IScanDetector> AggressiveDetectors =>
        _detectors.Where(detector => detector is IAggressiveDetector).ToArray();

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
    /// <param name="includeAggressive">
    /// True to also run the detectors of the AGGRESSIVE tier. It is false by default, so
    /// the aggressive rules never add noise to somebody who did not ask for them. The
    /// caller has to rebuild the registry when the setting changes.
    /// </param>
    public static DetectorRegistry CreateDefault(
        SignatureEngine? signatureEngine,
        ISuspiciousLocation? locations = null,
        bool includeAggressive = false)
    {
        var effectiveLocations = locations ?? new DefaultSuspiciousLocation();

        var detectors = new List<IScanDetector>
        {
            new EicarTestDetector(),
            new ScriptPatternDetector(),
            new FilenameHeuristicDetector(),
            signatureEngine ?? SignatureEngine.CreateEmbedded(includeAggressive: includeAggressive),
            new PortableExecutableDetector(SystemClock.Instance, effectiveLocations),
            new ScriptThreatDetector(),
            new OfficeMacroDetector(),
            new PdfDetector(),
            new ArchiveDetector(),
            new ShortcutDetector(),
            new HashReputationDetector(),
            new EntropyDetector(),
            new PhpWebshellDetector()
        };

        if (includeAggressive)
        {
            detectors.AddRange(AggressiveDetectors(effectiveLocations));
        }

        return new DetectorRegistry(detectors);
    }

    /// <summary>
    /// The detectors of the AGGRESSIVE tier.
    /// </summary>
    /// <remarks>
    /// These rules catch real techniques, but each of them is also something ordinary
    /// software can do, so they only run when the user has switched aggressive mode on.
    /// Every one of them is documented in <see cref="DetectionCatalog.Rules"/> and has a
    /// unit test.
    /// </remarks>
    private static IReadOnlyList<IScanDetector> AggressiveDetectors(ISuspiciousLocation locations) =>
    [
        new DllSideloadDetector(locations),
        new AntiAnalysisDetector(),
        new RansomwareIndicatorDetector(),
        new CryptominerIndicatorDetector(),
        new OfficeDdeDetector(),
        new PowerShellCradleDetector(),
        new LoaderMarkerDetector()
    ];

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

        if (IncludeAggressive)
        {
            var assessment = _combinationScorer.Evaluate(findings);
            if (assessment.Qualifies)
            {
                var combination = _combinationScorer.BuildFinding(assessment);
                if (seen.Add(combination.RuleId)) findings.Add(combination);
            }
        }

        return findings;
    }

    /// <summary>
    /// Combines findings into a risk score together with the breakdown that produced it.
    /// </summary>
    public RiskAssessment Assess(IReadOnlyList<Finding> findings) => _riskScorer.Evaluate(findings);
}
