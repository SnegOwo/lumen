using System.Text;
using Lumen.Core.Models;

namespace Lumen.Core.Detection;

/// <summary>
/// One weak signal that took part in a combination score.
/// </summary>
/// <param name="RuleId">The rule that produced the signal.</param>
/// <param name="Title">The title of the rule.</param>
/// <param name="Weight">How much the signal moved the score.</param>
/// <param name="Explanation">The plain-language explanation that came with the finding.</param>
public sealed record CombinationSignal(string RuleId, string Title, int Weight, string Explanation);

/// <summary>
/// The result of adding up several weak signals that point at the same file.
/// </summary>
/// <param name="Score">The sum of the weights of the contributing signals.</param>
/// <param name="Threshold">The score at which the combination is worth reporting.</param>
/// <param name="MinimumSignals">How many independent signals the combination needs.</param>
/// <param name="Signals">Every signal that contributed, in the order it was found.</param>
public sealed record CombinationAssessment(
    int Score,
    int Threshold,
    int MinimumSignals,
    IReadOnlyList<CombinationSignal> Signals)
{
    /// <summary>True when enough independent signals added up to reach the threshold.</summary>
    public bool Qualifies => Signals.Count >= MinimumSignals && Score >= Threshold;

    /// <summary>
    /// Builds the plain-language breakdown. Every contributor is named with its weight and
    /// the threshold is stated, so the total never stands on its own.
    /// </summary>
    public string BuildDetail()
    {
        var builder = new StringBuilder();
        builder.Append("Total ").Append(Score).Append(" points from ").Append(Signals.Count)
            .Append(" weak signal(s). The threshold is ").Append(Threshold)
            .Append(" and at least ").Append(MinimumSignals).Append(" independent signals are needed.");

        foreach (var signal in Signals)
        {
            builder.AppendLine();
            builder.Append("  - ").Append(signal.RuleId).Append(" (+").Append(signal.Weight).Append("): ").Append(signal.Explanation);
        }

        return builder.ToString().TrimEnd();
    }
}

/// <summary>
/// Turns several weak signals that point at the same file into a single finding.
/// </summary>
/// <remarks>
/// <para>
/// A single weak signal is rarely enough to act on, but several of them pointing at the
/// same file are worth a look. The scorer adds the weights of the signals, requires a
/// minimum number of independent rules, and returns every contributor so a reader can
/// judge each one on its own.
/// </para>
/// <para>
/// The weights are a table, not a probability. They say how much one signal should move
/// the total, and the total is only a way of sorting the findings so the interesting ones
/// come first. The finding says what was seen and never what it concluded.
/// </para>
/// <para>
/// This scorer belongs to the AGGRESSIVE tier: it is only used when the user has asked for
/// maximum sensitivity. See <see cref="DetectorRegistry.IncludeAggressive"/>.
/// </para>
/// </remarks>
public sealed class CombinationSignalScorer
{
    /// <summary>The score at which a combination of weak signals is reported by default.</summary>
    public const int DefaultThreshold = 50;

    /// <summary>
    /// How many independent signals a file needs before the combination is reported. One
    /// or two weak signals are normal on a healthy machine, so more are required.
    /// </summary>
    public const int DefaultMinimumSignals = 3;

    /// <summary>
    /// The weight of every rule that is weak enough to take part in a combination.
    /// </summary>
    /// <remarks>
    /// Only signals that are a hint on their own are listed. A rule that already reports
    /// something strong is left out, so a combination never counts the same observation
    /// twice.
    /// </remarks>
    public static IReadOnlyDictionary<string, int> WeakSignalWeights { get; } =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["pe.unsigned-executable"] = 15,
            ["pe.timestamp-anomaly"] = 10,
            ["pe.invalid-digital-signature"] = 15,
            ["pe.high-entropy-section"] = 20,
            ["pe.suspicious-api-import"] = 20,
            ["pe.packer-section-name"] = 20,
            ["pe.protector-section-name"] = 20,
            ["pe.no-import-table"] = 15,
            ["pe.entry-point-outside-section"] = 20,
            ["pe.unusual-section-name"] = 15,
            ["sig.base64-decode-call"] = 15,
            ["sig.windows-script-host-reference"] = 15,
            ["script.hidden-bypass"] = 10,
            ["office.external-template"] = 15,
            ["office.macro-enabled-extension"] = 10,
            ["archive.password-protected"] = 10,
            ["archive.nested-archive"] = 10,
            ["shortcut.dangling-target"] = 10,
            ["pdf.auto-open-action"] = 10,
            ["entropy.high-entropy-file"] = 15
        };

    private readonly int _threshold;
    private readonly int _minimumSignals;

    /// <summary>
    /// Creates the scorer.
    /// </summary>
    /// <param name="threshold">The score at which a combination is reported.</param>
    /// <param name="minimumSignals">How many independent signals are needed.</param>
    public CombinationSignalScorer(int threshold = DefaultThreshold, int minimumSignals = DefaultMinimumSignals)
    {
        _threshold = threshold;
        _minimumSignals = Math.Max(1, minimumSignals);
    }

    /// <summary>The score at which a combination of weak signals is reported.</summary>
    public int Threshold => _threshold;

    /// <summary>How many independent signals a file needs before the combination is reported.</summary>
    public int MinimumSignals => _minimumSignals;

    /// <summary>
    /// Adds up the weak signals that point at the same file. A rule that fired twice is
    /// still one signal, and only rules that are weak on their own are counted.
    /// </summary>
    /// <param name="findings">The findings produced for one file.</param>
    public CombinationAssessment Evaluate(IEnumerable<Finding> findings)
    {
        var signals = new List<CombinationSignal>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var score = 0;

        foreach (var finding in findings)
        {
            if (finding is null) continue;
            if (!WeakSignalWeights.TryGetValue(finding.RuleId, out var weight)) continue;
            if (!seen.Add(finding.RuleId)) continue;

            score += weight;
            signals.Add(new CombinationSignal(finding.RuleId, finding.Title, weight, finding.Summary));
        }

        return new CombinationAssessment(score, _threshold, _minimumSignals, signals);
    }

    /// <summary>
    /// Turns an assessment into a finding whose detail carries the full breakdown.
    /// </summary>
    /// <param name="assessment">The assessment to describe.</param>
    public Finding BuildFinding(CombinationAssessment assessment) => new()
    {
        RuleId = "risk.combination-signals",
        Title = "Several weak signals point at the same file",
        Category = FindingCategory.Heuristic,
        Confidence = Confidence.Medium,
        Summary =
            "Several independent signals that are each weak on their own point at the same file.",
        Detail = assessment.BuildDetail(),
        Advice =
            "Read the list of signals above. Each one is a hint on its own and several of them can have an ordinary explanation. " +
            "Decide for yourself what the file is, and check where it came from before you run it."
    };
}
