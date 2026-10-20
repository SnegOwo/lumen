using System.Text;
using Lumen.Core.Models;

namespace Lumen.Core.Detection;

/// <summary>
/// One signal that contributed to a risk score.
/// </summary>
/// <param name="RuleId">The rule that produced the signal.</param>
/// <param name="Title">The title of the rule.</param>
/// <param name="Weight">How much the signal moved the score.</param>
/// <param name="Explanation">The plain-language explanation that came with the finding.</param>
public sealed record RiskSignal(string RuleId, string Title, int Weight, string Explanation);

/// <summary>
/// The result of combining weak signals into one number, together with the full breakdown
/// that produced it.
/// </summary>
/// <param name="Score">The sum of the weights of every contributing signal.</param>
/// <param name="Threshold">The score at which the file is considered worth a warning.</param>
/// <param name="Signals">Every signal that contributed, in the order it was found.</param>
public sealed record RiskAssessment(int Score, int Threshold, IReadOnlyList<RiskSignal> Signals)
{
    /// <summary>True when the score reaches the threshold.</summary>
    public bool ExceedsThreshold => Score >= Threshold;

    /// <summary>
    /// Builds the plain-language breakdown. Every contributor is named with its weight, so
    /// the score is never shown without its reasons.
    /// </summary>
    public string BuildDetail()
    {
        var builder = new StringBuilder();
        builder.Append("Risk score ").Append(Score).Append('.');

        if (Signals.Count == 0)
        {
            builder.Append(" No rule contributed to this score.");
            return builder.ToString();
        }

        builder.Append(' ').Append(Signals.Count).Append(" signal(s) contributed:");
        foreach (var signal in Signals)
        {
            builder.AppendLine();
            builder.Append("  - ").Append(signal.RuleId).Append(" (+").Append(signal.Weight).Append("): ").Append(signal.Title);
        }

        return builder.ToString().TrimEnd();
    }
}

/// <summary>
/// Combines several weak signals into a single risk score without hiding what went into it.
/// </summary>
/// <remarks>
/// <para>
/// A single weak signal is rarely enough to act on, but several of them together are worth
/// a look. The scorer adds the weight of every rule that fired and returns the list of
/// contributors, so the user interface can always answer "why was this flagged".
/// </para>
/// <para>
/// The score is not a verdict and it is not a probability. It is a way of sorting the
/// findings so that the interesting ones come first.
/// </para>
/// </remarks>
public sealed class RiskScorer
{
    /// <summary>The score at which a file is considered worth a warning by default.</summary>
    public const int DefaultThreshold = 50;

    private readonly IReadOnlyDictionary<string, int> _weights;

    /// <summary>
    /// Creates a scorer. When no weight table is supplied the built-in
    /// <see cref="RiskWeights"/> table is used.
    /// </summary>
    public RiskScorer(IReadOnlyDictionary<string, int>? weights = null, int threshold = DefaultThreshold)
    {
        _weights = weights ?? RiskWeights.Weights;
        Threshold = threshold;
    }

    /// <summary>The score at which the file is considered worth a warning.</summary>
    public int Threshold { get; }

    /// <summary>
    /// Returns the weight of a rule.
    /// </summary>
    public int WeightFor(string? ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId)) return RiskWeights.DefaultWeight;
        return _weights.TryGetValue(ruleId, out var weight) ? weight : RiskWeights.DefaultWeight;
    }

    /// <summary>
    /// Combines findings into a score and a breakdown. Findings that share a rule
    /// identifier are counted once, because a rule that fired twice is still one signal.
    /// </summary>
    public RiskAssessment Evaluate(IEnumerable<Finding> findings)
    {
        var signals = new List<RiskSignal>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var score = 0;

        foreach (var finding in findings)
        {
            if (finding is null) continue;
            if (!seen.Add(finding.RuleId)) continue;

            var weight = WeightFor(finding.RuleId);
            score += weight;
            signals.Add(new RiskSignal(finding.RuleId, finding.Title, weight, finding.Summary));
        }

        return new RiskAssessment(score, Threshold, signals);
    }

    /// <summary>
    /// Turns an assessment into a finding whose detail carries the full breakdown.
    /// </summary>
    public Finding BuildFinding(RiskAssessment assessment)
    {
        var summary = assessment.Signals.Count == 0
            ? "No rule contributed to the risk score for this file."
            : assessment.ExceedsThreshold
                ? "Several weak signals added up to a score worth a look."
                : "A few weak signals added up to a low score.";

        return new Finding
        {
            RuleId = "risk.aggregate",
            Title = "Combined risk score",
            Category = FindingCategory.Heuristic,
            Confidence = assessment.ExceedsThreshold ? Confidence.Medium : Confidence.Low,
            Summary = summary,
            Detail = assessment.BuildDetail(),
            Advice =
                "The score only adds up the signals that were found. Read the list above and decide for yourself what the file is."
        };
    }
}
