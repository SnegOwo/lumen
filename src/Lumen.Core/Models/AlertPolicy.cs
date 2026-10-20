using Lumen.Core.Util;

namespace Lumen.Core.Models;

/// <summary>
/// Decides whether a detection deserves the loud, screen-taking alert.
///
/// <para>
/// The policy is small and pure on purpose: it takes the findings of one detection
/// and answers one question. It opens no window, calls no service and touches no
/// file, so it can be tested without a user interface and so its answer cannot
/// change because the machine happens to be busy.
/// </para>
///
/// <para>
/// The reasoning is about NOISE, never about safety. Whatever this policy decides,
/// the detection is still recorded in the results list and in the scan history, and
/// nothing is moved, deleted or quarantined because of it. The policy only decides
/// whether Lumen takes over the screen — and a tool that takes over the screen for
/// every heuristic hint is a tool the user learns to ignore, or to switch off.
/// </para>
/// </summary>
public static class AlertPolicy
{
    /// <summary>
    /// The confidences that are loud enough to interrupt the user.
    ///
    /// <para>
    /// A medium or low finding is a pattern that deserves a second look, not a
    /// conclusion. It is listed in the results and in the tray, and it waits there.
    /// </para>
    /// </summary>
    /// <param name="confidence">The confidence of the finding.</param>
    /// <returns>True when the finding alone justifies the loud alert.</returns>
    public static bool IsLoud(Confidence confidence) =>
        confidence is Confidence.High or Confidence.Definitive;

    /// <summary>
    /// Decides whether the findings of one detection deserve the loud alert.
    ///
    /// <para>
    /// The loud alert is raised for a high or definitive finding, and always for a
    /// test signature: EICAR and its relatives are deliberate test artifacts, and a
    /// user who placed one on purpose must always be told that it was seen.
    /// </para>
    ///
    /// <para>
    /// When a detection matches several rules, the strongest one decides. A file
    /// that matches one weak heuristic and one strong rule is still worth
    /// interrupting the user for.
    /// </para>
    /// </summary>
    /// <param name="findings">The findings of one detection. May be empty.</param>
    /// <param name="reason">
    /// A short explanation of the decision, in English, for the log and for the
    /// caller. It never repeats the contents of the file.
    /// </param>
    /// <returns>True when the alert should be shown.</returns>
    public static bool ShouldAlert(IReadOnlyList<Finding>? findings, out string reason)
    {
        if (findings is null || findings.Count == 0)
        {
            reason = "The detection has no finding, so there is nothing to announce.";
            return false;
        }

        var test = FirstTestSignature(findings);
        if (test is not null)
        {
            reason =
                "A test signature was matched (\"" + DisplayText.Sanitize(test.Title, 120) +
                "\"), and a test signature is always announced.";
            return true;
        }

        var strongest = Strongest(findings);
        if (strongest is null)
        {
            reason = "The detection has no finding, so there is nothing to announce.";
            return false;
        }

        var title = DisplayText.Sanitize(strongest.Title, 120);

        if (IsLoud(strongest.Confidence))
        {
            reason =
                "The strongest finding is " + strongest.Confidence + " confidence (\"" + title +
                "\"), so it is announced.";
            return true;
        }

        reason =
            "The strongest finding is only " + strongest.Confidence + " confidence (\"" + title +
            "\"), so it is listed instead of announced.";
        return false;
    }

    /// <summary>
    /// The finding with the strongest confidence, or null when there is none.
    ///
    /// <para>
    /// The confidence enum is ordered from the strongest value to the weakest, so
    /// the enum value itself cannot be compared: the order here is explicit.
    /// </para>
    /// </summary>
    /// <param name="findings">The findings of one detection. May be null or empty.</param>
    /// <returns>The strongest finding, or null.</returns>
    public static Finding? Strongest(IReadOnlyList<Finding>? findings)
    {
        if (findings is null) return null;

        Finding? strongest = null;
        foreach (var finding in findings)
        {
            if (finding is null) continue;
            if (strongest is null || Rank(finding.Confidence) > Rank(strongest.Confidence))
            {
                strongest = finding;
            }
        }

        return strongest;
    }

    /// <summary>
    /// The strongest confidence among the findings.
    /// </summary>
    /// <param name="findings">The findings of one detection. May be null or empty.</param>
    /// <returns>The strongest confidence, or <see cref="Confidence.Low"/> when there is no finding.</returns>
    public static Confidence StrongestConfidence(IReadOnlyList<Finding>? findings) =>
        Strongest(findings)?.Confidence ?? Confidence.Low;

    /// <summary>
    /// The first test signature among the findings, or null when there is none.
    /// </summary>
    /// <param name="findings">The findings of one detection. May be null or empty.</param>
    /// <returns>The test signature finding, or null.</returns>
    public static Finding? FirstTestSignature(IReadOnlyList<Finding>? findings)
    {
        if (findings is null) return null;

        foreach (var finding in findings)
        {
            if (finding is not null && finding.Category == FindingCategory.TestSignature) return finding;
        }

        return null;
    }

    /// <summary>
    /// How strong a confidence is, as a number. Higher is stronger.
    /// </summary>
    private static int Rank(Confidence confidence) => confidence switch
    {
        Confidence.Definitive => 3,
        Confidence.High => 2,
        Confidence.Medium => 1,
        _ => 0
    };
}
