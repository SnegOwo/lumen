using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.Core.Protection;

/// <summary>
/// How loudly Lumen should react to one real-time match.
/// </summary>
public enum RealtimeResponseLevel
{
    /// <summary>
    /// The match is listed in the results and nothing else happens: no window, no
    /// notification, no quarantine.
    /// </summary>
    ListOnly = 0,

    /// <summary>
    /// The match gets a quiet notification (a tray message). Lumen does not take over
    /// the screen and does not touch the file.
    /// </summary>
    Quiet = 1,

    /// <summary>
    /// The match gets the loud alert: Lumen interrupts the user. Only a strong match
    /// earns this, because an alert that fires for every hint is an alert the user
    /// learns to dismiss.
    /// </summary>
    Loud = 2
}

/// <summary>
/// What the caller should do with one real-time match.
///
/// <para>
/// The decision is about ALERTING and QUARANTINING. It never says to delete anything:
/// there is no member here that removes a file, and the monitor itself never writes,
/// moves or deletes a file. A quarantine is a move into the encrypted vault, it is
/// reversible, and it only happens when the user asked for it.
/// </para>
/// </summary>
public sealed record RealtimeResponseDecision
{
    /// <summary>How loudly Lumen should react to the match.</summary>
    public required RealtimeResponseLevel Level { get; init; }

    /// <summary>
    /// True when the loud, screen-taking alert should be raised. A quiet notification
    /// is not enough: this flag means "interrupt the user".
    /// </summary>
    public required bool ShouldAlert { get; init; }

    /// <summary>
    /// True when the match deserves a quiet notification: a tray message, an entry in
    /// the history, but no window.
    /// </summary>
    public required bool ShouldNotify { get; init; }

    /// <summary>
    /// True when the match may be moved into the quarantine vault without asking again.
    ///
    /// <para>
    /// This is only ever true when the user turned automatic quarantine on AND the
    /// match is strong enough to deserve it. It never means "delete": the vault is a
    /// move, the file can be restored, and the caller still has to check that the file
    /// could be hashed (an <see cref="RealtimeDetectionEvent.IsActionable"/> match is
    /// the only one that can be quarantined safely).
    /// </para>
    /// </summary>
    public required bool ShouldQuarantine { get; init; }

    /// <summary>
    /// A plain-language explanation of the decision, for the log and for the user. It
    /// never repeats the contents of the file.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// The strongest confidence among the findings of the match. <see cref="Confidence.Low"/>
    /// when there is no finding at all.
    /// </summary>
    public required Confidence StrongestConfidence { get; init; }
}

/// <summary>
/// Decides how the real-time monitor should react to a match.
///
/// <para>
/// The policy is PURE: it takes the findings of one match and returns a decision. It
/// opens no window, calls no service, touches no file and asks no question, so it can
/// be tested without a user interface and so its answer cannot change because the
/// machine happens to be busy.
/// </para>
///
/// <para>
/// The rules are deliberately conservative. A definitive or high-confidence finding, and
/// any test signature, earn the loud alert; a medium-confidence finding earns a quiet
/// notification; a low-confidence finding is listed and nothing else happens. The
/// strongest finding decides when several rules match, because a file that trips one
/// weak heuristic and one strong rule is still worth interrupting the user for.
/// </para>
///
/// <para>
/// Nothing here deletes anything. The only destructive-sounding answer the policy can
/// give is "quarantine", and even that requires the user to have asked for automatic
/// quarantine in the first place.
/// </para>
/// </summary>
public static class RealtimeResponsePolicy
{
    /// <summary>
    /// Decides how Lumen should react to one real-time match.
    /// </summary>
    /// <param name="findings">The findings of the match. May be null or empty.</param>
    /// <param name="autoQuarantineRequested">
    /// True when the user asked for real-time matches to be quarantined automatically.
    /// The policy never quarantines on its own: without this flag the decision is
    /// about alerting only.
    /// </param>
    /// <returns>The decision, with a human-readable reason.</returns>
    public static RealtimeResponseDecision Decide(
        IReadOnlyList<Finding>? findings,
        bool autoQuarantineRequested = false)
    {
        if (findings is null || findings.Count == 0)
        {
            return new RealtimeResponseDecision
            {
                Level = RealtimeResponseLevel.ListOnly,
                ShouldAlert = false,
                ShouldNotify = false,
                ShouldQuarantine = false,
                Reason = "The detection has no finding, so it is only listed.",
                StrongestConfidence = Confidence.Low
            };
        }

        var confidence = AlertPolicy.StrongestConfidence(findings);

        var test = AlertPolicy.FirstTestSignature(findings);
        if (test is not null)
        {
            // A test signature is a deliberate artifact (EICAR and its relatives). The
            // user who placed one on purpose must always be told that it was seen.
            var reason =
                "A test signature was matched (\"" + DisplayText.Sanitize(test.Title, 120) +
                "\"), and a test signature is always announced.";
            return Loud(reason, confidence, autoQuarantineRequested);
        }

        var strongest = AlertPolicy.Strongest(findings);
        var title = strongest is null
            ? "an unnamed rule"
            : DisplayText.Sanitize(strongest.Title, 120);

        if (confidence is Confidence.Definitive or Confidence.High)
        {
            var reason =
                "The strongest finding is " + confidence + " confidence (\"" + title +
                "\"), so it is announced.";
            return Loud(reason, confidence, autoQuarantineRequested);
        }

        if (confidence == Confidence.Medium)
        {
            // A medium finding is a pattern worth a second look, not a conclusion. It is
            // notified quietly and the file is left exactly where it is.
            var reason =
                "The strongest finding is only " + confidence + " confidence (\"" + title +
                "\"), so it is notified quietly and the file is left alone.";
            return new RealtimeResponseDecision
            {
                Level = RealtimeResponseLevel.Quiet,
                ShouldAlert = false,
                ShouldNotify = true,
                ShouldQuarantine = false,
                Reason = reason,
                StrongestConfidence = confidence
            };
        }

        var lowReason =
            "The strongest finding is only " + confidence + " confidence (\"" + title +
            "\"), so it is listed and nothing else happens.";
        return new RealtimeResponseDecision
        {
            Level = RealtimeResponseLevel.ListOnly,
            ShouldAlert = false,
            ShouldNotify = false,
            ShouldQuarantine = false,
            Reason = lowReason,
            StrongestConfidence = confidence
        };
    }

    /// <summary>
    /// Builds the "loud" decision. The quarantine is only asked for when the user asked
    /// for it; the policy itself never moves a file.
    /// </summary>
    private static RealtimeResponseDecision Loud(
        string reason,
        Confidence confidence,
        bool autoQuarantineRequested) =>
        new()
        {
            Level = RealtimeResponseLevel.Loud,
            ShouldAlert = true,
            ShouldNotify = true,
            ShouldQuarantine = autoQuarantineRequested,
            Reason = reason,
            StrongestConfidence = confidence
        };
}
