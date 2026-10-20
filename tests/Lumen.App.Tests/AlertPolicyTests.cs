using Lumen.Core.Models;

namespace Lumen.App.Tests;

/// <summary>
/// The alert policy decides whether a finding deserves the loud, screen-taking
/// alert. It is pure: no window, no service, no file and no clock, so it can be
/// tested directly and its answer never depends on the state of the machine.
/// </summary>
public sealed class AlertPolicyTests
{
    [Theory]
    [InlineData(Confidence.Definitive)]
    [InlineData(Confidence.High)]
    public void AStrongFinding_isAnnounced(Confidence confidence)
    {
        var findings = new[] { Finding(confidence) };

        Assert.True(AlertPolicy.ShouldAlert(findings, out var reason));
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Theory]
    [InlineData(Confidence.Medium)]
    [InlineData(Confidence.Low)]
    public void AWeakFinding_isNotAnnounced(Confidence confidence)
    {
        var findings = new[] { Finding(confidence) };

        Assert.False(AlertPolicy.ShouldAlert(findings, out var reason));
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public void ATestSignature_isAnnouncedEvenWhenTheConfidenceIsLow()
    {
        var findings = new[] { Finding(Confidence.Low, FindingCategory.TestSignature) };

        Assert.True(AlertPolicy.ShouldAlert(findings, out var reason));
        Assert.Contains("test signature", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ATestSignature_nextToAWeakFinding_isAnnounced()
    {
        var findings = new[]
        {
            Finding(Confidence.Low, FindingCategory.Heuristic, "A pattern that means nothing"),
            Finding(Confidence.Low, FindingCategory.TestSignature, "EICAR test file")
        };

        Assert.True(AlertPolicy.ShouldAlert(findings, out _));
    }

    [Fact]
    public void SeveralFindings_areDecidedByTheStrongestOne()
    {
        var findings = new[]
        {
            Finding(Confidence.Low, FindingCategory.Heuristic, "A weak pattern"),
            Finding(Confidence.High, FindingCategory.Signature, "An exact match")
        };

        Assert.True(AlertPolicy.ShouldAlert(findings, out var reason));
        Assert.Contains("An exact match", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void SeveralWeakFindings_areNotAnnounced()
    {
        var findings = new[]
        {
            Finding(Confidence.Low, FindingCategory.Heuristic, "A weak pattern"),
            Finding(Confidence.Medium, FindingCategory.Behavior, "A behaviour worth a look")
        };

        Assert.False(AlertPolicy.ShouldAlert(findings, out _));
    }

    [Fact]
    public void SeveralWeakFindings_useTheStrongestOneInTheReason()
    {
        var findings = new[]
        {
            Finding(Confidence.Low, FindingCategory.Heuristic, "A weak pattern"),
            Finding(Confidence.Medium, FindingCategory.Behavior, "A behaviour worth a look")
        };

        AlertPolicy.ShouldAlert(findings, out var reason);

        Assert.Contains("Medium", reason, StringComparison.Ordinal);
        Assert.Contains("A behaviour worth a look", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void NoFindings_areNotAnnounced()
    {
        Assert.False(AlertPolicy.ShouldAlert([], out var reason));
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public void NoFindingsAtAll_areNotAnnounced()
    {
        Assert.False(AlertPolicy.ShouldAlert(null, out var reason));
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public void TheReason_explainsTheDecision()
    {
        AlertPolicy.ShouldAlert([Finding(Confidence.High, FindingCategory.Signature, "An exact match")], out var loud);
        AlertPolicy.ShouldAlert([Finding(Confidence.Low, FindingCategory.Heuristic, "A weak pattern")], out var quiet);

        Assert.Contains("High", loud, StringComparison.Ordinal);
        Assert.Contains("An exact match", loud, StringComparison.Ordinal);

        Assert.Contains("Low", quiet, StringComparison.Ordinal);
        Assert.Contains("A weak pattern", quiet, StringComparison.Ordinal);
    }

    [Fact]
    public void TheReason_neverRepeatsTheContentsOfTheFile()
    {
        var findings = new[] { Finding(Confidence.Low, FindingCategory.Heuristic, "Rule\u0007name") };

        AlertPolicy.ShouldAlert(findings, out var reason);

        Assert.DoesNotContain('\u0007', reason);
    }

    [Fact]
    public void TheStrongestFinding_isTheOneWithTheHighestConfidence()
    {
        var findings = new[]
        {
            Finding(Confidence.Low, FindingCategory.Heuristic, "Weak"),
            Finding(Confidence.Definitive, FindingCategory.Signature, "Strong"),
            Finding(Confidence.Medium, FindingCategory.Behavior, "Middle")
        };

        Assert.Equal("Strong", AlertPolicy.Strongest(findings)?.Title);
        Assert.Equal(Confidence.Definitive, AlertPolicy.StrongestConfidence(findings));
    }

    [Fact]
    public void TheStrongestFinding_isNullWhenThereIsNone()
    {
        Assert.Null(AlertPolicy.Strongest([]));
        Assert.Null(AlertPolicy.Strongest(null));
        Assert.Equal(Confidence.Low, AlertPolicy.StrongestConfidence([]));
    }

    [Theory]
    [InlineData(Confidence.Definitive, true)]
    [InlineData(Confidence.High, true)]
    [InlineData(Confidence.Medium, false)]
    [InlineData(Confidence.Low, false)]
    public void OnlyHighAndDefinitiveAreLoud(Confidence confidence, bool expected)
    {
        Assert.Equal(expected, AlertPolicy.IsLoud(confidence));
    }

    private static Finding Finding(
        Confidence confidence,
        FindingCategory category = FindingCategory.Heuristic,
        string title = "A rule that matched") => new()
    {
        RuleId = "test.rule",
        Title = title,
        Category = category,
        Confidence = confidence,
        Summary = "A summary.",
        Detail = "A detail.",
        Advice = "An advice."
    };
}
