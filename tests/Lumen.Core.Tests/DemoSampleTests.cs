using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

/// <summary>
/// The demonstration file is only useful if Lumen actually flags it. These tests keep
/// that promise honest, so a future change to the heuristics cannot silently turn the
/// demonstration into a file that reports nothing.
/// </summary>
public sealed class DemoSampleTests
{
    [Fact]
    public void Demo_sample_trips_at_least_one_rule()
    {
        var registry = DetectorRegistry.CreateDefault();
        var probe = FileProbe.FromText(DemoSample.FileName, DemoSample.ScriptText);

        var findings = registry.Inspect(probe, CancellationToken.None);

        Assert.NotEmpty(findings);
    }

    [Fact]
    public void Demo_sample_is_never_reported_as_definitive_malware()
    {
        var registry = DetectorRegistry.CreateDefault();
        var probe = FileProbe.FromText(DemoSample.FileName, DemoSample.ScriptText);

        var findings = registry.Inspect(probe, CancellationToken.None);

        // The sample is harmless text. Lumen may flag it, but it must never claim
        // certainty, because Lumen cannot know what the text would do if it were run.
        Assert.All(findings, finding =>
            Assert.NotEqual(Confidence.Definitive, finding.Confidence));
    }

    [Fact]
    public void Demo_sample_is_described_as_a_heuristic_and_not_as_malware()
    {
        var registry = DetectorRegistry.CreateDefault();
        var probe = FileProbe.FromText(DemoSample.FileName, DemoSample.ScriptText);

        var findings = registry.Inspect(probe, CancellationToken.None);

        Assert.All(findings, finding =>
        {
            Assert.NotEqual(FindingCategory.TestSignature, finding.Category);
            Assert.False(string.IsNullOrWhiteSpace(finding.Advice));
        });
    }

    [Fact]
    public void Demo_sample_text_contains_nothing_that_could_execute()
    {
        // The demonstration file must not be able to do anything even if a user runs it.
        var text = DemoSample.ScriptText;

        Assert.DoesNotContain("Start-Process", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Invoke-Item", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Set-ExecutionPolicy", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("iex (", text, StringComparison.OrdinalIgnoreCase);
    }
}
