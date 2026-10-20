using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Archives;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection;

/// <summary>
/// Looks for macros and other active content inside office documents, both the modern
/// zip based format and the older compound file format.
/// </summary>
/// <remarks>
/// A document that carries a macro is not malicious. Most macro malware arrives as an
/// attachment that asks the user to enable content, so the finding explains what was found
/// and leaves the decision to the person.
/// </remarks>
public sealed class OfficeMacroDetector : IScanDetector
{
    private static ReadOnlySpan<byte> OleMagic => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private static readonly string[] MacroEnabledExtensions =
    [
        ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".xlsb", ".pptm", ".potm", ".ppam", ".ppsm"
    ];

    private static readonly string[] AutoExecutionMarkers =
    [
        "AutoOpen", "Auto_Open", "Document_Open", "Workbook_Open", "AutoExec", "DocumentOpen"
    ];

    private static readonly string[] VbaMarkers =
    [
        "vbaProject.bin", "_VBA_PROJECT", "VBA/dir", "VBA/_VBA_PROJECT", "VBA/ThisDocument"
    ];

    private const string Advice =
        "Open the document and choose not to enable macros. If you did not expect a macro, ask the sender about it before you do anything else.";

    /// <inheritdoc />
    public string Id => "office.macros";

    /// <inheritdoc />
    public string Name => "Office macro analysis";

    /// <inheritdoc />
    public string Description =>
        "Looks for a Visual Basic project, for macros that run when a document opens, and for external template references, in both modern and legacy office documents.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Heuristic;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var content = probe.Content.Span;
        if (content.Length < 8) return Array.Empty<Finding>();

        var extension = Path.GetExtension(probe.FileName);
        var findings = new List<Finding>();

        if (MacroEnabledExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
        {
            findings.Add(new Finding
            {
                RuleId = "office.macro-enabled-extension",
                Title = "Document is in a macro enabled format",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The file name marks this document as one that can carry macros.",
                Detail =
                    $"The file name ends with \"{extension}\", a format in which Visual Basic code can be stored. " +
                    "Documents are only dangerous once macros are enabled, and plenty of legitimate templates use this format.",
                Advice = Advice
            });
        }

        if (content.Length >= OleMagic.Length && content[..OleMagic.Length].SequenceEqual(OleMagic))
        {
            AddLegacyContainerFindings(content, findings);
            return findings;
        }

        if (ZipInspector.IsZip(content)) AddOpenXmlFindings(content, findings);

        return findings;
    }

    private static void AddLegacyContainerFindings(ReadOnlySpan<byte> content, List<Finding> findings)
    {
        var hasVba = false;
        foreach (var marker in VbaMarkers)
        {
            if (!ByteSearch.ContainsText(content, marker)) continue;
            hasVba = true;
            break;
        }

        if (hasVba)
        {
            findings.Add(new Finding
            {
                RuleId = "office.vba-macro-project",
                Title = "Legacy document contains a Visual Basic project",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.High,
                Summary = "The office document carries embedded Visual Basic code.",
                Detail =
                    "The compound document contains the internal markers of a Visual Basic project. " +
                    "The code inside was not run and was not decompiled. Documents from templates and older office suites often carry macros.",
                Advice = Advice
            });
        }

        string? autoRun = null;
        foreach (var marker in AutoExecutionMarkers)
        {
            if (!ByteSearch.ContainsText(content, marker)) continue;
            autoRun = marker;
            break;
        }

        if (autoRun is not null)
        {
            findings.Add(new Finding
            {
                RuleId = "office.macro-auto-execution",
                Title = "Document contains a macro that runs on open",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.High,
                Summary = "The document holds a macro that is named to run when the document opens.",
                Detail =
                    $"The marker \"{DisplayText.Sanitize(autoRun)}\" was found in the document. " +
                    "A macro with that name runs as soon as the document is opened and macros are enabled. " +
                    "This is the shape of a macro that arrives by mail and asks the reader to enable content.",
                Advice = Advice
            });
        }
    }

    private static void AddOpenXmlFindings(ReadOnlySpan<byte> content, List<Finding> findings)
    {
        var entries = ZipInspector.ListEntries(content);
        if (entries.Count == 0) return;

        ArchiveEntryInfo? macroEntry = null;
        foreach (var entry in entries)
        {
            if (!entry.Name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) continue;
            macroEntry = entry;
            break;
        }

        if (macroEntry is not null)
        {
            findings.Add(new Finding
            {
                RuleId = "office.vba-macro-project",
                Title = "Office document contains a Visual Basic project",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.High,
                Summary = "The office document carries embedded Visual Basic code.",
                Detail =
                    $"The package contains the entry \"{DisplayText.Sanitize(macroEntry.Name)}\", which holds the Visual Basic project for the document. " +
                    "The code inside was not run and was not decompiled.",
                Advice = Advice
            });
        }

        if (macroEntry is not null && ZipInspector.TryReadEntry(content, macroEntry, 512 * 1024, out var macroBytes))
        {
            string? autoRun = null;
            foreach (var marker in AutoExecutionMarkers)
            {
                if (!ByteSearch.ContainsText(macroBytes, marker)) continue;
                autoRun = marker;
                break;
            }

            if (autoRun is not null)
            {
                findings.Add(new Finding
                {
                    RuleId = "office.macro-auto-execution",
                    Title = "Document contains a macro that runs on open",
                    Category = FindingCategory.Heuristic,
                    Confidence = Confidence.High,
                    Summary = "The document holds a macro that is named to run when the document opens.",
                    Detail =
                        $"The marker \"{DisplayText.Sanitize(autoRun)}\" was found inside the Visual Basic project. " +
                        "A macro with that name runs as soon as the document is opened and macros are enabled.",
                    Advice = Advice
                });
            }
        }

        ArchiveEntryInfo? relationships = null;
        foreach (var entry in entries)
        {
            if (!entry.Name.EndsWith("_rels/settings.xml.rels", StringComparison.OrdinalIgnoreCase) &&
                !entry.Name.EndsWith("_rels/workbook.xml.rels", StringComparison.OrdinalIgnoreCase)) continue;
            relationships = entry;
            break;
        }

        if (relationships is null) return;
        if (!ZipInspector.TryReadEntry(content, relationships, 256 * 1024, out var relationshipBytes)) return;

        var text = System.Text.Encoding.UTF8.GetString(relationshipBytes);
        if (!text.Contains("TargetMode=\"External\"", StringComparison.OrdinalIgnoreCase) &&
            !text.Contains("TargetMode='External'", StringComparison.OrdinalIgnoreCase)) return;

        findings.Add(new Finding
        {
            RuleId = "office.external-template",
            Title = "Document refers to an outside template",
            Category = FindingCategory.Heuristic,
            Confidence = Confidence.Low,
            Summary = "The document links to a template that is not stored inside it.",
            Detail =
                "The document's relationship list points at an external template or link. " +
                "External templates can pull in content from the internet when the document is opened, which is worth knowing about.",
            Advice = "Check which file the link points at before you enable any content in the document."
        });
    }
}
