using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Archives;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection.Aggressive;

/// <summary>
/// Reports an office document that carries a DDE field, and a document package that
/// points at a template which is not stored inside it.
/// </summary>
/// <remarks>
/// <para>
/// A DDE field is a field that asks another program to run a command. Word and Excel can
/// be told to do this by the document itself, so opening a document that carries one can
/// start a program without the reader doing anything. Legitimate documents use links that
/// work the same way, which is why the finding describes the field rather than judging it.
/// </para>
/// <para>
/// The detector reads the bytes the scanner already loaded. For the modern package
/// format it unpacks the entries it needs from those bytes; for the older compound
/// format it looks at the text inside. It performs no file system access.
/// </para>
/// <para>
/// This rule belongs to the AGGRESSIVE tier: it only runs when the user has asked for
/// maximum sensitivity.
/// </para>
/// </remarks>
public sealed class OfficeDdeDetector : IScanDetector, IAggressiveDetector
{
    /// <summary>The identifier of the rule that reports a DDE field.</summary>
    public const string DdeRuleId = "office.dde-field";

    /// <summary>The identifier of the rule that reports an outside template.</summary>
    public const string TemplateRuleId = "office.template-relationship";

    private static readonly string[] DocumentExtensions =
    [
        ".doc", ".docx", ".docm", ".dot", ".dotm", ".dotx", ".rtf", ".xls", ".xlsx",
        ".xlsm", ".xlt", ".xltm", ".xltx", ".ppt", ".pptx", ".pptm", ".xml"
    ];

    /// <summary>
    /// The relationship files that the standard rules already look at. They are skipped
    /// here so that one observation is not reported twice under two identifiers.
    /// </summary>
    private static readonly string[] StandardRelationshipFiles =
    [
        "_rels/settings.xml.rels", "_rels/workbook.xml.rels"
    ];

    private const string Advice =
        "Open the document with the content and the links disabled, and ask the sender whether the document was expected to carry a field or a link. " +
        "Do not enable any content, and do not allow the document to start another program.";

    /// <inheritdoc />
    public string Id => "office.dde";

    /// <inheritdoc />
    public string Name => "Office field and template analysis";

    /// <inheritdoc />
    public string Description =>
        "Reports an office document that carries a DDE field, and a document package that points at a template outside itself.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var extension = Path.GetExtension(probe.FileName);
        if (!DocumentExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)) return Array.Empty<Finding>();

        var content = probe.Content.Span;
        if (content.Length < 8) return Array.Empty<Finding>();

        var findings = new List<Finding>();

        if (ZipInspector.IsZip(content))
        {
            AddPackageFindings(content, findings, cancellationToken);
        }
        else
        {
            AddLegacyFindings(content, findings);
        }

        return findings;
    }

    /// <summary>
    /// Looks inside the modern package format, where the document text lives in its own
    /// entries.
    /// </summary>
    private static void AddPackageFindings(ReadOnlySpan<byte> content, List<Finding> findings, CancellationToken cancellationToken)
    {
        var entries = ZipInspector.ListEntries(content);
        if (entries.Count == 0) return;

        var ddeEntries = new List<string>();

        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!IsDocumentPart(entry.Name)) continue;
            if (!ZipInspector.TryReadEntry(content, entry, 512 * 1024, out var bytes)) continue;

            var text = System.Text.Encoding.UTF8.GetString(bytes);
            if (!CarriesDdeField(text, out var description)) continue;

            ddeEntries.Add($"{entry.Name} ({description})");
        }

        if (ddeEntries.Count > 0)
        {
            findings.Add(new Finding
            {
                RuleId = DdeRuleId,
                Title = "Document carries a DDE field",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.Medium,
                Summary = "The document holds a field that asks another program to run a command.",
                Detail =
                    "The package part(s) " + string.Join("; ", ddeEntries) + " hold the field instruction. " +
                    "A field of that kind tells the office program to start another program, and the command can come from the document itself. " +
                    "Documents that link to other documents in this way exist as well, so the field is worth reading before the document is opened with its content enabled.",
                Advice = Advice
            });
        }

        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!entry.Name.EndsWith(".rels", StringComparison.OrdinalIgnoreCase)) continue;
            if (StandardRelationshipFiles.Any(known => entry.Name.EndsWith(known, StringComparison.OrdinalIgnoreCase))) continue;
            if (!ZipInspector.TryReadEntry(content, entry, 256 * 1024, out var bytes)) continue;

            var text = System.Text.Encoding.UTF8.GetString(bytes);
            if (!CarriesTemplateRelationship(text, out var target)) continue;

            findings.Add(new Finding
            {
                RuleId = TemplateRuleId,
                Title = "Document points at a template outside itself",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Low,
                Summary = "The package links to a template that is not stored inside it.",
                Detail =
                    $"The relationship file \"{DisplayText.Sanitize(entry.Name)}\" points at \"{DisplayText.Sanitize(target)}\", which is outside the document. " +
                    "Opening the document can pull in that content, and the content of a template can change what the document does.",
                Advice = "Check which file the link points at before you open the document with its content enabled."
            });
        }
    }

    /// <summary>
    /// Looks inside the older compound format, where the text of the document is stored as
    /// plain text inside the file.
    /// </summary>
    private static void AddLegacyFindings(ReadOnlySpan<byte> content, List<Finding> findings)
    {
        // Only the form that names the command it runs is looked for. A shorter form would
        // also turn up in ordinary sentences inside a document.
        if (!ByteSearch.ContainsText(content, "DDEAUTO")) return;

        findings.Add(new Finding
        {
            RuleId = DdeRuleId,
            Title = "Document carries a DDE field",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.Medium,
            Summary = "The document holds a field that asks another program to run a command.",
            Detail =
                "The text of the document contains a field instruction of the kind Windows calls DDE. " +
                "A field of that kind tells the office program to start another program, and the command can come from the document itself.",
            Advice = Advice
        });
    }

    /// <summary>
    /// True when the part of the package holds a field that asks another program to run a
    /// command.
    /// </summary>
    private static bool CarriesDdeField(string text, out string description)
    {
        description = string.Empty;

        if (text.Contains("DDEAUTO", StringComparison.OrdinalIgnoreCase))
        {
            description = "the field instruction DDEAUTO";
            return true;
        }

        var lower = text.ToLowerInvariant();
        if (!lower.Contains("instrtext", StringComparison.Ordinal) && !lower.Contains("fldsimple", StringComparison.Ordinal))
            return false;

        var index = lower.IndexOf("dde", StringComparison.Ordinal);
        if (index < 0) return false;

        description = "a field instruction that starts another program";
        return true;
    }

    /// <summary>
    /// True when the relationship file points at a template that is not inside the package.
    /// </summary>
    private static bool CarriesTemplateRelationship(string text, out string target)
    {
        target = string.Empty;

        if (!text.Contains("TargetMode=\"External\"", StringComparison.OrdinalIgnoreCase) &&
            !text.Contains("TargetMode='External'", StringComparison.OrdinalIgnoreCase))
            return false;

        var typeIndex = text.IndexOf("Type=", StringComparison.OrdinalIgnoreCase);
        var targetIndex = text.IndexOf("Target=", StringComparison.OrdinalIgnoreCase);
        if (targetIndex < 0) return false;

        target = ReadAttribute(text, targetIndex + "Target=".Length);
        if (target.Length == 0) return false;

        var type = typeIndex >= 0 ? ReadAttribute(text, typeIndex + "Type=".Length) : string.Empty;

        var looksLikeTemplate =
            type.Contains("attachedTemplate", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("/template", StringComparison.OrdinalIgnoreCase) ||
            target.EndsWith(".dot", StringComparison.OrdinalIgnoreCase) ||
            target.EndsWith(".dotm", StringComparison.OrdinalIgnoreCase) ||
            target.EndsWith(".dotx", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("\\\\", StringComparison.Ordinal);

        return looksLikeTemplate;
    }

    /// <summary>
    /// Reads one attribute value out of a relationship file.
    /// </summary>
    private static string ReadAttribute(string text, int start)
    {
        if (start >= text.Length) return string.Empty;

        var quote = text[start];
        if (quote is not ('"' or '\'')) return string.Empty;

        var end = text.IndexOf(quote, start + 1);
        return end < 0 ? string.Empty : text[(start + 1)..end];
    }

    /// <summary>
    /// True when the package entry holds document text rather than styles or images.
    /// </summary>
    private static bool IsDocumentPart(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower.EndsWith(".xml", StringComparison.Ordinal) &&
               (lower.Contains("document", StringComparison.Ordinal) ||
                lower.Contains("worksheet", StringComparison.Ordinal) ||
                lower.Contains("slide", StringComparison.Ordinal) ||
                lower.Contains("header", StringComparison.Ordinal) ||
                lower.Contains("footer", StringComparison.Ordinal) ||
                lower.Contains("notes", StringComparison.Ordinal));
    }
}
