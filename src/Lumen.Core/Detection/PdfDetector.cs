using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// Inspects PDF files for the active content that a PDF is able to carry: embedded
/// scripts, actions that start other programs, and open actions that run by themselves.
/// </summary>
/// <remarks>
/// A PDF with JavaScript is unusual but not automatically harmful, and plenty of legitimate
/// tools produce PDF forms with scripts. The findings say what was found so a reader can
/// judge it.
/// </remarks>
public sealed class PdfDetector : IScanDetector
{
    private static readonly byte[] PdfMarker = "%PDF-"u8.ToArray();

    private const string Advice =
        "Open the document in a reader with scripting turned off, and check where the file came from before you trust it.";

    /// <inheritdoc />
    public string Id => "pdf.analysis";

    /// <inheritdoc />
    public string Name => "PDF analysis";

    /// <inheritdoc />
    public string Description =>
        "Looks for embedded JavaScript, actions that start other programs, actions that run when the document opens, and files embedded in the document.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Heuristic;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var content = probe.Content.Span;
        if (content.Length < 16) return Array.Empty<Finding>();

        if (!ByteSearch.ContainsAscii(content, "%PDF-", caseSensitive: true)) return Array.Empty<Finding>();

        var findings = new List<Finding>();

        if (ByteSearch.ContainsAscii(content, "/JavaScript", caseSensitive: false) ||
            ByteSearch.ContainsAscii(content, "/JS ", caseSensitive: false))
        {
            findings.Add(new Finding
            {
                RuleId = "pdf.embedded-javascript",
                Title = "PDF carries embedded JavaScript",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The document contains a JavaScript action.",
                Detail =
                    "The PDF carries a JavaScript entry. Scripts in a PDF run inside the reader, and some readers hand the script more power than the document needs. " +
                    "Forms with scripts exist legitimately, so this is worth a look rather than a verdict.",
                Advice = Advice
            });
        }

        if (ByteSearch.ContainsAscii(content, "/Launch", caseSensitive: false))
        {
            findings.Add(new Finding
            {
                RuleId = "pdf.launch-action",
                Title = "PDF can start another program",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The document contains an action that can launch a program.",
                Detail =
                    "The PDF contains a launch action, which asks the reader to start another program. " +
                    "This is rarely needed for a document that only holds information.",
                Advice = Advice
            });
        }

        if (ByteSearch.ContainsAscii(content, "/OpenAction", caseSensitive: false))
        {
            findings.Add(new Finding
            {
                RuleId = "pdf.auto-open-action",
                Title = "PDF runs an action when it is opened",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Low,
                Summary = "The document asks the reader to perform an action as soon as it opens.",
                Detail =
                    "The PDF carries an open action. On some readers this runs without any further click. " +
                    "Many ordinary PDFs use an open action to jump to the first page, so this is a weak signal.",
                Advice = Advice
            });
        }

        if (ByteSearch.ContainsAscii(content, "/URI", caseSensitive: false) &&
            ByteSearch.ContainsAscii(content, "javascript:", caseSensitive: false))
        {
            findings.Add(new Finding
            {
                RuleId = "pdf.script-uri-action",
                Title = "PDF links to a script scheme",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The document contains a link that points at a script rather than at a page.",
                Detail =
                    "The PDF carries a URI action whose target uses a script scheme. " +
                    "Ordinary links point at web pages, so a link that points at a script is worth a look.",
                Advice = Advice
            });
        }

        if (ContainsEmbeddedExecutable(content))        {
            findings.Add(new Finding
            {
                RuleId = "pdf.embedded-executable",
                Title = "PDF contains an embedded executable",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.High,
                Summary = "The document carries a file that can run code inside it.",
                Detail =
                    "The PDF holds an embedded file stream whose content starts with a Windows executable header. " +
                    "A document that ships a program is worth a close look, because the program only has to be saved and run.",
                Advice = Advice
            });
        }

        return findings;
    }

    /// <summary>
    /// Looks for an executable header that sits directly inside a PDF stream.
    /// </summary>
    private static bool ContainsEmbeddedExecutable(ReadOnlySpan<byte> content)
    {
        var marker = "stream"u8;
        var index = 0;
        while (index < content.Length)
        {
            var found = ByteSearch.IndexOfAscii(content[index..], marker, caseSensitive: false);
            if (found < 0) return false;

            var position = index + found + marker.Length;
            var start = position;
            while (start < content.Length && content[start] is 0x0D or 0x0A or 0x20 or 0x09) start++;

            if (start + 2 <= content.Length && content[start] == 0x4D && content[start + 1] == 0x5A) return true;

            index = index + found + marker.Length;
        }

        return false;
    }
}
