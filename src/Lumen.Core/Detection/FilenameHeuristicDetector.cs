using System.Text.RegularExpressions;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// Filename-only heuristics. These are cheap, explainable signals that deserve a second look;
/// they are trivially bypassed and are not presented as reliable detection.
/// </summary>
public sealed class FilenameHeuristicDetector : IScanDetector
{
    private static readonly Regex DoubleExtension = new(
        @"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|bmp|txt|rtf|csv|zip|rar|7z|tar|gz|mp3|mp4|avi|mkv|mov|dwg|iso|img)\.(exe|scr|com|bat|cmd|js|jse|vbs|vbe|ps1|hta|msi|lnk|reg|pif|cpl)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public string Id => "name.heuristics";
    public string Name => "Filename heuristics";
    public string Description =>
        "Flags deceptive double extensions and bidirectional filename overrides. Filename checks only; they cannot tell whether a file is malicious.";
    public FindingCategory Category => FindingCategory.Heuristic;
    public Confidence Confidence => Confidence.Medium;

    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var name = probe.FileName;
        if (string.IsNullOrWhiteSpace(name)) return Array.Empty<Finding>();

        var findings = new List<Finding>(2);

        if (DoubleExtension.IsMatch(name))
        {
            findings.Add(new Finding
            {
                RuleId = "name.double-extension",
                Title = "Double extension hides an executable",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The file name uses a document-like extension followed by an executable extension.",
                Detail = "This naming pattern is commonly used to disguise executables. It is also used by legitimate installers, so context matters.",
                Advice = "Confirm what the file is with the sender. Do not open it unless you expected an executable."
            });
        }

        if (name.Any(IsStrongBidiControl))
        {
            findings.Add(new Finding
            {
                RuleId = "name.bidi-override",
                Title = "Filename contains bidirectional control characters",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The file name contains characters that can make it appear to have a different extension in some apps.",
                Detail = "Bidirectional formatting controls can reverse how part of a name is displayed. Legitimate files rarely use them.",
                Advice = "Inspect the real file name with a tool you trust before opening the file."
            });
        }

        return findings;
    }

    private static bool IsStrongBidiControl(char character) =>
        character is >= '\u202A' and <= '\u202E'
            or >= '\u2066' and <= '\u2069';
}
