using Lumen.Core.Models;

namespace Lumen.Core.Detection;

/// <summary>
/// A user-facing description of every rule that Lumen can report. The Settings page renders
/// this list so detection behavior is not a black box.
/// </summary>
public static class DetectionCatalog
{
    public static IReadOnlyList<DetectionRuleSummary> Rules { get; } =
    [
        new(
            "test.eicar",
            "EICAR test signature",
            "Finds the harmless, industry-standard EICAR test file. It verifies scanner plumbing only; it is not a malware signature.",
            FindingCategory.TestSignature,
            Confidence.Definitive),
        new(
            "script.download-execute",
            "Script download + execution",
            "A script contains a remote-download primitive and an execution or decoding primitive.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "script.encoded-command",
            "PowerShell encoded command",
            "Text references PowerShell together with an encoded-command switch.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "script.hidden-bypass",
            "Hidden window + policy bypass",
            "Text combines a hidden window with an execution-policy bypass. Administrators use this too.",
            FindingCategory.Heuristic,
            Confidence.Low),
        new(
            "script.reflection-load",
            "In-memory assembly loading",
            "Text combines in-memory assembly loading with encoded or downloaded data.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "script.tamper-defender",
            "Defender tampering command",
            "A script references Microsoft Defender settings changes. Some administrative scripts do this legitimately.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "name.double-extension",
            "Deceptive double extension",
            "A document-like extension is followed by an executable extension, for example report.pdf.exe.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "name.bidi-override",
            "Bidirectional filename override",
            "The file name contains bidirectional control characters that can disguise its real extension.",
            FindingCategory.Heuristic,
            Confidence.Medium)
    ];
}
