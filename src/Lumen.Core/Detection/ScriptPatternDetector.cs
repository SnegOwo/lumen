using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// Transparent, low-confidence heuristics for script text. These rules flag combinations of
/// tokens commonly seen in suspicious scripts; they are not signatures and they are not proof
/// of malware. Deliberately limited and documented in the UI and README.
/// </summary>
public sealed class ScriptPatternDetector : IScanDetector
{
    private const string Advice =
        "Review the script before opening it. This is a pattern heuristic, not proof of malware. Use Microsoft Defender for an authoritative scan.";

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".hta", ".txt", ".log", ".py", ".sh", ".reg", ".inf", ".url"
    };

    private static readonly ScriptRule[] Rules =
    [
        new ScriptRule(
            "script.download-execute",
            "Script combines download and execution behavior",
            [
                ["downloadstring", "downloadfile", "invoke-webrequest", "start-bitstransfer", "webclient"],
                ["invoke-expression", "iex(", "iex ", "frombase64string", "-encodedcommand", "-enc "]
            ],
            Confidence.Medium,
            "The script text contains both a remote-download primitive and an execution or decoding primitive."),
        new ScriptRule(
            "script.encoded-command",
            "PowerShell encoded command",
            [
                ["powershell", "pwsh"],
                ["-encodedcommand", "-enc "]
            ],
            Confidence.Medium,
            "The script text references PowerShell together with an encoded-command switch, which can hide intent."),
        new ScriptRule(
            "script.hidden-bypass",
            "Hidden window with execution-policy bypass",
            [
                ["-windowstyle hidden", "-w hidden"],
                ["-executionpolicy bypass", "-ep bypass"]
            ],
            Confidence.Low,
            "The script text combines a hidden window with an execution-policy bypass. Administrators do use this, so context matters."),
        new ScriptRule(
            "script.reflection-load",
            "In-memory assembly loading",
            [
                ["[reflection.assembly]::load", "assembly.load("],
                ["frombase64string", "downloadstring", "downloaddata"]
            ],
            Confidence.Medium,
            "The script text combines in-memory assembly loading with encoded or downloaded data."),
        new ScriptRule(
            "script.tamper-defender",
            "Defender tampering command",
            [
                ["set-mppreference", "add-mppreference"],
                ["disablerealtimemonitoring", "disableioavprotection", "disableantispyware", "exclusionpath"]
            ],
            Confidence.Medium,
            "The script text references PowerShell cmdlets that change Microsoft Defender settings. Legitimate administration is possible, so review carefully.")
    ];

    public string Id => "script.patterns";
    public string Name => "Script pattern heuristics";
    public string Description =>
        "Flags a small set of documented token combinations in script-like text files. Low confidence, high false-positive potential; it does not identify malware families.";
    public FindingCategory Category => FindingCategory.Heuristic;
    public Confidence Confidence => Confidence.Medium;

    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!TextExtensions.Contains(Path.GetExtension(probe.FileName))) return Array.Empty<Finding>();

        var text = probe.GetTextSample();
        if (string.IsNullOrWhiteSpace(text)) return Array.Empty<Finding>();

        var lower = text.ToLowerInvariant();
        var findings = new List<Finding>();

        foreach (var rule in Rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var matches = true;
            foreach (var group in rule.TokenGroups)
            {
                if (!group.Any(token => lower.Contains(token, StringComparison.Ordinal)))
                {
                    matches = false;
                    break;
                }
            }

            if (!matches) continue;

            findings.Add(new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Category = FindingCategory.Heuristic,
                Confidence = rule.Confidence,
                Summary = "A suspicious script pattern was found. This is not a malware identification.",
                Detail = rule.Detail,
                Advice = Advice
            });
        }

        return findings;
    }

    private sealed record ScriptRule(
        string Id,
        string Title,
        string[][] TokenGroups,
        Confidence Confidence,
        string Detail);
}
