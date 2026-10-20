using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// Looks for the habits of scripts that are built to download, hide, persist, tamper with
/// security software, steal credentials or open a remote shell.
/// </summary>
/// <remarks>
/// <para>
/// Every rule here is a pattern heuristic. Administrators and installers use many of the
/// same building blocks, so the findings say what was observed and leave the judgement to
/// the person reading them.
/// </para>
/// <para>
/// The detector reads only the text the scanner already decoded. It performs no file system
/// access and never copies file content into a finding.
/// </para>
/// </remarks>
public sealed class ScriptThreatDetector : IScanDetector
{
    private const string Advice =
        "Read the script before you run it, and check where it came from. These are pattern heuristics, not proof of malware.";

    private static readonly string[] ScriptExtensions =
    [
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".hta", ".txt", ".log", ".py", ".sh", ".reg", ".inf", ".url", ".ini"
    ];

    private static readonly TokenRule[] Rules =
    [
        new(
            "script.lolbin-download",
            "Living-off-the-land binary used to download",
            [
                ["certutil", "bitsadmin", "mshta", "curl", "wget", "certutil.exe", "bitsadmin.exe"],
                ["http://", "https://", "-urlcache", "/transfer", "-split", "-decode", "--output", "-out"]
            ],
            Confidence.Medium,
            "The script uses a built-in Windows or command-line tool together with a download target. These tools are meant for ordinary administration, so the context decides what this means.",
            FindingCategory.Heuristic,
            ScriptExtensions),
        new(
            "script.lolbin-script-execution",
            "Living-off-the-land binary used to run a script",
            [
                ["rundll32", "regsvr32", "mshta", "wscript", "cscript", "rundll32.exe", "regsvr32.exe"],
                ["javascript:", "vbscript:", ".js", ".vbs", ".hta", ".dll", "http://", "https://"]
            ],
            Confidence.Medium,
            "The script starts a built-in Windows host and points it at a script or a downloaded file. Software installers do this too, so the context decides what this means.",
            FindingCategory.Heuristic,
            ScriptExtensions),
        new(
            "script.amsi-bypass",
            "Antimalware scan interface tampering",
            [["amsiutils", "amsiinitfailed", "amsiscanbuffer", "amsiinitialize"]],
            Confidence.Medium,
            "The script mentions an internal name of the antimalware scanning interface. Ordinary scripts do not need to touch it.",
            FindingCategory.Behavior,
            ScriptExtensions),
        new(
            "script.stealth-powershell",
            "PowerShell started with concealment switches",
            [
                ["powershell", "pwsh", "powershell.exe", "pwsh.exe"],
                ["-w hidden", "-windowstyle hidden", "-noninteractive", "-noprofile", "-ep bypass", "-executionpolicy bypass", "-encodedcommand", "-enc "]
            ],
            Confidence.Medium,
            "The script starts PowerShell with a switch that hides the window or relaxes the execution policy. Scheduled tasks are often built this way.",
            FindingCategory.Behavior,
            ScriptExtensions),
        new(
            "script.persistence",
            "Script sets up persistence",
            [
                ["new-service", "register-scheduledtask", "schtasks", "reg add", "reg.exe add", "startup"],
                ["-createnew", "/create", "\\currentversion\\run", "\\currentversion\\runonce", "start menu\\programs\\startup", "-displayname", "new-service", "schtasks"]
            ],
            Confidence.Medium,
            "The script creates a service, a scheduled task or a run key so that it starts again after a restart. Many installers do this as well.",
            FindingCategory.Behavior,
            ScriptExtensions),
        new(
            "script.av-tampering",
            "Script interferes with security software",
            [
                ["sc.exe", "sc ", "net stop", "net.exe stop", "taskkill", "wmic", "uninstall"],
                ["msmpeng", "windefend", "securityhealthservice", "antivirus", "defender", "sense"]
            ],
            Confidence.Medium,
            "The script tries to stop or remove a security product. A person doing this by hand is unusual.",
            FindingCategory.Behavior,
            ScriptExtensions),
        new(
            "script.credential-theft",
            "Script reaches for credentials",
            [["invoke-mimikatz", "sekurlsa", "lsadump", "comsvcs.dll", "minidump", "procdump", "ntds.dit", "credential dump", "lsass"]],
            Confidence.High,
            "The script mentions a known credential dumping tool or the credential store of Windows. Red team and research tooling uses the same names.",
            FindingCategory.Behavior,
            ScriptExtensions),
        new(
            "script.reverse-shell",
            "Script opens a remote shell",
            [
                ["new-object net.sockets.tcpclient", "system.net.sockets.tcpclient", "tcpclient(", "socket.socket", "nc.exe -e", "ncat -e", "bash -i >& /dev/tcp/", "sh -i >& /dev/tcp/"],
                ["connect", "stream", "-nop", "cmd.exe", "powershell"]
            ],
            Confidence.High,
            "The script creates a network connection that carries a command stream back to another machine, which is the shape of a reverse shell.",
            FindingCategory.Behavior,
            ScriptExtensions)
    ];

    /// <inheritdoc />
    public string Id => "script.threats";

    /// <inheritdoc />
    public string Name => "Script threat heuristics";

    /// <inheritdoc />
    public string Description =>
        "Flags documented token combinations that describe downloading, hiding, persisting, tampering with security software, credential theft and remote shells. These are heuristics with a real false-positive rate.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var extension = Path.GetExtension(probe.FileName);
        if (!ScriptExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)) return Array.Empty<Finding>();

        var text = probe.GetTextSample();
        if (string.IsNullOrWhiteSpace(text)) return Array.Empty<Finding>();

        var lower = text.ToLowerInvariant();
        var findings = new List<Finding>();

        foreach (var rule in Rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!rule.Matches(lower)) continue;

            findings.Add(new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Category = rule.Category,
                Confidence = rule.Confidence,
                Summary = "A documented script pattern was found. This is not a malware identification.",
                Detail = rule.Detail,
                Advice = Advice
            });
        }

        AddObfuscationFinding(lower, findings);

        return findings;
    }

    private static void AddObfuscationFinding(string lower, List<Finding> findings)
    {
        var signals = ScriptObfuscation.Analyze(lower);
        var reasons = new List<string>();

        if (signals.Base64DecodeCalls >= 2)
            reasons.Add($"{signals.Base64DecodeCalls} base64 decoding calls");
        if (signals.LongestBase64Literal >= ScriptObfuscation.LongBase64LiteralLength)
            reasons.Add($"a {signals.LongestBase64Literal} character base64-like literal");
        if (signals.CharArrayCasts >= 3)
            reasons.Add($"{signals.CharArrayCasts} character-array or join expressions");
        if (signals.ConcatenatedFragments >= 5)
            reasons.Add($"{signals.ConcatenatedFragments} concatenated string fragments");

        if (reasons.Count == 0) return;

        findings.Add(new Finding
        {
            RuleId = "script.powershell-obfuscation",
            Title = "Script hides its content behind encoding",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.Medium,
            Summary = "The script builds or decodes its content in a way that makes it hard to read.",
            Detail =
                $"The script contains {string.Join(", ", reasons)}. " +
                "Scripts that are obfuscated like this are hiding something from a reader. " +
                "Some packaging tools and installers obfuscate harmless code too, so this is a hint and not a verdict.",
            Advice = Advice
        });
    }
}
