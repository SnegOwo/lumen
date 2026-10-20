using Lumen.Core.Models;

namespace Lumen.Core.Detection;

/// <summary>
/// The weight each rule contributes to the overall risk score. The table is explicit so a
/// person can read why a file scored the way it did.
/// </summary>
/// <remarks>
/// A weight is not a probability. It says how much one particular signal should move the
/// score, and every contributing signal is listed in the breakdown, so the number never
/// stands on its own.
/// </remarks>
public static class RiskWeights
{
    /// <summary>The weight used for a rule that is not listed here.</summary>
    public const int DefaultWeight = 20;

    private static readonly Dictionary<string, int> Table = new(StringComparer.OrdinalIgnoreCase)
    {
        ["test.eicar"] = 100,
        ["test.eicar-hash"] = 100,
        ["reputation.known-bad-hash"] = 80,

        ["sig.pe-header-in-document-file"] = 70,
        ["sig.upx-packer-marker"] = 45,
        ["sig.windows-script-host-reference"] = 25,
        ["sig.amsi-bypass-marker"] = 60,
        ["sig.powershell-stealth-switch"] = 40,
        ["sig.base64-decode-call"] = 30,

        ["pe.packer-section-name"] = 55,
        ["pe.high-entropy-section"] = 35,
        ["pe.suspicious-api-import"] = 50,
        ["pe.unsigned-executable"] = 10,
        ["pe.invalid-digital-signature"] = 30,
        ["pe.timestamp-anomaly"] = 10,

        ["script.download-execute"] = 45,
        ["script.encoded-command"] = 40,
        ["script.hidden-bypass"] = 25,
        ["script.reflection-load"] = 45,
        ["script.tamper-defender"] = 45,
        ["script.lolbin-download"] = 35,
        ["script.lolbin-script-execution"] = 35,
        ["script.powershell-obfuscation"] = 40,
        ["script.amsi-bypass"] = 55,
        ["script.stealth-powershell"] = 30,
        ["script.persistence"] = 40,
        ["script.av-tampering"] = 50,
        ["script.credential-theft"] = 70,
        ["script.reverse-shell"] = 70,

        ["office.vba-macro-project"] = 35,
        ["office.macro-auto-execution"] = 55,
        ["office.macro-enabled-extension"] = 20,
        ["office.external-template"] = 10,

        ["pdf.embedded-javascript"] = 35,
        ["pdf.launch-action"] = 35,
        ["pdf.auto-open-action"] = 15,
        ["pdf.script-uri-action"] = 30,
        ["pdf.embedded-executable"] = 65,

        ["archive.executable-inside"] = 45,
        ["archive.nested-archive"] = 30,
        ["archive.password-protected"] = 10,
        ["archive.suspicious-compression-ratio"] = 40,
        ["archive.magic-in-document-extension"] = 55,

        ["shortcut.script-target"] = 40,
        ["shortcut.temp-path-target"] = 30,
        ["shortcut.dangling-target"] = 10,

        ["name.double-extension"] = 35,
        ["name.bidi-override"] = 30,

        ["entropy.high-entropy-file"] = 25,
        ["entropy.encrypted-tail"] = 40,

        ["risk.aggregate"] = 0
    };

    /// <summary>
    /// Returns the weight of a rule.
    /// </summary>
    public static int For(string? ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId)) return DefaultWeight;
        return Table.TryGetValue(ruleId, out var weight) ? weight : DefaultWeight;
    }

    /// <summary>Every rule that has an explicit weight.</summary>
    public static IReadOnlyDictionary<string, int> Weights => Table;
}
