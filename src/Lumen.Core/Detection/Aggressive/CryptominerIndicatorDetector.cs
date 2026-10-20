using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection.Aggressive;

/// <summary>
/// Reports a file that points at a mining pool or carries the settings a mining program
/// takes.
/// </summary>
/// <remarks>
/// <para>
/// The rule looks for three kinds of marker: the protocol a mining pool is reached with, a
/// wallet address, and the switches a mining program is started with. Any one of them on
/// its own can turn up in an unusual but harmless file, so the rule needs at least two of
/// the three before it reports anything.
/// </para>
/// <para>
/// The strings that were found are named in the finding, because the reader has to be
/// able to see what the rule matched.
/// </para>
/// <para>
/// This rule belongs to the AGGRESSIVE tier: it only runs when the user has asked for
/// maximum sensitivity.
/// </para>
/// </remarks>
public sealed class CryptominerIndicatorDetector : IScanDetector, IAggressiveDetector
{
    /// <summary>The identifier of the rule this detector reports.</summary>
    public const string RuleId = "script.mining-configuration";

    private static readonly string[] ScriptExtensions =
    [
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta", ".txt", ".json",
        ".cfg", ".conf", ".ini", ".xml", ".log", ".sh", ".py"
    ];

    /// <summary>
    /// The ways a mining pool is addressed. These are protocol markers, not addresses:
    /// nothing in this list points at a particular server.
    /// </summary>
    private static readonly string[] PoolTokens =
    [
        "stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "mining pool",
        "mining address", "pool address", "pool_url", "poolurl"
    ];

    /// <summary>
    /// The switches and program names a mining program is started with.
    /// </summary>
    private static readonly string[] MinerTokens =
    [
        "--donate-level", "--donate-to", "--donate", "--url=", "--user=", "--coin",
        "--rig-id", "--cpu-priority", "xmrig", "minerd", "cpuminer", "ethminer",
        "nbminer", "phoenixminer", "randomx", "cryptonight", "ethash", "kawpow",
        "rx/0", "nicehash", "minergate"
    ];

    /// <summary>
    /// The ways a wallet is written down.
    /// </summary>
    private static readonly string[] WalletTokens =
    [
        "wallet=", "wallet_address", "walletaddress", "--wallet", "user=", "address=",
        "donateaddress"
    ];

    private const string Advice =
        "Find out what the file is for and where it came from. " +
        "A file that points at a mining pool and carries a wallet is set up to mine, and it will use the machine while it runs.";

    /// <inheritdoc />
    public string Id => "script.mining";

    /// <inheritdoc />
    public string Name => "Mining configuration";

    /// <inheritdoc />
    public string Description =>
        "Reports a file that mentions a mining pool, a wallet address or the switches a mining program takes.";

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

        var pools = PoolTokens.Where(token => TextPatterns.Contains(lower, token)).ToArray();
        var miners = MinerTokens.Where(token => TextPatterns.Contains(lower, token)).ToArray();
        var wallets = WalletTokens.Where(token => TextPatterns.Contains(lower, token)).ToArray();

        var walletAddresses = FindWalletAddresses(lower);

        var groups = 0;
        if (pools.Length > 0) groups++;
        if (miners.Length > 0) groups++;
        if (wallets.Length > 0 || walletAddresses.Count > 0) groups++;

        if (groups < 2) return Array.Empty<Finding>();

        var found = new List<string>();
        found.AddRange(pools.Select(token => $"\"{DisplayText.Sanitize(token)}\""));
        found.AddRange(miners.Select(token => $"\"{DisplayText.Sanitize(token)}\""));
        found.AddRange(wallets.Select(token => $"\"{DisplayText.Sanitize(token)}\""));
        found.AddRange(walletAddresses.Select(address => $"the wallet address \"{DisplayText.Sanitize(address)}\""));

        return
        [
            new Finding
            {
                RuleId = RuleId,
                Title = "Mining pool or wallet settings",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.Medium,
                Summary = "The file carries the settings a mining program needs.",
                Detail =
                    "The file was found to hold " + string.Join(", ", found) + ". " +
                    "These are the markers a mining program is configured with, and none of them turn up in ordinary software. " +
                    "Lumen did not connect to anything and did not read any wallet.",
                Advice = Advice
            }
        ];
    }

    /// <summary>
    /// Looks for the shape of a wallet address: a long run of hexadecimal characters,
    /// which is how the common wallet addresses are written.
    /// </summary>
    private static List<string> FindWalletAddresses(string lower)
    {
        var found = new List<string>();
        var index = 0;

        while (index < lower.Length)
        {
            var start = lower.IndexOf("0x", index, StringComparison.Ordinal);
            if (start < 0) break;

            var cursor = start + 2;
            while (cursor < lower.Length && IsHexDigit(lower[cursor])) cursor++;

            if (cursor - (start + 2) == 40)
            {
                found.Add(lower[start..cursor]);
            }

            index = cursor > start ? cursor : start + 2;
        }

        return found;
    }

    private static bool IsHexDigit(char value) =>
        value is >= '0' and <= '9' or >= 'a' and <= 'f';
}
