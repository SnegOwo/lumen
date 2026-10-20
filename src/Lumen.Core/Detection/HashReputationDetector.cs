using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection;

/// <summary>
/// Reports files whose SHA-256 hash is on the local reputation list.
/// </summary>
/// <remarks>
/// <para>
/// The list is supplied to the detector, so the detector itself never reads a file and
/// never asks a server anything. Lumen performs no network lookups of any kind.
/// </para>
/// <para>
/// The hash can only be computed when the scanner read the whole file. When only a prefix
/// was read the detector stays quiet, because hashing a prefix would produce a value that
/// matches nothing and could mislead.
/// </para>
/// </remarks>
public sealed class HashReputationDetector : IScanDetector
{
    private readonly HashReputationList _list;

    /// <summary>
    /// Creates the detector with the list it should consult.
    /// </summary>
    public HashReputationDetector(HashReputationList list)
    {
        _list = list;
    }

    /// <summary>
    /// Creates the detector with the built-in list, which holds the EICAR test file.
    /// </summary>
    public HashReputationDetector() : this(HashReputationList.CreateDefault())
    {
    }

    /// <inheritdoc />
    public string Id => "reputation.hashes";

    /// <inheritdoc />
    public string Name => "Local hash reputation";

    /// <inheritdoc />
    public string Description =>
        "Compares the SHA-256 of a file with a local list of known hashes. The list is read from the local disk only; Lumen never looks a file up online.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Reputation;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.High;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_list.Count == 0) return Array.Empty<Finding>();
        if (probe.ContentTruncated) return Array.Empty<Finding>();

        var hash = HashUtil.Sha256Bytes(probe.Content.Span);
        var entry = _list.Lookup(hash);
        if (entry is null) return Array.Empty<Finding>();

        return
        [
            new Finding
            {
                RuleId = entry.RuleId,
                Title = entry.Label,
                Category = entry.Category,
                Confidence = entry.Confidence,
                Summary =
                    "The SHA-256 of this file is on the local hash list. " +
                    "Lumen only compares against the list stored on this machine.",
                Detail =
                    $"The file hashes to {hash}, which is listed as \"{DisplayText.Sanitize(entry.Label)}\" " +
                    $"(source: {DisplayText.Sanitize(entry.Source ?? "local list")}).",
                Advice =
                    "A hash match means the file is identical to a listed file. Review it before you run it, and check where it came from."
            }
        ];
    }
}
