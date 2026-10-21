using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// Looks at how evenly the bytes of a file are spread, which is a cheap way to notice data
/// that has been compressed or encrypted.
/// </summary>
/// <remarks>
/// <para>
/// Entropy is a weak signal on its own. Packed installers, encrypted documents and media
/// files all look like this, and a file that merely contains a compressed picture does too.
/// The findings say what was measured and nothing more.
/// </para>
/// <para>
/// The detector works on the bytes the scanner already read and performs no file system
/// access.
/// </para>
/// </remarks>
public sealed class EntropyDetector : IScanDetector
{
    /// <summary>The entropy, in bits per byte, at which a whole file is treated as packed or encrypted.</summary>
    public const double HighFileEntropy = 7.5;

    /// <summary>The entropy, in bits per byte, at which a trailing block is treated as packed or encrypted.</summary>
    public const double HighTailEntropy = 7.0;

    /// <summary>The smallest file the detector measures, in bytes.</summary>
    public const int MinimumBytes = 1024;

    /// <summary>The size of the window used to look at the end of a file, in bytes.</summary>
    public const int TailWindowBytes = 4096;

    private const string Advice =
        "Files that look packed or encrypted are hard to review. Check the file with a tool you trust before you open it.";

    /// <inheritdoc />
    public string Id => "entropy.analysis";

    /// <inheritdoc />
    public string Name => "Entropy and packing heuristics";

    /// <inheritdoc />
    public string Description =>
        "Measures how evenly the bytes of a file are spread. Highly even data is usually compressed or encrypted, which makes a file hard to read and review.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Low;

    /// <summary>
    /// Extensions whose contents are normally compressed or encrypted.
    ///
    /// <para>
    /// A high entropy measurement says NOTHING about a PNG, a video or a ZIP: their
    /// bytes are supposed to look random. Reporting them would fill a user's results
    /// with noise and train them to ignore Lumen. The interesting cases inside those
    /// formats - an executable in an archive, a script in a document - are covered by
    /// the archive and document rules, which look at the STRUCTURE rather than at the
    /// byte spread.
    /// </para>
    /// </summary>
    private static readonly HashSet<string> ExpectedHighEntropyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Images
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico", ".heic",
        // Audio and video
        ".mp3", ".m4a", ".wav", ".flac", ".ogg", ".mp4", ".mkv", ".avi", ".mov", ".wmv",
        ".webm", ".m4v", ".3gp",
        // Archives and containers
        ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tgz", ".cab", ".jar", ".apk", ".iso",
        // Documents that are containers
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".epub"
    };

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var content = probe.Content.Span;
        if (content.Length < MinimumBytes) return Array.Empty<Finding>();

        var findings = new List<Finding>();

        // A media file or an archive is expected to have even bytes. Measuring it and
        // saying so is not a finding, it is a fact about the format.
        var expectedToBeEven = ExpectedHighEntropyExtensions.Contains(Path.GetExtension(probe.FileName));

        var overall = Entropy.Shannon(content);
        if (!expectedToBeEven && overall >= HighFileEntropy)
        {
            findings.Add(new Finding
            {
                RuleId = "entropy.high-entropy-file",
                Title = "File contents are almost perfectly even",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.Medium,
                Summary = "The bytes of the file are spread almost evenly, which usually means compressed or encrypted data.",
                Detail =
                    $"The file measures {overall:F2} bits per byte, at or above the {HighFileEntropy:F1} that only compressed or encrypted data reaches. " +
                    "An ordinary program or document sits far below that. Media files, encrypted documents and packed installers look the same way, so this is a hint and not a verdict.",
                Advice = Advice
            });
        }

        if (content.Length < TailWindowBytes * 2) return findings;

        var head = content[..Math.Min(512, content.Length)];
        if (Entropy.PrintableRatio(head) < 0.9) return findings;
        if (overall >= 6.5) return findings;
        var tail = Entropy.ShannonTail(content, TailWindowBytes);
        if (tail < HighTailEntropy) return findings;

        findings.Add(new Finding
        {
            RuleId = "entropy.encrypted-tail",
            Title = "Readable text with a packed or encrypted block at the end",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.Medium,
            Summary = "The file starts as ordinary text and ends with data that looks compressed or encrypted.",
            Detail =
                $"The first part of the file is plain text, but the last {TailWindowBytes} bytes measure {tail:F2} bits per byte while the whole file measures {overall:F2}. " +
                "A payload hidden behind the end of a text file is a well-known trick. Legitimate files also append binary trailers, so this needs a look rather than a conclusion.",
            Advice = Advice
        });

        return findings;
    }
}
