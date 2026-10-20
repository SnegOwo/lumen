using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Archives;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection;

/// <summary>
/// Looks inside archive containers for things that deserve a second look: executables,
/// archives inside archives, encrypted entries and extreme compression ratios.
/// </summary>
/// <remarks>
/// The detector only works with the bytes the scanner already read, so it can see the
/// beginning of a container and not its whole content. It reports what it saw and does not
/// claim that an archive is harmful because it carries a program: that is a normal thing
/// for installers and software updates to do.
/// </remarks>
public sealed class ArchiveDetector : IScanDetector
{
    /// <summary>The uncompressed size, in bytes, at which a single entry is treated as a decompression risk.</summary>
    public const long LargeEntryBytes = 10L * 1024 * 1024;

    /// <summary>The compression ratio at which an entry is treated as a decompression risk.</summary>
    public const double HighCompressionRatio = 100.0;

    /// <summary>The largest number of bytes read from any single archive entry.</summary>
    public const int MaxEntryBytes = 512 * 1024;

    /// <summary>The largest number of entries the detector looks at inside one container.</summary>
    public const int MaxExaminedEntries = 512;

    private static readonly string[] DocumentExtensions =
    [
        ".pdf", ".doc", ".xls", ".ppt", ".rtf",
        ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp",
        ".mp3", ".mp4", ".avi", ".mkv", ".wav", ".xml", ".json", ".html", ".htm", ".md"
    ];

    /// <summary>
    /// The names of the files that Windows can start on its own when a user opens them.
    /// Script files that need another program to run, such as a JavaScript file, are not in
    /// this list: a web project zipped up for a colleague is not an archive carrying a
    /// program. A file that carries the executable marker is still reported whatever it is
    /// called.
    /// </summary>
    private static readonly string[] ExecutableExtensions =
    [
        ".exe", ".dll", ".scr", ".com", ".cpl", ".pif", ".sys", ".msi", ".msp",
        ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".hta", ".lnk"
    ];

    private static readonly string[] ArchiveExtensions =
    [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".cab", ".iso", ".jar", ".war"
    ];

    private const string Advice =
        "Open the archive in an archive tool and look at what is inside before you run anything. An archive carrying a program is not unusual on its own.";

    /// <inheritdoc />
    public string Id => "archive.analysis";

    /// <inheritdoc />
    public string Name => "Archive analysis";

    /// <inheritdoc />
    public string Description =>
        "Examines archive containers for executables, nested archives, encrypted entries and extreme compression ratios, and notices archives that are disguised as documents.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Heuristic;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var content = probe.Content.Span;
        if (content.Length < 4) return Array.Empty<Finding>();

        var extension = Path.GetExtension(probe.FileName);
        var findings = new List<Finding>();

        var magic = ZipInspector.DescribeArchiveMagic(content);
        if (magic is not null && DocumentExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
        {
            findings.Add(new Finding
            {
                RuleId = "archive.magic-in-document-extension",
                Title = "Archive content in a file named as a document",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.High,
                Summary = "The file is an archive even though its name says it is a document.",
                Detail =
                    $"The file starts with the signature of a {magic} archive, but its name ends with \"{extension}\". " +
                    "Renaming a file does not change what it is, and this is a common way to make a payload look harmless.",
                Advice = "Look at the file with an archive tool, not with the program its name suggests."
            });
        }

        if (!ZipInspector.IsZip(content)) return findings;

        var entries = ZipInspector.ListEntries(content);
        if (entries.Count == 0) return findings;

        AddExecutableFindings(entries, content, findings);
        AddNestedArchiveFindings(entries, content, findings);
        AddPasswordFindings(entries, findings);
        AddCompressionRatioFindings(entries, findings);

        return findings;
    }

    private static void AddExecutableFindings(
        IReadOnlyList<ArchiveEntryInfo> entries,
        ReadOnlySpan<byte> content,
        List<Finding> findings)
    {
        var executableNames = new List<string>();
        var examined = 0;
        foreach (var entry in entries)
        {
            if (examined++ >= MaxExaminedEntries) break;

            var extension = Path.GetExtension(entry.Name);
            if (ExecutableExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
            {
                executableNames.Add(entry.Name);
                continue;
            }

            // A file that does not look executable by name can still carry an executable header.
            if (entry.DataOffset >= 0 && entry.DataOffset + 2 <= content.Length &&
                content[entry.DataOffset] == 0x4D && content[entry.DataOffset + 1] == 0x5A)
            {
                executableNames.Add(entry.Name);
            }
        }

        if (executableNames.Count == 0) return;

        var names = executableNames.Take(8).Select(name => DisplayText.Sanitize(name)).ToArray();
        findings.Add(new Finding
        {
            RuleId = "archive.executable-inside",
            Title = "Archive contains a program Windows can start",
            Category = FindingCategory.Heuristic,
            Confidence = Confidence.High,
            Summary = "The archive holds at least one file that Windows can start.",
            Detail =
                $"The archive contains {executableNames.Count} file(s) that Windows can start: {string.Join(", ", names)}" +
                (executableNames.Count > names.Length ? ", and more" : string.Empty) + ". " +
                "Installers and software updates routinely ship programs, so this is worth checking rather than proof of anything.",
            Advice = Advice
        });
    }

    private static void AddNestedArchiveFindings(
        IReadOnlyList<ArchiveEntryInfo> entries,
        ReadOnlySpan<byte> content,
        List<Finding> findings)
    {
        var nested = new List<string>();
        var depth = 1;
        var examined = 0;

        foreach (var entry in entries)
        {
            if (examined++ >= MaxExaminedEntries) break;

            var extension = Path.GetExtension(entry.Name);
            var looksNested = ArchiveExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
            if (!looksNested && ZipInspector.TryReadEntry(content, entry, 64, out var head))
            {
                looksNested = ZipInspector.IsArchiveMagic(head);
            }

            if (!looksNested) continue;

            nested.Add(entry.Name);

            // Look one level deeper when the inner archive can be read.
            if (ZipInspector.TryReadEntry(content, entry, MaxEntryBytes, out var inner))
            {
                var innerEntries = ZipInspector.ListEntries(inner);
                foreach (var innerEntry in innerEntries)
                {
                    if (!ArchiveExtensions.Contains(Path.GetExtension(innerEntry.Name), StringComparer.OrdinalIgnoreCase)) continue;
                    depth = Math.Max(depth, 2);
                    nested.Add(innerEntry.Name);
                }
            }
        }

        if (nested.Count == 0) return;

        var names = nested.Take(8).Select(name => DisplayText.Sanitize(name)).ToArray();
        findings.Add(new Finding
        {
            RuleId = "archive.nested-archive",
            Title = "Archive inside an archive",
            Category = FindingCategory.Heuristic,
            Confidence = Confidence.Medium,
            Summary = "The archive contains further archives.",
            Detail =
                $"At least {nested.Count} archive(s) were found inside the container: {string.Join(", ", names)}. " +
                $"The nesting depth that could be observed is {depth}. " +
                "Nested archives make a payload harder to see, which is why they are worth checking. " +
                "Backup tools and installers also nest archives.",
            Advice = Advice
        });
    }

    private static void AddPasswordFindings(IReadOnlyList<ArchiveEntryInfo> entries, List<Finding> findings)
    {
        var encrypted = entries.Where(entry => entry.IsEncrypted).Select(entry => entry.Name).ToArray();
        if (encrypted.Length == 0) return;

        findings.Add(new Finding
        {
            RuleId = "archive.password-protected",
            Title = "Archive is password protected",
            Category = FindingCategory.Heuristic,
            Confidence = Confidence.Low,
            Summary = "The archive marks its content as encrypted.",
            Detail =
                $"{encrypted.Length} entry(s) in the archive are marked as encrypted. " +
                "Password protection is a normal way to ship an archive, but it also means the content cannot be reviewed without the password.",
            Advice = "Only open it with a password you were given directly by a person you trust."
        });
    }

    private static void AddCompressionRatioFindings(IReadOnlyList<ArchiveEntryInfo> entries, List<Finding> findings)
    {
        var risky = entries
            .Where(entry => entry.CompressedSize > 0 &&
                            entry.UncompressedSize >= LargeEntryBytes &&
                            entry.UncompressedSize / (double)entry.CompressedSize >= HighCompressionRatio)
            .ToArray();

        if (risky.Length == 0) return;

        var largest = risky.Max(entry => entry.UncompressedSize);
        findings.Add(new Finding
        {
            RuleId = "archive.suspicious-compression-ratio",
            Title = "Archive expands by a very large factor",
            Category = FindingCategory.Heuristic,
            Confidence = Confidence.Medium,
            Summary = "The archive claims to expand into far more data than it stores.",
            Detail =
                $"{risky.Length} entry(s) compress by a factor of {HighCompressionRatio:F0} or more; the largest claims to expand to {largest / (1024 * 1024)} MB. " +
                "Archives like this are used to exhaust memory or disk when they are unpacked.",
            Advice = "Do not unpack the archive on a machine you care about until you know what it contains."
        });
    }
}
