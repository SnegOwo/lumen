using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Pe;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection.Aggressive;

/// <summary>
/// Reports the shapes that a program built to unpack or protect itself leaves in its
/// header.
/// </summary>
/// <remarks>
/// <para>
/// Four things are looked at: a section named after a commercial protector, an image with
/// no import table at all, an entry point that is not inside a section marked as code, and
/// a section whose name is built from characters that ordinary compilers do not use.
/// </para>
/// <para>
/// Each of them is weak on its own. Legitimate software uses protectors, and a few
/// unusual but honest programs have no import table, so the rule reports what it saw and
/// leaves the judgement to the reader.
/// </para>
/// <para>
/// The detector reads the bytes the scanner already loaded and parses the header from
/// them. It performs no file system access.
/// </para>
/// <para>
/// This rule belongs to the AGGRESSIVE tier: it only runs when the user has asked for
/// maximum sensitivity.
/// </para>
/// </remarks>
public sealed class LoaderMarkerDetector : IScanDetector, IAggressiveDetector
{
    /// <summary>The identifier of the rule that reports a protector section name.</summary>
    public const string ProtectorRuleId = "pe.protector-section-name";

    /// <summary>The identifier of the rule that reports a missing import table.</summary>
    public const string NoImportRuleId = "pe.no-import-table";

    /// <summary>The identifier of the rule that reports an entry point outside the code.</summary>
    public const string EntryPointRuleId = "pe.entry-point-outside-section";

    /// <summary>The identifier of the rule that reports an unusual section name.</summary>
    public const string UnusualNameRuleId = "pe.unusual-section-name";

    /// <summary>
    /// The section names that belong to commercial protectors and crypters. The names the
    /// standard rules already know are left out, so one observation is never reported
    /// twice under two identifiers.
    /// </summary>
    public static IReadOnlyCollection<string> ProtectorSectionNames { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".vmp3", ".winlice", ".winlicense", ".yoda", ".yp", ".y0da", ".rlpack", ".pec",
        ".execryptor", ".gentee", ".shrink", ".shrink1", ".shrink2", ".neolit",
        ".safengine", ".svkp", ".upack", ".upack0", ".upack1", ".pecompact", ".taz",
        ".taz1", ".boom", ".pklstb", "pelocknt", "mew", ".pklite", ".aplib", ".nspack",
        ".nsp2", ".nsp3", ".enigma1", ".enigma2", ".enigma3", "bitarts", ".crypter",
        ".krypton", ".sforce", ".hive", ".adata1", ".ccg", ".wwpack", ".winpack"
    };

    private const string Advice =
        "Look at the file in a tool you trust before you run it. A protected or packed file cannot be read, so there is nothing in it to review.";

    /// <inheritdoc />
    public string Id => "pe.loader-markers";

    /// <inheritdoc />
    public string Name => "Loader and protector markers";

    /// <inheritdoc />
    public string Description =>
        "Reports a section named after a protector, an image with no import table, an entry point outside the code and a section with an unusual name.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var content = probe.Content.Span;
        if (content.Length < 64) return Array.Empty<Finding>();

        if (!PeParser.TryParse(content, probe.ContentTruncated, out var header, out _)) return Array.Empty<Finding>();
        if (header is null) return Array.Empty<Finding>();

        var findings = new List<Finding>();

        AddProtectorFindings(header, findings);
        AddNoImportFindings(header, findings);
        AddEntryPointFindings(header, findings);
        AddUnusualNameFindings(header, findings);

        return findings;
    }

    private static void AddProtectorFindings(PeHeader header, List<Finding> findings)
    {
        var names = header.Sections
            .Where(section => ProtectorSectionNames.Contains(section.Name))
            .Select(section => section.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (names.Length == 0) return;

        findings.Add(new Finding
        {
            RuleId = ProtectorRuleId,
            Title = "Section named after a protector",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.High,
            Summary = "The executable contains a section named after a commercial protector.",
            Detail =
                $"The section table contains the name \"{DisplayText.Sanitize(string.Join(", ", names))}\", which belongs to a known protector or crypter. " +
                "A protected file is deliberately hard to read, and the protection itself is not what makes a file harmful.",
            Advice = Advice
        });
    }

    private static void AddNoImportFindings(PeHeader header, List<Finding> findings)
    {
        if (header.HasImportDirectory) return;

        findings.Add(new Finding
        {
            RuleId = NoImportRuleId,
            Title = "Executable with no import table",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.Low,
            Summary = "The executable declares no import table.",
            Detail =
                "The header points at no import directory, so the functions the program uses are not named in the file at all. " +
                "A packer usually works this way, because it rebuilds the imports when the program runs. " +
                "A few unusual but legitimate programs are built without an import table as well.",
            Advice = Advice
        });
    }

    private static void AddEntryPointFindings(PeHeader header, List<Finding> findings)
    {
        if (header.AddressOfEntryPoint == 0) return;

        var section = PeParser.SectionAt(header, header.AddressOfEntryPoint);
        if (section is not null && section.IsExecutable) return;

        var detail = section is null
            ? $"The header says the program starts at address 0x{header.AddressOfEntryPoint:X8}, which is not inside any section of the file."
            : $"The header says the program starts at address 0x{header.AddressOfEntryPoint:X8}, which is inside the section \"{DisplayText.Sanitize(section.Name)}\". " +
              "That section is not marked as executable code.";

        findings.Add(new Finding
        {
            RuleId = EntryPointRuleId,
            Title = "Entry point outside an executable section",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.Medium,
            Summary = "The program starts at an address that is not inside a section marked as code.",
            Detail =
                detail + " " +
                "The header and the section table do not agree with each other, which happens when a file is put together by hand or when its header has been altered.",
            Advice = Advice
        });
    }

    private static void AddUnusualNameFindings(PeHeader header, List<Finding> findings)
    {
        var names = header.Sections
            .Where(section => section.Name.Length > 0 && !IsOrdinarySectionName(section.Name))
            .Select(section => section.Name)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (names.Length == 0) return;

        findings.Add(new Finding
        {
            RuleId = UnusualNameRuleId,
            Title = "Section with an unusual name",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.Low,
            Summary = "A section of the executable has a name built from characters that ordinary compilers do not use.",
            Detail =
                $"The section table holds the name \"{DisplayText.Sanitize(string.Join(", ", names))}\". " +
                "Ordinary compilers use letters, digits and a few punctuation marks for section names, and a name made from other characters usually means the file was put together by a tool of its own.",
            Advice = Advice
        });
    }

    /// <summary>
    /// True when the section name is built from the characters ordinary compilers use.
    /// Only ASCII letters and digits count, so a name built from bytes above the ASCII
    /// range is treated as unusual.
    /// </summary>
    private static bool IsOrdinarySectionName(string name)
    {
        foreach (var character in name)
        {
            if (character is >= 'a' and <= 'z') continue;
            if (character is >= 'A' and <= 'Z') continue;
            if (character is >= '0' and <= '9') continue;
            if (character is '.' or '_' or '$') continue;
            return false;
        }

        return true;
    }
}
