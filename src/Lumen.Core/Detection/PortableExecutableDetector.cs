using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Pe;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection;

/// <summary>
/// Reads Windows executable headers straight from the bytes the scanner already read and
/// reports the things that are worth a second look.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here proves that a file is harmful. A high entropy section and a process
/// injection import are things that legitimate software does too. The findings say exactly
/// what was observed so a person can decide.
/// </para>
/// <para>
/// The detector performs no file system access. The only outside inputs are the current
/// time, which is injected so the timestamp check can be tested, and the answer to "where
/// does this file live", which decides whether a missing signature is worth mentioning at
/// all.
/// </para>
/// </remarks>
public sealed class PortableExecutableDetector : IScanDetector
{
    /// <summary>The entropy, in bits per byte, above which a section is treated as packed or encrypted.</summary>
    public const double HighEntropyThreshold = 7.2;

    /// <summary>The date before which a compilation timestamp is treated as implausibly old.</summary>
    public static readonly DateTimeOffset EarliestPlausibleCompileTime = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly HashSet<string> PackerSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0", "UPX1", "UPX2", "UPX!", ".aspack", ".adata", ".enigma", ".nsp0", ".nsp1",
        ".perplex", ".petite", ".spack", ".themida", ".vmp0", ".vmp1", ".vmp2", ".winzip",
        "MPRESS1", "MPRESS2", ".packed", ".crypted"
    };

    private const string Advice =
        "Look at the file in a tool you trust before you run it. None of these signals on its own proves that a file is harmful.";

    private readonly IClock _clock;
    private readonly ISuspiciousLocation _locations;

    /// <summary>
    /// Creates the detector using the system clock for the timestamp check and the folders
    /// of this machine to decide where a file lives.
    /// </summary>
    public PortableExecutableDetector() : this(SystemClock.Instance, new DefaultSuspiciousLocation())
    {
    }

    /// <summary>
    /// Creates the detector with an explicit clock so the timestamp rule can be tested
    /// without depending on the current date.
    /// </summary>
    public PortableExecutableDetector(IClock clock) : this(clock, new DefaultSuspiciousLocation())
    {
    }

    /// <summary>
    /// Creates the detector with an explicit clock and an explicit answer to the question
    /// of where a file lives, so both rules can be tested without depending on the machine.
    /// </summary>
    /// <param name="clock">The clock used for the compilation timestamp check.</param>
    /// <param name="locations">Decides whether a path is in a folder the user can write to.</param>
    public PortableExecutableDetector(IClock clock, ISuspiciousLocation locations)
    {
        _clock = clock;
        _locations = locations;
    }

    /// <inheritdoc />
    public string Id => "pe.analysis";

    /// <inheritdoc />
    public string Name => "Executable analysis";

    /// <inheritdoc />
    public string Description =>
        "Reads the Windows executable header, section table and import table from the bytes already read, and reports packing, notable API imports, a missing signature in a folder the user can write to, and implausible timestamps.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <summary>
    /// The names of the sections that are known to belong to common packers.
    /// </summary>
    public static IReadOnlyCollection<string> KnownPackerSectionNames => PackerSectionNames;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var content = probe.Content.Span;
        if (content.Length < 64) return Array.Empty<Finding>();

        if (!PeParser.TryParse(content, probe.ContentTruncated, out var header, out _))
            return Array.Empty<Finding>();

        if (header is null) return Array.Empty<Finding>();

        var findings = new List<Finding>();

        AddPackerSectionFindings(header, findings);
        AddHighEntropyFindings(header, findings);
        AddImportFindings(header, findings);
        AddSignatureFindings(header, probe, findings);
        AddTimestampFindings(header, findings);

        return findings;
    }

    private static void AddPackerSectionFindings(PeHeader header, List<Finding> findings)
    {
        var packed = header.Sections
            .Where(section => PackerSectionNames.Contains(section.Name))
            .Select(section => section.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (packed.Length == 0) return;

        findings.Add(new Finding
        {
            RuleId = "pe.packer-section-name",
            Title = "Section name belongs to a known packer",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.High,
            Summary = "The executable contains a section named after a well-known packer.",
            Detail =
                $"The section table contains the name \"{DisplayText.Sanitize(string.Join(", ", packed))}\", which is used by common executable packers. " +
                "Packed executables are compressed on purpose, which makes them harder to read and to review.",
            Advice = Advice
        });
    }

    private static void AddHighEntropyFindings(PeHeader header, List<Finding> findings)
    {
        var high = header.Sections
            .Where(section => section.SizeOfRawData >= 256 && section.Entropy >= HighEntropyThreshold)
            .Select(section => $"{DisplayText.Sanitize(section.Name)} ({section.Entropy:F2} bits per byte)")
            .ToArray();

        if (high.Length == 0) return;

        findings.Add(new Finding
        {
            RuleId = "pe.high-entropy-section",
            Title = "Section has very high entropy",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.Medium,
            Summary = "Part of the executable looks compressed or encrypted.",
            Detail =
                $"The section(s) {string.Join(", ", high)} have entropy at or above {HighEntropyThreshold:F1} bits per byte. " +
                "Ordinary code sits far below that, while packed or encrypted data sits close to the maximum of 8. " +
                "Compressed installers and encrypted resources look the same way.",
            Advice = Advice
        });
    }

    private static void AddImportFindings(PeHeader header, List<Finding> findings)
    {
        var matches = SuspiciousApiCatalog.Match(header.Imports);
        if (matches.Count == 0) return;

        var described = matches
            .Select(match => $"{match.Group.Title}: {string.Join(", ", match.Functions.Select(DisplayText.Sanitize))}")
            .ToArray();

        findings.Add(new Finding
        {
            RuleId = "pe.suspicious-api-import",
            Title = "Executable imports notable Windows APIs",
            Category = FindingCategory.Behavior,
            Confidence = Confidence.Medium,
            Summary = "The executable imports Windows APIs that are commonly associated with injection, hooking or capture.",
            Detail =
                $"The import table contains {string.Join("; ", described)}. " +
                "Each of these APIs is used by legitimate software as well, so the import alone does not mean anything on its own.",
            Advice = Advice
        });
    }

    private void AddSignatureFindings(PeHeader header, FileProbe probe, List<Finding> findings)
    {
        // When only the beginning of the file was read, the certificate table may be past
        // the end of what was read. Nothing can be said about the signature then, so
        // nothing is said.
        if (!header.SignatureCheckComplete) return;

        if (header.HasCertificateTable && !header.HasValidDigitalSignature)
        {
            findings.Add(new Finding
            {
                RuleId = "pe.invalid-digital-signature",
                Title = "Digital signature information is not valid",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The executable declares a digital signature that does not read as a valid signature.",
                Detail =
                    "The file points at a certificate table, but the data in it is not a well-formed signed-data blob. " +
                    "That can mean a damaged signature, a self-made certificate, or an attempt to look signed without being signed.",
                Advice = "Check the publisher of the file in the file properties, and verify it with a full antivirus product."
            });

            return;
        }

        if (header.HasValidDigitalSignature) return;

        // Being unsigned is not a finding on its own: plenty of ordinary tools ship without
        // a signature. It only becomes worth mentioning when the file also sits somewhere
        // the user can freely write to, where any program running as that user can replace
        // it without asking.
        if (!_locations.IsSuspicious(probe.Path)) return;

        findings.Add(new Finding
        {
            RuleId = "pe.unsigned-executable",
            Title = "Unsigned executable in a folder the user can write to",
            Category = FindingCategory.Heuristic,
            Confidence = Confidence.Low,
            Summary = "The executable is not signed and sits in a folder the user can freely write to.",
            Detail =
                "The file has no certificate table, so nothing in it says who published it, and it sits in a folder " +
                "that any program running as this user can replace. " +
                "A missing signature on its own is normal: many small and open-source tools are not signed, and an " +
                "unsigned program in Program Files is not worth a second look. " +
                "The combination of the two is what is worth a look here.",
            Advice =
                "Find out where the file came from before you run it. " +
                "Right-click the file and open the digital signature tab in the properties: an unsigned file has nothing there. " +
                "Compare the file with a copy from the publisher if you can."
        });
    }

    private void AddTimestampFindings(PeHeader header, List<Finding> findings)
    {
        if (header.CompiledUtc is null) return;

        var compiled = header.CompiledUtc.Value;
        var now = _clock.UtcNow;

        if (compiled < EarliestPlausibleCompileTime)
        {
            findings.Add(new Finding
            {
                RuleId = "pe.timestamp-anomaly",
                Title = "Compilation timestamp is implausibly old",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Low,
                Summary = "The executable claims to have been compiled long before it could have existed.",
                Detail =
                    $"The header records a compilation date of {compiled:yyyy-MM-dd}, which is earlier than {EarliestPlausibleCompileTime:yyyy-MM-dd}. " +
                    "Build tools set this field from the file system, so it can be wrong. A deliberately back-dated value is also possible.",
                Advice = Advice
            });

            return;
        }

        if (compiled > now.AddDays(1))
        {
            findings.Add(new Finding
            {
                RuleId = "pe.timestamp-anomaly",
                Title = "Compilation timestamp is in the future",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Low,
                Summary = "The executable claims to have been compiled in the future.",
                Detail =
                    $"The header records a compilation date of {compiled:yyyy-MM-dd}, which is later than the current date. " +
                    "Build tools set this field from the file system, so it can be wrong when the clock is off. " +
                    "A deliberately wrong value is also possible.",
                Advice = Advice
            });
        }
    }
}
