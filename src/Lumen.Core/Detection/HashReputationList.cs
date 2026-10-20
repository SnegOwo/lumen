using System.Text.Json;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Storage;

namespace Lumen.Core.Detection;

/// <summary>
/// One entry in the local hash reputation list.
/// </summary>
/// <param name="Sha256">The lower-case SHA-256 of the file.</param>
/// <param name="Label">A short description shown to the user. It never contains file content.</param>
/// <param name="Category">The kind of signal the entry produces.</param>
/// <param name="Confidence">How much the entry should be trusted.</param>
/// <param name="RuleId">The rule identifier reported when the hash matches.</param>
/// <param name="Source">Where the entry came from, for example "local list".</param>
public sealed record ReputationEntry(
    string Sha256,
    string Label,
    FindingCategory Category = FindingCategory.Reputation,
    Confidence Confidence = Confidence.High,
    string RuleId = "reputation.known-bad-hash",
    string? Source = null);

/// <summary>
/// The outcome of loading a reputation list. A list that cannot be parsed is rejected in
/// full, so a damaged file can never make Lumen quietly ignore the entries it should have.
/// </summary>
/// <param name="Ok">True when the list was loaded.</param>
/// <param name="Entries">The loaded entries, keyed by hash. Empty when the load failed.</param>
/// <param name="Problem">A plain-language description of the problem, or null on success.</param>
public sealed record ReputationListLoadResult(
    bool Ok,
    IReadOnlyDictionary<string, ReputationEntry> Entries,
    string? Problem)
{
    /// <summary>Creates a successful result.</summary>
    public static ReputationListLoadResult Success(IReadOnlyDictionary<string, ReputationEntry> entries) =>
        new(true, entries, null);

    /// <summary>Creates a failed result. No entries are trusted when this is returned.</summary>
    public static ReputationListLoadResult Failure(string problem) =>
        new(false, new Dictionary<string, ReputationEntry>(StringComparer.OrdinalIgnoreCase), problem);
}

/// <summary>
/// A local list of file hashes that are worth reporting. Lumen never asks anyone else what
/// a file is: the list is read from the local disk and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// An unknown hash produces no finding. That is a statement about this list only and never
/// a claim that the file is safe.
/// </para>
/// <para>
/// A malformed list is rejected as a whole rather than partly applied, so a broken file
/// cannot silently disable the entries that were readable.
/// </para>
/// </remarks>
public sealed class HashReputationList
{
    /// <summary>The schema version this build understands.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>The name of the list file inside the application data folder.</summary>
    public const string DefaultFileName = "reputation.json";

    /// <summary>
    /// The SHA-256 of the EICAR antivirus test file. This is a harmless, industry-standard
    /// test artifact and not malware, so an entry for it is reported as a test signature.
    /// </summary>
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private readonly IReadOnlyDictionary<string, ReputationEntry> _entries;

    private HashReputationList(IReadOnlyDictionary<string, ReputationEntry> entries)
    {
        _entries = entries;
    }

    /// <summary>An empty list. It never reports anything.</summary>
    public static HashReputationList Empty { get; } =
        new(new Dictionary<string, ReputationEntry>(StringComparer.OrdinalIgnoreCase));

    /// <summary>The entries in the list, keyed by their lower-case hash.</summary>
    public IReadOnlyDictionary<string, ReputationEntry> Entries => _entries;

    /// <summary>How many entries the list holds.</summary>
    public int Count => _entries.Count;

    /// <summary>
    /// Looks up a hash. The comparison ignores case because hash values are written in
    /// different cases in the wild.
    /// </summary>
    public ReputationEntry? Lookup(string? sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return null;
        return _entries.TryGetValue(sha256.Trim(), out var entry) ? entry : null;
    }

    /// <summary>
    /// Builds a list from entries the caller already holds.
    /// </summary>
    public static HashReputationList FromEntries(IEnumerable<ReputationEntry> entries)
    {
        var map = new Dictionary<string, ReputationEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Sha256)) continue;
            map[entry.Sha256.Trim()] = entry;
        }

        return new HashReputationList(map);
    }

    /// <summary>
    /// The list Lumen starts with. It holds the EICAR test file, which is harmless, and
    /// nothing else. Everything else a user wants to block belongs in the list file, so
    /// that it is visible and can be changed.
    /// </summary>
    public static HashReputationList CreateDefault() => FromEntries(
    [
        new ReputationEntry(
            EicarSha256,
            "EICAR antivirus test file",
            FindingCategory.TestSignature,
            Confidence.Definitive,
            "test.eicar-hash",
            "built-in")
    ]);

    /// <summary>
    /// Loads a list from a file. The file is parsed strictly: one bad entry rejects the
    /// whole file, and the problem is reported rather than thrown.
    /// </summary>
    public static ReputationListLoadResult LoadFromFile(string path, ILog? log = null)
    {
        string source;
        try
        {
            source = Path.GetFullPath(path);
            if (!File.Exists(source)) return ReputationListLoadResult.Failure("The reputation list file does not exist.");

            var text = File.ReadAllText(source);
            return Parse(text, source, log);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            log?.Warn("Detection.Reputation", "The reputation list could not be read.", ex);
            return ReputationListLoadResult.Failure("The reputation list file could not be read.");
        }
    }

    /// <summary>
    /// Loads the list from the application data folder. The caller decides where that
    /// folder is; Lumen.Core never picks a location on its own.
    /// </summary>
    public static ReputationListLoadResult LoadForAppPaths(AppPaths paths, ILog? log = null) =>
        LoadFromFile(Path.Combine(paths.Root, DefaultFileName), log);

    /// <summary>
    /// Parses a list from text. Exposed so a caller can validate a file before installing it.
    /// </summary>
    public static ReputationListLoadResult Parse(string json, string source, ILog? log = null)
    {
        ReputationFile? file;
        try
        {
            file = JsonSerializer.Deserialize<ReputationFile>(json, ReputationJson.Options);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
        {
            log?.Warn("Detection.Reputation", "The reputation list is malformed and was rejected in full.");
            return ReputationListLoadResult.Failure("The reputation list is not valid JSON.");
        }

        if (file is null)
        {
            log?.Warn("Detection.Reputation", "The reputation list was empty and was rejected.");
            return ReputationListLoadResult.Failure("The reputation list contained no data.");
        }

        if (file.SchemaVersion != CurrentSchemaVersion)
        {
            log?.Warn(
                "Detection.Reputation",
                $"The reputation list uses schema version {file.SchemaVersion} but this build understands version {CurrentSchemaVersion}.");
            return ReputationListLoadResult.Failure(
                $"The reputation list uses schema version {file.SchemaVersion}; this build understands version {CurrentSchemaVersion}.");
        }

        var entries = new Dictionary<string, ReputationEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var dto in file.Entries ?? [])
        {
            if (string.IsNullOrWhiteSpace(dto.Sha256)) continue;

            var hash = dto.Sha256.Trim().ToLowerInvariant();
            if (hash.Length != 64 || !hash.All(Uri.IsHexDigit))
            {
                log?.Warn("Detection.Reputation", "A reputation entry did not hold a SHA-256 hash; the whole list was rejected.");
                return ReputationListLoadResult.Failure("A reputation entry did not hold a valid SHA-256 hash.");
            }

            var category = FindingCategory.Reputation;
            if (!string.IsNullOrWhiteSpace(dto.Category) &&
                !Enum.TryParse(dto.Category, ignoreCase: true, out category))
            {
                log?.Warn("Detection.Reputation", "A reputation entry used an unknown category; the whole list was rejected.");
                return ReputationListLoadResult.Failure("A reputation entry used an unknown category.");
            }

            var confidence = Confidence.High;
            if (!string.IsNullOrWhiteSpace(dto.Confidence) &&
                !Enum.TryParse(dto.Confidence, ignoreCase: true, out confidence))
            {
                log?.Warn("Detection.Reputation", "A reputation entry used an unknown confidence level; the whole list was rejected.");
                return ReputationListLoadResult.Failure("A reputation entry used an unknown confidence level.");
            }

            var ruleId = string.IsNullOrWhiteSpace(dto.RuleId) ? "reputation.known-bad-hash" : dto.RuleId.Trim();
            var label = string.IsNullOrWhiteSpace(dto.Label) ? "File listed in the local hash list" : dto.Label.Trim();

            entries[hash] = new ReputationEntry(
                hash,
                label,
                category,
                confidence,
                ruleId,
                string.IsNullOrWhiteSpace(dto.Source) ? source : dto.Source.Trim());
        }

        return ReputationListLoadResult.Success(entries);
    }

    /// <summary>
    /// Produces the text of a starter list file. The application uses it to create the
    /// list on first run so the user has something to look at and add to.
    /// </summary>
    public static string BuildTemplateText()
    {
        var file = new ReputationFile
        {
            SchemaVersion = CurrentSchemaVersion,
            Entries =
            [
                new ReputationEntryDto
                {
                    Sha256 = EicarSha256,
                    Label = "EICAR antivirus test file",
                    Category = "TestSignature",
                    Confidence = "Definitive",
                    RuleId = "test.eicar-hash",
                    Source = "built-in"
                }
            ]
        };

        return JsonSerializer.Serialize(file, ReputationJson.Options);
    }
}

/// <summary>The on-disk shape of the reputation list file.</summary>
internal sealed class ReputationFile
{
    public int SchemaVersion { get; set; } = HashReputationList.CurrentSchemaVersion;

    public List<ReputationEntryDto> Entries { get; set; } = [];
}

/// <summary>The on-disk shape of one reputation entry.</summary>
internal sealed class ReputationEntryDto
{
    public string Sha256 { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Confidence { get; set; } = string.Empty;

    public string RuleId { get; set; } = string.Empty;

    public string Source { get; set; } = string.Empty;
}

/// <summary>
/// JSON settings for the reputation list. Property names are matched case-insensitively so
/// a hand-edited file does not fail on a stray capital letter.
/// </summary>
internal static class ReputationJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        MaxDepth = 16
    };
}
