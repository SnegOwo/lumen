using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// How a signature pattern is written. The three kinds cover the cases Lumen actually
/// needs: readable text, exact bytes with wildcards, and combinations of tokens.
/// </summary>
public enum SignaturePatternKind
{
    /// <summary>
    /// A plain ASCII string that must appear somewhere in the file. Matching ignores case
    /// unless the rule asks for exact case.
    /// </summary>
    Ascii,

    /// <summary>
    /// A byte pattern written as hexadecimal pairs, for example "4D 5A ?? 50 45". The
    /// tokens "??" and "?" match any single byte.
    /// </summary>
    Hex,

    /// <summary>
    /// Groups of alternative tokens. Every group must be satisfied by at least one of its
    /// alternatives, so "a,b|c,d" means (a or b) and (c or d).
    /// </summary>
    TokenGroups
}

/// <summary>
/// One pattern inside a signature rule. A rule fires when any of its patterns matches.
/// </summary>
public sealed record SignaturePattern
{
    /// <summary>How the pattern is expressed.</summary>
    public required SignaturePatternKind Kind { get; init; }

    /// <summary>
    /// The pattern body. ASCII rules hold the literal text, hexadecimal rules hold space
    /// separated byte pairs, and token-group rules hold groups separated by "|" with
    /// alternatives inside a group separated by ",".
    /// </summary>
    public required string Value { get; init; }

    /// <summary>Whether letter case must match exactly. Defaults to false.</summary>
    public bool CaseSensitive { get; init; }

    /// <summary>
    /// Optional list of file extensions the pattern applies to, for example ".ps1". An empty
    /// list means the pattern applies to every file.
    /// </summary>
    public IReadOnlyList<string> Extensions { get; init; } = [];

    /// <summary>
    /// A short human readable description of the pattern that is safe to show in the UI.
    /// It never contains file contents.
    /// </summary>
    public string Describe() => Kind switch
    {
        SignaturePatternKind.Ascii => $"text pattern \"{Value}\"",
        SignaturePatternKind.Hex => $"byte pattern {Value}",
        _ => "token combination"
    };
}

/// <summary>
/// A single data-driven detection rule. The identifier is stable so the catalogue, the
/// UI and saved history can refer to a rule that never changes meaning.
/// </summary>
public sealed record SignatureRule
{
    /// <summary>Stable rule identifier, for example "sig.upx-packer-marker".</summary>
    public required string Id { get; init; }

    /// <summary>Short title shown in the findings list.</summary>
    public required string Title { get; init; }

    /// <summary>The kind of signal the rule produces.</summary>
    public required FindingCategory Category { get; init; }

    /// <summary>How much the rule should be trusted.</summary>
    public required Confidence Confidence { get; init; }

    /// <summary>Plain-language explanation of what the rule looks for.</summary>
    public required string Description { get; init; }

    /// <summary>Plain-language explanation of what was actually observed.</summary>
    public required string Detail { get; init; }

    /// <summary>A safe next step for the user.</summary>
    public required string Advice { get; init; }

    /// <summary>The patterns that make this rule fire. Any single match is enough.</summary>
    public required IReadOnlyList<SignaturePattern> Patterns { get; init; }
}

/// <summary>
/// A parsed rule file. The schema version is recorded so a future format change can be
/// detected instead of silently misread.
/// </summary>
public sealed record SignatureRuleSet(int SchemaVersion, IReadOnlyList<SignatureRule> Rules);

/// <summary>
/// The outcome of trying to load a rule file. Failures are reported here rather than
/// thrown so a broken file can never stop the application from scanning.
/// </summary>
/// <param name="Ok">True when a complete, valid rule set was produced.</param>
/// <param name="Source">Where the rules came from, for example a file path or "embedded".</param>
/// <param name="RuleCount">How many rules were loaded.</param>
/// <param name="Problem">A plain-language description of the problem, or null on success.</param>
/// <param name="RuleSet">The parsed rules when the load succeeded, otherwise null.</param>
public sealed record SignatureLoadResult(
    bool Ok,
    string Source,
    int RuleCount,
    string? Problem,
    SignatureRuleSet? RuleSet = null)
{
    /// <summary>Creates a successful result.</summary>
    public static SignatureLoadResult Success(string source, SignatureRuleSet ruleSet) =>
        new(true, source, ruleSet.Rules.Count, null, ruleSet);

    /// <summary>Creates a failed result. No rules are trusted when this is returned.</summary>
    public static SignatureLoadResult Failure(string source, string problem) => new(false, source, 0, problem);
}

/// <summary>
/// A signature engine that matches files against data-driven rules. The rules live in a
/// JSON file so new patterns can be shipped without recompiling the application.
/// </summary>
/// <remarks>
/// <para>
/// The engine only reads the bytes the scanner already loaded (<see cref="FileProbe.Content"/>)
/// and never touches the filesystem while inspecting a file.
/// </para>
/// <para>
/// When a rule file cannot be parsed the engine fails closed: the broken file contributes
/// no rules at all, a warning is logged, and the problem is reported through
/// <see cref="Load"/> so the caller can surface it. The shipped, embedded rule set keeps
/// working so a bad overlay cannot disable the product.
/// </para>
/// </remarks>
public sealed class SignatureEngine : IScanDetector
{
    /// <summary>The schema version this build understands.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>The manifest name of the embedded default rule file.</summary>
    public const string EmbeddedResourceName = "Lumen.Core.Detection.Signatures.rules.json";

    /// <summary>The relative location of the default rule file next to the application.</summary>
    public const string DefaultRuleFileName = "rules.json";

    private readonly IReadOnlyList<SignatureRule> _rules;

    /// <summary>
    /// Creates an engine from an already parsed rule set. The rules are trusted because the
    /// caller parsed them.
    /// </summary>
    public SignatureEngine(SignatureRuleSet ruleSet)
    {
        _rules = ruleSet.Rules;
        Load = SignatureLoadResult.Success($"parsed rule set (schema {ruleSet.SchemaVersion})", ruleSet);
    }

    private SignatureEngine(IReadOnlyList<SignatureRule> rules, SignatureLoadResult load)
    {
        _rules = rules;
        Load = load;
    }

    /// <summary>How this engine was built, including any problem that was reported.</summary>
    public SignatureLoadResult Load { get; }

    /// <summary>The rules this engine applies.</summary>
    public IReadOnlyList<SignatureRule> Rules => _rules;

    /// <inheritdoc />
    public string Id => "signature.engine";

    /// <inheritdoc />
    public string Name => "Signature rules";

    /// <inheritdoc />
    public string Description =>
        "Applies the shipped and user-supplied signature rules to the bytes the scanner already read. A signature match says a known pattern is present; it does not by itself say the file is malware.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Signature;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <summary>
    /// Creates the engine from the rule set embedded in the assembly. No file system access
    /// happens, so this is safe to call while a scan is running.
    /// </summary>
    public static SignatureEngine CreateEmbedded(ILog? log = null)
    {
        var result = LoadEmbedded(log);
        return result.RuleSet is null
            ? new SignatureEngine([], SignatureLoadResult.Failure("embedded", result.Problem ?? "The embedded rules could not be read."))
            : new SignatureEngine(result.RuleSet.Rules, SignatureLoadResult.Success("embedded", result.RuleSet));
    }

    /// <summary>
    /// Creates the engine, preferring a rule file supplied by the caller and falling back to
    /// the embedded rule set. A malformed file is rejected in full: none of its rules are
    /// trusted, a warning is logged, and the problem is reported through <see cref="Load"/>.
    /// </summary>
    public static SignatureEngine CreateDefault(string? ruleFilePath, ILog? log = null)
    {
        if (string.IsNullOrWhiteSpace(ruleFilePath)) return CreateEmbedded(log);

        var full = Path.GetFullPath(ruleFilePath);
        if (!File.Exists(full)) return CreateEmbedded(log);

        var result = LoadFromFile(full, log);
        if (result.Ok && result.RuleSet is not null)
            return new SignatureEngine(result.RuleSet.Rules, SignatureLoadResult.Success(full, result.RuleSet));

        // Fail closed for the untrusted file: none of its rules are used. The embedded rules
        // stay in force so a broken overlay cannot silently disable detection.
        var embedded = LoadEmbedded(log);
        var embeddedRules = embedded.RuleSet?.Rules ?? [];

        return new SignatureEngine(
            embeddedRules,
            SignatureLoadResult.Failure(
                full,
                $"The rule file was rejected and none of its rules were applied. {result.Problem}"));
    }

    /// <summary>
    /// Creates the engine from a rule file placed next to the application, falling back to
    /// the embedded rules when that file is absent.
    /// </summary>
    public static SignatureEngine CreateDefault(ILog? log = null) =>
        CreateDefault(Path.Combine(AppContext.BaseDirectory, "Signatures", DefaultRuleFileName), log);

    /// <summary>
    /// Parses a rule file from disk. The file is parsed strictly: one bad rule rejects the
    /// whole file so a partially understood rule set is never applied.
    /// </summary>
    public static SignatureLoadResult LoadFromFile(string path, ILog? log = null)
    {
        var source = path;
        try
        {
            source = Path.GetFullPath(path);
            if (!File.Exists(source)) return SignatureLoadResult.Failure(source, "The rule file does not exist.");
            var text = File.ReadAllText(source);
            return Parse(text, source, log);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            log?.Warn("Detection.Signature", "The signature rule file could not be read.", ex);
            return SignatureLoadResult.Failure(source, "The rule file could not be read.");
        }
    }

    /// <summary>
    /// Reads and parses the rule set embedded in the assembly.
    /// </summary>
    public static SignatureLoadResult LoadEmbedded(ILog? log = null)
    {
        try
        {
            using var stream = typeof(SignatureEngine).Assembly.GetManifestResourceStream(EmbeddedResourceName);
            if (stream is null)
            {
                log?.Warn("Detection.Signature", "The embedded signature rules were not found.");
                return SignatureLoadResult.Failure("embedded", "The embedded rule set is missing.");
            }

            using var reader = new StreamReader(stream);
            return Parse(reader.ReadToEnd(), "embedded", log);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or NotSupportedException)
        {
            log?.Warn("Detection.Signature", "The embedded signature rules could not be read.", ex);
            return SignatureLoadResult.Failure("embedded", "The embedded rule set could not be read.");
        }
    }

    /// <summary>
    /// Parses rule text. Exposed so callers can validate a file before installing it.
    /// </summary>
    public static SignatureLoadResult Parse(string json, string source, ILog? log = null)
    {
        SignatureRuleFile? file;
        try
        {
            file = SignatureRuleFile.Parse(json);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or FormatException or ArgumentException)
        {
            log?.Warn("Detection.Signature", "The signature rule file is malformed and was rejected in full.");
            return SignatureLoadResult.Failure(source, "The rule file is not valid JSON or is not shaped like a rule file.");
        }

        if (file is null)
        {
            log?.Warn("Detection.Signature", "The signature rule file was empty and was rejected.");
            return SignatureLoadResult.Failure(source, "The rule file contained no rules.");
        }

        if (file.SchemaVersion != CurrentSchemaVersion)
        {
            log?.Warn(
                "Detection.Signature",
                $"The signature rule file uses schema version {file.SchemaVersion} but this build understands version {CurrentSchemaVersion}.");
            return SignatureLoadResult.Failure(
                source,
                $"The rule file uses schema version {file.SchemaVersion}; this build understands version {CurrentSchemaVersion}.");
        }

        var rules = new List<SignatureRule>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var dto in file.Rules)
        {
            if (dto is null)
            {
                log?.Warn("Detection.Signature", "A signature rule was empty; the whole rule file was rejected.");
                return SignatureLoadResult.Failure(source, "The rule file contains an empty rule.");
            }

            var built = dto.Build(source);
            if (built.Problem is not null)
            {
                log?.Warn("Detection.Signature", "A signature rule was malformed; the whole rule file was rejected.");
                return SignatureLoadResult.Failure(source, built.Problem);
            }

            if (!seen.Add(built.Rule!.Id))
            {
                log?.Warn("Detection.Signature", "A signature rule used a duplicate identifier; the whole rule file was rejected.");
                return SignatureLoadResult.Failure(source, $"Two rules share the identifier \"{built.Rule!.Id}\".");
            }

            rules.Add(built.Rule);
        }

        if (rules.Count == 0)
        {
            log?.Warn("Detection.Signature", "The signature rule file contained no usable rules.");
            return SignatureLoadResult.Failure(source, "The rule file contained no usable rules.");
        }

        return SignatureLoadResult.Success(source, new SignatureRuleSet(file.SchemaVersion, rules));
    }

    /// <summary>
    /// Tests the rules against a probe without producing findings. Useful for diagnostics
    /// and for the unit tests that exercise the engine directly.
    /// </summary>
    public IReadOnlyList<SignatureMatch> Match(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_rules.Count == 0) return [];

        var content = probe.Content.Span;
        if (content.Length == 0) return [];

        var extension = Path.GetExtension(probe.FileName);
        var matches = new List<SignatureMatch>();

        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var pattern in rule.Patterns)
            {
                if (!AppliesToExtension(pattern, extension)) continue;

                var offset = MatchPattern(pattern, content, probe);
                if (offset < 0) continue;

                matches.Add(new SignatureMatch(rule, pattern, offset));
                break;
            }
        }

        return matches;
    }

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        foreach (var match in Match(probe, cancellationToken))
        {
            yield return new Finding
            {
                RuleId = match.Rule.Id,
                Title = match.Rule.Title,
                Category = match.Rule.Category,
                Confidence = match.Rule.Confidence,
                Summary = match.Rule.Description,
                Detail = $"{match.Rule.Detail} The {match.Pattern.Describe()} matched at byte offset {match.Offset}.",
                Advice = match.Rule.Advice
            };
        }
    }

    private static bool AppliesToExtension(SignaturePattern pattern, string extension)
    {
        if (pattern.Extensions.Count == 0) return true;
        if (string.IsNullOrEmpty(extension)) return false;

        foreach (var candidate in pattern.Extensions)
        {
            if (string.Equals(candidate, extension, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    private static int MatchPattern(SignaturePattern pattern, ReadOnlySpan<byte> content, FileProbe probe)
    {
        switch (pattern.Kind)
        {
            case SignaturePatternKind.Ascii:
            {
                var needle = System.Text.Encoding.ASCII.GetBytes(pattern.Value);
                if (needle.Length == 0) return -1;
                return ByteSearch.IndexOfAscii(content, needle, pattern.CaseSensitive);
            }

            case SignaturePatternKind.Hex:
            {
                if (!HexPattern.TryParse(pattern.Value, out var bytes)) return -1;
                return MatchHex(content, bytes);
            }

            case SignaturePatternKind.TokenGroups:
            {
                var text = probe.GetTextSample();
                if (string.IsNullOrEmpty(text)) return -1;
                var groups = TokenGroupPattern.Parse(pattern.Value);
                if (groups.Count == 0) return -1;

                var lower = text.ToLowerInvariant();
                foreach (var group in groups)
                {
                    if (!group.Any(token => lower.Contains(token, StringComparison.Ordinal))) return -1;
                }

                return 0;
            }

            default:
                return -1;
        }
    }

    private static int MatchHex(ReadOnlySpan<byte> content, IReadOnlyList<HexByte> pattern)
    {
        if (pattern.Count == 0 || pattern.Count > content.Length) return -1;

        var first = pattern[0];
        var limit = content.Length - pattern.Count;

        for (var start = 0; start <= limit; start++)
        {
            // Most positions fail on the first byte, so the rest is only compared there.
            if (!first.IsWildcard && content[start] != first.Value) continue;

            var matched = true;
            for (var index = 1; index < pattern.Count; index++)
            {
                var expected = pattern[index];
                if (expected.IsWildcard) continue;
                if (content[start + index] == expected.Value) continue;
                matched = false;
                break;
            }

            if (matched) return start;
        }

        return -1;
    }
}

/// <summary>
/// One successful signature match. It records which rule fired, which pattern matched and
/// where, so the UI can explain the result without exposing file contents.
/// </summary>
public sealed record SignatureMatch(SignatureRule Rule, SignaturePattern Pattern, int Offset);
