using System.Diagnostics;
using System.Numerics;
using System.Text;
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

    /// <summary>
    /// True when the rule belongs to the AGGRESSIVE tier. Aggressive rules only run when
    /// the user has asked for maximum sensitivity, because they are noisier than the
    /// standard rules. The flag changes WHEN a rule runs, never WHETHER it is honest.
    /// </summary>
    public bool Aggressive { get; init; }

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
    private readonly IReadOnlyList<CompiledRule> _compiled;

    /// <summary>
    /// Creates an engine from an already parsed rule set. The rules are trusted because the
    /// caller parsed them.
    /// </summary>
    /// <param name="ruleSet">The rules to apply.</param>
    /// <param name="includeAggressive">
    /// True to also apply the rules that belong to the AGGRESSIVE tier. It is false by
    /// default so an aggressive rule never fires unless somebody asked for it.
    /// </param>
    public SignatureEngine(SignatureRuleSet ruleSet, bool includeAggressive = false)
    {
        _rules = includeAggressive
            ? ruleSet.Rules.ToArray()
            : ruleSet.Rules.Where(rule => !rule.Aggressive).ToArray();
        _compiled = Compile(_rules);
        Load = SignatureLoadResult.Success($"parsed rule set (schema {ruleSet.SchemaVersion})", ruleSet);
    }

    private SignatureEngine(IReadOnlyList<SignatureRule> rules, SignatureLoadResult load, bool includeAggressive)
    {
        _rules = includeAggressive
            ? rules.ToArray()
            : rules.Where(rule => !rule.Aggressive).ToArray();
        _compiled = Compile(_rules);
        Load = load;
    }

    /// <summary>How this engine was built, including any problem that was reported.</summary>
    public SignatureLoadResult Load { get; }

    /// <summary>
    /// The rules this engine applies. Aggressive rules are only in this list when the
    /// engine was built with the aggressive tier switched on.
    /// </summary>
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
    /// <param name="log">Where a problem with the embedded rules is reported.</param>
    /// <param name="includeAggressive">
    /// True to also apply the rules that belong to the AGGRESSIVE tier. It is false by
    /// default, so the aggressive rules stay out of the way until the user asks for them.
    /// </param>
    public static SignatureEngine CreateEmbedded(ILog? log = null, bool includeAggressive = false)
    {
        var result = LoadEmbedded(log);
        return result.RuleSet is null
            ? new SignatureEngine([], SignatureLoadResult.Failure("embedded", result.Problem ?? "The embedded rules could not be read."), includeAggressive)
            : new SignatureEngine(result.RuleSet.Rules, SignatureLoadResult.Success("embedded", result.RuleSet), includeAggressive);
    }

    /// <summary>
    /// Creates the engine, preferring a rule file supplied by the caller and falling back to
    /// the embedded rule set. A malformed file is rejected in full: none of its rules are
    /// trusted, a warning is logged, and the problem is reported through <see cref="Load"/>.
    /// </summary>
    public static SignatureEngine CreateDefault(string? ruleFilePath, ILog? log = null, bool includeAggressive = false)
    {
        if (string.IsNullOrWhiteSpace(ruleFilePath)) return CreateEmbedded(log, includeAggressive);

        var full = Path.GetFullPath(ruleFilePath);
        if (!File.Exists(full)) return CreateEmbedded(log, includeAggressive);

        var result = LoadFromFile(full, log);
        if (result.Ok && result.RuleSet is not null)
            return new SignatureEngine(result.RuleSet.Rules, SignatureLoadResult.Success(full, result.RuleSet), includeAggressive);

        // Fail closed for the untrusted file: none of its rules are used. The embedded rules
        // stay in force so a broken overlay cannot silently disable detection.
        var embedded = LoadEmbedded(log);
        var embeddedRules = embedded.RuleSet?.Rules ?? [];

        return new SignatureEngine(
            embeddedRules,
            SignatureLoadResult.Failure(
                full,
                $"The rule file was rejected and none of its rules were applied. {result.Problem}"),
            includeAggressive);
    }

    /// <summary>
    /// Creates the engine from a rule file placed next to the application, falling back to
    /// the embedded rules when that file is absent.
    /// </summary>
    public static SignatureEngine CreateDefault(ILog? log = null, bool includeAggressive = false) =>
        CreateDefault(Path.Combine(AppContext.BaseDirectory, "Signatures", DefaultRuleFileName), log, includeAggressive);

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
        if (_compiled.Count == 0) return [];

        var content = probe.Content.Span;
        if (content.Length == 0) return [];

        var extension = Path.GetExtension(probe.FileName);

        // The list is only created when a rule actually fires. Most files match nothing,
        // and a scan of ten thousand files should not throw ten thousand lists away.
        List<SignatureMatch>? matches = null;

        // The lower case form of the text is built once per file and only when a rule
        // actually needs it. It used to be built again for every pattern.
        string? lowerText = null;

        foreach (var rule in _compiled)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var pattern in rule.Patterns)
            {
                if (!pattern.AppliesTo(extension)) continue;

                var offset = pattern.Match(content, probe, ref lowerText);
                if (offset < 0) continue;

                matches ??= new List<SignatureMatch>();
                matches.Add(new SignatureMatch(rule.Rule, pattern.Pattern, offset));
                break;
            }
        }

        return matches ?? (IReadOnlyList<SignatureMatch>)Array.Empty<SignatureMatch>();
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

    /// <summary>
    /// Prepares the rules once, so that matching a file never parses a pattern again.
    /// </summary>
    private static IReadOnlyList<CompiledRule> Compile(IReadOnlyList<SignatureRule> rules)
    {
        var compiled = new List<CompiledRule>(rules.Count);
        foreach (var rule in rules) compiled.Add(new CompiledRule(rule));
        return compiled;
    }

    /// <summary>
    /// A rule whose patterns are ready to be applied. The text of a pattern is turned into
    /// bytes once, when the engine is built, instead of once per inspected file.
    /// </summary>
    private sealed class CompiledRule
    {
        public CompiledRule(SignatureRule rule)
        {
            Rule = rule;

            var patterns = new List<CompiledPattern>(rule.Patterns.Count);
            foreach (var pattern in rule.Patterns) patterns.Add(new CompiledPattern(pattern));
            Patterns = patterns;
        }

        public SignatureRule Rule { get; }

        public IReadOnlyList<CompiledPattern> Patterns { get; }
    }

    /// <summary>
    /// One pattern of a rule, prepared for matching.
    /// </summary>
    private sealed class CompiledPattern
    {
        private readonly byte[]? _ascii;
        private readonly byte[]? _asciiSwapped;
        private readonly CompiledHex? _hex;
        private readonly IReadOnlyList<IReadOnlyList<string>>? _tokenGroups;

        public CompiledPattern(SignaturePattern pattern)
        {
            Pattern = pattern;

            switch (pattern.Kind)
            {
                case SignaturePatternKind.Ascii:
                {
                    var needle = Encoding.ASCII.GetBytes(pattern.Value);
                    if (needle.Length > 0)
                    {
                        _ascii = needle;
                        _asciiSwapped = pattern.CaseSensitive ? null : VectorByteSearch.SwapCase(needle);
                    }

                    break;
                }

                case SignaturePatternKind.Hex:
                {
                    if (HexPattern.TryParse(pattern.Value, out var bytes))
                    {
                        _hex = CompiledHex.Create(bytes);
                    }

                    break;
                }

                case SignaturePatternKind.TokenGroups:
                {
                    var groups = TokenGroupPattern.Parse(pattern.Value);
                    if (groups.Count > 0) _tokenGroups = groups;
                    break;
                }
            }
        }

        public SignaturePattern Pattern { get; }

        /// <summary>
        /// True when the pattern applies to a file with this extension. A pattern without
        /// an extension list applies to every file.
        /// </summary>
        public bool AppliesTo(string extension)
        {
            if (Pattern.Extensions.Count == 0) return true;
            if (string.IsNullOrEmpty(extension)) return false;

            foreach (var candidate in Pattern.Extensions)
            {
                if (string.Equals(candidate, extension, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        /// <summary>
        /// Returns the offset of the match, or -1 when the pattern does not match.
        /// </summary>
        /// <param name="content">The bytes of the file.</param>
        /// <param name="probe">The probe, used for the text sample of the token rules.</param>
        /// <param name="lowerText">
        /// The lower case form of the text sample. It is built once per file and reused by
        /// every token rule, because building it copies the whole sample.
        /// </param>
        public int Match(ReadOnlySpan<byte> content, FileProbe probe, ref string? lowerText)
        {
            switch (Pattern.Kind)
            {
                case SignaturePatternKind.Ascii:
                {
                    if (_ascii is null) return -1;
                    return Pattern.CaseSensitive
                        ? VectorByteSearch.IndexOf(content, _ascii)
                        : VectorByteSearch.IndexOfIgnoreCase(content, _ascii, _asciiSwapped!);
                }

                case SignaturePatternKind.Hex:
                {
                    if (_hex is null) return -1;
                    return _hex.Match(content);
                }

                case SignaturePatternKind.TokenGroups:
                {
                    if (_tokenGroups is null) return -1;

                    var text = probe.GetTextSample();
                    if (string.IsNullOrEmpty(text)) return -1;

                    var lower = lowerText ??= text.ToLowerInvariant();
                    foreach (var group in _tokenGroups)
                    {
                        if (!group.Any(token => lower.Contains(token, StringComparison.Ordinal))) return -1;
                    }

                    return 0;
                }

                default:
                    return -1;
            }
        }
    }

    /// <summary>
    /// A hexadecimal pattern prepared for matching.
    /// </summary>
    /// <remarks>
    /// The longest run of bytes without a wildcard is used to find the places where the
    /// pattern can start. The search for that run is a plain byte search, which the
    /// processor does several bytes at a time, and only the few places it finds are checked
    /// against the whole pattern.
    /// </remarks>
    private sealed class CompiledHex
    {
        private readonly byte[] _values;
        private readonly bool[] _wildcards;
        private readonly int _anchorOffset;
        private readonly byte[] _anchor;

        private CompiledHex(byte[] values, bool[] wildcards, int anchorOffset, byte[] anchor)
        {
            _values = values;
            _wildcards = wildcards;
            _anchorOffset = anchorOffset;
            _anchor = anchor;
        }

        public static CompiledHex Create(IReadOnlyList<HexByte> pattern)
        {
            var values = new byte[pattern.Count];
            var wildcards = new bool[pattern.Count];
            for (var index = 0; index < pattern.Count; index++)
            {
                values[index] = pattern[index].Value;
                wildcards[index] = pattern[index].IsWildcard;
            }

            // Find the longest run of bytes that have to match exactly.
            var bestOffset = -1;
            var bestLength = 0;
            var runOffset = -1;
            var runLength = 0;
            for (var index = 0; index < pattern.Count; index++)
            {
                if (wildcards[index])
                {
                    runLength = 0;
                    runOffset = -1;
                    continue;
                }

                if (runOffset < 0) runOffset = index;
                runLength++;
                if (runLength > bestLength)
                {
                    bestLength = runLength;
                    bestOffset = runOffset;
                }
            }

            if (bestOffset < 0)
            {
                // Every byte is a wildcard, so the pattern matches anywhere.
                return new CompiledHex(values, wildcards, 0, []);
            }

            var anchor = new byte[bestLength];
            Array.Copy(values, bestOffset, anchor, 0, bestLength);
            return new CompiledHex(values, wildcards, bestOffset, anchor);
        }

        public int Match(ReadOnlySpan<byte> content)
        {
            if (_values.Length == 0 || _values.Length > content.Length) return -1;
            if (_anchor.Length == 0) return 0;

            var index = VectorByteSearch.IndexOf(content, _anchor);
            while (index >= 0)
            {
                var start = index - _anchorOffset;
                if (start >= 0 && MatchesAt(content, start)) return start;

                index = VectorByteSearch.IndexOf(content, _anchor, index + 1);
            }

            return -1;
        }

        private bool MatchesAt(ReadOnlySpan<byte> content, int start)
        {
            for (var index = 0; index < _values.Length; index++)
            {
                if (_wildcards[index]) continue;
                if (content[start + index] != _values[index]) return false;
            }

            return true;
        }
    }
}

/// <summary>
/// One successful signature match. It records which rule fired, which pattern matched and
/// where, so the UI can explain the result without exposing file contents.
/// </summary>
public sealed record SignatureMatch(SignatureRule Rule, SignaturePattern Pattern, int Offset);

/// <summary>
/// Byte searches that use the vector instructions of the processor. They live next to the
/// signature engine because that is the only place that needs them: the engine runs its
/// patterns over every file it inspects, so a faster search is worth a lot of processor
/// time on a large scan. None of them allocates.
/// </summary>
internal static class VectorByteSearch
{
    private static readonly Vector<byte> FullMask = Vector.Create((byte)0x80);
    private static readonly Vector<byte> NoMask = Vector.Create((byte)0);
    private static readonly Vector<byte> FullMatch = Vector.Create((byte)1);
    private static readonly Vector<byte> NoMatch = Vector.Create((byte)0);

    /// <summary>
    /// Finds the first occurrence of a byte sequence, or -1 when it is not there.
    /// </summary>
    public static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) =>
        IndexOf(haystack, needle, 0);

    /// <summary>
    /// Finds the first occurrence of a byte sequence at or after <paramref name="from"/>.
    /// </summary>
    public static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle, int from)
    {
        if (needle.Length == 0) return from <= haystack.Length ? from : -1;
        if (needle.Length > haystack.Length) return -1;

        var limit = haystack.Length - needle.Length;
        var index = Math.Max(0, from);

        while (index <= limit)
        {
            var candidate = IndexOfByte(haystack, index, limit, needle[0], null);
            if (candidate < 0) return -1;

            if (MatchesAt(haystack, candidate, needle, null)) return candidate;
            index = candidate + 1;
        }

        return -1;
    }

    /// <summary>
    /// Finds the first occurrence of an ASCII needle, ignoring the case of letters.
    /// </summary>
    /// <param name="haystack">The bytes to search.</param>
    /// <param name="needle">The needle, in the case the rule wrote it in.</param>
    /// <param name="swappedNeedle">
    /// The needle with the case of every letter flipped. A byte matches when it is equal
    /// to one of the two, which is the same rule the byte wise search applies.
    /// </param>
    public static int IndexOfIgnoreCase(
        ReadOnlySpan<byte> haystack,
        ReadOnlySpan<byte> needle,
        byte[] swappedNeedle)
    {
        if (needle.Length == 0) return 0;
        if (needle.Length > haystack.Length) return -1;

        var limit = haystack.Length - needle.Length;
        var index = 0;

        while (index <= limit)
        {
            var candidate = IndexOfByte(haystack, index, limit, needle[0], swappedNeedle[0]);
            if (candidate < 0) return -1;

            if (MatchesAt(haystack, candidate, needle, swappedNeedle)) return candidate;
            index = candidate + 1;
        }

        return -1;
    }

    /// <summary>
    /// Flips the case of every ASCII letter and leaves every other byte alone.
    /// </summary>
    public static byte[] SwapCase(ReadOnlySpan<byte> value)
    {
        var result = new byte[value.Length];
        for (var index = 0; index < value.Length; index++) result[index] = SwapCase(value[index]);
        return result;
    }

    /// <summary>
    /// Finds the first byte at or after <paramref name="from"/> that is equal to the target.
    /// When an alternative is given, a byte with that value counts as well. Several bytes
    /// are compared at a time, which is what makes the search quick.
    /// </summary>
    private static int IndexOfByte(
        ReadOnlySpan<byte> haystack,
        int from,
        int limit,
        byte target,
        byte? alternative)
    {
        var width = Vector<byte>.Count;
        var targetVector = Vector.Create(target);
        var alternativeVector = Vector.Create(alternative ?? target);
        var index = from;

        while (index + width <= haystack.Length)
        {
            var chunk = new Vector<byte>(haystack.Slice(index, width));

            var equal = Vector.Equals(chunk, targetVector);
            if (alternative is not null) equal |= Vector.Equals(chunk, alternativeVector);

            // The lanes that matched are marked with the highest bit of their byte.
            var mask = Vector.ConditionalSelect(equal, FullMask, NoMask);
            if (!Vector.EqualsAll(mask, NoMask))
            {
                // The chunk holds at least one candidate, so the first marked lane is the
                // answer. This happens once per match, not once per chunk.
                for (var lane = 0; lane < width; lane++)
                {
                    if (mask.GetElement(lane) == 0) continue;

                    var position = index + lane;
                    return position <= limit ? position : -1;
                }
            }

            index += width;
        }

        for (; index <= limit; index++)
        {
            var value = haystack[index];
            if (value == target) return index;
            if (alternative is not null && value == alternative.Value) return index;
        }

        return -1;
    }

    /// <summary>
    /// Checks whether the needle is at the given position. Whole vectors are compared at a
    /// time and only the last few bytes are compared one by one.
    /// </summary>
    private static bool MatchesAt(
        ReadOnlySpan<byte> haystack,
        int position,
        ReadOnlySpan<byte> needle,
        byte[]? swappedNeedle)
    {
        // The last byte is checked first because it rejects most of the candidates that
        // the first byte search produces.
        var last = needle.Length - 1;
        var lastValue = haystack[position + last];
        if (lastValue != needle[last] &&
            (swappedNeedle is null || lastValue != swappedNeedle[last])) return false;
        if (needle.Length == 1) return true;

        var width = Vector<byte>.Count;
        var offset = 0;

        while (offset + width <= needle.Length)
        {
            var chunk = new Vector<byte>(haystack.Slice(position + offset, width));
            var expected = new Vector<byte>(needle.Slice(offset, width));

            var equal = Vector.Equals(chunk, expected);
            if (swappedNeedle is not null)
            {
                var swapped = new Vector<byte>(swappedNeedle.AsSpan(offset, width));
                equal |= Vector.Equals(chunk, swapped);
            }

            // Every lane of the comparison has to be true.
            var lanes = Vector.ConditionalSelect(equal, FullMatch, NoMatch);
            if (!Vector.EqualsAll(lanes, FullMatch)) return false;
            offset += width;
        }

        for (; offset < last; offset++)
        {
            var value = haystack[position + offset];
            if (value == needle[offset]) continue;
            if (swappedNeedle is not null && value == swappedNeedle[offset]) continue;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Flips the case of a single ASCII letter and leaves every other byte alone.
    /// </summary>
    private static byte SwapCase(byte value)
    {
        if (value is >= (byte)'A' and <= (byte)'Z') return (byte)(value + 32);
        if (value is >= (byte)'a' and <= (byte)'z') return (byte)(value - 32);
        return value;
    }
}