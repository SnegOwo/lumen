using System.Text.Json;
using Lumen.Core.Models;

namespace Lumen.Core.Detection;

/// <summary>
/// A single byte in a hexadecimal signature. A wildcard byte matches any value.
/// </summary>
/// <param name="Value">The byte value, or zero when the byte is a wildcard.</param>
/// <param name="IsWildcard">True when the pattern used "?" or "??" for this position.</param>
public readonly record struct HexByte(byte Value, bool IsWildcard);

/// <summary>
/// Parses and applies hexadecimal byte patterns such as "4D 5A ?? 50 45".
/// </summary>
public static class HexPattern
{
    /// <summary>
    /// Parses a hexadecimal pattern. Returns false when the text contains anything that is
    /// not a byte pair or a wildcard, so a malformed pattern can be rejected instead of
    /// quietly matching nothing.
    /// </summary>
    public static bool TryParse(string? text, out IReadOnlyList<HexByte> bytes)
    {
        bytes = [];
        if (string.IsNullOrWhiteSpace(text)) return false;

        var result = new List<HexByte>();
        foreach (var token in text.Split([' ', '\t', '-'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (token is "?" or "??")
            {
                result.Add(new HexByte(0, true));
                continue;
            }

            if (token.Length != 2 || !byte.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out var value))
                return false;

            result.Add(new HexByte(value, false));
        }

        if (result.Count == 0) return false;

        bytes = result;
        return true;
    }
}

/// <summary>
/// Parses the token-group syntax used by signature rules: groups are separated by "|"
/// and the alternatives inside a group are separated by ",".
/// </summary>
public static class TokenGroupPattern
{
    /// <summary>
    /// Parses a token-group expression into groups of alternatives. Returns an empty list
    /// when the expression is empty or malformed.
    /// </summary>
    public static IReadOnlyList<IReadOnlyList<string>> Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return [];

        var groups = new List<IReadOnlyList<string>>();
        foreach (var rawGroup in text.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var alternatives = rawGroup
                .Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(token => token.Trim().ToLowerInvariant())
                .Where(token => token.Length > 0)
                .ToArray();

            if (alternatives.Length == 0) return [];
            groups.Add(alternatives);
        }

        return groups;
    }
}

/// <summary>
/// The on-disk shape of a rule file. It is kept separate from <see cref="SignatureRule"/>
/// so the file format can evolve without changing the in-memory model.
/// </summary>
internal sealed class SignatureRuleFile
{
    public int SchemaVersion { get; set; }

    public List<SignatureRuleDto> Rules { get; set; } = [];

    public static SignatureRuleFile? Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;

        var file = JsonSerializer.Deserialize<SignatureRuleFile>(json, SignatureJson.Options);
        if (file is null) return null;
        if (file.Rules is null) file.Rules = [];
        return file;
    }
}

/// <summary>The on-disk shape of one rule.</summary>
internal sealed class SignatureRuleDto
{
    public string Id { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Confidence { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string Detail { get; set; } = string.Empty;

    public string Advice { get; set; } = string.Empty;

    /// <summary>
    /// True when the rule belongs to the AGGRESSIVE tier. The flag is optional so a rule
    /// file written before the tier existed keeps working unchanged.
    /// </summary>
    public bool Aggressive { get; set; }

    public List<SignaturePatternDto> Patterns { get; set; } = [];

    /// <summary>
    /// Turns the file entry into a rule, or explains why the entry cannot be used.
    /// </summary>
    public (SignatureRule? Rule, string? Problem) Build(string source)
    {
        if (string.IsNullOrWhiteSpace(Id)) return (null, $"A rule in \"{source}\" has no identifier.");
        if (string.IsNullOrWhiteSpace(Title)) return (null, $"Rule \"{Id}\" has no title.");
        if (string.IsNullOrWhiteSpace(Description)) return (null, $"Rule \"{Id}\" has no description.");
        if (string.IsNullOrWhiteSpace(Detail)) return (null, $"Rule \"{Id}\" has no detail text.");
        if (string.IsNullOrWhiteSpace(Advice)) return (null, $"Rule \"{Id}\" has no advice text.");
        if (Patterns is null || Patterns.Count == 0) return (null, $"Rule \"{Id}\" has no patterns.");

        if (!Enum.TryParse<FindingCategory>(Category, ignoreCase: true, out var category))
            return (null, $"Rule \"{Id}\" uses an unknown category.");
        if (!Enum.TryParse<Confidence>(Confidence, ignoreCase: true, out var confidence))
            return (null, $"Rule \"{Id}\" uses an unknown confidence level.");

        var patterns = new List<SignaturePattern>();
        foreach (var dto in Patterns)
        {
            if (!Enum.TryParse<SignaturePatternKind>(dto.Kind, ignoreCase: true, out var kind))
                return (null, $"Rule \"{Id}\" uses an unknown pattern kind.");
            if (string.IsNullOrWhiteSpace(dto.Value)) return (null, $"Rule \"{Id}\" has an empty pattern.");

            if (kind == SignaturePatternKind.Hex && !HexPattern.TryParse(dto.Value, out _))
                return (null, $"Rule \"{Id}\" has a malformed hexadecimal pattern.");

            if (kind == SignaturePatternKind.TokenGroups && TokenGroupPattern.Parse(dto.Value).Count == 0)
                return (null, $"Rule \"{Id}\" has a malformed token pattern.");

            var extensions = (dto.Extensions ?? [])
                .Where(extension => !string.IsNullOrWhiteSpace(extension))
                .Select(extension => extension.Trim().ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            patterns.Add(new SignaturePattern
            {
                Kind = kind,
                Value = dto.Value,
                CaseSensitive = dto.CaseSensitive,
                Extensions = extensions
            });
        }

        var rule = new SignatureRule
        {
            Id = Id.Trim(),
            Title = Title.Trim(),
            Category = category,
            Confidence = confidence,
            Description = Description.Trim(),
            Detail = Detail.Trim(),
            Advice = Advice.Trim(),
            Aggressive = Aggressive,
            Patterns = patterns
        };

        return (rule, null);
    }
}

/// <summary>The on-disk shape of one pattern.</summary>
internal sealed class SignaturePatternDto
{
    public string Kind { get; set; } = string.Empty;

    public string Value { get; set; } = string.Empty;

    public bool CaseSensitive { get; set; }

    public List<string> Extensions { get; set; } = [];
}

/// <summary>
/// JSON settings used for rule files. Property names are matched case-insensitively so a
/// hand-edited file does not fail on a stray capital letter.
/// </summary>
internal static class SignatureJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        MaxDepth = 32
    };
}
