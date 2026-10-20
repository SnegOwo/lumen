using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

/// <summary>
/// All user-facing wording lives here so the views and view models never build
/// strings inline. The labels describe what Lumen OBSERVED, never what it proved:
/// a category is a kind of signal, not a verdict.
/// </summary>
public static class Presentation
{
    /// <summary>
    /// Names the kind of signal behind a finding. "Test signature" is deliberately
    /// distinct from everything else so nobody mistakes EICAR for a malware hit.
    /// </summary>
    public static string Category(FindingCategory category) => category switch
    {
        FindingCategory.TestSignature => "Test signature",
        FindingCategory.Signature => "Signature match",
        FindingCategory.Behavior => "Behaviour",
        FindingCategory.Reputation => "Known bad hash",
        _ => "Heuristic"
    };

    /// <summary>
    /// A short explanation of what a category means, for tooltips and the rule list.
    /// </summary>
    public static string CategoryHint(FindingCategory category) => category switch
    {
        FindingCategory.TestSignature => "A harmless, industry-standard test artifact. It verifies the scanner plumbing only.",
        FindingCategory.Signature => "An exact byte or pattern match against a known signature.",
        FindingCategory.Behavior => "Indicators of packing, obfuscation or suspicious API use. Not proof of malware.",
        FindingCategory.Reputation => "The file hash is on the local known-bad list. Lumen never checks hashes online.",
        _ => "A combination of suspicious characteristics. Not proof of malware."
    };

    public static string ConfidenceText(Confidence confidence) => confidence switch
    {
        Confidence.Definitive => "Definitive",
        Confidence.High => "High confidence",
        Confidence.Medium => "Medium confidence",
        _ => "Low confidence"
    };

    public static string Scope(ScanScopeKind scope) => scope switch
    {
        ScanScopeKind.Quick => "Quick scan",
        ScanScopeKind.FullUserProfile => "Full profile scan",
        ScanScopeKind.Folder => "Folder scan",
        _ => "File scan"
    };

    public static string ErrorKind(ScanErrorKind kind) => kind switch
    {
        ScanErrorKind.AccessDenied => "Access denied",
        ScanErrorKind.NotFound => "Not found",
        ScanErrorKind.InUse => "In use",
        ScanErrorKind.PathTooLong => "Path too long",
        ScanErrorKind.InvalidPath => "Invalid path",
        ScanErrorKind.ReparsePoint => "Link skipped",
        ScanErrorKind.Offline => "Cloud placeholder",
        ScanErrorKind.Io => "Read error",
        ScanErrorKind.Security => "Blocked by policy",
        _ => "Skipped"
    };

    /// <summary>
    /// Formats a count with a correctly pluralised noun. The codebase previously had
    /// three different pluralisation approaches, one of which produced "1 scan(s)".
    /// </summary>
    public static string Count(long value, string singular, string? plural = null) =>
        value == 1 ? "1 " + singular : value.ToString("N0") + " " + (plural ?? Plural(singular));

    /// <summary>
    /// Pluralises an English noun. Handles the common -s, -es and -y cases so callers
    /// do not have to pass a plural for ordinary words.
    /// </summary>
    public static string Plural(string singular)
    {
        if (string.IsNullOrWhiteSpace(singular)) return string.Empty;

        var lower = singular.ToLowerInvariant();
        if (lower.EndsWith("s", StringComparison.Ordinal) ||
            lower.EndsWith("x", StringComparison.Ordinal) ||
            lower.EndsWith("z", StringComparison.Ordinal) ||
            lower.EndsWith("ch", StringComparison.Ordinal) ||
            lower.EndsWith("sh", StringComparison.Ordinal))
        {
            return singular + "es";
        }

        if (lower.EndsWith("y", StringComparison.Ordinal) &&
            singular.Length > 1 &&
            !IsVowel(singular[^2]))
        {
            return singular[..^1] + "ies";
        }

        return singular + "s";
    }

    private static bool IsVowel(char character) => character is 'a' or 'e' or 'i' or 'o' or 'u';

    public static string Sanitize(string? value, int max = 300) => DisplayText.Sanitize(value, max);

    public static string SanitizePath(string? value, int maxLength = 520) =>
        DisplayText.SanitizePath(value, maxLength);
}
