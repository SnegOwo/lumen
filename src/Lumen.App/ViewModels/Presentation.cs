using Lumen.App.Localization;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

/// <summary>
/// All user-facing wording lives here so the views and view models never build
/// strings inline. The labels describe what Lumen OBSERVED, never what it proved:
/// a category is a kind of signal, not a verdict.
///
/// <para>
/// The wording itself is held by <see cref="Text"/> in
/// <c>Lumen.App.Localization</c>, which carries both shipped languages. This class
/// stays the single entry point used by the view models, so switching the language
/// changes every label at once.
/// </para>
/// </summary>
public static class Presentation
{
    /// <summary>
    /// Names the kind of signal behind a finding. "Test signature" is deliberately
    /// distinct from everything else so nobody mistakes EICAR for a malware hit.
    /// </summary>
    public static string Category(FindingCategory category) => Text.Category(category);

    /// <summary>
    /// A short explanation of what a category means, for tooltips and the rule list.
    /// </summary>
    public static string CategoryHint(FindingCategory category) => Text.CategoryHint(category);

    /// <summary>How confident the rule engine is.</summary>
    public static string ConfidenceText(Confidence confidence) => Text.Confidence(confidence);

    /// <summary>The name of a scan scope.</summary>
    public static string Scope(ScanScopeKind scope) => Text.Scope(scope);

    /// <summary>Why an item could not be inspected.</summary>
    public static string ErrorKind(ScanErrorKind kind) => Text.ErrorKind(kind);

    /// <summary>
    /// Formats a count with a correctly pluralised noun, in the current language.
    /// The codebase previously had three different pluralisation approaches, one of
    /// which produced "1 scan(s)".
    /// </summary>
    public static string Count(long value, string singular, string? plural = null)
    {
        // The caller only knows the English wording. When it is one of the nouns the
        // application counts, the French form is used instead of a naive translation.
        if (Text.TryGetNoun(singular, out var noun)) return Text.Count(value, noun);

        return value == 1 ? "1 " + singular : value.ToString("N0") + " " + (plural ?? Plural(singular));
    }

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

    /// <summary>Removes control characters and clips a piece of untrusted text.</summary>
    public static string Sanitize(string? value, int max = 300) => DisplayText.Sanitize(value, max);

    /// <summary>Removes control characters from a path and clips it.</summary>
    public static string SanitizePath(string? value, int maxLength = 520) =>
        DisplayText.SanitizePath(value, maxLength);
}
