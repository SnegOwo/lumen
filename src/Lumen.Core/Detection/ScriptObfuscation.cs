namespace Lumen.Core.Detection;

/// <summary>
/// The individual signals that make a script look obfuscated. They are reported separately
/// so a person can see exactly which habit of the script triggered the rule.
/// </summary>
/// <param name="Base64DecodeCalls">How many times the script decodes base64 data.</param>
/// <param name="LongestBase64Literal">The length of the longest base64-looking run of characters.</param>
/// <param name="CharArrayCasts">How many times the script casts characters into an array.</param>
/// <param name="ConcatenatedFragments">How many times the script builds a string by gluing quoted pieces together.</param>
/// <param name="UsesEncodedCommand">True when an encoded-command switch is present.</param>
/// <param name="UsesHiddenWindow">True when a hidden-window switch is present.</param>
/// <param name="UsesAmsiBypassMarker">True when a marker of antimalware interface tampering is present.</param>
public sealed record ScriptObfuscationSignals(
    int Base64DecodeCalls,
    int LongestBase64Literal,
    int CharArrayCasts,
    int ConcatenatedFragments,
    bool UsesEncodedCommand,
    bool UsesHiddenWindow,
    bool UsesAmsiBypassMarker);

/// <summary>
/// Measures the habits of a script that are used to hide what it does. Every measure is a
/// count or a flag, so a script can be described by numbers rather than by a verdict.
/// </summary>
public static class ScriptObfuscation
{
    /// <summary>The length at which a run of base64-looking characters is considered notable.</summary>
    public const int LongBase64LiteralLength = 120;

    /// <summary>
    /// Counts the signals in already lower-cased script text.
    /// </summary>
    public static ScriptObfuscationSignals Analyze(string lowerText)
    {
        if (string.IsNullOrEmpty(lowerText))
            return new ScriptObfuscationSignals(0, 0, 0, 0, false, false, false);

        var base64Calls = CountOccurrences(lowerText, "frombase64string")
                        + CountOccurrences(lowerText, "frombase64 ")
                        + CountOccurrences(lowerText, "[convert]::frombase64string");

        var longestBase64 = LongestBase64Run(lowerText);
        var charCasts = CountOccurrences(lowerText, "[char]")
                      + CountOccurrences(lowerText, "char[]")
                      + CountOccurrences(lowerText, "-join");

        var concatenations = CountConcatenations(lowerText);

        var encodedCommand = lowerText.Contains("-encodedcommand", StringComparison.Ordinal)
                          || lowerText.Contains("-enc ", StringComparison.Ordinal)
                          || lowerText.Contains("-ec ", StringComparison.Ordinal);

        var hiddenWindow = lowerText.Contains("-w hidden", StringComparison.Ordinal)
                        || lowerText.Contains("-windowstyle hidden", StringComparison.Ordinal)
                        || lowerText.Contains("-windowstyle", StringComparison.Ordinal);

        var amsiBypass = lowerText.Contains("amsiutils", StringComparison.Ordinal)
                       || lowerText.Contains("amsiinitfailed", StringComparison.Ordinal)
                       || lowerText.Contains("amsiscanbuffer", StringComparison.Ordinal)
                       || lowerText.Contains("amsiinitialize", StringComparison.Ordinal);

        return new ScriptObfuscationSignals(
            base64Calls,
            longestBase64,
            charCasts,
            concatenations,
            encodedCommand,
            hiddenWindow,
            amsiBypass);
    }

    /// <summary>
    /// Counts how many times a token appears in the text.
    /// </summary>
    public static int CountOccurrences(string text, string token)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(token)) return 0;

        var count = 0;
        var index = 0;
        while ((index = text.IndexOf(token, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += token.Length;
        }

        return count;
    }

    /// <summary>
    /// Finds the longest run of characters that could be a base64 payload. A run has to be
    /// long and either contain a base64-only symbol or be a multiple of four, which keeps
    /// ordinary words and hashes from being counted.
    /// </summary>
    public static int LongestBase64Run(string text)
    {
        var longest = 0;
        var run = 0;
        var sawSymbol = false;
        var sawUpper = false;
        var sawLower = false;

        foreach (var character in text)
        {
            var isBase64 = character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '+' or '/';
            if (!isBase64)
            {
                longest = Math.Max(longest, Qualify(run, sawSymbol, sawUpper, sawLower));
                run = 0;
                sawSymbol = false;
                sawUpper = false;
                sawLower = false;
                continue;
            }

            run++;
            if (character is '+' or '/') sawSymbol = true;
            if (character is >= 'a' and <= 'z') sawLower = true;
            if (character is >= 'A' and <= 'Z') sawUpper = true;
        }

        return Math.Max(longest, Qualify(run, sawSymbol, sawUpper, sawLower));
    }

    private static int Qualify(int run, bool sawSymbol, bool sawUpper, bool sawLower)
    {
        if (run < LongBase64LiteralLength) return 0;
        if (!sawUpper || !sawLower) return 0;
        return sawSymbol || run % 4 == 0 ? run : 0;
    }

    /// <summary>
    /// Counts the places where two quoted pieces of text are glued together, which is the
    /// classic way of hiding a readable string from a naive text search.
    /// </summary>
    public static int CountConcatenations(string text)
    {
        var count = 0;
        for (var index = 0; index + 2 < text.Length; index++)
        {
            var first = text[index];
            if (first is not ('"' or '\'')) continue;

            var second = text[index + 1];
            if (second != '+') continue;

            var third = text[index + 2];
            if (third is not ('"' or '\'')) continue;

            count++;
            index += 2;
        }

        return count;
    }
}
