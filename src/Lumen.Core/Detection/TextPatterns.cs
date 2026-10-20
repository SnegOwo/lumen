namespace Lumen.Core.Detection;

/// <summary>
/// Small text helpers shared by the detectors that look at script and page source.
/// </summary>
/// <remarks>
/// The helpers work on the text the scanner already decoded. They never touch the file
/// system and they never execute anything they find: the text is only measured.
/// </remarks>
internal static class TextPatterns
{
    /// <summary>
    /// Finds the next call to a named function and returns the index of the parenthesis
    /// that opens its argument list.
    /// </summary>
    /// <param name="lowerText">The text, already lower-cased.</param>
    /// <param name="name">The function name, in lower case.</param>
    /// <param name="openParenthesis">The index of the opening parenthesis.</param>
    /// <remarks>
    /// The name must stand on its own: "eval" does not match "evaluate", and a name that
    /// is preceded by a letter, a digit or an underscore is part of a longer word.
    /// </remarks>
    public static bool TryFindCall(string lowerText, string name, out int openParenthesis)
    {
        openParenthesis = -1;
        if (string.IsNullOrEmpty(lowerText) || string.IsNullOrEmpty(name)) return false;

        var index = 0;
        while (index < lowerText.Length)
        {
            var found = lowerText.IndexOf(name, index, StringComparison.Ordinal);
            if (found < 0) return false;

            var end = found + name.Length;
            var before = found > 0 ? lowerText[found - 1] : ' ';
            var after = end < lowerText.Length ? lowerText[end] : ' ';

            var startsWord = !char.IsLetterOrDigit(before) && before != '_' && before != '$' && before != '>';
            var endsWord = !char.IsLetterOrDigit(after) && after != '_';

            if (startsWord && endsWord)
            {
                var cursor = end;
                while (cursor < lowerText.Length && char.IsWhiteSpace(lowerText[cursor])) cursor++;
                if (cursor < lowerText.Length && lowerText[cursor] == '(')
                {
                    openParenthesis = cursor;
                    return true;
                }
            }

            index = found + 1;
        }

        return false;
    }

    /// <summary>
    /// Returns the text between the parenthesis at <paramref name="openParenthesis"/> and the
    /// parenthesis that closes it.
    /// </summary>
    /// <param name="text">The text the call was found in.</param>
    /// <param name="openParenthesis">The index of the opening parenthesis.</param>
    /// <remarks>
    /// Quoted sections are skipped so a parenthesis inside a string does not confuse the
    /// count. When the closing parenthesis is missing the rest of the text is returned, so
    /// a truncated file still produces a result instead of an exception.
    /// </remarks>
    public static string ExtractArguments(string text, int openParenthesis)
    {
        if (openParenthesis < 0 || openParenthesis >= text.Length) return string.Empty;

        var depth = 0;
        var quote = '\0';

        for (var index = openParenthesis; index < text.Length; index++)
        {
            var character = text[index];

            if (quote != '\0')
            {
                if (character == '\\') index++;
                else if (character == quote) quote = '\0';
                continue;
            }

            switch (character)
            {
                case '\'':
                case '"':
                    quote = character;
                    continue;
                case '(':
                    depth++;
                    continue;
                case ')':
                    depth--;
                    if (depth > 0) continue;
                    return text[(openParenthesis + 1)..index];
            }
        }

        return text[(openParenthesis + 1)..];
    }

    /// <summary>
    /// Returns the first index at which the token appears, or -1 when it does not.
    /// </summary>
    public static int IndexOf(string lowerText, string token) =>
        string.IsNullOrEmpty(token)
            ? -1
            : lowerText.IndexOf(token, StringComparison.Ordinal);

    /// <summary>
    /// True when the text holds the token.
    /// </summary>
    public static bool Contains(string lowerText, string token) => IndexOf(lowerText, token) >= 0;
}
