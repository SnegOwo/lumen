using System.Text;

namespace Lumen.Core.Util;

/// <summary>
/// File names and error text are untrusted input. This helper makes control characters and
/// bidirectional overrides visible so they cannot spoof the UI, and caps display length.
/// </summary>
public static class DisplayText
{
    private const int DefaultMaxLength = 300;

    public static string Sanitize(string? value, int maxLength = DefaultMaxLength)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;

        var builder = new StringBuilder(Math.Min(value.Length, maxLength) + 8);
        foreach (var character in value)
        {
            if (character is '\r' or '\n' or '\t')
            {
                builder.Append(' ');
                continue;
            }

            if (char.IsControl(character) || character is '\u2028' or '\u2029')
            {
                builder.Append(' ');
                continue;
            }

            if (IsBidiControl(character))
            {
                builder.Append("\\u").Append(((int)character).ToString("X4"));
                continue;
            }

            builder.Append(character);
        }

        var text = builder.ToString().Trim();
        if (text.Length > maxLength)
        {
            text = string.Concat(text.AsSpan(0, Math.Max(0, maxLength - 1)), "\u2026");
        }

        return text;
    }

    public static bool IsBidiControl(char character) =>
        character is >= '\u202A' and <= '\u202E'
            or >= '\u2066' and <= '\u2069'
            or '\u200E'
            or '\u200F';

    public static string SanitizePath(string? path, int maxLength = 520) => Sanitize(path, maxLength);
}
