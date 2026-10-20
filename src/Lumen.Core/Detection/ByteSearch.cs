namespace Lumen.Core.Detection;

/// <summary>
/// Small byte-level search helpers. Detectors work on the raw bytes the scanner already
/// read, so they never decode a file and never touch the filesystem.
/// </summary>
internal static class ByteSearch
{
    /// <summary>
    /// Finds the first occurrence of <paramref name="needle"/> in <paramref name="haystack"/>
    /// and returns its offset, or -1 when it is not present.
    /// </summary>
    public static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.Length == 0) return 0;
        if (needle.Length > haystack.Length) return -1;

        // The framework search compares whole blocks at a time, which matters because the
        // real time monitor runs these searches over every file it sees.
        return haystack.IndexOf(needle);
    }

    /// <summary>
    /// Finds the first occurrence of an ASCII needle, optionally ignoring letter case.
    /// </summary>
    public static int IndexOfAscii(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle, bool caseSensitive)
    {
        if (needle.Length == 0) return 0;
        if (needle.Length > haystack.Length) return -1;

        if (caseSensitive) return haystack.IndexOf(needle);

        // Only the positions whose first byte matches are worth comparing in full.
        var first = Fold(needle[0]);
        var limit = haystack.Length - needle.Length;
        for (var start = 0; start <= limit; start++)
        {
            if (Fold(haystack[start]) != first) continue;

            var matched = true;
            for (var offset = 1; offset < needle.Length; offset++)
            {
                if (Fold(haystack[start + offset]) == Fold(needle[offset])) continue;
                matched = false;
                break;
            }

            if (matched) return start;
        }

        return -1;
    }

    /// <summary>
    /// Counts how many times an ASCII needle appears. The scan stops at
    /// <paramref name="limit"/> matches so a pathological file cannot stall a scan.
    /// </summary>
    public static int CountAscii(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle, bool caseSensitive, int limit = 64)
    {
        var count = 0;
        var offset = 0;
        while (count < limit)
        {
            var index = IndexOfAscii(haystack[offset..], needle, caseSensitive);
            if (index < 0) break;
            count++;
            offset += index + Math.Max(1, needle.Length);
            if (offset >= haystack.Length) break;
        }

        return count;
    }

    /// <summary>
    /// Folds an ASCII letter to lower case so case-insensitive searches stay allocation free.
    /// </summary>
    private static byte Fold(byte value) =>
        value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;

    /// <summary>
    /// Returns true when the buffer holds the supplied ASCII text.
    /// </summary>
    public static bool ContainsAscii(ReadOnlySpan<byte> haystack, string marker, bool caseSensitive = true)
    {
        if (string.IsNullOrEmpty(marker)) return false;
        var needle = System.Text.Encoding.ASCII.GetBytes(marker);
        return IndexOfAscii(haystack, needle, caseSensitive) >= 0;
    }

    /// <summary>
    /// Returns true when the buffer holds the supplied text encoded as UTF-16 little endian.
    /// Office containers store their stream names that way, so both encodings are checked.
    /// </summary>
    public static bool ContainsUtf16Le(ReadOnlySpan<byte> haystack, string marker)
    {
        if (string.IsNullOrEmpty(marker)) return false;
        var needle = System.Text.Encoding.Unicode.GetBytes(marker);
        return IndexOf(haystack, needle) >= 0;
    }

    /// <summary>
    /// Returns true when the buffer holds the supplied text in either ASCII or UTF-16 little endian.
    /// </summary>
    public static bool ContainsText(ReadOnlySpan<byte> haystack, string marker, bool caseSensitive = true) =>
        ContainsAscii(haystack, marker, caseSensitive) || ContainsUtf16Le(haystack, marker);
}
