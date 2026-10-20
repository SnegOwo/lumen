namespace Lumen.Core.Detection;

/// <summary>
/// Shannon entropy helpers. Entropy measures how evenly distributed the byte values in a
/// buffer are; ordinary text sits low (roughly 3.5-4.5 bits per byte) while encrypted or
/// packed data sits near the 8.0 ceiling.
/// </summary>
/// <remarks>
/// Entropy is a weak signal on its own. Plenty of legitimate formats - compressed media,
/// encrypted office documents, already-packed installers - are high entropy. Every rule that
/// uses it says so in plain language and never claims that a file is malicious because of it.
/// </remarks>
public static class Entropy
{
    /// <summary>The largest value Shannon entropy can take for byte data, in bits per byte.</summary>
    public const double MaxBitsPerByte = 8.0;

    /// <summary>
    /// Computes the Shannon entropy of a buffer in bits per byte. An empty buffer has zero
    /// entropy because it carries no information at all.
    /// </summary>
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;

        Span<int> counts = stackalloc int[256];
        foreach (var value in data) counts[value]++;

        var total = (double)data.Length;
        var sum = 0.0;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var probability = count / total;
            sum -= probability * Math.Log2(probability);
        }

        return sum;
    }

    /// <summary>
    /// Computes the entropy of the last <paramref name="windowSize"/> bytes of a buffer.
    /// Used to look for a high-entropy blob appended to otherwise ordinary content.
    /// </summary>
    public static double ShannonTail(ReadOnlySpan<byte> data, int windowSize)
    {
        if (windowSize <= 0 || data.Length == 0) return 0.0;
        var start = data.Length > windowSize ? data.Length - windowSize : 0;
        return Shannon(data[start..]);
    }

    /// <summary>
    /// Computes the entropy of the first <paramref name="windowSize"/> bytes of a buffer.
    /// </summary>
    public static double ShannonHead(ReadOnlySpan<byte> data, int windowSize)
    {
        if (windowSize <= 0 || data.Length == 0) return 0.0;
        var length = Math.Min(windowSize, data.Length);
        return Shannon(data[..length]);
    }

    /// <summary>
    /// Estimates how much of a buffer looks like readable text by counting bytes that are
    /// printable ASCII or common whitespace. This is a shape check, not a decoding attempt.
    /// </summary>
    public static double PrintableRatio(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;

        var printable = 0;
        foreach (var value in data)
        {
            if (value is 0x09 or 0x0A or 0x0D) printable++;
            else if (value >= 0x20 && value < 0x7F) printable++;
        }

        return (double)printable / data.Length;
    }
}
