using System.Text;

namespace Lumen.Core.Scanning;

/// <summary>
/// A bounded, immutable snapshot of what the scanner read from one file. Detectors only see
/// this object, never the filesystem. Content is capped by the caller's inspection limit.
/// </summary>
public sealed class FileProbe
{
    private const int MaxTextSampleBytes = 512 * 1024;
    private readonly byte[] _content;
    private readonly object _textGate = new();
    private string? _textSample;
    private bool _textDecoded;

    public FileProbe(
        string path,
        long sizeBytes,
        FileAttributes attributes,
        byte[] content,
        bool contentTruncated)
    {
        Path = path;
        SizeBytes = sizeBytes;
        Attributes = attributes;
        _content = content;
        ContentTruncated = contentTruncated;
        LooksTextual = TextHeuristics.LooksTextual(content);
    }

    public string Path { get; }
    public string FileName => System.IO.Path.GetFileName(Path);
    public long SizeBytes { get; }
    public FileAttributes Attributes { get; }
    public ReadOnlyMemory<byte> Content => _content;
    public bool ContentTruncated { get; }
    public bool LooksTextual { get; }

    public static FileProbe FromBytes(
        string path,
        byte[] content,
        FileAttributes attributes = FileAttributes.Normal) =>
        new(path, content.LongLength, attributes, content, contentTruncated: false);

    public static FileProbe FromText(string path, string text) =>
        FromBytes(path, Encoding.UTF8.GetBytes(text));

    /// <summary>
    /// Returns a decoded text sample when the content looks like text; otherwise null.
    /// The result is cached per probe.
    /// </summary>
    public string? GetTextSample()
    {
        if (!LooksTextual) return null;

        lock (_textGate)
        {
            if (_textDecoded) return _textSample;
            _textDecoded = true;

            var length = Math.Min(_content.Length, MaxTextSampleBytes);
            if (length == 0)
            {
                _textSample = string.Empty;
                return _textSample;
            }

            var span = _content.AsSpan(0, length);
            try
            {
                if (span.Length >= 3 && span[0] == 0xEF && span[1] == 0xBB && span[2] == 0xBF)
                    _textSample = Encoding.UTF8.GetString(span[3..]);
                else if (span.Length >= 2 && span[0] == 0xFF && span[1] == 0xFE)
                    _textSample = Encoding.Unicode.GetString(span[2..]);
                else if (span.Length >= 2 && span[0] == 0xFE && span[1] == 0xFF)
                    _textSample = Encoding.BigEndianUnicode.GetString(span[2..]);
                else
                    _textSample = Encoding.UTF8.GetString(span);
            }
            catch (ArgumentException)
            {
                _textSample = null;
            }

            return _textSample;
        }
    }
}

internal static class TextHeuristics
{
    public static bool LooksTextual(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0) return true;
        if (content.Length >= 2 &&
            ((content[0] == 0xFF && content[1] == 0xFE) || (content[0] == 0xFE && content[1] == 0xFF)))
        {
            return true;
        }

        var sample = content.Length > 4096 ? content[..4096] : content;
        var controls = 0;
        foreach (var value in sample)
        {
            if (value == 0) return false;
            if (value < 0x20 && value is not (0x09 or 0x0A or 0x0D)) controls++;
        }

        return controls * 20 <= sample.Length;
    }
}
