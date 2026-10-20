using System.Buffers.Binary;
using System.Text;

namespace Lumen.Core.Detection.Shortcuts;

/// <summary>
/// What a shortcut points at.
/// </summary>
/// <param name="TargetPath">The absolute path the shortcut launches, when it has one.</param>
/// <param name="RelativePath">The relative path the shortcut launches, when it has one.</param>
/// <param name="Arguments">The command line arguments stored in the shortcut.</param>
/// <param name="WorkingDirectory">The working directory stored in the shortcut.</param>
/// <param name="IconLocation">The icon location stored in the shortcut.</param>
public sealed record ShortcutInfo(
    string? TargetPath,
    string? RelativePath,
    string? Arguments,
    string? WorkingDirectory,
    string? IconLocation)
{
    /// <summary>The best available description of what the shortcut launches.</summary>
    public string? EffectiveTarget => string.IsNullOrWhiteSpace(TargetPath) ? RelativePath : TargetPath;

    /// <summary>True when the shortcut names a target at all.</summary>
    public bool HasTarget => !string.IsNullOrWhiteSpace(EffectiveTarget);
}

/// <summary>
/// A reader for Windows shortcut files. The format is the shell link binary format, which
/// is a sequence of a fixed header, an optional target list, an optional link information
/// block and then a set of length prefixed strings.
/// </summary>
/// <remarks>
/// The reader never resolves or opens the target. It only reports what the file says, so
/// the caller stays in charge of any file system access.
/// </remarks>
public static class ShortcutParser
{
    private const uint HasLinkTargetIdList = 0x0000_0001;
    private const uint HasLinkInfo = 0x0000_0002;
    private const uint HasName = 0x0000_0004;
    private const uint HasRelativePath = 0x0000_0008;
    private const uint HasWorkingDir = 0x0000_0010;
    private const uint HasArguments = 0x0000_0020;
    private const uint HasIconLocation = 0x0000_0040;
    private const uint IsUnicode = 0x0000_0080;

    /// <summary>
    /// Reads a shell link file. Returns false when the bytes are not a shortcut or when the
    /// structure is damaged, together with a plain-language reason.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out ShortcutInfo? info, out string? error)
    {
        info = null;
        error = null;

        if (data.Length < 76)
        {
            error = "The shortcut file is too small to hold a header.";
            return false;
        }

        var headerSize = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (headerSize < 0x4C || headerSize > data.Length)
        {
            error = "The shortcut header size is not valid.";
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt32LittleEndian(data[20..]);
        var offset = (int)headerSize;

        if ((flags & HasLinkTargetIdList) != 0)
        {
            if (offset + 2 > data.Length)
            {
                error = "The shortcut target list is truncated.";
                return false;
            }

            var listSize = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
            offset += 2 + listSize;
        }

        string? localBasePath = null;
        string? commonPathSuffix = null;

        if ((flags & HasLinkInfo) != 0)
        {
            if (offset + 28 > data.Length)
            {
                error = "The shortcut link information block is truncated.";
                return false;
            }

            var linkInfoSize = BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
            var linkInfoFlags = BinaryPrimitives.ReadUInt32LittleEndian(data[(offset + 8)..]);
            var localBasePathOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[(offset + 16)..]);
            var commonPathSuffixOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[(offset + 24)..]);

            if ((linkInfoFlags & 0x01) != 0 && localBasePathOffset > 0)
            {
                localBasePath = ReadNullTerminated(data, offset + (int)localBasePathOffset);
            }

            if (commonPathSuffixOffset > 0)
            {
                commonPathSuffix = ReadNullTerminated(data, offset + (int)commonPathSuffixOffset);
            }

            if (linkInfoSize == 0) linkInfoSize = 28;
            offset += (int)linkInfoSize;
        }

        if (offset > data.Length)
        {
            error = "The shortcut points past the end of the file.";
            return false;
        }

        string? relativePath = null;
        string? workingDirectory = null;
        string? arguments = null;
        string? iconLocation = null;

        if ((flags & HasName) != 0) (_, offset) = ReadString(data, offset, (flags & IsUnicode) != 0);
        if ((flags & HasRelativePath) != 0) (relativePath, offset) = ReadString(data, offset, (flags & IsUnicode) != 0);
        if ((flags & HasWorkingDir) != 0) (workingDirectory, offset) = ReadString(data, offset, (flags & IsUnicode) != 0);
        if ((flags & HasArguments) != 0) (arguments, offset) = ReadString(data, offset, (flags & IsUnicode) != 0);
        if ((flags & HasIconLocation) != 0) (iconLocation, offset) = ReadString(data, offset, (flags & IsUnicode) != 0);

        var target = CombinePath(localBasePath, commonPathSuffix) ?? relativePath;

        info = new ShortcutInfo(target, relativePath, arguments, workingDirectory, iconLocation);
        return true;
    }

    /// <summary>
    /// Reads the target of a web shortcut file, which is a small text file in the old
    /// internet shortcut format.
    /// </summary>
    public static ShortcutInfo? ParseUrlFile(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        string? url = null;
        string? icon = null;

        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim().TrimStart('﻿');
            var separator = trimmed.IndexOf('=');
            if (separator <= 0) continue;

            var key = trimmed[..separator].Trim();
            var value = trimmed[(separator + 1)..].Trim();

            if (key.Equals("URL", StringComparison.OrdinalIgnoreCase) && url is null) url = value;
            if (key.Equals("IconFile", StringComparison.OrdinalIgnoreCase) && icon is null) icon = value;
        }

        if (url is null) return null;

        return new ShortcutInfo(TargetFromUrl(url), url, null, null, icon);
    }

    /// <summary>
    /// Reads the target of a desktop entry file.
    /// </summary>
    public static ShortcutInfo? ParseDesktopFile(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        string? url = null;
        string? exec = null;

        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim();
            var separator = trimmed.IndexOf('=');
            if (separator <= 0) continue;

            var key = trimmed[..separator].Trim();
            var value = trimmed[(separator + 1)..].Trim();

            if (key.Equals("URL", StringComparison.OrdinalIgnoreCase) && url is null) url = value;
            if (key.Equals("Exec", StringComparison.OrdinalIgnoreCase) && exec is null) exec = value;
        }

        if (url is null && exec is null) return null;

        var target = url is not null ? TargetFromUrl(url) : exec;
        return new ShortcutInfo(target, url ?? exec, null, null, null);
    }

    /// <summary>
    /// Turns a file URL into a path. Other schemes are returned unchanged so the caller can
    /// decide what to make of them.
    /// </summary>
    public static string? TargetFromUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;

        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.IsFile)
        {
            try
            {
                return uri.LocalPath;
            }
            catch (InvalidOperationException)
            {
                return uri.ToString();
            }
        }

        return url;
    }

    private static string? CombinePath(string? basePath, string? suffix)
    {
        if (string.IsNullOrWhiteSpace(basePath)) return string.IsNullOrWhiteSpace(suffix) ? null : suffix;
        if (string.IsNullOrWhiteSpace(suffix)) return basePath;

        return basePath.TrimEnd('\\', '/') + suffix;
    }

    private static (string? Value, int Next) ReadString(ReadOnlySpan<byte> data, int offset, bool unicode)
    {
        if (offset + 2 > data.Length) return (null, offset);

        var count = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
        if (count == 0) return (null, offset + 2);

        if (unicode)
        {
            var byteCount = count * 2;
            if (offset + 2 + byteCount > data.Length) return (null, offset + 2);

            var value = Encoding.Unicode.GetString(data.Slice(offset + 2, byteCount));
            var terminator = value.IndexOf('\0');
            if (terminator >= 0) value = value[..terminator];
            return (value, offset + 2 + byteCount);
        }

        if (offset + 2 + count > data.Length) return (null, offset + 2);

        var text = Encoding.Default.GetString(data.Slice(offset + 2, count));
        var nullIndex = text.IndexOf('\0');
        if (nullIndex >= 0) text = text[..nullIndex];
        return (text, offset + 2 + count);
    }

    private static string? ReadNullTerminated(ReadOnlySpan<byte> data, int offset)
    {
        if (offset < 0 || offset >= data.Length) return null;

        var end = offset;
        var limit = Math.Min(data.Length, offset + 1024);
        while (end < limit && data[end] != 0) end++;
        if (end == offset) return null;

        return Encoding.Default.GetString(data.Slice(offset, end - offset));
    }
}
