using System.Buffers.Binary;
using System.IO.Compression;

namespace Lumen.Core.Detection.Archives;

/// <summary>
/// One entry inside a zip container, described from the local file header.
/// </summary>
/// <param name="Name">The entry name as stored in the archive.</param>
/// <param name="Method">The compression method; 0 is stored and 8 is deflate.</param>
/// <param name="CompressedSize">The compressed size in bytes, when the header knows it.</param>
/// <param name="UncompressedSize">The uncompressed size in bytes, when the header knows it.</param>
/// <param name="IsEncrypted">True when the entry is marked as encrypted.</param>
/// <param name="DataOffset">Offset of the entry data inside the container.</param>
public sealed record ArchiveEntryInfo(
    string Name,
    ushort Method,
    uint CompressedSize,
    uint UncompressedSize,
    bool IsEncrypted,
    int DataOffset);

/// <summary>
/// A small reader for zip containers. Lumen reads the local file headers directly instead
/// of using a full archive library, because the scanner usually holds only the first part
/// of a file and a library needs the directory at the end.
/// </summary>
/// <remarks>
/// The reader is deliberately read-only and defensive. A damaged archive produces fewer
/// entries, never an exception, because one broken file must not stop a scan.
/// </remarks>
public static class ZipInspector
{
    private const uint LocalHeaderSignature = 0x0403_4B50;
    private const uint DataDescriptorSignature = 0x0807_4B50;
    private const uint CentralDirectorySignature = 0x0201_4B50;
    private const uint EndOfCentralDirectorySignature = 0x0605_4B50;
    private const int LocalHeaderSize = 30;
    private const int MaxEntries = 2048;

    /// <summary>
    /// Returns true when the bytes start with the zip local file header signature.
    /// </summary>
    public static bool IsZip(ReadOnlySpan<byte> data) =>
        data.Length >= 4 &&
        BinaryPrimitives.ReadUInt32LittleEndian(data) == LocalHeaderSignature;

    /// <summary>
    /// Lists the entries the local headers describe. The scan stops at the first header it
    /// cannot read, so a truncated container yields the entries it does contain.
    /// </summary>
    public static IReadOnlyList<ArchiveEntryInfo> ListEntries(ReadOnlySpan<byte> data)
    {
        var entries = new List<ArchiveEntryInfo>();
        if (!IsZip(data)) return entries;

        var offset = 0;
        while (offset + LocalHeaderSize <= data.Length && entries.Count < MaxEntries)
        {
            var signature = BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
            if (signature != LocalHeaderSignature) break;

            var flags = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 6)..]);
            var method = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 8)..]);
            var compressedSize = BinaryPrimitives.ReadUInt32LittleEndian(data[(offset + 18)..]);
            var uncompressedSize = BinaryPrimitives.ReadUInt32LittleEndian(data[(offset + 22)..]);
            var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 26)..]);
            var extraLength = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 28)..]);

            var nameOffset = offset + LocalHeaderSize;
            if (nameOffset + nameLength > data.Length) break;

            var name = System.Text.Encoding.UTF8.GetString(data.Slice(nameOffset, nameLength));
            var dataOffset = nameOffset + nameLength + extraLength;

            var encrypted = (flags & 0x0001) != 0;
            var hasDescriptor = (flags & 0x0008) != 0;

            entries.Add(new ArchiveEntryInfo(
                name,
                method,
                compressedSize,
                uncompressedSize,
                encrypted,
                dataOffset));

            if (hasDescriptor)
            {
                // The sizes live in a descriptor after the data, so the next header has to be
                // found by scanning. This is slow but it only happens for streamed archives.
                var next = FindNextHeader(data, dataOffset);
                if (next < 0) break;
                offset = next;
                continue;
            }

            var advance = (long)dataOffset + compressedSize;
            if (advance <= 0 || advance > int.MaxValue) break;
            offset = (int)advance;
        }

        return entries;
    }

    /// <summary>
    /// Reads the content of one entry. Only stored and deflated entries are supported,
    /// which covers every archive format in normal use.
    /// </summary>
    /// <param name="data">The bytes of the container.</param>
    /// <param name="entry">The entry to read.</param>
    /// <param name="maxBytes">The largest number of bytes to return.</param>
    /// <param name="content">The entry content when it could be read.</param>
    public static bool TryReadEntry(ReadOnlySpan<byte> data, ArchiveEntryInfo entry, int maxBytes, out byte[] content)
    {
        content = [];

        if (entry.DataOffset < 0 || entry.DataOffset >= data.Length) return false;
        if (entry.IsEncrypted) return false;

        var available = data.Length - entry.DataOffset;
        var length = (int)Math.Min(entry.CompressedSize == 0 ? available : entry.CompressedSize, available);
        if (length <= 0) return false;

        var payload = data.Slice(entry.DataOffset, length);

        if (entry.Method == 0)
        {
            var count = Math.Min(payload.Length, maxBytes);
            content = payload[..count].ToArray();
            return true;
        }

        if (entry.Method != 8) return false;

        try
        {
            using var source = new MemoryStream(payload.ToArray(), writable: false);
            using var deflate = new DeflateStream(source, CompressionMode.Decompress);
            using var target = new MemoryStream();
            var buffer = new byte[8192];
            var read = 0;
            while (read < maxBytes)
            {
                var wanted = Math.Min(buffer.Length, maxBytes - read);
                var count = deflate.Read(buffer, 0, wanted);
                if (count <= 0) break;
                target.Write(buffer, 0, count);
                read += count;
            }

            content = target.ToArray();
            return content.Length > 0;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    /// <summary>
    /// Returns true when the bytes start with a recognised archive signature.
    /// </summary>
    public static bool IsArchiveMagic(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(data) == LocalHeaderSignature) return true;
        if (data.Length >= 8 && data[0] == 0x52 && data[1] == 0x61 && data[2] == 0x72 && data[3] == 0x21 && data[4] == 0x1A && data[5] == 0x07) return true;
        if (data.Length >= 6 && data[0] == 0x37 && data[1] == 0x7A && data[2] == 0xBC && data[3] == 0xAF && data[4] == 0x27 && data[5] == 0x1C) return true;
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B) return true;
        if (data.Length >= 4 && data[0] == 0x4D && data[1] == 0x53 && data[2] == 0x43 && data[3] == 0x46) return true;
        if (data.Length >= 4 && data[0] == 0x42 && data[1] == 0x5A && data[2] == 0x68 && data[3] == 0x39) return true;
        return false;
    }

    /// <summary>
    /// Returns a readable name for the archive format the bytes start with, or null when
    /// the bytes do not look like an archive.
    /// </summary>
    public static string? DescribeArchiveMagic(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(data) == LocalHeaderSignature) return "zip";
        if (data.Length >= 8 && data[0] == 0x52 && data[1] == 0x61 && data[2] == 0x72 && data[3] == 0x21 && data[4] == 0x1A && data[5] == 0x07) return "rar";
        if (data.Length >= 6 && data[0] == 0x37 && data[1] == 0x7A && data[2] == 0xBC && data[3] == 0xAF && data[4] == 0x27 && data[5] == 0x1C) return "7-zip";
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B) return "gzip";
        if (data.Length >= 4 && data[0] == 0x4D && data[1] == 0x53 && data[2] == 0x43 && data[3] == 0x46) return "cabinet";
        if (data.Length >= 4 && data[0] == 0x42 && data[1] == 0x5A && data[2] == 0x68 && data[3] == 0x39) return "bzip2";
        return null;
    }

    /// <summary>
    /// Scans forward for the next local file header. Used for streamed archives whose sizes
    /// are only known after the data.
    /// </summary>
    private static int FindNextHeader(ReadOnlySpan<byte> data, int start)
    {
        for (var index = Math.Max(0, start); index + LocalHeaderSize <= data.Length; index++)
        {
            var signature = BinaryPrimitives.ReadUInt32LittleEndian(data[index..]);
            if (signature == LocalHeaderSignature) return index;
            if (signature is CentralDirectorySignature or EndOfCentralDirectorySignature or DataDescriptorSignature) return -1;
        }

        return -1;
    }
}
