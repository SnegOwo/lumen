using System.Buffers.Binary;
using System.Text;

namespace Lumen.Core.Tests;

/// <summary>
/// Synthetic builders for the byte shapes the detection tests need. Everything here is
/// constructed from scratch so no real malware, no real document and no real exploit ever
/// reaches the test suite.
/// </summary>
internal static class DetectionFixtures
{
    /// <summary>The magic bytes that start a Windows executable image.</summary>
    public static byte[] PeImage(PeImageOptions? options = null)
    {
        options ??= new PeImageOptions();

        var userSections = options.Sections is { Length: > 0 }
            ? options.Sections
            : [new PeSectionSpec(".text", new byte[512], 0x6000_0020)];

        var hasImports = options.Imports is { Length: > 0 };
        var sectionCount = userSections.Length + (hasImports ? 1 : 0);

        var optionalHeaderSize = options.Is64Bit ? 240 : 224;
        var headerEnd = Align(0x80 + 4 + 20 + optionalHeaderSize + 40 * sectionCount, 0x200);

        var importContent = hasImports ? BuildImportSection(options.Imports!, 0x1000u * (uint)(userSections.Length + 1)) : [];

        // Assign the file offset and the address of every section.
        var sectionData = new byte[sectionCount][];
        for (var index = 0; index < userSections.Length; index++) sectionData[index] = userSections[index].Data;
        if (hasImports) sectionData[sectionCount - 1] = importContent;

        var fileOffsets = new int[sectionCount];
        var virtualAddresses = new uint[sectionCount];
        var cursor = headerEnd;
        for (var index = 0; index < sectionCount; index++)
        {
            fileOffsets[index] = cursor;
            virtualAddresses[index] = 0x1000u * (uint)(index + 1);
            cursor += Align(sectionData[index].Length, 0x200);
        }

        var certificateOffset = 0;
        var certificateSize = 0;
        if (options.Certificate is not null)
        {
            certificateOffset = cursor;
            certificateSize = options.Certificate.Length;
            cursor += certificateSize;
        }

        var buffer = new byte[cursor];
        var writer = new BinaryWriter(new MemoryStream(buffer, writable: true));

        // DOS header. The PE header lives at 0x80, so the stub fills the gap in between.
        writer.Write(Encoding.ASCII.GetBytes("MZ"));
        writer.Write(new byte[0x3A]);
        writer.Write((uint)0x80);
        writer.Write(new byte[0x80 - 0x40]);

        // PE signature and COFF header.
        writer.Write(Encoding.ASCII.GetBytes("PE\0\0"));
        writer.Write((ushort)(options.Machine ?? 0x014C));
        writer.Write((ushort)sectionCount);
        writer.Write(options.Timestamp ?? 1_700_000_000u);
        writer.Write((uint)0);
        writer.Write((uint)0);
        writer.Write((ushort)optionalHeaderSize);
        writer.Write((ushort)(options.Characteristics ?? 0x0102));

        // Optional header.
        writer.Write((ushort)(options.Is64Bit ? 0x020B : 0x010B));
        writer.Write((byte)14);
        writer.Write((byte)0);
        writer.Write((uint)0x200);
        writer.Write((uint)0x200);
        writer.Write((uint)0);
        writer.Write((uint)virtualAddresses[0]);
        writer.Write((uint)virtualAddresses[0]);
        if (!options.Is64Bit) writer.Write((uint)0);

        if (options.Is64Bit) writer.Write((ulong)0x0000_0001_4000_0000);
        else writer.Write((uint)0x0040_0000);

        writer.Write((uint)0x1000);
        writer.Write((uint)0x200);
        writer.Write((ushort)6);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)6);
        writer.Write((ushort)0);
        writer.Write((uint)0);
        writer.Write((uint)0x1000u * (uint)(sectionCount + 1));
        writer.Write((uint)headerEnd);
        writer.Write((uint)0);
        writer.Write((ushort)(options.Subsystem ?? 3));
        writer.Write((ushort)0x8140);

        if (options.Is64Bit)
        {
            writer.Write((ulong)0x100000);
            writer.Write((ulong)0x1000);
            writer.Write((ulong)0x100000);
            writer.Write((ulong)0x1000);
        }
        else
        {
            writer.Write((uint)0x100000);
            writer.Write((uint)0x1000);
            writer.Write((uint)0x100000);
            writer.Write((uint)0x1000);
        }

        writer.Write((uint)0);
        writer.Write((uint)16);

        // Data directories. Only the import and security directories are filled in.
        var directories = new uint[16 * 2];
        if (hasImports)
        {
            directories[2] = virtualAddresses[sectionCount - 1];
            directories[3] = (uint)importContent.Length;
        }

        if (options.Certificate is not null)
        {
            directories[8] = (uint)certificateOffset;
            directories[9] = (uint)certificateSize;
        }

        for (var index = 0; index < 16; index++)
        {
            writer.Write(directories[index * 2]);
            writer.Write(directories[index * 2 + 1]);
        }

        // Section headers.
        for (var index = 0; index < sectionCount; index++)
        {
            var section = index < userSections.Length
                ? userSections[index]
                : new PeSectionSpec(".idata", importContent, 0xC000_0040);

            var name = new byte[8];
            var nameBytes = Encoding.ASCII.GetBytes(section.Name);
            Array.Copy(nameBytes, name, Math.Min(nameBytes.Length, 8));

            writer.Write(name);
            writer.Write(section.VirtualSize ?? (uint)section.Data.Length);
            writer.Write(virtualAddresses[index]);
            writer.Write((uint)section.Data.Length);
            writer.Write((uint)fileOffsets[index]);
            writer.Write((uint)0);
            writer.Write((uint)0);
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write(section.Characteristics);
        }

        // Section data.
        for (var index = 0; index < sectionCount; index++)
        {
            writer.BaseStream.Position = fileOffsets[index];
            writer.Write(sectionData[index]);
        }

        if (options.Certificate is not null)
        {
            writer.BaseStream.Position = certificateOffset;
            writer.Write(options.Certificate);
        }

        writer.Flush();
        return buffer;
    }

    private static byte[] BuildImportSection(PeImportSpec[] imports, uint baseRva)
    {
        var descriptorSize = (imports.Length + 1) * 20;
        var cursor = descriptorSize;

        var iltOffsets = new int[imports.Length];
        var iatOffsets = new int[imports.Length];
        var nameOffsets = new int[imports.Length];
        var functionOffsets = new int[imports.Length][];

        for (var index = 0; index < imports.Length; index++)
        {
            iltOffsets[index] = cursor;
            cursor += (imports[index].Functions.Length + 1) * 4;
            iatOffsets[index] = cursor;
            cursor += (imports[index].Functions.Length + 1) * 4;

            nameOffsets[index] = cursor;
            cursor += imports[index].Module.Length + 1;
            if (cursor % 2 != 0) cursor++;

            functionOffsets[index] = new int[imports[index].Functions.Length];
            for (var function = 0; function < imports[index].Functions.Length; function++)
            {
                functionOffsets[index][function] = cursor;
                cursor += 2 + imports[index].Functions[function].Length + 1;
                if (cursor % 2 != 0) cursor++;
            }
        }

        var content = new byte[cursor];

        for (var index = 0; index < imports.Length; index++)
        {
            var descriptor = index * 20;
            BinaryPrimitives.WriteUInt32LittleEndian(content.AsSpan(descriptor, 20), baseRva + (uint)iltOffsets[index]);
            BinaryPrimitives.WriteUInt32LittleEndian(content.AsSpan(descriptor + 12, 4), baseRva + (uint)nameOffsets[index]);
            BinaryPrimitives.WriteUInt32LittleEndian(content.AsSpan(descriptor + 16, 4), baseRva + (uint)iatOffsets[index]);

            var ilt = iltOffsets[index];
            var iat = iatOffsets[index];
            for (var function = 0; function < imports[index].Functions.Length; function++)
            {
                var value = baseRva + (uint)functionOffsets[index][function];
                BinaryPrimitives.WriteUInt32LittleEndian(content.AsSpan(ilt + function * 4, 4), value);
                BinaryPrimitives.WriteUInt32LittleEndian(content.AsSpan(iat + function * 4, 4), value);
            }

            Encoding.ASCII.GetBytes(imports[index].Module).CopyTo(content, nameOffsets[index]);
            content[nameOffsets[index] + imports[index].Module.Length] = 0;

            for (var function = 0; function < imports[index].Functions.Length; function++)
            {
                var offset = functionOffsets[index][function];
                BinaryPrimitives.WriteUInt16LittleEndian(content.AsSpan(offset, 2), (ushort)function);
                Encoding.ASCII.GetBytes(imports[index].Functions[function]).CopyTo(content, offset + 2);
                content[offset + 2 + imports[index].Functions[function].Length] = 0;
            }
        }

        return content;
    }

    /// <summary>
    /// Builds a zip container with stored entries. The archive is written by hand so the
    /// tests do not depend on any compression library.
    /// </summary>
    public static byte[] Zip(params ZipEntrySpec[] entries)
    {
        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true);

        var offsets = new int[entries.Length];
        for (var index = 0; index < entries.Length; index++)
        {
            var entry = entries[index];
            var name = Encoding.UTF8.GetBytes(entry.Name);
            offsets[index] = (int)buffer.Position;

            writer.Write((uint)0x0403_4B50);
            writer.Write((ushort)20);
            writer.Write((ushort)(entry.Encrypted ? 0x0001 : 0));
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write((uint)0);
            writer.Write((uint)entry.Content.Length);
            writer.Write((uint)entry.Content.Length);
            writer.Write((ushort)name.Length);
            writer.Write((ushort)0);
            writer.Write(name);
            writer.Write(entry.Content);
        }

        var centralStart = (int)buffer.Position;
        for (var index = 0; index < entries.Length; index++)
        {
            var entry = entries[index];
            var name = Encoding.UTF8.GetBytes(entry.Name);

            writer.Write((uint)0x0201_4B50);
            writer.Write((ushort)20);
            writer.Write((ushort)20);
            writer.Write((ushort)(entry.Encrypted ? 0x0001 : 0));
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write((uint)0);
            writer.Write((uint)entry.Content.Length);
            writer.Write((uint)entry.Content.Length);
            writer.Write((ushort)name.Length);
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write((uint)0);
            writer.Write((uint)offsets[index]);
            writer.Write(name);
        }

        var centralSize = (int)buffer.Position - centralStart;
        writer.Write((uint)0x0605_4B50);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)entries.Length);
        writer.Write((ushort)entries.Length);
        writer.Write((uint)centralSize);
        writer.Write((uint)centralStart);
        writer.Write((ushort)0);

        writer.Flush();
        return buffer.ToArray();
    }

    /// <summary>
    /// Builds a file that starts with the OLE compound document signature.
    /// </summary>
    public static byte[] OleCompoundFile(byte[] payload)
    {
        var content = new byte[512 + payload.Length];
        content[0] = 0xD0;
        content[1] = 0xCF;
        content[2] = 0x11;
        content[3] = 0xE0;
        content[4] = 0xA1;
        content[5] = 0xB1;
        content[6] = 0x1A;
        content[7] = 0xE1;
        payload.CopyTo(content, 512);
        return content;
    }

    /// <summary>
    /// Builds a small PDF with the supplied body text.
    /// </summary>
    public static byte[] Pdf(string body)
    {
        var text = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + body + "\ntrailer\n<< >>\n%%EOF\n";
        return Encoding.ASCII.GetBytes(text);
    }

    /// <summary>
    /// Builds a Windows shortcut file that launches the supplied target.
    /// </summary>
    public static byte[] Shortcut(string target, string? arguments = null, string? iconLocation = null, bool unicode = true)
    {
        const int headerSize = 0x4C;
        var flags = 0x0000_0002 | 0x0000_0040; // HasLinkInfo and HasIconLocation
        if (arguments is not null) flags |= 0x0000_0020;
        if (unicode) flags |= 0x0000_0080;

        var linkInfo = BuildLinkInfo(target);
        var stringData = new MemoryStream();
        if (arguments is not null) WriteString(stringData, arguments, unicode);
        if (iconLocation is not null) WriteString(stringData, iconLocation, unicode);

        var total = headerSize + linkInfo.Length + (int)stringData.Length + 4;
        var bytes = new byte[total];
        var writer = new BinaryWriter(new MemoryStream(bytes, writable: true));

        writer.Write((uint)headerSize);
        writer.Write(new byte[16]);
        writer.Write((uint)flags);
        writer.Write((uint)0);
        writer.Write((long)0);
        writer.Write((long)0);
        writer.Write((long)0);
        writer.Write((uint)0);
        writer.Write((uint)0);
        writer.Write((uint)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(new byte[8]);

        writer.Write(linkInfo);
        stringData.Position = 0;
        stringData.CopyTo(writer.BaseStream);
        writer.Write((uint)0x0000_0000);

        writer.Flush();
        return bytes;
    }

    private static byte[] BuildLinkInfo(string target)
    {
        var localBasePath = Encoding.Default.GetBytes(target);
        var suffix = new byte[1];

        const int headerSize = 28;
        var suffixOffset = headerSize + localBasePath.Length + 1;

        var info = new byte[suffixOffset + suffix.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(0, 4), (uint)info.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(4, 4), headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(8, 4), 0x0000_0001);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(12, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(16, 4), headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(20, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(24, 4), (uint)suffixOffset);

        localBasePath.CopyTo(info, headerSize);
        info[headerSize + localBasePath.Length] = 0;
        return info;
    }

    private static void WriteString(MemoryStream stream, string value, bool unicode)
    {
        if (unicode)
        {
            var bytes = Encoding.Unicode.GetBytes(value);
            var count = bytes.Length / 2 + 1;
            var buffer = new byte[count * 2];
            bytes.CopyTo(buffer, 0);
            stream.Write(BitConverter.GetBytes((ushort)count));
            stream.Write(buffer);
            return;
        }

        var ansi = Encoding.Default.GetBytes(value);
        var ansiBuffer = new byte[ansi.Length + 1];
        ansi.CopyTo(ansiBuffer, 0);
        stream.Write(BitConverter.GetBytes((ushort)ansiBuffer.Length));
        stream.Write(ansiBuffer);
    }

    /// <summary>
    /// Builds an internet shortcut file.
    /// </summary>
    public static string UrlShortcut(string url) =>
        "[InternetShortcut]\r\nURL=" + url + "\r\nIconFile=C:\\Windows\\System32\\shell32.dll\r\n";

    /// <summary>
    /// Builds bytes whose entropy is close to the maximum, without using any real payload.
    /// </summary>
    public static byte[] HighEntropyBytes(int length, int seed = 1133741823)
    {
        var bytes = new byte[length];
        var state = (uint)seed;
        if (state == 0) state = 2463534242u;

        for (var index = 0; index < length; index++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[index] = (byte)(state >> 24);
        }

        return bytes;
    }

    /// <summary>
    /// Builds a text file that ends with a block of high entropy bytes.
    /// </summary>
    public static byte[] TextWithBinaryTail(string text, int tailLength)
    {
        var head = Encoding.UTF8.GetBytes(text);
        var tail = HighEntropyBytes(tailLength);
        var result = new byte[head.Length + tail.Length];
        head.CopyTo(result, 0);
        tail.CopyTo(result, head.Length);
        return result;
    }

    /// <summary>
    /// Builds a rule file body for the signature engine.
    /// </summary>
    public static string SignatureRuleFile(
        string id,
        string kind,
        string value,
        bool caseSensitive = false,
        IEnumerable<string>? extensions = null,
        int schemaVersion = 1) =>
        "{\"schemaVersion\":" + schemaVersion + ",\"rules\":[{" +
        "\"id\":\"" + id + "\"," +
        "\"title\":\"Test rule\"," +
        "\"category\":\"Signature\"," +
        "\"confidence\":\"High\"," +
        "\"description\":\"A rule used by the tests.\"," +
        "\"detail\":\"The rule matched.\"," +
        "\"advice\":\"Look at the file.\"," +
        "\"patterns\":[{" +
        "\"kind\":\"" + kind + "\"," +
        "\"value\":\"" + value + "\"," +
        "\"caseSensitive\":" + (caseSensitive ? "true" : "false") +
        (extensions is null ? string.Empty : ",\"extensions\":[" + string.Join(",", extensions.Select(extension => "\"" + extension + "\"")) + "]") +
        "}]}]}";

    private static int Align(int value, int alignment) => (value + alignment - 1) / alignment * alignment;
}

/// <summary>The shape of a section in a synthetic executable image.</summary>
/// <param name="Name">The section name.</param>
/// <param name="Data">The bytes of the section.</param>
/// <param name="Characteristics">The section characteristic flags.</param>
/// <param name="VirtualSize">Overrides the virtual size when the section is larger in memory.</param>
internal sealed record PeSectionSpec(string Name, byte[] Data, uint Characteristics, uint? VirtualSize = null);

/// <summary>The imports of a synthetic executable image.</summary>
/// <param name="Module">The DLL name.</param>
/// <param name="Functions">The imported function names.</param>
internal sealed record PeImportSpec(string Module, string[] Functions);

/// <summary>Options for building a synthetic executable image.</summary>
internal sealed record PeImageOptions
{
    public PeSectionSpec[]? Sections { get; init; }

    public PeImportSpec[]? Imports { get; init; }

    public ushort? Machine { get; init; }

    public ushort? Subsystem { get; init; }

    public uint? Timestamp { get; init; }

    public ushort? Characteristics { get; init; }

    public bool Is64Bit { get; init; }

    /// <summary>The bytes of the certificate table, when the image should carry one.</summary>
    public byte[]? Certificate { get; init; }
}

/// <summary>One entry of a synthetic zip archive.</summary>
/// <param name="Name">The entry name.</param>
/// <param name="Content">The entry content.</param>
/// <param name="Encrypted">True when the entry is marked as encrypted.</param>
internal sealed record ZipEntrySpec(string Name, byte[] Content, bool Encrypted = false);
