using System.Buffers.Binary;
using Lumen.Core.Models;

namespace Lumen.Core.Detection.Pe;

/// <summary>
/// One section of a Windows executable image.
/// </summary>
/// <param name="Name">The section name as stored in the file, for example ".text".</param>
/// <param name="VirtualSize">Size of the section once it is loaded into memory.</param>
/// <param name="VirtualAddress">The address the section is loaded at.</param>
/// <param name="SizeOfRawData">Size of the section on disk.</param>
/// <param name="PointerToRawData">Offset of the section data inside the file.</param>
/// <param name="Characteristics">The raw section characteristic flags.</param>
/// <param name="Entropy">Shannon entropy of the section bytes that were available, in bits per byte.</param>
public sealed record PeSection(
    string Name,
    uint VirtualSize,
    uint VirtualAddress,
    uint SizeOfRawData,
    uint PointerToRawData,
    uint Characteristics,
    double Entropy)
{
    /// <summary>True when the section is marked executable in memory.</summary>
    public bool IsExecutable => (Characteristics & 0x2000_0000) != 0;

    /// <summary>True when the section is marked writable in memory.</summary>
    public bool IsWritable => (Characteristics & 0x8000_0000) != 0;

    /// <summary>True when the section is marked readable in memory.</summary>
    public bool IsReadable => (Characteristics & 0x4000_0000) != 0;
}

/// <summary>
/// One imported function.
/// </summary>
/// <param name="Module">The DLL the function is imported from.</param>
/// <param name="Function">The function name, or the ordinal number when it is imported by ordinal.</param>
/// <param name="IsOrdinal">True when the import uses an ordinal instead of a name.</param>
public sealed record PeImportEntry(string Module, string Function, bool IsOrdinal);

/// <summary>
/// The parts of a Windows executable image that Lumen understands.
/// </summary>
/// <param name="Machine">The raw machine type.</param>
/// <param name="MachineName">A readable name for the machine type.</param>
/// <param name="Subsystem">The raw subsystem value.</param>
/// <param name="SubsystemName">A readable name for the subsystem.</param>
/// <param name="TimeDateStamp">The raw compilation timestamp.</param>
/// <param name="CompiledUtc">The compilation timestamp as a date, when it is a plausible value.</param>
/// <param name="Characteristics">The raw file characteristic flags.</param>
/// <param name="Is32Bit">True for the 32-bit image format, false for 64-bit.</param>
/// <param name="Sections">The section table.</param>
/// <param name="Imports">The imported functions.</param>
/// <param name="HasCertificateTable">True when the file points at a certificate table.</param>
/// <param name="HasValidDigitalSignature">True when the certificate table held a well-formed signed-data blob.</param>
/// <param name="SignatureCheckComplete">
/// False when the bytes read were only a prefix of the file, so the presence of a signature
/// could not be settled either way.
/// </param>
/// <param name="HasDebugDirectory">True when the image carries debug information.</param>
/// <param name="Warnings">Plain-language notes about anything unusual in the header.</param>
public sealed record PeHeader(
    ushort Machine,
    string MachineName,
    ushort Subsystem,
    string SubsystemName,
    uint TimeDateStamp,
    DateTimeOffset? CompiledUtc,
    ushort Characteristics,
    bool Is32Bit,
    IReadOnlyList<PeSection> Sections,
    IReadOnlyList<PeImportEntry> Imports,
    bool HasCertificateTable,
    bool HasValidDigitalSignature,
    bool SignatureCheckComplete,
    bool HasDebugDirectory,
    IReadOnlyList<string> Warnings);

/// <summary>
/// A hand-written reader for the Windows Portable Executable format. Lumen parses the
/// header itself instead of taking a dependency on a Windows specific library, which keeps
/// the core project portable and testable with synthetic files.
/// </summary>
/// <remarks>
/// The parser is deliberately forgiving: a truncated or damaged file produces a clear error
/// or a partially filled <see cref="PeHeader"/> rather than an exception, because a scan
/// must never fall over because of one bad file.
/// </remarks>
public static class PeParser
{
    private const int DosHeaderSize = 0x40;
    private const int CoffHeaderSize = 20;
    private const int SectionHeaderSize = 40;
    private const int OptionalHeaderSizeAtLeast = 96;
    private const int MaxSections = 96;
    private const int MaxImports = 512;

    /// <summary>
    /// The signature bytes of a PKCS#7 signed-data blob, as used by Authenticode.
    /// </summary>
    private static ReadOnlySpan<byte> SignedDataOid => [0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];

    /// <summary>
    /// Attempts to read a Portable Executable image from the supplied bytes.
    /// </summary>
    /// <param name="data">The bytes the scanner already read from the file.</param>
    /// <param name="truncated">True when the bytes are only a prefix of a larger file.</param>
    /// <param name="header">The parsed header when parsing succeeded.</param>
    /// <param name="error">A plain-language reason when parsing failed.</param>
    public static bool TryParse(ReadOnlySpan<byte> data, bool truncated, out PeHeader? header, out string? error)
    {
        header = null;
        error = null;

        if (data.Length < 2 || data[0] != 0x4D || data[1] != 0x5A)
        {
            error = "The file does not start with the MZ marker.";
            return false;
        }

        if (data.Length < DosHeaderSize)
        {
            error = "The DOS header is truncated.";
            return false;
        }

        var peOffset = (int)ReadUInt32(data, 0x3C);
        if (peOffset < DosHeaderSize || peOffset + 4 + CoffHeaderSize > data.Length)
        {
            error = "The PE header offset points outside the file.";
            return false;
        }

        if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45 || data[peOffset + 2] != 0x00 || data[peOffset + 3] != 0x00)
        {
            error = "The PE signature is missing at the declared offset.";
            return false;
        }

        var coff = peOffset + 4;
        var machine = ReadUInt16(data, coff);
        var numberOfSections = ReadUInt16(data, coff + 2);
        var timeDateStamp = ReadUInt32(data, coff + 4);
        var sizeOfOptionalHeader = ReadUInt16(data, coff + 16);
        var characteristics = ReadUInt16(data, coff + 18);

        var optional = coff + CoffHeaderSize;
        if (optional + (int)Math.Min((int)sizeOfOptionalHeader, OptionalHeaderSizeAtLeast) > data.Length)
        {
            error = "The optional header is truncated.";
            return false;
        }

        if (sizeOfOptionalHeader < OptionalHeaderSizeAtLeast)
        {
            error = "The optional header is too small to describe a Windows executable.";
            return false;
        }

        var magic = ReadUInt16(data, optional);
        var is32Bit = magic switch
        {
            0x010B => true,
            0x020B => false,
            _ => (bool?)null
        };

        if (is32Bit is null)
        {
            error = "The optional header uses an unknown format.";
            return false;
        }

        var subsystem = ReadUInt16(data, optional + 68);
        var numberOfRvaAndSizes = ReadUInt32(data, optional + 92);
        var directoryOffset = optional + (is32Bit.Value ? 96 : 112);
        var directoryCount = Math.Min((int)numberOfRvaAndSizes, 16);
        if (directoryOffset + directoryCount * 8 > data.Length)
        {
            error = "The data directory is truncated.";
            return false;
        }

        var warnings = new List<string>();

        // Sections.
        var sectionTable = optional + sizeOfOptionalHeader;
        var sections = new List<PeSection>();
        var sectionCount = Math.Min((int)numberOfSections, MaxSections);
        for (var index = 0; index < sectionCount; index++)
        {
            var entry = sectionTable + index * SectionHeaderSize;
            if (entry + SectionHeaderSize > data.Length)
            {
                warnings.Add("The section table is truncated.");
                break;
            }

            var name = ReadSectionName(data, entry);
            var virtualSize = ReadUInt32(data, entry + 8);
            var virtualAddress = ReadUInt32(data, entry + 12);
            var sizeOfRawData = ReadUInt32(data, entry + 16);
            var pointerToRawData = ReadUInt32(data, entry + 20);
            var sectionFlags = ReadUInt32(data, entry + 36);

            var entropy = 0.0;
            if (sizeOfRawData > 0 && pointerToRawData < (uint)data.Length)
            {
                var start = (int)pointerToRawData;
                var available = (int)Math.Min(sizeOfRawData, (uint)(data.Length - start));
                if (available > 0) entropy = Entropy.Shannon(data.Slice(start, available));
            }

            sections.Add(new PeSection(
                name,
                virtualSize,
                virtualAddress,
                sizeOfRawData,
                pointerToRawData,
                sectionFlags,
                entropy));
        }

        // Import directory.
        var imports = new List<PeImportEntry>();
        if (directoryCount > 1)
        {
            var importRva = ReadUInt32(data, directoryOffset + 8);
            var importSize = ReadUInt32(data, directoryOffset + 12);
            if (importRva != 0 && importSize != 0)
            {
                ReadImports(data, sections, importRva, is32Bit.Value, imports, warnings);
            }
        }

        // Certificate table. The security directory holds a file offset, not an address.
        var hasCertificateTable = false;
        var hasValidSignature = false;
        if (directoryCount > 4)
        {
            var certificateOffset = ReadUInt32(data, directoryOffset + 32);
            var certificateSize = ReadUInt32(data, directoryOffset + 36);
            if (certificateOffset != 0 && certificateSize != 0)
            {
                hasCertificateTable = true;
                var start = (int)certificateOffset;
                if (start + 8 <= data.Length)
                {
                    var revision = ReadUInt16(data, start + 4);
                    var certificateType = ReadUInt16(data, start + 6);
                    if (revision == 0x0200 && certificateType == 0x0002 &&
                        start + 8 + SignedDataOid.Length <= data.Length &&
                        data.Slice(start + 8, SignedDataOid.Length).SequenceEqual(SignedDataOid))
                    {
                        hasValidSignature = true;
                    }
                    else
                    {
                        warnings.Add("The certificate table is present but does not hold a well-formed signed-data blob.");
                    }
                }
                else
                {
                    warnings.Add("The certificate table is outside the bytes that were read.");
                }
            }
        }

        var hasDebugDirectory = directoryCount > 6 && ReadUInt32(data, directoryOffset + 48) != 0;

        DateTimeOffset? compiled = null;
        if (timeDateStamp > 0 && timeDateStamp < 4_000_000_000)
        {
            try
            {
                compiled = DateTimeOffset.FromUnixTimeSeconds(timeDateStamp);
            }
            catch (ArgumentOutOfRangeException)
            {
                compiled = null;
            }
        }

        header = new PeHeader(
            machine,
            MachineName(machine),
            subsystem,
            SubsystemName(subsystem),
            timeDateStamp,
            compiled,
            characteristics,
            is32Bit.Value,
            sections,
            imports,
            hasCertificateTable,
            hasValidSignature,
            !truncated,
            hasDebugDirectory,
            warnings);

        return true;
    }

    /// <summary>
    /// Returns a readable name for a machine type value.
    /// </summary>
    public static string MachineName(ushort machine) => machine switch
    {
        0x014C => "Intel 386",
        0x0166 => "MIPS little endian",
        0x01A2 => "Hitachi SH3",
        0x01C0 => "ARM",
        0x01C4 => "ARM Thumb-2",
        0x0200 => "Intel Itanium",
        0x0266 => "MIPS",
        0x0284 => "Alpha",
        0x0366 => "MIPS little endian 2",
        0x0466 => "MIPS 16-bit",
        0x0520 => "TriCore",
        0x0CEF => "EFI",
        0x0EBC => "EFI byte code",
        0x8664 => "AMD64",
        0x9041 => "MIPS little endian 3",
        0xAA64 => "ARM64",
        0xC0EE => "CEF",
        _ => $"Unknown machine type 0x{machine:X4}"
    };

    /// <summary>
    /// Returns a readable name for a subsystem value.
    /// </summary>
    public static string SubsystemName(ushort subsystem) => subsystem switch
    {
        0 => "Unknown",
        1 => "Native",
        2 => "Windows graphical",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        9 => "Windows CE graphical",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM image",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => $"Unknown subsystem {subsystem}"
    };

    private static void ReadImports(
        ReadOnlySpan<byte> data,
        IReadOnlyList<PeSection> sections,
        uint importRva,
        bool is32Bit,
        List<PeImportEntry> imports,
        List<string> warnings)
    {
        var directoryOffset = RvaToOffset(sections, importRva);
        if (directoryOffset < 0)
        {
            warnings.Add("The import directory points outside the file.");
            return;
        }

        var descriptor = directoryOffset;
        var descriptorCount = 0;
        while (descriptorCount < 64 && descriptor + 20 <= data.Length)
        {
            descriptorCount++;

            var originalFirstThunk = ReadUInt32(data, descriptor);
            var nameRva = ReadUInt32(data, descriptor + 12);
            var firstThunk = ReadUInt32(data, descriptor + 16);

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

            var module = ReadStringAtRva(data, sections, nameRva) ?? "(unknown)";
            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            var thunkOffset = RvaToOffset(sections, thunkRva);

            if (thunkOffset >= 0)
            {
                var step = is32Bit ? 4 : 8;
                var cursor = thunkOffset;
                while (cursor + step <= data.Length && imports.Count < MaxImports)
                {
                    ulong value = is32Bit
                        ? ReadUInt32(data, cursor)
                        : ReadUInt64(data, cursor);

                    if (value == 0) break;

                    var ordinalFlag = is32Bit ? 0x8000_0000UL : 0x8000_0000_0000_0000UL;
                    if ((value & ordinalFlag) != 0)
                    {
                        imports.Add(new PeImportEntry(module, $"ordinal {value & 0xFFFF}", true));
                    }
                    else
                    {
                        // The name is stored behind a two byte hint, so the address points at
                        // the hint and the text starts two bytes later.
                        var hintName = RvaToOffset(sections, (uint)value);
                        if (hintName >= 0 && hintName + 2 < data.Length)
                        {
                            var name = ReadAsciiAt(data, hintName + 2);
                            if (name is not null)
                            {
                                imports.Add(new PeImportEntry(module, name, false));
                            }
                            else
                            {
                                var ordinal = ReadUInt16(data, hintName);
                                imports.Add(new PeImportEntry(module, $"ordinal {ordinal}", true));
                            }
                        }
                    }

                    cursor += step;
                }
            }
            else
            {
                warnings.Add($"The import table for \"{module}\" points outside the file.");
            }

            descriptor += 20;
        }
    }

    private static string? ReadStringAtRva(ReadOnlySpan<byte> data, IReadOnlyList<PeSection> sections, uint rva)
    {
        var offset = RvaToOffset(sections, rva);
        if (offset < 0 || offset >= data.Length) return null;

        return ReadAsciiAt(data, offset);
    }

    private static string? ReadAsciiAt(ReadOnlySpan<byte> data, int offset)
    {
        if (offset < 0 || offset >= data.Length) return null;

        var end = offset;
        var limit = Math.Min(data.Length, offset + 256);
        while (end < limit && data[end] != 0) end++;

        if (end == offset) return null;
        return System.Text.Encoding.ASCII.GetString(data.Slice(offset, end - offset));
    }

    private static int RvaToOffset(IReadOnlyList<PeSection> sections, uint rva)
    {
        if (rva == 0) return -1;

        foreach (var section in sections)
        {
            var span = Math.Max(section.VirtualSize, section.SizeOfRawData);
            if (span == 0) continue;
            if (rva < section.VirtualAddress || rva >= section.VirtualAddress + span) continue;

            return (int)(section.PointerToRawData + (rva - section.VirtualAddress));
        }

        return -1;
    }

    private static string ReadSectionName(ReadOnlySpan<byte> data, int offset)
    {
        var length = 0;
        while (length < 8 && data[offset + length] != 0) length++;
        return System.Text.Encoding.ASCII.GetString(data.Slice(offset, length));
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));

    private static ulong ReadUInt64(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8));
}
