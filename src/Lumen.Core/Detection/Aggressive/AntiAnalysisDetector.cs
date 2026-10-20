using System.Buffers.Binary;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Pe;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection.Aggressive;

/// <summary>
/// Reports a program that checks whether it is being analysed and also checks whether it
/// is running inside a virtual machine or a sandbox.
/// </summary>
/// <remarks>
/// <para>
/// Both halves are ordinary on their own. A program that reports a diagnostic message
/// with <c>OutputDebugString</c> is not unusual, and a program that mentions VMware is
/// not unusual either. Together they describe a program that wants to behave differently
/// depending on where it runs, which is why the rule needs both halves before it says
/// anything.
/// </para>
/// <para>
/// The detector reads the bytes the scanner already loaded and the import table it parses
/// from them. It performs no file system access.
/// </para>
/// <para>
/// This rule belongs to the AGGRESSIVE tier: it only runs when the user has asked for
/// maximum sensitivity.
/// </para>
/// </remarks>
public sealed class AntiAnalysisDetector : IScanDetector, IAggressiveDetector
{
    /// <summary>The identifier of the rule this detector reports.</summary>
    public const string RuleId = "pe.anti-analysis-checks";

    /// <summary>
    /// The names a program uses to notice that a debugger is attached.
    /// </summary>
    public static IReadOnlyCollection<string> DebuggerMarkers { get; } = new[]
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtSetInformationThread", "OutputDebugString", "SetInformationThread",
        "DebugActiveProcess"
    };

    /// <summary>
    /// The names of the virtual machines a program may look for.
    /// </summary>
    public static IReadOnlyCollection<string> VirtualMachineMarkers { get; } = new[]
    {
        "VMware", "vmtoolsd", "vmwaretray", "vboxservice", "vboxtray", "virtualbox",
        "VBoxGuest", "qemu-ga", "xen"
    };

    /// <summary>
    /// The names of the sandboxes a program may look for.
    /// </summary>
    public static IReadOnlyCollection<string> SandboxMarkers { get; } = new[]
    {
        "SbieDll", "wine_get_unix_file_name", "wine_get_version", "\\wine\\"
    };

    /// <summary>
    /// The delay, in milliseconds, that has to be found near the entry point before a
    /// sleep is treated as a way of slowing an analysis down. A second is not much of a
    /// delay; ten seconds is.
    /// </summary>
    public const long MinimumDelayMilliseconds = 10_000;

    /// <summary>
    /// How many bytes around the entry point are read looking for the delay.
    /// </summary>
    public const int EntryPointWindowBytes = 256;

    private static readonly string[] SleepImports = ["Sleep", "SleepEx", "NtDelayExecution"];

    private const string Advice =
        "Find out what the program is for and who published it. " +
        "A program that looks for analysis tools and for virtual machines often wants to be somewhere else when it runs.";

    /// <inheritdoc />
    public string Id => "pe.anti-analysis";

    /// <inheritdoc />
    public string Name => "Analysis and sandbox checks";

    /// <inheritdoc />
    public string Description =>
        "Reports a program that mentions a debugger check and also mentions a virtual machine or a sandbox.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var content = probe.Content.Span;
        if (content.Length < 64) return Array.Empty<Finding>();

        if (!PeParser.TryParse(content, probe.ContentTruncated, out var header, out _)) return Array.Empty<Finding>();
        if (header is null) return Array.Empty<Finding>();

        var environment = new List<string>();
        var analysis = new List<string>();

        foreach (var marker in DebuggerMarkers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsPresent(content, header, marker)) continue;
            analysis.Add(marker);
        }

        foreach (var marker in VirtualMachineMarkers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsPresent(content, header, marker)) continue;
            environment.Add(marker);
        }

        foreach (var marker in SandboxMarkers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsPresent(content, header, marker)) continue;
            environment.Add(marker);
        }

        if (FindLongDelay(content, header, out var delay))
        {
            analysis.Add($"a delay of {delay / 1000} seconds near the entry point");
        }

        if (analysis.Count == 0 || environment.Count == 0) return Array.Empty<Finding>();

        return
        [
            new Finding
            {
                RuleId = RuleId,
                Title = "Checks for analysis tools and virtual machines",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.Medium,
                Summary = "The program looks for a debugger and also looks for a virtual machine or a sandbox.",
                Detail =
                    "The file mentions " + string.Join(", ", analysis.Select(DisplayText.Sanitize)) +
                    " and also mentions " + string.Join(", ", environment.Select(DisplayText.Sanitize)) + ". " +
                    "Both halves are ordinary on their own: programs write debug messages and programs mention virtual machines. " +
                    "Together they describe a program that wants to behave differently depending on where it runs.",
                Advice = Advice
            }
        ];
    }

    /// <summary>
    /// Returns true when the marker appears in the import table or in the raw bytes of the
    /// file. A program can call a function by name without importing it, so both are checked.
    /// </summary>
    private static bool IsPresent(ReadOnlySpan<byte> content, PeHeader header, string marker)
    {
        foreach (var import in header.Imports)
        {
            if (string.Equals(import.Function, marker, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return ByteSearch.ContainsAscii(content, marker, caseSensitive: false);
    }

    /// <summary>
    /// Looks for a long delay written as a number near the entry point. The number is what
    /// a program passes to a sleep function, and it is the only part that says the delay
    /// is long.
    /// </summary>
    private static bool FindLongDelay(ReadOnlySpan<byte> content, PeHeader header, out long delay)
    {
        delay = 0;

        var sleeps = header.Imports.Any(import => SleepImports.Contains(import.Function, StringComparer.OrdinalIgnoreCase));
        if (!sleeps) return false;
        if (header.AddressOfEntryPoint == 0) return false;
        if (!PeParser.TryResolveOffset(header, header.AddressOfEntryPoint, out var offset)) return false;
        if (offset < 0 || offset >= content.Length) return false;

        var end = Math.Min(content.Length, offset + EntryPointWindowBytes);
        for (var index = offset; index + 4 <= end; index++)
        {
            var value = BinaryPrimitives.ReadUInt32LittleEndian(content.Slice(index, 4));
            if (value is < MinimumDelayMilliseconds or > 0x7FFF_FFFF) continue;

            delay = value;
            return true;
        }

        return false;
    }
}
