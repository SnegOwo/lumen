using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Pe;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection.Aggressive;

/// <summary>
/// Reports the shape of a program that loads a library from its own folder.
/// </summary>
/// <remarks>
/// <para>
/// Windows loads a library from the folder of the program first when the name is not a
/// full path, so a library that sits next to a program can be loaded instead of the one
/// in the Windows folder. This is the shape a program that copies itself into a folder
/// and brings its own library along has, and it is also the shape of a program that was
/// dropped into a folder and had a library placed beside it.
/// </para>
/// <para>
/// The detector cannot list the folder, because a detector never touches the file system.
/// It works from the path of the probe instead, and it only reports a folder the user can
/// write to, so a program installed under Program Files is never reported for this.
/// </para>
/// <para>
/// This rule belongs to the AGGRESSIVE tier: it only runs when the user has asked for
/// maximum sensitivity.
/// </para>
/// </remarks>
public sealed class DllSideloadDetector : IScanDetector, IAggressiveDetector
{
    /// <summary>The identifier of the rule this detector reports.</summary>
    public const string RuleId = "pe.dll-sideload-candidate";

    /// <summary>
    /// The libraries that ship with Windows. The list is deliberately short and
    /// conservative: a library that is not on it is only interesting when it also has
    /// something else going for it.
    /// </summary>
    public static IReadOnlyCollection<string> KnownSystemLibraries { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "kernel32", "kernelbase", "ntdll", "user32", "gdi32", "gdiplus", "advapi32", "shell32",
        "ole32", "oleaut32", "comctl32", "comdlg32", "shlwapi", "ws2_32", "wsock32", "wininet",
        "urlmon", "crypt32", "wintrust", "secur32", "rpcrt4", "msvcrt", "ucrtbase", "vcruntime140",
        "vcruntime140_1", "msvcp140", "psapi", "iphlpapi", "winmm", "version", "shcore",
        "propsys", "dbghelp", "msimg32", "uxtheme", "dwmapi", "pdh", "difxapi", "setupapi",
        "cfgmgr32", "netapi32", "userenv", "powrprof", "bcrypt", "ncrypt", "credui", "mpr",
        "winspool", "imm32", "msacm32", "winhttp", "sspicli", "cryptui", "cabinet"
    };

    /// <summary>
    /// The Windows libraries that a program is often made to load from its own folder
    /// instead of from the Windows folder.
    /// </summary>
    public static IReadOnlyCollection<string> ReplaceableWindowsLibraries { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "version", "dbghelp", "winhttp", "wintrust", "crypt32", "secur32", "cabinet",
        "propsys", "taskschd", "msimg32", "pdh", "uxtheme", "dwmapi", "difxapi"
    };

    private const string Advice =
        "Look at the folder the program sits in and see what else is in it. " +
        "A program that loads a library from its own folder can be made to run a different library than the one you expect.";

    private readonly ISuspiciousLocation _locations;

    /// <summary>
    /// Creates the detector using the folders of this machine to decide where a file lives.
    /// </summary>
    public DllSideloadDetector() : this(new DefaultSuspiciousLocation())
    {
    }

    /// <summary>
    /// Creates the detector with an explicit answer to the question of where a file lives,
    /// so the rule can be tested without depending on the machine it runs on.
    /// </summary>
    /// <param name="locations">Decides whether a path is in a folder the user can write to.</param>
    public DllSideloadDetector(ISuspiciousLocation locations)
    {
        _locations = locations;
    }

    /// <inheritdoc />
    public string Id => "pe.dll-sideload";

    /// <inheritdoc />
    public string Name => "Library sideloading shapes";

    /// <inheritdoc />
    public string Description =>
        "Reports a program that loads a library of its own name from a folder the user can write to, and a file that is named after a Windows library and sits in such a folder.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Heuristic;

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

        // Only a folder the user can write to is interesting. A program installed under
        // Program Files loads its libraries from there for good reasons.
        if (!_locations.IsSuspicious(probe.Path)) return Array.Empty<Finding>();

        var observations = new List<string>();

        var ownName = Path.GetFileNameWithoutExtension(probe.FileName);
        foreach (var module in header.Imports.Select(import => import.Module).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var libraryName = Path.GetFileNameWithoutExtension(module);
            if (libraryName.Length == 0) continue;
            if (KnownSystemLibraries.Contains(libraryName)) continue;
            if (!string.Equals(libraryName, ownName, StringComparison.OrdinalIgnoreCase)) continue;

            observations.Add($"the import table names \"{DisplayText.Sanitize(module)}\", which has the same name as the program itself");
        }

        var fileName = Path.GetFileName(probe.FileName);
        var fileLibraryName = Path.GetFileNameWithoutExtension(fileName);
        var isLibrary = (header.Characteristics & 0x2000) != 0;
        if (isLibrary && ReplaceableWindowsLibraries.Contains(fileLibraryName))
        {
            var signing = header.HasValidDigitalSignature
                ? "The file carries a certificate table."
                : "Nothing in the file says who published it.";

            observations.Add(
                $"the file is a library named \"{DisplayText.Sanitize(fileName)}\", the name of a Windows library that a program often loads from its own folder. {signing}");
        }

        if (observations.Count == 0) return Array.Empty<Finding>();

        return
        [
            new Finding
            {
                RuleId = RuleId,
                Title = "Library loaded from the program's own folder",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The program can load a library that sits next to it instead of the one in the Windows folder.",
                Detail =
                    "The file was found to have: " + string.Join("; ", observations) + ". " +
                    "The program sits in a folder the user can write to, so a library placed in that folder can be loaded in place of the Windows one. " +
                    "Lumen cannot list the folder, so this rule reports the shape that makes it possible rather than the file that was found there.",
                Advice = Advice
            }
        ];
    }
}
