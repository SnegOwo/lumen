using Lumen.Core.Models;

namespace Lumen.Core.Remediation;

/// <summary>
/// The hardcoded list of things Lumen refuses to touch. This list is deliberately small,
/// explicit and built into the product rather than configured, so it cannot be weakened
/// by a settings file, a registry value or a downloaded update. Two rules apply:
/// a process with a protected name is never stopped, and a process that runs from the
/// Windows or Program Files folders is never stopped either.
/// </summary>
public static class ProtectedProcesses
{
    private static readonly string[] Names =
    [
        "lsass",
        "wininit",
        "csrss",
        "services",
        "smss",
        "winlogon",
        "dwm"
    ];

    private static readonly HashSet<string> NameSet = new(Names, StringComparer.OrdinalIgnoreCase);

    /// <summary>The process names that are never terminated, in lower case.</summary>
    public static IReadOnlyList<string> ProtectedNames => Names;

    /// <summary>
    /// Decides whether a process is off limits. The answer is true when the operating
    /// system reports a system process, when the image name is on the protected list, or
    /// when the executable runs from a system folder.
    /// </summary>
    public static bool IsProtected(ProcessInfo process)
    {
        ArgumentNullException.ThrowIfNull(process);

        if (process.IsSystemProcess) return true;
        if (IsProtectedName(process.Name)) return true;
        return IsProtectedLocation(process.ExecutablePath);
    }

    /// <summary>True when the given image name is on the protected list.</summary>
    public static bool IsProtectedName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        return NameSet.Contains(name.Trim());
    }

    /// <summary>
    /// True when the path runs from the Windows or Program Files folders. The check looks
    /// at the first folder under the drive root, so "C:\Users\me\Windows\notes.txt" is
    /// not treated as a system path.
    /// </summary>
    public static bool IsProtectedLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        string full;
        try
        {
            full = Path.GetFullPath(path.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        var segments = full.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0) return false;

        // A drive-rooted path starts with "C:"; anything under it starts at index 1.
        var index = segments[0].EndsWith(":", StringComparison.Ordinal) ? 1 : 0;
        if (index >= segments.Length) return false;

        var first = segments[index];
        return first.Equals("Windows", StringComparison.OrdinalIgnoreCase)
            || first.Equals("Program Files", StringComparison.OrdinalIgnoreCase)
            || first.Equals("Program Files (x86)", StringComparison.OrdinalIgnoreCase);
    }
}
