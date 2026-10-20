using Lumen.Core.Abstractions;
using Lumen.Core.Detection.Shortcuts;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection;

/// <summary>
/// Answers whether a shortcut target exists. The detector never touches the file system
/// itself, so this is how the caller supplies that knowledge.
/// </summary>
public interface IShortcutTargetResolver
{
    /// <summary>
    /// Returns true when the target exists, false when it does not, and null when the
    /// answer is not known. A null answer must never be treated as "does not exist".
    /// </summary>
    bool? TargetExists(string target);
}

/// <summary>
/// A resolver that never answers. It is the default so that a shortcut is never called
/// dangling just because nobody checked.
/// </summary>
public sealed class UnknownShortcutTargetResolver : IShortcutTargetResolver
{
    /// <summary>The shared instance.</summary>
    public static UnknownShortcutTargetResolver Instance { get; } = new();

    /// <inheritdoc />
    public bool? TargetExists(string target) => null;
}

/// <summary>
/// Reads shortcuts and web shortcuts and reports the ones that point somewhere a person
/// would not expect.
/// </summary>
/// <remarks>
/// <para>
/// A shortcut is a small file that starts another file. Shortcuts that launch a script
/// interpreter, that point into a temporary folder, or that point at a file which is not
/// there are all worth a second look.
/// </para>
/// <para>
/// The detector performs no file system access of its own. Whether the target exists is
/// answered by an injected <see cref="IShortcutTargetResolver"/>, which keeps the
/// detector pure and testable.
/// </para>
/// </remarks>
public sealed class ShortcutDetector : IScanDetector
{
    private static readonly string[] ShortcutExtensions = [".lnk", ".url", ".desktop"];

    private static readonly string[] ScriptInterpreterNames =
    [
        "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe",
        "wscript", "cscript", "mshta", "powershell", "pwsh"
    ];

    private static readonly string[] ScriptExtensions =
    [
        ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".scr"
    ];

    private static readonly string[] TemporaryPathMarkers =
    [
        "\\appdata\\", "\\local\\", "\\roaming\\", "\\temp\\", "\\tmp\\", "\\downloads\\",
        "\\public\\", "\\windows\\temp\\", "\\recycler\\", "\\$recycle.bin\\"
    ];

    private readonly IShortcutTargetResolver _resolver;

    /// <summary>
    /// Creates the detector with the default resolver, which never claims that a target is
    /// missing.
    /// </summary>
    public ShortcutDetector() : this(UnknownShortcutTargetResolver.Instance)
    {
    }

    /// <summary>
    /// Creates the detector with an explicit resolver for checking whether the target of a
    /// shortcut exists.
    /// </summary>
    public ShortcutDetector(IShortcutTargetResolver resolver)
    {
        _resolver = resolver;
    }

    /// <inheritdoc />
    public string Id => "shortcut.analysis";

    /// <inheritdoc />
    public string Name => "Shortcut analysis";

    /// <inheritdoc />
    public string Description =>
        "Reads Windows shortcuts, internet shortcuts and desktop entries, and reports targets that run a script interpreter, point into a temporary folder, or point at something that is not there.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var extension = Path.GetExtension(probe.FileName);
        if (!ShortcutExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)) return Array.Empty<Finding>();

        var info = ReadShortcut(probe, extension);
        if (info is null) return Array.Empty<Finding>();

        var target = info.EffectiveTarget;
        if (string.IsNullOrWhiteSpace(target)) return Array.Empty<Finding>();

        var findings = new List<Finding>();
        var safeTarget = DisplayText.SanitizePath(target);

        if (IsScriptTarget(target))
        {
            findings.Add(new Finding
            {
                RuleId = "shortcut.script-target",
                Title = "Shortcut launches a script interpreter",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.Medium,
                Summary = "The shortcut starts a program whose job is to run scripts.",
                Detail =
                    $"The shortcut points at \"{safeTarget}\", which runs scripts rather than doing a job of its own. " +
                    "A shortcut that launches a script is a common way to make a payload look like a normal shortcut. " +
                    "Shortcuts to the command prompt or to PowerShell are also common.",
                Advice = "Open the target and read it before you use the shortcut."
            });
        }

        if (LooksTemporary(target))
        {
            findings.Add(new Finding
            {
                RuleId = "shortcut.temp-path-target",
                Title = "Shortcut points into a temporary or shared folder",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Medium,
                Summary = "The shortcut launches a file from a folder that is meant to hold temporary downloads.",
                Detail =
                    $"The shortcut points at \"{safeTarget}\". " +
                    "Files in temporary and shared folders are easy to replace and are a usual place for a payload to sit.",
                Advice = "Check the target file itself before you run the shortcut."
            });
        }

        if (IsMissing(target))
        {
            findings.Add(new Finding
            {
                RuleId = "shortcut.dangling-target",
                Title = "Shortcut points at a file that is not there",
                Category = FindingCategory.Heuristic,
                Confidence = Confidence.Low,
                Summary = "The shortcut launches a target that does not exist on this machine.",
                Detail =
                    $"The shortcut points at \"{safeTarget}\", and that file is not present. " +
                    "A shortcut whose target is missing either points at a program that was uninstalled, or at a file that " +
                    "was meant to be dropped in later.",
                Advice = "Look at where the shortcut came from before you use it."
            });
        }

        return findings;
    }

    private static ShortcutInfo? ReadShortcut(FileProbe probe, string extension)
    {
        if (extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            if (!ShortcutParser.TryParse(probe.Content.Span, out var info, out _)) return null;
            return info;
        }

        var text = probe.GetTextSample();
        if (string.IsNullOrWhiteSpace(text)) return null;

        return extension.Equals(".desktop", StringComparison.OrdinalIgnoreCase)
            ? ShortcutParser.ParseDesktopFile(text)
            : ShortcutParser.ParseUrlFile(text);
    }

    private bool IsMissing(string target)
    {
        try
        {
            return _resolver.TargetExists(target) == false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool IsScriptTarget(string target)
    {
        var fileName = Path.GetFileName(target);
        if (ScriptInterpreterNames.Contains(fileName, StringComparer.OrdinalIgnoreCase)) return true;

        var extension = Path.GetExtension(fileName);
        return ScriptExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
    }

    private static bool LooksTemporary(string target)
    {
        var lower = target.ToLowerInvariant();
        if (lower.StartsWith("\\\\", StringComparison.Ordinal)) return true;

        foreach (var marker in TemporaryPathMarkers)
        {
            if (lower.Contains(marker, StringComparison.Ordinal)) return true;
        }

        return false;
    }
}
