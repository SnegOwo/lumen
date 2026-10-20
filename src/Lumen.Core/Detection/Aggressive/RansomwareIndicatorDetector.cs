using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection.Aggressive;

/// <summary>
/// Reports a script that walks a set of files, looks at their extensions and renames
/// them.
/// </summary>
/// <remarks>
/// <para>
/// Renaming files in bulk is a normal thing for a backup or housekeeping script to do, so
/// the rule needs the whole shape: the script has to enumerate files, it has to care
/// about their extensions, and it has to rename them. One of those three on its own is
/// ordinary.
/// </para>
/// <para>
/// The detector reads only the text the scanner already decoded and performs no file
/// system access.
/// </para>
/// <para>
/// This rule belongs to the AGGRESSIVE tier: it only runs when the user has asked for
/// maximum sensitivity. The commands that delete shadow copies and the wording of a ransom
/// note are covered by the signature rules, which are marked aggressive as well.
/// </para>
/// </remarks>
public sealed class RansomwareIndicatorDetector : IScanDetector, IAggressiveDetector
{
    /// <summary>The identifier of the rule this detector reports.</summary>
    public const string RuleId = "script.bulk-file-rename";

    private static readonly string[] ScriptExtensions =
    [
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".hta", ".py", ".sh", ".txt", ".log"
    ];

    /// <summary>
    /// The ways a script walks over files.
    /// </summary>
    private static readonly string[] EnumerationTokens =
    [
        "get-childitem", "gci ", "dir /s", "dir /b", "foreach", "for each", "os.walk",
        "glob.glob", "enumeratefiles", "readdir", "forfiles", "getfilesystemitems",
        "get-childitem -", "find /f"
    ];

    /// <summary>
    /// The extensions a script that renames files by type tends to look for.
    /// </summary>
    private static readonly string[] ExtensionTokens =
    [
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg",
        ".png", ".zip", ".rar", ".sql", ".mdb", ".bak", ".pst", ".vmdk", ".csv", ".txt"
    ];

    /// <summary>
    /// The ways a script changes the name of a file.
    /// </summary>
    private static readonly string[] RenameTokens =
    [
        "rename-item", "rename ", "move-item", "os.rename", "shutil.move", ".rename(",
        "mv ", "ren "
    ];

    private const string Advice =
        "Read the script before you run it and find out where it came from. " +
        "A script that renames files in bulk is used by housekeeping and backup tools as well, so the context decides what it means.";

    /// <inheritdoc />
    public string Id => "script.bulk-rename";

    /// <inheritdoc />
    public string Name => "Bulk file renaming";

    /// <inheritdoc />
    public string Description =>
        "Reports a script that enumerates files, looks at their extensions and renames them.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var extension = Path.GetExtension(probe.FileName);
        if (!ScriptExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)) return Array.Empty<Finding>();

        var text = probe.GetTextSample();
        if (string.IsNullOrWhiteSpace(text)) return Array.Empty<Finding>();

        var lower = text.ToLowerInvariant();

        var enumeration = EnumerationTokens.Where(token => TextPatterns.ContainsWord(lower, token)).ToArray();

        // The extensions are matched as plain text, because the extension of a file is
        // often followed by more of the name, as in "*.docx".
        var extensions = ExtensionTokens.Where(token => TextPatterns.Contains(lower, token)).ToArray();

        var renames = RenameTokens.Where(token => TextPatterns.ContainsWord(lower, token)).ToArray();

        if (enumeration.Length == 0 || extensions.Length == 0 || renames.Length == 0) return Array.Empty<Finding>();

        return
        [
            new Finding
            {
                RuleId = RuleId,
                Title = "Script renames many files at once",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.Medium,
                Summary = "The script walks over files, looks at their extensions and renames them.",
                Detail =
                    "The script enumerates files (" + string.Join(", ", enumeration) + "), " +
                    "mentions the extensions " + string.Join(", ", extensions) + " and " +
                    "renames files (" + string.Join(", ", renames) + "). " +
                    "Backup and housekeeping scripts do this too, so the shape alone does not say what the files are for.",
                Advice = Advice
            }
        ];
    }
}
