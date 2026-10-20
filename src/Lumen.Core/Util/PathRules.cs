namespace Lumen.Core.Util;

public sealed record PathValidation(bool IsValid, bool IsDirectory, string? Error)
{
    public static PathValidation Invalid(string error) => new(false, false, error);
    public static PathValidation File(string path) => new(true, false, null);
    public static PathValidation Directory(string path) => new(true, true, null);
}

/// <summary>
/// Path normalization and containment rules. These are security relevant: they decide what
/// is skipped for safety (reparse points, offline placeholders) and what counts as a
/// system-critical location.
/// </summary>
public static class PathRules
{
    private static readonly char Separator = Path.DirectorySeparatorChar;

    public static string NormalizeDirectory(string path)
    {
        var full = Path.GetFullPath(path.Trim());
        var root = Path.GetPathRoot(full);
        if (!string.IsNullOrEmpty(root) && full.Length > root.Length)
        {
            full = Path.TrimEndingDirectorySeparator(full);
        }

        return full;
    }

    public static string NormalizeFile(string path) => Path.GetFullPath(path.Trim());

    public static bool IsWithin(string path, string directory)
    {
        var candidate = NormalizeDirectory(path);
        var parent = NormalizeDirectory(directory);
        if (string.Equals(candidate, parent, StringComparison.OrdinalIgnoreCase)) return true;

        var prefix = parent.EndsWith(Separator) ? parent : parent + Separator;
        return candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsExcluded(string path, IReadOnlyList<string> excludedDirectories)
    {
        foreach (var excluded in excludedDirectories)
        {
            if (string.IsNullOrWhiteSpace(excluded)) continue;
            try
            {
                if (IsWithin(path, excluded)) return true;
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // A malformed exclusion rule is ignored rather than crashing a scan.
            }
        }

        return false;
    }

    public static bool IsReparsePoint(FileAttributes attributes) =>
        (attributes & FileAttributes.ReparsePoint) != 0;

    public static bool IsOfflinePlaceholder(FileAttributes attributes) =>
        (attributes & FileAttributes.Offline) != 0;

    public static bool IsNetworkPath(string path)
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return true;
        return Uri.TryCreate(path, UriKind.Absolute, out var uri) && uri.IsUnc;
    }

    public static bool IsDriveRoot(string path)
    {
        var full = NormalizeDirectory(path);
        var root = Path.GetPathRoot(full);
        return !string.IsNullOrEmpty(root) &&
               string.Equals(
                   Path.TrimEndingDirectorySeparator(full),
                   Path.TrimEndingDirectorySeparator(root),
                   StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsSystemCritical(string path)
    {
        try
        {
            var full = NormalizeDirectory(path);
            if (IsDriveRoot(full)) return true;

            var sensitiveRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                Environment.SystemDirectory
            };

            foreach (var root in sensitiveRoots)
            {
                if (string.IsNullOrWhiteSpace(root)) continue;
                if (IsWithin(full, root)) return true;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        return false;
    }

    public static PathValidation ValidateTarget(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return PathValidation.Invalid("Choose a file or folder first.");

        string full;
        try
        {
            full = Path.GetFullPath(input.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return PathValidation.Invalid("That path is not valid on this system.");
        }

        try
        {
            if (Directory.Exists(full)) return PathValidation.Directory(full);
            if (File.Exists(full)) return PathValidation.File(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PathTooLongException)
        {
            return PathValidation.Invalid("That location could not be accessed with your current permissions.");
        }

        return PathValidation.Invalid("That file or folder does not exist.");
    }

    public static IReadOnlyList<string> DefaultFullScanExclusions(string userProfile, string appDataRoot)
    {
        var candidates = new[]
        {
            Path.Combine(userProfile, "AppData"),
            Path.Combine(userProfile, ".git"),
            Path.Combine(userProfile, ".vs"),
            Path.Combine(userProfile, ".nuget"),
            Path.Combine(userProfile, ".cache"),
            Path.Combine(userProfile, ".gradle"),
            Path.Combine(userProfile, "node_modules"),
            Path.Combine(userProfile, "$Recycle.Bin"),
            appDataRoot
        };

        return candidates
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path =>
            {
                try { return NormalizeDirectory(path); }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
            })
            .Where(path => path is not null)
            .Select(path => path!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<string> NormalizeRoots(IEnumerable<string> roots)
    {
        var normalized = new List<string>();
        foreach (var root in roots)
        {
            if (string.IsNullOrWhiteSpace(root)) continue;
            var full = Path.GetFullPath(root.Trim());
            if (!normalized.Contains(full, StringComparer.OrdinalIgnoreCase))
                normalized.Add(full);
        }

        // Remove roots that are already inside another root so files are not scanned twice.
        var result = new List<string>();
        foreach (var root in normalized.OrderBy(path => path.Length))
        {
            if (result.Any(parent => IsWithin(root, parent))) continue;
            result.Add(root);
        }

        return result;
    }
}
