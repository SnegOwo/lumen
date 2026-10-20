using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.Core.Scanning;

/// <summary>
/// Builds safe default scan scopes. Quick and full scans never include system-critical
/// locations; user-selected scans may, but the UI warns first.
/// </summary>
public sealed class ScanPlanner
{
    private readonly string _userProfile;
    private readonly string _appDataRoot;
    private readonly AppSettings _settings;

    public ScanPlanner(string userProfile, string appDataRoot, AppSettings settings)
    {
        _userProfile = PathRules.NormalizeDirectory(userProfile);
        _appDataRoot = PathRules.NormalizeDirectory(appDataRoot);
        _settings = settings.Normalize();
    }

    public ScanRequest CreateQuick()
    {
        var folders = QuickFolders(_userProfile);
        return new ScanRequest
        {
            Scope = ScanScopeKind.Quick,
            Roots = folders,
            Description = "Quick scan \u2014 Desktop, Documents, Downloads",
            MaxInspectBytes = InspectBytes
        };
    }

    public ScanRequest CreateFullProfile()
    {
        return new ScanRequest
        {
            Scope = ScanScopeKind.FullUserProfile,
            Roots = [_userProfile],
            Description = "Full scan \u2014 user files (system and cache folders excluded)",
            ExcludedDirectories = PathRules.DefaultFullScanExclusions(_userProfile, _appDataRoot),
            MaxInspectBytes = InspectBytes
        };
    }

    public ScanRequest CreateFolder(string folder)
    {
        var validation = PathRules.ValidateTarget(folder);
        if (!validation.IsValid) throw new ArgumentException(validation.Error);
        if (!validation.IsDirectory) throw new ArgumentException("Choose a folder, not a file.");

        var full = PathRules.NormalizeDirectory(folder);
        var name = Path.GetFileName(full);
        if (string.IsNullOrWhiteSpace(name)) name = full;

        return new ScanRequest
        {
            Scope = ScanScopeKind.Folder,
            Roots = [full],
            Description = "Folder scan \u2014 " + DisplayText.Sanitize(name, 120),
            MaxInspectBytes = InspectBytes
        };
    }

    public ScanRequest CreateFile(string file)
    {
        var validation = PathRules.ValidateTarget(file);
        if (!validation.IsValid) throw new ArgumentException(validation.Error);
        if (validation.IsDirectory) throw new ArgumentException("Choose a file, not a folder.");

        var full = PathRules.NormalizeFile(file);
        return new ScanRequest
        {
            Scope = ScanScopeKind.File,
            Roots = [full],
            Description = "File scan \u2014 " + DisplayText.Sanitize(Path.GetFileName(full), 120),
            MaxInspectBytes = InspectBytes
        };
    }

    public static IReadOnlyList<string> QuickFolders(string userProfile)
    {
        var candidates = new List<string>();
        if (IsCurrentUserProfile(userProfile))
        {
            AddIfDirectory(candidates, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            AddIfDirectory(candidates, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        }
        else
        {
            AddIfDirectory(candidates, Path.Combine(userProfile, "Desktop"));
            AddIfDirectory(candidates, Path.Combine(userProfile, "Documents"));
        }

        AddIfDirectory(candidates, Path.Combine(userProfile, "Downloads"));

        return candidates
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Builds the folder list the real-time monitor should watch: the standard quick-scan
    /// folders plus the folders the user configured. Nested duplicates are removed so a
    /// folder is never watched twice, and a root that lies inside an excluded subtree is
    /// left out entirely.
    /// </summary>
    /// <param name="userProfile">The profile whose Desktop, Documents and Downloads folders
    /// are the default watch roots.</param>
    /// <param name="extraWatchFolders">Additional folders the user wants watched. Missing or
    /// malformed paths are ignored.</param>
    /// <param name="excludedFolders">Folders whose subtree is skipped entirely.</param>
    /// <returns>The watch roots in a stable order, without nested duplicates.</returns>
    public static IReadOnlyList<string> RealtimeWatchFolders(
        string userProfile,
        IEnumerable<string>? extraWatchFolders = null,
        IEnumerable<string>? excludedFolders = null)
    {
        var candidates = new List<string>(QuickFolders(userProfile));

        if (extraWatchFolders is not null)
        {
            foreach (var folder in extraWatchFolders)
            {
                if (string.IsNullOrWhiteSpace(folder)) continue;
                try
                {
                    candidates.Add(PathRules.NormalizeDirectory(folder));
                }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
                {
                    // A malformed path in the settings file is ignored rather than
                    // preventing real-time protection from starting.
                }
            }
        }

        var exclusions = new List<string>();
        if (excludedFolders is not null)
        {
            foreach (var folder in excludedFolders)
            {
                if (string.IsNullOrWhiteSpace(folder)) continue;
                try
                {
                    var full = PathRules.NormalizeDirectory(folder);
                    if (!exclusions.Contains(full, StringComparer.OrdinalIgnoreCase)) exclusions.Add(full);
                }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
                {
                    // A malformed exclusion rule is ignored rather than breaking monitoring.
                }
            }
        }

        var distinct = candidates
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(root => !exclusions.Any(excluded => PathRules.IsWithin(root, excluded)))
            .OrderBy(root => root.Length)
            .ToList();

        var result = new List<string>();
        foreach (var root in distinct)
        {
            var nested = false;
            foreach (var parent in result)
            {
                if (!PathRules.IsWithin(root, parent)) continue;
                nested = true;
                break;
            }

            if (!nested) result.Add(root);
        }

        return result;
    }

    private long InspectBytes =>
        Math.Clamp(
            (long)_settings.MaxInspectMegabytes * 1024L * 1024L,
            64L * 1024L,
            16L * 1024L * 1024L);

    private static bool IsCurrentUserProfile(string profile)
    {
        var current = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(current)) return false;
        try
        {
            return string.Equals(
                PathRules.NormalizeDirectory(profile),
                PathRules.NormalizeDirectory(current),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void AddIfDirectory(List<string> paths, string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            if (Directory.Exists(path)) paths.Add(PathRules.NormalizeDirectory(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // A missing or inaccessible known folder is simply omitted.
        }
    }
}
