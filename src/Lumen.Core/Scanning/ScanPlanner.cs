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
