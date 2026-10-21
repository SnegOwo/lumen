using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Protection;

/// <summary>
/// Builds the watch list for AGGRESSIVE mode.
///
/// <para>
/// The standard watch list is the quick-scan folders: Desktop, Documents, Downloads and
/// whatever the user added. Those are the folders a user checks by hand. Aggressive
/// mode adds the folders a dropper actually uses, because those are the folders nobody
/// looks at:
///
/// </para>
/// <list type="bullet">
/// <item><description>the Downloads folder, where a browser puts what it downloaded;</description></item>
/// <item><description>
/// the per-user Startup folder, where a file is run at every logon;
/// </description></item>
/// <item><description>
/// the per-user temporary folder, where an installer unpacks itself.
/// </description></item>
/// </list>
///
/// <para>
/// The cost is real: more folders means more file-system events, and more eager
/// inspection means more CPU. The caller is expected to show the number of watched
/// folders so the user knows what aggressive mode costs them.
/// </para>
///
/// <para>
/// Every path here is derived from the profile the caller passes in. Nothing in this
/// class reads the real user profile, so a test can point it at a temporary folder and
/// get a list that describes that folder.
/// </para>
/// </summary>
public static class AggressiveWatchList
{
    /// <summary>
    /// The name of the Startup folder inside the per-user application data folder.
    /// A file dropped there is started at every logon.
    /// </summary>
    public const string StartupFolderName = "Startup";

    /// <summary>
    /// Builds the aggressive watch list: the standard watch roots plus the dropper
    /// locations, minus everything inside an excluded subtree, with nested folders
    /// removed so no folder is watched twice.
    /// </summary>
    /// <param name="userProfile">
    /// The profile whose Downloads, Startup and temporary folders are added.
    /// </param>
    /// <param name="extraWatchFolders">Additional folders the user wants watched.</param>
    /// <param name="excludedFolders">
    /// Folders whose subtree is skipped. A root inside one of them is not watched at
    /// all, and the dropper locations are skipped the same way.
    /// </param>
    /// <returns>The watch roots, in a stable order, without nested duplicates.</returns>
    public static IReadOnlyList<string> Build(
        string userProfile,
        IEnumerable<string>? extraWatchFolders = null,
        IEnumerable<string>? excludedFolders = null)
    {
        var exclusions = Normalize(excludedFolders);

        var candidates = new List<string>(
            ScanPlanner.RealtimeWatchFolders(userProfile, extraWatchFolders, exclusions));

        foreach (var location in DropperLocations(userProfile))
        {
            // A location that does not exist is left out: a watcher on a folder that is
            // not there would keep the monitor in a permanently degraded state and would
            // pretend to cover something it cannot watch.
            if (!Exists(location)) continue;
            candidates.Add(location);
        }

        return Deduplicate(candidates, exclusions);
    }

    /// <summary>
    /// The watch list used when aggressive mode is OFF.
    ///
    /// <para>
    /// It is the standard quick-scan folders PLUS the per-user Startup folder and the
    /// per-user temporary folder.
    /// </para>
    ///
    /// <para>
    /// Those two are in the standard list on purpose. A file dropped in the Startup
    /// folder is run at every logon, and a file unpacked into the temporary folder is
    /// exactly the kind of thing nobody looks at by hand. Watching them costs a folder
    /// watch and nothing else — the cost of aggressive mode is the extra DETECTION RULES
    /// and the eagerness, not the number of folders.
    /// </para>
    /// </summary>
    /// <param name="userProfile">The profile whose folders are watched.</param>
    /// <param name="extraWatchFolders">Additional folders the user wants watched.</param>
    /// <param name="excludedFolders">Folders whose subtree is skipped.</param>
    /// <returns>The watch roots, in a stable order, without nested duplicates.</returns>
    public static IReadOnlyList<string> BuildStandard(
        string userProfile,
        IEnumerable<string>? extraWatchFolders = null,
        IEnumerable<string>? excludedFolders = null)
    {
        var exclusions = Normalize(excludedFolders);

        var candidates = new List<string>(
            ScanPlanner.RealtimeWatchFolders(userProfile, extraWatchFolders, exclusions));

        // The Startup folder and the temporary folder. The Downloads folder is already
        // part of the standard roots.
        foreach (var location in new[] { StartupFolder(userProfile), TempFolder(userProfile) })
        {
            if (!Exists(location)) continue;
            candidates.Add(location);
        }

        return Deduplicate(candidates, exclusions);
    }

    /// <summary>
    /// The folders a dropper uses, derived from the given profile: the Downloads
    /// folder, the per-user Startup folder and the per-user temporary folder.
    ///
    /// <para>
    /// The paths are returned whether or not they exist, so a caller can decide what to
    /// do with a folder that is not there.
    /// </para>
    /// </summary>
    /// <param name="userProfile">The profile the folders belong to.</param>
    /// <returns>The three locations, normalized.</returns>
    public static IReadOnlyList<string> DropperLocations(string userProfile)
    {
        var results = new List<string>();

        Add(results, Path.Combine(userProfile, "Downloads"));
        Add(results, StartupFolder(userProfile));
        Add(results, TempFolder(userProfile));

        return results;
    }

    /// <summary>
    /// The per-user Startup folder: a file that is dropped there runs at every logon.
    /// </summary>
    /// <param name="userProfile">The profile the folder belongs to.</param>
    /// <returns>The full path of the Startup folder.</returns>
    public static string StartupFolder(string userProfile) =>
        Path.Combine(
            userProfile,
            "AppData",
            "Roaming",
            "Microsoft",
            "Windows",
            "Start Menu",
            "Programs",
            StartupFolderName);

    /// <summary>
    /// The per-user temporary folder: an installer unpacks itself here.
    /// </summary>
    /// <param name="userProfile">The profile the folder belongs to.</param>
    /// <returns>The full path of the temporary folder.</returns>
    public static string TempFolder(string userProfile) =>
        Path.Combine(userProfile, "AppData", "Local", "Temp");

    /// <summary>
    /// Removes the roots that lie inside an excluded subtree and the roots that are
    /// nested inside another root, so a folder is never watched twice.
    /// </summary>
    private static IReadOnlyList<string> Deduplicate(
        IEnumerable<string> candidates,
        IReadOnlyList<string> exclusions)
    {
        var normalized = new List<string>();
        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate)) continue;

            string full;
            try
            {
                full = PathRules.NormalizeDirectory(candidate);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // A malformed path is ignored rather than breaking monitoring.
                continue;
            }

            // Containment, not a string prefix: "C:\Folder" must not match "C:\Folder2".
            if (PathRules.IsExcluded(full, exclusions)) continue;
            if (normalized.Contains(full, StringComparer.OrdinalIgnoreCase)) continue;
            normalized.Add(full);
        }

        // The parents come first, so a nested folder is recognized as nested.
        var result = new List<string>();
        foreach (var root in normalized.OrderBy(path => path.Length))
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

    /// <summary>
    /// Normalizes the exclusion rules and drops the malformed ones.
    /// </summary>
    private static IReadOnlyList<string> Normalize(IEnumerable<string>? folders)
    {
        if (folders is null) return [];

        var result = new List<string>();
        foreach (var folder in folders)
        {
            if (string.IsNullOrWhiteSpace(folder)) continue;
            try
            {
                var full = PathRules.NormalizeDirectory(folder);
                if (!result.Contains(full, StringComparer.OrdinalIgnoreCase)) result.Add(full);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // A malformed exclusion rule is ignored rather than breaking monitoring.
            }
        }

        return result;
    }

    private static void Add(List<string> paths, string path)
    {
        try
        {
            paths.Add(PathRules.NormalizeDirectory(path));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            // A profile path that Windows cannot parse simply has no dropper location.
        }
    }

    private static bool Exists(string path)
    {
        try
        {
            return Directory.Exists(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }
}
