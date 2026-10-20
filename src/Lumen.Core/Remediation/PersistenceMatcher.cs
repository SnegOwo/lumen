using Lumen.Core.Models;

namespace Lumen.Core.Remediation;

/// <summary>
/// Decides whether an autostart entry really points at the file Lumen wants to clean up.
/// The check is deliberately generous about the shape of the target (a command line may
/// quote the path or add arguments) and strict about the file itself: the path has to
/// appear in the entry. Lumen re-checks every entry the operating system reports, so a
/// report that contains unrelated entries cannot turn into unrelated removals.
/// </summary>
public static class PersistenceMatcher
{
    /// <summary>
    /// True when the entry refers to the given file. A file that is not there is never
    /// matched, so an empty or missing target path cannot match everything.
    /// </summary>
    public static bool PointsAt(PersistenceEntry entry, string? filePath)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (string.IsNullOrWhiteSpace(filePath)) return false;

        string target;
        try
        {
            target = Path.GetFullPath(filePath.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        foreach (var candidate in Candidates(entry))
        {
            if (candidate is null) continue;
            if (candidate.Contains(target, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    private static IEnumerable<string?> Candidates(PersistenceEntry entry)
    {
        yield return entry.TargetPath;
        yield return entry.Location;
        yield return entry.RestoreData.RegistryValueData;
        yield return entry.RestoreData.ServiceImagePath;
        yield return entry.RestoreData.StartupItemPath;
        yield return entry.RestoreData.ScheduledTaskXml;
    }
}
