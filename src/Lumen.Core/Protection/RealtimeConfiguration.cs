using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.Core.Protection;

/// <summary>
/// The effective real-time configuration: what the monitor watches, how fast it reacts
/// and how much it reads.
///
/// <para>
/// This is pure data. The application and the tests build it the same way, through
/// <see cref="RealtimeConfigurationResolver.Resolve"/>, so the behaviour that is tested
/// is the behaviour that runs.
/// </para>
/// </summary>
public sealed record RealtimeConfiguration
{
    /// <summary>
    /// The folders to watch, after nested duplicates were removed and excluded
    /// subtrees were dropped. Nothing is watched twice.
    /// </summary>
    public required IReadOnlyList<string> WatchRoots { get; init; }

    /// <summary>The subtree roots that are skipped entirely.</summary>
    public required IReadOnlyList<string> ExcludedFolders { get; init; }

    /// <summary>
    /// How long a file has to stay unchanged before it is inspected. Aggressive mode
    /// uses no delay at all: a file that is still being written is re-armed by the
    /// pending ledger and inspected again once it settles, so an early inspection is
    /// safe.
    /// </summary>
    public required TimeSpan SettleDelay { get; init; }

    /// <summary>
    /// How many files may be inspected at the same time. More workers mean a shorter
    /// answer when several files arrive together, and more CPU spent on inspection.
    /// </summary>
    public required int WorkerCount { get; init; }

    /// <summary>The number of leading bytes read per file.</summary>
    public required long MaxInspectBytes { get; init; }

    /// <summary>
    /// True when aggressive mode is on. The user interface shows this, because
    /// aggressive mode costs more CPU and covers more folders.
    /// </summary>
    public required bool AggressiveMode { get; init; }
}

/// <summary>
/// Turns the user's settings into the configuration the real-time monitor runs with.
///
/// <para>
/// This is the single place where the aggressive switch changes something. The
/// application and the tests both go through it, so there is exactly one answer to
/// "what does aggressive mode actually do".
/// </para>
///
/// <para>
/// Aggressive mode does two things: it watches the dropper locations as well as the
/// standard folders, and it stops waiting. The settle delay goes to zero and the
/// worker count goes up, which is why the mode costs more CPU. It does NOT change what
/// happens to a match: that is the job of <see cref="RealtimeResponsePolicy"/>, and it
/// still never deletes anything.
/// </para>
/// </summary>
public static class RealtimeConfigurationResolver
{
    /// <summary>
    /// The number of inspection workers aggressive mode uses. It is higher than the
    /// standard count so that a burst of files is answered faster, and it stays inside
    /// the bounds the monitor accepts.
    /// </summary>
    public const int AggressiveWorkerCount = 6;

    /// <summary>
    /// The settle delay aggressive mode uses: none at all. A file that is still being
    /// written is re-armed instead of being inspected half-written.
    /// </summary>
    public static readonly TimeSpan AggressiveSettleDelay = TimeSpan.Zero;

    /// <summary>
    /// Builds the effective configuration for the given settings.
    /// </summary>
    /// <param name="settings">The user's settings. They are normalized first, so a
    /// broken settings file cannot produce a broken configuration.</param>
    /// <param name="userProfile">The profile whose folders are watched.</param>
    /// <param name="additionalExcludedFolders">
    /// Folders to skip on top of the ones in the settings. The application passes
    /// Lumen's own data folder here, so Lumen never watches itself.
    /// </param>
    /// <returns>The configuration the monitor should run with.</returns>
    public static RealtimeConfiguration Resolve(
        AppSettings settings,
        string userProfile,
        IEnumerable<string>? additionalExcludedFolders = null)
    {
        var current = settings.Normalize();
        var exclusions = NormalizeExclusions(current.RealtimeExcludedFolders, additionalExcludedFolders);

        // Both watch lists cover the dropper locations: the Downloads folder, the
        // per-user Startup folder and the per-user temporary folder. Aggressive mode
        // adds the extra detection rules and the eagerness, not more folders.
        var roots = current.AggressiveMode
            ? AggressiveWatchList.Build(userProfile, current.RealtimeWatchFolders, exclusions)
            : AggressiveWatchList.BuildStandard(userProfile, current.RealtimeWatchFolders, exclusions);

        var settleDelay = current.AggressiveMode
            ? AggressiveSettleDelay
            : TimeSpan.FromMilliseconds(Math.Clamp(current.RealtimeSettleDelayMs, 0, 2000));

        var workerCount = current.AggressiveMode
            ? Math.Clamp(
                Math.Max(current.RealtimeWorkerCount, AggressiveWorkerCount),
                RealtimeMonitor.MinWorkerCount,
                RealtimeMonitor.MaxWorkerCount)
            : Math.Clamp(
                current.RealtimeWorkerCount,
                RealtimeMonitor.MinWorkerCount,
                RealtimeMonitor.MaxWorkerCount);

        return new RealtimeConfiguration
        {
            WatchRoots = roots,
            ExcludedFolders = exclusions,
            SettleDelay = settleDelay,
            WorkerCount = workerCount,
            MaxInspectBytes = InspectBytes(current),
            AggressiveMode = current.AggressiveMode
        };
    }

    /// <summary>
    /// The number of leading bytes read per file, clamped to the supported range.
    /// </summary>
    private static long InspectBytes(AppSettings settings) =>
        Math.Clamp(
            (long)settings.MaxInspectMegabytes * 1024L * 1024L,
            64L * 1024L,
            16L * 1024L * 1024L);

    /// <summary>
    /// Combines the excluded folders of the settings with the ones the caller adds, and
    /// drops the duplicates and the malformed paths.
    /// </summary>
    private static IReadOnlyList<string> NormalizeExclusions(
        IEnumerable<string>? fromSettings,
        IEnumerable<string>? additional)
    {
        var result = new List<string>();

        foreach (var folder in Enumerate(fromSettings).Concat(Enumerate(additional)))
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

    private static IEnumerable<string> Enumerate(IEnumerable<string>? folders) =>
        folders ?? [];
}
