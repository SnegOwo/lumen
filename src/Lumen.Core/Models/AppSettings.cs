using Lumen.Core.Util;

namespace Lumen.Core.Models;

public sealed record AppSettings
{
    public const int MinAllowedInspectMegabytes = 1;
    public const int MaxAllowedInspectMegabytes = 16;
    public const int DefaultInspectMegabytes = 1;

    public int SchemaVersion { get; init; } = 1;
    public AppTheme Theme { get; init; } = AppTheme.System;
    public bool LoggingEnabled { get; init; } = true;
    public int MaxInspectMegabytes { get; init; } = DefaultInspectMegabytes;
    public bool MinimizeToTray { get; init; } = false;
    public bool ShowTrayNotifications { get; init; } = true;

    /// <summary>
    /// Inspect new and changed files in the quick-scan folders while Lumen is running.
    /// This is a user-mode watcher, not a driver; system folders are never covered.
    /// </summary>
    public bool RealtimeProtectionEnabled { get; init; } = true;

    /// <summary>
    /// Move real-time matches straight into the encrypted vault without an extra prompt.
    /// Off by default: with it off, Lumen only reports matches and never changes files.
    /// </summary>
    public bool RealtimeAutoQuarantine { get; init; } = false;

    /// <summary>
    /// Extra folders the real-time monitor should watch, in addition to the standard
    /// quick-scan folders. Empty means "the quick-scan folders only", which is the
    /// behaviour of Lumen 1.0. Paths that do not exist are ignored at runtime.
    /// </summary>
    public IReadOnlyList<string> RealtimeWatchFolders { get; init; } = [];

    /// <summary>
    /// Folders whose entire subtree the real-time monitor must skip, in addition to
    /// Lumen's own data folder. Use this for build caches and tool directories that
    /// are noisy but harmless.
    /// </summary>
    public IReadOnlyList<string> RealtimeExcludedFolders { get; init; } = [];

    /// <summary>
    /// Master switch for the remediation engine (process termination, permanent
    /// removal, persistence cleanup). Off by default: with it off, Lumen can only
    /// detect and quarantine, exactly as in Lumen 1.0.
    /// </summary>
    public bool RemediationEnabled { get; init; } = false;

    /// <summary>
    /// The user interface language. English and French are shipped.
    /// </summary>
    public AppLanguage Language { get; init; } = AppLanguage.English;

    /// <summary>
    /// Show the full-screen detection alert when something is flagged. The alert is
    /// deliberately loud: this is a demonstration build, and a detection that nobody
    /// notices is a detection that did not happen.
    /// </summary>
    public bool DetectionAlertEnabled { get; init; } = true;

    /// <summary>
    /// Play a sound with the detection alert. Off by default because an unexpected
    /// noise on someone's machine is rude.
    /// </summary>
    public bool DetectionAlertSoundEnabled { get; init; } = false;

    /// <summary>
    /// Show the cat. It has no effect on any detection; it exists because a security
    /// tool that takes itself too seriously is a security tool nobody wants to open.
    /// </summary>
    public bool DetectionAlertCatEnabled { get; init; } = true;

    /// <summary>
    /// Stop the processes that are using a file the real-time monitor flagged.
    ///
    /// This is off by default and it also needs <see cref="RemediationEnabled"/>. Even
    /// then, only processes whose executable or loaded module IS the flagged file are
    /// stopped, and never a protected or system process.
    /// </summary>
    public bool RealtimeAutoKill { get; init; } = false;

    /// <summary>
    /// How long the real-time monitor waits for a file to stop changing before it
    /// inspects it. A short delay means a faster answer; a long one means fewer
    /// half-written files.
    /// </summary>
    public int RealtimeSettleDelayMs { get; init; } = 150;

    /// <summary>
    /// How many files the real-time monitor may inspect at the same time. More workers
    /// react faster but use more CPU.
    /// </summary>
    public int RealtimeWorkerCount { get; init; } = 3;

    /// <summary>
    /// How long Lumen stays quiet about a file it has already raised the alert for.
    /// Without this, a file that is touched repeatedly takes over the screen every time.
    /// </summary>
    public int AlertCooldownSeconds { get; init; } = 120;

    /// <summary>
    /// Aggressive mode.
    ///
    /// It turns on the extra detection tier, the folders that matter most for a
    /// dropper (Downloads, Startup, the temp folder), and the automatic quarantine of
    /// high-confidence matches. It is off by default because the extra tier is
    /// noisier than the standard rules, even though every rule in it is documented
    /// and tested.
    /// </summary>
    public bool AggressiveMode { get; init; } = false;

    public static AppSettings Default => new();

    /// <summary>Clamps out-of-range or unknown values so a bad file cannot break startup.</summary>
    public AppSettings Normalize()
    {
        var theme = Enum.IsDefined(Theme) ? Theme : AppTheme.System;
        var megabytes = Math.Clamp(MaxInspectMegabytes, MinAllowedInspectMegabytes, MaxAllowedInspectMegabytes);
        return this with
        {
            SchemaVersion = 1,
            Theme = theme,
            MaxInspectMegabytes = megabytes,
            RealtimeWatchFolders = NormalizeFolders(RealtimeWatchFolders),
            RealtimeExcludedFolders = NormalizeFolders(RealtimeExcludedFolders),
            RealtimeSettleDelayMs = Math.Clamp(RealtimeSettleDelayMs, 0, 2000),
            RealtimeWorkerCount = Math.Clamp(RealtimeWorkerCount, 1, 8),
            AlertCooldownSeconds = Math.Clamp(AlertCooldownSeconds, 0, 3600)        };
    }

    /// <summary>
    /// Normalizes and de-duplicates a folder list. Unusable paths are dropped rather
    /// than throwing, because this runs during startup on a file the user may have
    /// edited by hand.
    /// </summary>
    private static IReadOnlyList<string> NormalizeFolders(IEnumerable<string>? folders)
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
                // A malformed path in the settings file is ignored rather than
                // preventing the application from starting.
            }
        }

        // Returned as an array so that the value is stable and cheap to compare. The
        // empty case returns the shared Array.Empty instance: List<T>.ToArray() always
        // allocates, so an empty list would otherwise produce a different instance on
        // every call and break reference-based comparisons of the default settings.
        return result.Count == 0 ? Array.Empty<string>() : result.ToArray();
    }

    /// <summary>
    /// Compares two settings records by VALUE. The generated record equality would
    /// compare the folder lists by reference, so two settings that describe the same
    /// folders would be reported as different — which made "the corrupt file falls back
    /// to the defaults" impossible to assert.
    /// </summary>
    public bool Equals(AppSettings? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;

        return SchemaVersion == other.SchemaVersion
            && Theme == other.Theme
            && LoggingEnabled == other.LoggingEnabled
            && MaxInspectMegabytes == other.MaxInspectMegabytes
            && MinimizeToTray == other.MinimizeToTray
            && ShowTrayNotifications == other.ShowTrayNotifications
            && RealtimeProtectionEnabled == other.RealtimeProtectionEnabled
            && RealtimeAutoQuarantine == other.RealtimeAutoQuarantine
            && RemediationEnabled == other.RemediationEnabled
            && Language == other.Language
            && DetectionAlertEnabled == other.DetectionAlertEnabled
            && DetectionAlertSoundEnabled == other.DetectionAlertSoundEnabled
            && DetectionAlertCatEnabled == other.DetectionAlertCatEnabled
            && RealtimeAutoKill == other.RealtimeAutoKill
            && RealtimeSettleDelayMs == other.RealtimeSettleDelayMs
            && RealtimeWorkerCount == other.RealtimeWorkerCount
            && AlertCooldownSeconds == other.AlertCooldownSeconds
            && RealtimeWatchFolders.SequenceEqual(other.RealtimeWatchFolders, StringComparer.OrdinalIgnoreCase)
            && RealtimeExcludedFolders.SequenceEqual(other.RealtimeExcludedFolders, StringComparer.OrdinalIgnoreCase);
    }

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(SchemaVersion);
        hash.Add(Theme);
        hash.Add(LoggingEnabled);
        hash.Add(MaxInspectMegabytes);
        hash.Add(MinimizeToTray);
        hash.Add(ShowTrayNotifications);
        hash.Add(RealtimeProtectionEnabled);
        hash.Add(RealtimeAutoQuarantine);
        hash.Add(RemediationEnabled);
        hash.Add(Language);
        hash.Add(DetectionAlertEnabled);
        hash.Add(DetectionAlertSoundEnabled);
        hash.Add(DetectionAlertCatEnabled);
        hash.Add(RealtimeAutoKill);
        hash.Add(RealtimeSettleDelayMs);
        hash.Add(RealtimeWorkerCount);
        hash.Add(AlertCooldownSeconds);
        foreach (var folder in RealtimeWatchFolders) hash.Add(folder, StringComparer.OrdinalIgnoreCase);
        foreach (var folder in RealtimeExcludedFolders) hash.Add(folder, StringComparer.OrdinalIgnoreCase);
        return hash.ToHashCode();
    }
}
