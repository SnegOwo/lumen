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
            MaxInspectMegabytes = megabytes
        };
    }
}
