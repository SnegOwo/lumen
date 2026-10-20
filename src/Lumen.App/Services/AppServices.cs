using System.Diagnostics;
using System.Reflection;
using Lumen.App.Dialogs;
using Lumen.App.ViewModels;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Logging;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Quarantine;
using Lumen.Core.Scanning;
using Lumen.Core.Storage;
using Lumen.Core.Util;

namespace Lumen.App.Services;

/// <summary>
/// Composition root for the desktop shell. All state is per-user; the install folder is never
/// written to. Views and view models receive this object and never construct storage directly.
/// </summary>
public sealed class AppServices : IDisposable
{
    private bool _disposed;

    public AppServices()
    {
        Paths = AppPaths.ForCurrentUser();
        Paths.EnsureCreated();

        Clock = SystemClock.Instance;
        Log = new FileLog(
            Paths.LogDirectory,
            Clock,
            enabled: true,
            userProfilePath: Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            dataDirectory: Paths.Root);

        SettingsStore = new SettingsStore(Paths, Log);
        Settings = SettingsStore.Load();
        Log.Enabled = Settings.LoggingEnabled;

        HistoryStore = new HistoryStore(Paths, Log);
        Quarantine = new QuarantineService(
            Paths.QuarantineDirectory,
            Paths.QuarantineManifestFile,
            new DpapiSecretProtector(),
            Clock,
            Log);

        var detectors = DetectorRegistry.CreateDefault();
        ScanEngine = new ScanEngine(detectors, Clock, Log);
        Realtime = new RealtimeMonitor(
            detectors,
            ScanPlanner.QuickFolders(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
            [Paths.Root],
            Math.Clamp((long)Settings.MaxInspectMegabytes * 1024L * 1024L, 64L * 1024L, 16L * 1024L * 1024L),
            Clock,
            Log);
        Realtime.Detection += OnRealtimeDetection;
        Defender = new DefenderStatusService(Clock);
        TestFiles = new TestFileService();
        Theme = new ThemeService();
        Dialogs = new DialogService(Theme);

        var warnings = new List<string>();
        if (!string.IsNullOrWhiteSpace(SettingsStore.LoadWarning)) warnings.Add(SettingsStore.LoadWarning);
        if (!string.IsNullOrWhiteSpace(HistoryStore.LoadWarning)) warnings.Add(HistoryStore.LoadWarning);
        if (!string.IsNullOrWhiteSpace(Quarantine.LoadWarning)) warnings.Add(Quarantine.LoadWarning);
        StartupWarnings = warnings;

        if (Settings.RealtimeProtectionEnabled) Realtime.Start();

        Log.Info(
            "App",
            "Lumen started. On-demand scanning plus on-access monitoring of user folders" +
            (Realtime.IsRunning ? " (real-time protection active)." : " (real-time protection paused).") +
            " No driver; system folders are never covered.");
    }

    public AppPaths Paths { get; }
    public IClock Clock { get; }
    public FileLog Log { get; }
    public SettingsStore SettingsStore { get; }
    public HistoryStore HistoryStore { get; }
    public QuarantineService Quarantine { get; }
    public ScanEngine ScanEngine { get; }

    /// <summary>On-access monitoring of the quick-scan folders while Lumen runs.</summary>
    public RealtimeMonitor Realtime { get; }
    public DefenderStatusService Defender { get; }
    public TestFileService TestFiles { get; }
    public ThemeService Theme { get; }
    public DialogService Dialogs { get; }
    public IReadOnlyList<string> StartupWarnings { get; }
    public AppSettings Settings { get; private set; }
    public TrayService? Tray { get; private set; }

    public string UserProfile =>
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    public string DataDirectory => Paths.Root;

    public event EventHandler? DataChanged;
    public event EventHandler? SettingsChanged;

    public void AttachTray(TrayService tray)
    {
        Tray = tray;
        tray.NotificationsEnabled = Settings.ShowTrayNotifications;
    }

    public ScanPlanner CreatePlanner() => new(UserProfile, Paths.Root, Settings);

    public OperationResult UpdateSettings(Func<AppSettings, AppSettings> update)
    {
        var next = update(Settings).Normalize();
        var saved = SettingsStore.Save(next);
        if (!saved.Ok)
        {
            Log.Warn("Settings", saved.Message ?? "Settings could not be saved.");
            return saved;
        }

        Settings = next;
        Log.Enabled = next.LoggingEnabled;
        if (Tray is not null) Tray.NotificationsEnabled = next.ShowTrayNotifications;

        ApplyRealtimeSetting(next);

        try
        {
            Theme.Apply(next.Theme);
        }
        catch (Exception ex)
        {
            Log.Warn("Settings", "The selected theme could not be applied.", ex);
        }

        SettingsChanged?.Invoke(this, EventArgs.Empty);
        OnDataChanged();
        return OperationResult.Success();
    }

    public void NotifyDataChanged() => OnDataChanged();

    /// <summary>Starts or stops on-access monitoring to match the saved setting.</summary>
    private void ApplyRealtimeSetting(AppSettings settings)
    {
        try
        {
            if (settings.RealtimeProtectionEnabled && !Realtime.IsRunning) Realtime.Start();
            else if (!settings.RealtimeProtectionEnabled && Realtime.IsRunning) Realtime.Stop();
        }
        catch (Exception ex)
        {
            Log.Warn("Realtime", "Real-time protection could not be reconfigured.", ex);
        }
    }

    /// <summary>
    /// Raised on the UI thread whenever real-time protection reports a match. Auto-quarantine
    /// stays off by default; when enabled it goes through the same confirmed vault service
    /// as manual quarantines, never a silent delete.
    /// </summary>
    public event EventHandler<RealtimeDetectionEvent>? RealtimeDetected;

    private void OnRealtimeDetection(object? sender, RealtimeDetectionEvent detection)
    {
        var primary = detection.PrimaryFinding;
        Log.Info(
            "Realtime",
            $"Match: {primary?.RuleId ?? "unknown"} on file ({detection.FileName})." +
            (Settings.RealtimeAutoQuarantine ? " Auto-quarantine enabled." : string.Empty));

        var notify = Tray is not null && Settings.ShowTrayNotifications;
        var auto = Settings.RealtimeAutoQuarantine && detection.Sha256 is not null;

        RunOnUI(() =>
        {
            RealtimeDetected?.Invoke(this, detection);

            if (auto)
            {
                _ = AutoQuarantineAsync(detection);
            }
            else if (notify)
            {
                Tray?.Notify(
                    "Real-time protection",
                    $"{detection.FileName} matched {Presentation.Count(detection.Findings.Count, "rule")}. " +
                    "Nothing was changed.");
            }
        });
    }

    private async Task AutoQuarantineAsync(RealtimeDetectionEvent detection)
    {
        try
        {
            var primary = detection.PrimaryFinding;
            var result = await Quarantine.QuarantineAsync(
                new QuarantineRequest
                {
                    FilePath = detection.FilePath,
                    FindingTitle = primary?.Title ?? "Real-time match",
                    Category = primary?.Category ?? FindingCategory.Heuristic,
                    FindingDetail = primary?.Detail ?? "Matched by real-time protection.",
                    ExpectedSha256 = detection.Sha256,
                    SourceScanId = "realtime",
                    DetectedUtc = detection.DetectedUtc
                },
                progress: null,
                CancellationToken.None).ConfigureAwait(false);

            RunOnUI(() =>
            {
                if (result.Status is QuarantineStatus.Quarantined or QuarantineStatus.QuarantinedOriginalRetained)
                {
                    Tray?.Notify(
                        "Real-time protection",
                        $"{detection.FileName} was moved to quarantine.");
                    OnDataChanged();
                }
                else if (Tray is not null && Settings.ShowTrayNotifications)
                {
                    Tray.Notify(
                        "Real-time protection",
                        $"{detection.FileName} could not be quarantined: {result.Message}");
                }
            });
        }
        catch (Exception ex)
        {
            Log.Warn("Realtime", "Auto-quarantine failed unexpectedly.", ex);
        }
    }

    private static void RunOnUI(Action action)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess()) action();
        else dispatcher.BeginInvoke(action);
    }

    public bool OpenFolder(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn("Shell", "A folder could not be opened.", ex);
            return false;
        }
    }

    public bool OpenWindowsSecurity()
    {
        foreach (var target in new[] { "windowsdefender://", "ms-settings:windowsdefender" })
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = target, UseShellExecute = true });
                return true;
            }
            catch (Exception ex)
            {
                Log.Warn("Shell", "Windows Security could not be opened with " + target, ex);
            }
        }

        return false;
    }

    public bool RevealFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = "/select,\"" + path.Replace("\"", string.Empty, StringComparison.Ordinal) + "\"",
                UseShellExecute = true
            });
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn("Shell", "A file could not be revealed in Explorer.", ex);
            return false;
        }
    }

    public string SanitizePath(string? path) => DisplayText.SanitizePath(path);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Realtime.Detection -= OnRealtimeDetection;
        Realtime.Dispose();
        Quarantine.Dispose();
        Tray?.Dispose();
        Log.Info("App", "Lumen exited.");
    }

    private void OnDataChanged() => DataChanged?.Invoke(this, EventArgs.Empty);
}
