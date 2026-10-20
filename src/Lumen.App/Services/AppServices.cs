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
using Lumen.Core.Remediation;
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

    public AppServices(AppPaths? paths = null, bool startRealtimeProtection = true)
    {
        Paths = paths ?? AppPaths.ForCurrentUser();
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

        // The remediation engine is pure orchestration over these four seams. Every
        // operating-system call happens inside one of the adapters, so the engine itself
        // can be tested without touching a real process, registry or file.
        var fileOperations = new WindowsFileOperations();
        Remediation = new RemediationEngine(
            new WindowsProcessTerminator(),
            new WindowsPersistenceEnumerator(Log),
            fileOperations,
            fileOperations,
            FileAuditJournal.CreateUnder(Paths, Clock, Log),
            Clock,
            Log,
            remediationEnabled: Settings.RemediationEnabled);

        Realtime = new RealtimeMonitor(
            detectors,
            RealtimeWatchRoots(),
            RealtimeExclusions(),
            InspectBytesFor(),
            Clock,
            Log);
        Realtime.Detection += OnRealtimeDetection;
        Defender = new DefenderStatusService(Clock);
        TestFiles = new TestFileService();
        Theme = new ThemeService();
        Dialogs = new DialogService(Theme);
        Alerts = new Alerts.AlertService(this);

        var warnings = new List<string>();
        if (!string.IsNullOrWhiteSpace(SettingsStore.LoadWarning)) warnings.Add(SettingsStore.LoadWarning);
        if (!string.IsNullOrWhiteSpace(HistoryStore.LoadWarning)) warnings.Add(HistoryStore.LoadWarning);
        if (!string.IsNullOrWhiteSpace(Quarantine.LoadWarning)) warnings.Add(Quarantine.LoadWarning);
        StartupWarnings = warnings;

        if (startRealtimeProtection && Settings.RealtimeProtectionEnabled) Realtime.Start();

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

    /// <summary>
    /// The remediation engine. It refuses to plan or to act unless
    /// <see cref="AppSettings.RemediationEnabled"/> is on.
    /// </summary>
    public RemediationEngine Remediation { get; }

    /// <summary>On-access monitoring of the quick-scan folders while Lumen runs.</summary>
    public RealtimeMonitor Realtime { get; }
    public DefenderStatusService Defender { get; }
    public TestFileService TestFiles { get; }
    public ThemeService Theme { get; }
    public DialogService Dialogs { get; }

    /// <summary>
    /// The loud detection alert. It shows a window, plays a noise and draws a cat. It
    /// exists because a detection nobody notices is a detection that did not happen.
    /// </summary>
    public Alerts.AlertService Alerts { get; }
    public IReadOnlyList<string> StartupWarnings { get; }
    public AppSettings Settings { get; private set; }
    public TrayService? Tray { get; private set; }

    public string UserProfile =>
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    public string DataDirectory => Paths.Root;

    /// <summary>The user interface language, taken from the saved settings.</summary>
    public AppLanguage Language => Settings.Language;

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
        Remediation.RemediationEnabled = next.RemediationEnabled;

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

    /// <summary>
    /// Starts or stops on-access monitoring to match the saved setting, and pushes the
    /// watched folders, the exclusions and the inspection limit into the running monitor.
    /// The limit used to be frozen when the monitor was created, so changing it in
    /// Settings had no effect on real-time protection.
    /// </summary>
    private void ApplyRealtimeSetting(AppSettings settings)
    {
        try
        {
            var configured = Realtime.Configure(
                RealtimeWatchRoots(settings),
                RealtimeExclusions(settings),
                InspectBytesFor(settings));

            if (!configured.Ok)
                Log.Warn("Realtime", configured.Message ?? "Real-time protection could not be reconfigured.");

            if (settings.RealtimeProtectionEnabled && !Realtime.IsRunning) Realtime.Start();
            else if (!settings.RealtimeProtectionEnabled && Realtime.IsRunning) Realtime.Stop();
        }
        catch (Exception ex)
        {
            Log.Warn("Realtime", "Real-time protection could not be reconfigured.", ex);
        }
    }

    /// <summary>
    /// The folders the real-time monitor watches: the standard quick-scan folders plus
    /// any folder the user added.
    /// </summary>
    private IReadOnlyList<string> RealtimeWatchRoots(AppSettings? settings = null)
    {
        var current = settings ?? Settings;
        return RealtimeMonitor.BuildWatchRoots(
            UserProfile,
            current.RealtimeWatchFolders,
            RealtimeExcludedFolders(current));
    }

    /// <summary>
    /// The subtrees the real-time monitor skips: Lumen's own data folder, plus anything
    /// the user excluded.
    /// </summary>
    private IReadOnlyList<string> RealtimeExcludedFolders(AppSettings settings)
    {
        var exclusions = new List<string> { Paths.Root };
        exclusions.AddRange(settings.RealtimeExcludedFolders);
        return exclusions;
    }

    private IReadOnlyList<string> RealtimeExclusions(AppSettings? settings = null) =>
        RealtimeExcludedFolders(settings ?? Settings);

    private long InspectBytesFor(AppSettings? settings = null)
    {
        var current = settings ?? Settings;
        return Math.Clamp(
            (long)current.MaxInspectMegabytes * 1024L * 1024L,
            64L * 1024L,
            16L * 1024L * 1024L);
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

        // A detection is only actionable when its digest could be read. The previous code
        // silently did nothing in that case, so the file was neither quarantined nor
        // reported to the user.
        var auto = Settings.RealtimeAutoQuarantine && detection.IsActionable;

        RunOnUI(() =>
        {
            RealtimeDetected?.Invoke(this, detection);

            if (auto)
            {
                _ = AutoQuarantineAsync(detection);
            }
            else if (notify)
            {
                var reason = detection.IsActionable
                    ? string.Empty
                    : $" The file could not be hashed ({detection.Sha256Error}), so it was left alone.";
                Tray?.Notify(
                    "Real-time protection",
                    $"{detection.FileName} matched {Presentation.Count(detection.Findings.Count, "rule")}. " +
                    "Nothing was changed." + reason);
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

    /// <summary>
    /// Creates a harmless demonstration file, scans it and raises the alert exactly as a
    /// real detection would. Nothing is quarantined and nothing is deleted.
    ///
    /// This exists so the detection pipeline can be shown end to end — the alert, the
    /// rule, the file — without EICAR, without real malware, and without Microsoft
    /// Defender removing the evidence before the camera is ready.
    /// </summary>
    /// <returns>The detection that was raised, or null when the sample could not be made.</returns>
    public Core.Models.ScanDetection? TriggerDemoDetection()
    {
        try
        {
            var folder = Path.Combine(Path.GetTempPath(), "lumen-demo");
            var created = TestFiles.CreateDemoSample(folder);
            if (!created.Ok || created.Created.Count == 0)
            {
                Log.Warn("Demo", "The demonstration file could not be created: " + created.Message);
                return null;
            }

            var path = created.Created[0];
            var registry = Lumen.Core.Detection.DetectorRegistry.CreateDefault();
            var probe = new Lumen.Core.Scanning.ProbeReader(1024 * 1024).Read(path, File.GetAttributes(path), CancellationToken.None);
            if (!probe.Success || probe.Probe is null) return null;

            var findings = registry.Inspect(probe.Probe, CancellationToken.None);
            if (findings.Count == 0)
            {
                Log.Warn("Demo", "The demonstration file did not match any rule.");
                return null;
            }

            var detection = new Core.Models.ScanDetection
            {
                FilePath = path,
                SizeBytes = probe.Probe.SizeBytes,
                Sha256 = Lumen.Core.Util.HashUtil.Sha256File(path, CancellationToken.None),
                Findings = findings,
                DetectedUtc = Clock.UtcNow
            };

            var primary = detection.PrimaryFinding;
            Alerts.Show(
                detection,
                detection.FileName,
                primary?.Title ?? "Suspicious behaviour",
                ViewModels.Presentation.ConfidenceText(primary?.Confidence ?? Core.Models.Confidence.Medium));

            return detection;
        }
        catch (Exception ex)
        {
            Log.Warn("Demo", "The demonstration could not be run.", ex);
            return null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Realtime.Detection -= OnRealtimeDetection;
        Realtime.Dispose();
        Quarantine.Dispose();
        Tray?.Dispose();
        Theme.Dispose();
        Log.Info("App", "Lumen exited.");
    }

    private void OnDataChanged() => DataChanged?.Invoke(this, EventArgs.Empty);
}
