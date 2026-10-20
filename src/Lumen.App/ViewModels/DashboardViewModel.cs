using System.Collections.ObjectModel;
using System.ComponentModel;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Localization;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

/// <summary>
/// The dashboard: the state of the protection, the last scan and a small activity
/// chart drawn from the local history.
/// </summary>
public sealed class DashboardViewModel : ObservableObject, IPageViewModel, IDisposable
{
    private readonly AppServices _services;
    private readonly Action<ScanScopeKind> _startScan;
    private readonly Action<ScanScopeKind, bool> _prepareScan;
    private readonly Action<string> _navigate;

    private bool _hasHistory;
    private string _lastScanTitle = string.Empty;
    private string _lastScanWhen = string.Empty;
    private string _lastScanMeta = string.Empty;
    private string _lastScanStatus = string.Empty;
    private bool _lastScanHasDetections;
    private bool _lastScanHasErrors;
    private bool _lastScanCancelled;
    private int _quarantineCount;
    private bool _hasRecentActivity;
    private bool _realtimeActive;
    private bool _realtimeDegraded;
    private bool _hasRealtimeError;
    private string _realtimeStatusTitle = string.Empty;
    private string _realtimeStatusDetail = string.Empty;
    private string _realtimeWatchedText = string.Empty;
    private string _realtimeQueueText = string.Empty;
    private string _realtimeDroppedText = string.Empty;
    private string _realtimeWatcherFailureText = string.Empty;
    private string _realtimeLastErrorText = string.Empty;
    private string _realtimeCheckedText = string.Empty;
    private string _realtimeDetectionsText = string.Empty;
    private string _realtimeLastDetectionText = string.Empty;
    private IReadOnlyList<double> _detectionTrend = [];
    private IReadOnlyList<double> _lastScanBars = [];
    private IReadOnlyList<string> _lastScanBarLabels = [];
    private bool _hasCharts;
    private bool _disposed;

    /// <summary>Creates the dashboard view model.</summary>
    public DashboardViewModel(
        AppServices services,
        Action<ScanScopeKind> startScan,
        Action<ScanScopeKind, bool> prepareScan,
        Action<string> navigate)
    {
        _services = services;
        _startScan = startScan;
        _prepareScan = prepareScan;
        _navigate = navigate;

        Defender = new DefenderStatusViewModel(services);

        QuickScanCommand = new RelayCommand(() => _startScan(ScanScopeKind.Quick));
        FullScanCommand = new RelayCommand(() => _prepareScan(ScanScopeKind.FullUserProfile, false));
        ChooseFolderCommand = new RelayCommand(() => _prepareScan(ScanScopeKind.Folder, true));
        ViewHistoryCommand = new RelayCommand(() => _navigate("history"));
        OpenQuarantineCommand = new RelayCommand(() => _navigate("quarantine"));
        OpenSettingsCommand = new RelayCommand(() => _navigate("settings"));
        OpenRealtimeSettingsCommand = new RelayCommand(() => _navigate("settings"));
        RefreshDefenderCommand = Defender.RefreshCommand;
        OpenWindowsSecurityCommand = new RelayCommand(OpenWindowsSecurity);

        _services.RealtimeDetected += OnRealtimeDetected;
        Text.LanguageChanged += OnLanguageChanged;

        RefreshRealtime();
        RefreshGreeting();
    }

    /// <summary>The greeting shown at the top of the page.</summary>
    public string Greeting { get; private set; } = string.Empty;

    /// <summary>The date shown under the greeting.</summary>
    public string TodayText { get; private set; } = string.Empty;

    public RelayCommand QuickScanCommand { get; }
    public RelayCommand FullScanCommand { get; }
    public RelayCommand ChooseFolderCommand { get; }
    public RelayCommand ViewHistoryCommand { get; }
    public RelayCommand OpenQuarantineCommand { get; }
    public RelayCommand OpenSettingsCommand { get; }
    public AsyncRelayCommand RefreshDefenderCommand { get; }
    public RelayCommand OpenWindowsSecurityCommand { get; }
    public RelayCommand OpenRealtimeSettingsCommand { get; }

    public DefenderStatusViewModel Defender { get; }

    public bool HasHistory
    {
        get => _hasHistory;
        private set => SetProperty(ref _hasHistory, value);
    }

    public string LastScanTitle
    {
        get => _lastScanTitle;
        private set => SetProperty(ref _lastScanTitle, value);
    }

    public string LastScanWhen
    {
        get => _lastScanWhen;
        private set => SetProperty(ref _lastScanWhen, value);
    }

    public string LastScanMeta
    {
        get => _lastScanMeta;
        private set => SetProperty(ref _lastScanMeta, value);
    }

    public string LastScanStatus
    {
        get => _lastScanStatus;
        private set => SetProperty(ref _lastScanStatus, value);
    }

    /// <summary>
    /// True when the last scan reported a detection. The card picks its icon from
    /// this, so the icon always says what the status says.
    /// </summary>
    public bool LastScanHasDetections
    {
        get => _lastScanHasDetections;
        private set => SetProperty(ref _lastScanHasDetections, value);
    }

    /// <summary>True when the last scan reported warnings.</summary>
    public bool LastScanHasErrors
    {
        get => _lastScanHasErrors;
        private set => SetProperty(ref _lastScanHasErrors, value);
    }

    /// <summary>True when the last scan was cancelled.</summary>
    public bool LastScanCancelled
    {
        get => _lastScanCancelled;
        private set => SetProperty(ref _lastScanCancelled, value);
    }

    public int QuarantineCount
    {
        get => _quarantineCount;
        private set
        {
            if (!SetProperty(ref _quarantineCount, value)) return;
            OnPropertyChanged(nameof(QuarantineCountText), nameof(QuarantineDetail));
        }
    }

    public string QuarantineCountText => _quarantineCount.ToString("N0");

    public string QuarantineDetail => _quarantineCount == 0
        ? Text.QuarantineSummaryEmpty
        : Text.QuarantineSummary(_quarantineCount);

    public ObservableCollection<HistoryRowViewModel> RecentActivity { get; } = [];

    public bool HasRecentActivity
    {
        get => _hasRecentActivity;
        private set => SetProperty(ref _hasRecentActivity, value);
    }

    // ----------------------------------------------------------------------
    // Real-time protection, reported honestly
    // ----------------------------------------------------------------------

    public bool RealtimeActive
    {
        get => _realtimeActive;
        private set
        {
            if (!SetProperty(ref _realtimeActive, value)) return;
            OnPropertyChanged(nameof(RealtimeBadgeText));
        }
    }

    /// <summary>True when the monitor does not cover everything it was asked to cover.</summary>
    public bool RealtimeDegraded
    {
        get => _realtimeDegraded;
        private set => SetProperty(ref _realtimeDegraded, value);
    }

    /// <summary>True when the monitor reported an error.</summary>
    public bool HasRealtimeError
    {
        get => _hasRealtimeError;
        private set => SetProperty(ref _hasRealtimeError, value);
    }

    public string RealtimeBadgeText => RealtimeActive ? "ON" : "OFF";

    public string RealtimeStatusTitle
    {
        get => _realtimeStatusTitle;
        private set => SetProperty(ref _realtimeStatusTitle, value);
    }

    public string RealtimeStatusDetail
    {
        get => _realtimeStatusDetail;
        private set => SetProperty(ref _realtimeStatusDetail, value);
    }

    /// <summary>How many of the configured folders are actually watched.</summary>
    public string RealtimeWatchedText
    {
        get => _realtimeWatchedText;
        private set => SetProperty(ref _realtimeWatchedText, value);
    }

    /// <summary>How many paths are waiting in the inspection queue.</summary>
    public string RealtimeQueueText
    {
        get => _realtimeQueueText;
        private set => SetProperty(ref _realtimeQueueText, value);
    }

    /// <summary>How many paths were dropped because the queue was full.</summary>
    public string RealtimeDroppedText
    {
        get => _realtimeDroppedText;
        private set => SetProperty(ref _realtimeDroppedText, value);
    }

    /// <summary>How many times a watcher failed and had to be rebuilt.</summary>
    public string RealtimeWatcherFailureText
    {
        get => _realtimeWatcherFailureText;
        private set => SetProperty(ref _realtimeWatcherFailureText, value);
    }

    /// <summary>The last error the monitor reported.</summary>
    public string RealtimeLastErrorText
    {
        get => _realtimeLastErrorText;
        private set => SetProperty(ref _realtimeLastErrorText, value);
    }

    public string RealtimeCheckedText
    {
        get => _realtimeCheckedText;
        private set => SetProperty(ref _realtimeCheckedText, value);
    }

    public string RealtimeDetectionsText
    {
        get => _realtimeDetectionsText;
        private set => SetProperty(ref _realtimeDetectionsText, value);
    }

    public string RealtimeLastDetectionText
    {
        get => _realtimeLastDetectionText;
        private set => SetProperty(ref _realtimeLastDetectionText, value);
    }

    // ----------------------------------------------------------------------
    // Activity chart
    // ----------------------------------------------------------------------

    /// <summary>The number of detections per scan, oldest first. Drawn as a sparkline.</summary>
    public IReadOnlyList<double> DetectionTrend
    {
        get => _detectionTrend;
        private set => SetProperty(ref _detectionTrend, value);
    }

    /// <summary>The inspected, skipped and warned-about counts of the last scan.</summary>
    public IReadOnlyList<double> LastScanBars
    {
        get => _lastScanBars;
        private set => SetProperty(ref _lastScanBars, value);
    }

    /// <summary>The labels of the bars of the last scan.</summary>
    public IReadOnlyList<string> LastScanBarLabels
    {
        get => _lastScanBarLabels;
        private set => SetProperty(ref _lastScanBarLabels, value);
    }

    /// <summary>
    /// The theme resource keys of the bar colours: inspected, skipped and
    /// warned-about files each get their own colour.
    /// </summary>
    public IReadOnlyList<string> LastScanBarBrushKeys { get; } =
        ["Accent.Primary", "App.TextMuted", "Danger.Text"];

    /// <summary>True when there is enough history to draw the chart.</summary>
    public bool HasCharts
    {
        get => _hasCharts;
        private set => SetProperty(ref _hasCharts, value);
    }

    public void OnNavigatedTo()
    {
        Refresh();
        _ = Defender.RefreshAsync(false);
    }

    public void Refresh()
    {
        RefreshRealtime();
        RefreshGreeting();

        var entries = _services.HistoryStore.GetEntries();
        var last = entries.FirstOrDefault();
        HasHistory = last is not null;

        if (last is null)
        {
            LastScanTitle = Text.ScanNoneYet;
            LastScanWhen = string.Empty;
            LastScanMeta = Text.DashboardRunQuickScan;
            LastScanStatus = Text.ScanNotRun;
            LastScanHasDetections = false;
            LastScanHasErrors = false;
            LastScanCancelled = false;
        }
        else
        {
            var row = new HistoryRowViewModel(last, _services.Clock.UtcNow);
            LastScanTitle = row.Title;
            LastScanWhen = Text.HistoryFinished(
                TimeFormatter.Relative(last.FinishedUtc, _services.Clock.UtcNow));
            LastScanMeta = row.MetaText;
            LastScanStatus = row.StatusText;
            LastScanHasDetections = row.HasDetections;
            LastScanHasErrors = row.HasErrors;
            LastScanCancelled = row.Cancelled;
        }

        RecentActivity.Clear();
        foreach (var entry in entries.Take(4))
            RecentActivity.Add(new HistoryRowViewModel(entry, _services.Clock.UtcNow));
        HasRecentActivity = RecentActivity.Count > 0;

        QuarantineCount = _services.Quarantine.GetItems().Count;

        RefreshCharts(entries);
    }

    private void RefreshCharts(IReadOnlyList<ScanHistoryEntry> entries)
    {
        // The sparkline shows the detections of the most recent scans, oldest first.
        var ordered = entries.TakeLast(12).Reverse().ToArray();
        DetectionTrend = ordered.Select(entry => (double)entry.DetectionCount).ToArray();

        if (ordered.Length > 0)
        {
            var last = ordered[^1];
            LastScanBars = [last.FilesScanned, last.FilesSkipped, last.ErrorCount];
            LastScanBarLabels =
            [
                Text.ScanInspected,
                Text.ScanSkipped,
                Text.ScanWarnings
            ];
        }
        else
        {
            LastScanBars = [];
            LastScanBarLabels = [];
        }

        HasCharts = DetectionTrend.Count > 0;
    }

    private void RefreshGreeting()
    {
        var localNow = _services.Clock.UtcNow.ToLocalTime();
        Greeting = localNow.Hour switch
        {
            < 12 => Text.GreetingMorning,
            < 18 => Text.GreetingAfternoon,
            _ => Text.GreetingEvening
        };
        TodayText = localNow.ToString("dddd, MMMM d", System.Globalization.CultureInfo.CurrentUICulture);
    }

    private void RefreshRealtime()
    {
        var stats = _services.Realtime.GetStats();
        RealtimeActive = stats.IsRunning;

        // "Degraded" means protection is ON but not doing its job. When protection is
        // simply off, saying it is degraded is misleading: nothing is broken, the user
        // turned it off.
        RealtimeDegraded = stats.IsRunning && stats.IsDegraded;

        if (stats.IsRunning)
        {
            RealtimeStatusTitle = Text.RealtimeTitleOn;
            RealtimeStatusDetail = Text.RealtimeDetailOn;
        }
        else
        {
            RealtimeStatusTitle = Text.RealtimeTitleOff;
            RealtimeStatusDetail = Text.RealtimeDetailOff;
        }

        RealtimeWatchedText = stats.ConfiguredFolderCount > 0
            ? Text.RealtimeWatching(stats.WatchedFolderCount, stats.ConfiguredFolderCount)
            : Text.RealtimeTitleOff;

        RealtimeQueueText = Text.RealtimeQueue(stats.QueueDepth);
        RealtimeDroppedText = Text.RealtimeDropped(stats.DroppedPathCount);
        RealtimeWatcherFailureText = Text.RealtimeWatcherFailures(stats.WatcherFailureCount);

        HasRealtimeError = !string.IsNullOrWhiteSpace(stats.LastError);
        RealtimeLastErrorText = HasRealtimeError
            ? Text.RealtimeLastError(Presentation.Sanitize(stats.LastError, 200))
            : string.Empty;

        RealtimeCheckedText = Text.RealtimeChecked(stats.FilesChecked);
        RealtimeDetectionsText = Text.RealtimeMatches(stats.DetectionCount);
        RealtimeLastDetectionText = stats.LastEventUtc is null || stats.LastDetectionPath is null
            ? Text.RealtimeNothingYet
            : Text.RealtimeLastMatch(
                Presentation.SanitizePath(stats.LastDetectionPath, 120),
                TimeFormatter.Relative(stats.LastEventUtc.Value, _services.Clock.UtcNow));
    }

    private void OnRealtimeDetected(object? sender, RealtimeDetectionEvent e) => RefreshRealtime();

    private void OpenWindowsSecurity()
    {
        if (_services.OpenWindowsSecurity()) return;

        _services.Dialogs.ShowMessage(
            Text.WindowsSecurityFailedTitle,
            Text.WindowsSecurityFailedBody,
            MessageSeverity.Info);
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(
            nameof(Greeting),
            nameof(TodayText),
            nameof(LastScanTitle),
            nameof(LastScanMeta),
            nameof(QuarantineDetail),
            nameof(RealtimeStatusTitle),
            nameof(RealtimeStatusDetail),
            nameof(RealtimeWatchedText),
            nameof(RealtimeQueueText),
            nameof(RealtimeDroppedText),
            nameof(RealtimeWatcherFailureText),
            nameof(RealtimeLastErrorText),
            nameof(RealtimeCheckedText),
            nameof(RealtimeDetectionsText),
            nameof(RealtimeLastDetectionText));

        Refresh();
    }

    /// <summary>Unsubscribes from the events this view model listens to.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _services.RealtimeDetected -= OnRealtimeDetected;
        Text.LanguageChanged -= OnLanguageChanged;
        Defender.Dispose();
    }
}
