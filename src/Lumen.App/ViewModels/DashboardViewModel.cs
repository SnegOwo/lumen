using System.Collections.ObjectModel;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

public sealed class DashboardViewModel : ObservableObject, IPageViewModel
{
    private readonly AppServices _services;
    private readonly Action<ScanScopeKind> _startScan;
    private readonly Action<ScanScopeKind, bool> _prepareScan;
    private readonly Action<string> _navigate;

    private bool _hasHistory;
    private string _lastScanTitle = "No scans yet";
    private string _lastScanWhen = string.Empty;
    private string _lastScanMeta = "Run a quick scan to establish a baseline.";
    private string _lastScanStatus = "Not run";
    private bool _lastScanHasDetections;
    private string _lastScanGlyph = "\uE721";
    private int _quarantineCount;
    private bool _hasRecentActivity;
    private bool _realtimeActive;
    private string _realtimeStatusTitle = string.Empty;
    private string _realtimeStatusDetail = string.Empty;
    private string _realtimeCheckedText = "0 files checked";
    private string _realtimeDetectionsText = "0 matches";
    private string _realtimeLastDetectionText = "Nothing detected yet";

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

        var localNow = services.Clock.UtcNow.ToLocalTime();
        Greeting = localNow.Hour switch
        {
            < 12 => "Good morning",
            < 18 => "Good afternoon",
            _ => "Good evening"
        };
        TodayText = localNow.ToString("dddd, MMMM d");

        QuickScanCommand = new RelayCommand(() => _startScan(ScanScopeKind.Quick));
        FullScanCommand = new RelayCommand(() => _prepareScan(ScanScopeKind.FullUserProfile, false));
        ChooseFolderCommand = new RelayCommand(() => _prepareScan(ScanScopeKind.Folder, true));
        OpenScanCommand = new RelayCommand(() => _navigate("scan"));
        ViewHistoryCommand = new RelayCommand(() => _navigate("history"));
        OpenQuarantineCommand = new RelayCommand(() => _navigate("quarantine"));
        OpenSettingsCommand = new RelayCommand(() => _navigate("settings"));
        OpenRealtimeSettingsCommand = new RelayCommand(() => _navigate("settings"));
        RefreshDefenderCommand = Defender.RefreshCommand;
        OpenWindowsSecurityCommand = new RelayCommand(OpenWindowsSecurity);

        _services.RealtimeDetected += OnRealtimeDetected;
        RefreshRealtime();
    }

    public string Greeting { get; }
    public string TodayText { get; }

    public RelayCommand QuickScanCommand { get; }
    public RelayCommand FullScanCommand { get; }
    public RelayCommand ChooseFolderCommand { get; }
    public RelayCommand OpenScanCommand { get; }
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

    public bool LastScanHasDetections
    {
        get => _lastScanHasDetections;
        private set => SetProperty(ref _lastScanHasDetections, value);
    }

    public string LastScanGlyph
    {
        get => _lastScanGlyph;
        private set => SetProperty(ref _lastScanGlyph, value);
    }

    public int QuarantineCount
    {
        get => _quarantineCount;
        private set
        {
            if (!SetProperty(ref _quarantineCount, value)) return;
            OnPropertyChanged(nameof(QuarantineCountText), nameof(QuarantineDetail), nameof(HasQuarantine));
        }
    }

    public string QuarantineCountText => _quarantineCount.ToString("N0");
    public bool HasQuarantine => _quarantineCount > 0;
    public string QuarantineDetail => _quarantineCount == 0
        ? "The encrypted vault is empty."
        : "Encrypted copies you can restore or delete.";

    public ObservableCollection<HistoryRowViewModel> RecentActivity { get; } = [];

    public bool HasRecentActivity
    {
        get => _hasRecentActivity;
        private set => SetProperty(ref _hasRecentActivity, value);
    }

    public string VaultPathShort => Presentation.SanitizePath(_services.Paths.QuarantineDirectory);

    public bool RealtimeActive
    {
        get => _realtimeActive;
        private set
        {
            if (!SetProperty(ref _realtimeActive, value)) return;
            OnPropertyChanged(nameof(RealtimeBadgeText));
        }
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

    public void OnNavigatedTo()
    {
        Refresh();
        _ = Defender.RefreshAsync(false);
    }

    public void Refresh()
    {
        RefreshRealtime();

        var entries = _services.HistoryStore.GetEntries();
        var last = entries.FirstOrDefault();
        HasHistory = last is not null;

        if (last is null)
        {
            LastScanTitle = "No scans yet";
            LastScanWhen = string.Empty;
            LastScanMeta = "Run a quick scan to establish a baseline.";
            LastScanStatus = "Not run";
            LastScanHasDetections = false;
            LastScanGlyph = "\uE721";
        }
        else
        {
            var row = new HistoryRowViewModel(last, _services.Clock.UtcNow);
            LastScanTitle = row.Title;
            LastScanWhen = "Finished " + TimeFormatter.Relative(last.FinishedUtc, _services.Clock.UtcNow);
            LastScanMeta = row.MetaText;
            LastScanStatus = row.StatusText;
            LastScanHasDetections = row.HasDetections;
            LastScanGlyph = row.Glyph;
        }

        RecentActivity.Clear();
        foreach (var entry in entries.Take(4))
            RecentActivity.Add(new HistoryRowViewModel(entry, _services.Clock.UtcNow));
        HasRecentActivity = RecentActivity.Count > 0;

        QuarantineCount = _services.Quarantine.GetItems().Count;
        OnPropertyChanged(nameof(VaultPathShort));
    }

    private void RefreshRealtime()
    {
        var stats = _services.Realtime.GetStats();
        RealtimeActive = stats.IsRunning;

        if (stats.IsRunning)
        {
            RealtimeStatusTitle = "Real-time protection is on";
            RealtimeStatusDetail =
                "New and changed files in Desktop, Documents and Downloads are re-checked while Lumen runs.";
        }
        else
        {
            RealtimeStatusTitle = "Real-time protection is off";
            RealtimeStatusDetail =
                "Turn it on in Settings to re-check new and changed files while Lumen runs.";
        }

        RealtimeCheckedText = Presentation.Count(stats.FilesChecked, "file") + " checked";
        RealtimeDetectionsText = Presentation.Count(stats.DetectionCount, "match");
        RealtimeLastDetectionText = stats.LastEventUtc is null || stats.LastDetectionPath is null
            ? "Nothing detected yet"
            : "Last match: " + Presentation.SanitizePath(stats.LastDetectionPath, 120) +
              " \u00B7 " + TimeFormatter.Relative(stats.LastEventUtc.Value, _services.Clock.UtcNow);
    }

    private void OnRealtimeDetected(object? sender, RealtimeDetectionEvent e) => RefreshRealtime();

    private void OpenWindowsSecurity()
    {
        if (_services.OpenWindowsSecurity()) return;

        _services.Dialogs.ShowMessage(
            "Windows Security could not be opened",
            "Your system may not include the Windows Security app. Microsoft Defender settings can also be managed by your organization.",
            MessageSeverity.Info);
    }
}
