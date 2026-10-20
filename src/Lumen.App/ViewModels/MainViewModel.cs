using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using Lumen.App.Alerts;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Localization;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Quarantine;

namespace Lumen.App.ViewModels;

/// <summary>
/// The shell view model: navigation, the status line and the theme toggle.
/// </summary>
public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly AppServices _services;
    private object _currentPage;
    private string _headerStatusText = "Ready";
    private string _headerStatusDetail = "Real-time protection active";
    private bool _isBusy;
    private string _themeTooltip = "Switch theme";
    private bool _canToggleTheme = true;
    private int _quietDetections;
    private bool _disposed;

    public MainViewModel(AppServices services)
    {
        _services = services;

        Scan = new ScanViewModel(services);
        Quarantine = new QuarantineViewModel(services, () => Navigate("scan"));
        History = new HistoryViewModel(services, StartQuickScan);
        Settings = new SettingsViewModel(services, OpenScanWithFolder);
        Dashboard = new DashboardViewModel(services, StartScan, PrepareScan, Navigate);

        NavigationItems =
        [
            new NavigationItemViewModel("dashboard", Text.NavDashboard, Dashboard, Navigate),
            new NavigationItemViewModel("scan", Text.NavScan, Scan, Navigate),
            new NavigationItemViewModel("quarantine", Text.NavQuarantine, Quarantine, Navigate),
            new NavigationItemViewModel("history", Text.NavHistory, History, Navigate),
            new NavigationItemViewModel("settings", Text.NavSettings, Settings, Navigate)
        ];

        NavigateCommand = new RelayCommand<string>(key => Navigate(key ?? string.Empty));
        QuickScanCommand = new RelayCommand(StartQuickScan);
        ToggleThemeCommand = new RelayCommand(ToggleTheme, () => CanToggleTheme);
        OpenSettingsCommand = new RelayCommand(() => Navigate("settings"));

        _currentPage = Dashboard;
        NavigationItems[0].IsSelected = true;

        Scan.PropertyChanged += OnScanPropertyChanged;
        _services.DataChanged += OnDataChanged;
        _services.SettingsChanged += OnSettingsChanged;
        _services.RealtimeDetected += OnRealtimeDetected;
        _services.Alerts.QuarantineRequested += OnQuarantineRequested;
        _services.Alerts.AlertSuppressed += OnAlertSuppressed;
        Text.LanguageChanged += OnLanguageChanged;

        UpdateHeader();
        UpdateBadges();
        UpdateThemeState();
    }

    public ScanViewModel Scan { get; }
    public QuarantineViewModel Quarantine { get; }
    public HistoryViewModel History { get; }
    public SettingsViewModel Settings { get; }
    public DashboardViewModel Dashboard { get; }

    public ObservableCollection<NavigationItemViewModel> NavigationItems { get; }

    public RelayCommand<string> NavigateCommand { get; }
    public RelayCommand QuickScanCommand { get; }
    public RelayCommand ToggleThemeCommand { get; }
    public RelayCommand OpenSettingsCommand { get; }

    /// <summary>The title of the window, in the interface language.</summary>
    public string WindowTitle => Text.WindowTitle;

    /// <summary>The page that is currently shown. It is one of the five page view models.</summary>
    public object CurrentPage
    {
        get => _currentPage;
        private set
        {
            if (!SetProperty(ref _currentPage, value)) return;
            OnPropertyChanged(
                nameof(IsDashboardCurrent),
                nameof(IsScanCurrent),
                nameof(IsQuarantineCurrent),
                nameof(IsHistoryCurrent),
                nameof(IsSettingsCurrent));
        }
    }

    /// <summary>True when the dashboard is the visible page.</summary>
    public bool IsDashboardCurrent => ReferenceEquals(CurrentPage, Dashboard);

    /// <summary>True when the scan page is the visible page.</summary>
    public bool IsScanCurrent => ReferenceEquals(CurrentPage, Scan);

    /// <summary>True when the quarantine page is the visible page.</summary>
    public bool IsQuarantineCurrent => ReferenceEquals(CurrentPage, Quarantine);

    /// <summary>True when the history page is the visible page.</summary>
    public bool IsHistoryCurrent => ReferenceEquals(CurrentPage, History);

    /// <summary>True when the settings page is the visible page.</summary>
    public bool IsSettingsCurrent => ReferenceEquals(CurrentPage, Settings);

    public string HeaderStatusText
    {
        get => _headerStatusText;
        private set => SetProperty(ref _headerStatusText, value);
    }

    public string HeaderStatusDetail
    {
        get => _headerStatusDetail;
        private set => SetProperty(ref _headerStatusDetail, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set => SetProperty(ref _isBusy, value);
    }

    public string ThemeTooltip
    {
        get => _themeTooltip;
        private set => SetProperty(ref _themeTooltip, value);
    }

    /// <summary>True when the dark palette is in effect. The toggle shows the moon.</summary>
    public bool IsDarkTheme => _services.Settings.Theme == AppTheme.Dark;

    /// <summary>True when the palette follows Windows. The toggle shows the system glyph.</summary>
    public bool UsesSystemTheme => _services.Settings.Theme == AppTheme.System;

    /// <summary>
    /// False when Windows itself asks for a high-contrast theme. The palette is then
    /// owned by the operating system and the toggle would be a silent no-op.
    /// </summary>
    public bool CanToggleTheme
    {
        get => _canToggleTheme;
        private set
        {
            if (!SetProperty(ref _canToggleTheme, value)) return;
            ToggleThemeCommand.RaiseCanExecuteChanged();
        }
    }

    public void Navigate(string key)
    {
        var item = NavigationItems.FirstOrDefault(
            candidate => string.Equals(candidate.Key, key, StringComparison.OrdinalIgnoreCase));
        if (item is null) return;

        foreach (var candidate in NavigationItems) candidate.IsSelected = ReferenceEquals(candidate, item);
        CurrentPage = item.Page;
        if (item.Page is IPageViewModel page) page.OnNavigatedTo();
        UpdateHeader();
    }

    public void StartQuickScan()
    {
        if (Scan.IsScanning)
        {
            Navigate("scan");
            return;
        }

        Navigate("scan");
        Scan.SetScope(ScanScopeKind.Quick);
        Scan.StartScanCommand.Execute(null);
    }

    public void StartScan(ScanScopeKind scope)
    {
        if (Scan.IsScanning)
        {
            Navigate("scan");
            return;
        }

        Navigate("scan");
        Scan.SetScope(scope);
        Scan.StartScanCommand.Execute(null);
    }

    public void PrepareScan(ScanScopeKind scope, bool browse)
    {
        Navigate("scan");
        Scan.SetScope(scope);
        if (browse && Scan.CanBrowse) Scan.BrowseCommand.Execute(null);
    }

    public void OpenScanWithFolder(string folder)
    {
        if (Scan.IsScanning)
        {
            Navigate("scan");
            return;
        }

        Navigate("scan");
        Scan.SetScope(ScanScopeKind.Folder);
        Scan.SelectedFolder = folder;
        if (Scan.CanStartScan) Scan.StartScanCommand.Execute(null);
    }

    public void CancelActiveWork()
    {
        if (Scan.IsScanning) Scan.CancelScan();
    }

    private void OnScanPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ScanViewModel.IsScanning)
            or nameof(ScanViewModel.IsQuarantining)
            or nameof(ScanViewModel.FilesScanned)
            or nameof(ScanViewModel.PhaseText))
        {
            UpdateHeader();
        }
    }

    private void OnDataChanged(object? sender, EventArgs e)
    {
        UpdateBadges();
        Dashboard.Refresh();
    }

    private void OnSettingsChanged(object? sender, EventArgs e)
    {
        // A language change is a setting change: the static XAML wording and the wording
        // the view models own both have to follow.
        if (_services.Language != Text.Current) Text.Set(_services.Language);

        UpdateThemeState();
        UpdateHeader();
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        NavigationItems[0].Title = Text.NavDashboard;
        NavigationItems[1].Title = Text.NavScan;
        NavigationItems[2].Title = Text.NavQuarantine;
        NavigationItems[3].Title = Text.NavHistory;
        NavigationItems[4].Title = Text.NavSettings;

        UpdateHeader();
        UpdateThemeState();
        OnPropertyChanged(nameof(WindowTitle));
    }

    /// <summary>
    /// Raises the loud detection alert for a real-time match. A clean scan never
    /// raises it: only a real detection does.
    ///
    /// <para>
    /// The alert service decides whether the finding is strong enough to take over
    /// the screen. A weak one is still reported — the real-time monitor has already
    /// put a message in the notification area, and the match is in the log — but it
    /// does not open a window over the user's work.
    /// </para>
    /// </summary>
    private void OnRealtimeDetected(object? sender, RealtimeDetectionEvent detection)
    {
        var primary = detection.PrimaryFinding;

        var report = new ScanDetection
        {
            FilePath = detection.FilePath,
            SizeBytes = detection.SizeBytes,
            Sha256 = detection.Sha256,
            Findings = detection.Findings,
            DetectedUtc = detection.DetectedUtc
        };

        _services.Alerts.Show(
            report,
            detection.FileName,
            primary?.Title ?? Text.PotentialIssueTitle,
            Presentation.ConfidenceText(primary?.Confidence ?? Confidence.Low),
            AlertOrigin.Realtime);
    }

    /// <summary>
    /// A detection was recorded but no loud alert was shown. The status line says
    /// so, so the user knows that Lumen saw something without being interrupted.
    /// </summary>
    private void OnAlertSuppressed(object? sender, AlertSuppression suppression)
    {
        _quietDetections++;
        UpdateHeader();
    }

    /// <summary>
    /// The user asked for the alerted file to be quarantined. It goes through the
    /// same confirmed vault service as a manual quarantine; the alert window was
    /// the confirmation.
    /// </summary>
    private async void OnQuarantineRequested(object? sender, string path)
    {
        try
        {
            var result = await _services.Quarantine.QuarantineAsync(
                new QuarantineRequest
                {
                    FilePath = path,
                    FindingTitle = Text.QuarantineAlertTitle,
                    Category = FindingCategory.Heuristic,
                    FindingDetail = Text.QuarantineAlertDetail,
                    SourceScanId = "alert",
                    DetectedUtc = _services.Clock.UtcNow
                },
                progress: null,
                CancellationToken.None);

            if (result.Status is QuarantineStatus.Quarantined or QuarantineStatus.QuarantinedOriginalRetained)
            {
                _services.Dialogs.ShowMessage(
                    Text.QuarantineAlertDoneTitle,
                    Text.QuarantineAlertDoneBody,
                    MessageSeverity.Success);
                _services.NotifyDataChanged();
                return;
            }

            _services.Dialogs.ShowMessage(
                Text.QuarantineAlertFailedTitle,
                result.Message ?? Text.QuarantineAlertFailedBody,
                MessageSeverity.Warning);
        }
        catch (Exception ex)
        {
            _services.Log.Error("Alert", "The alerted file could not be quarantined.", ex);
            _services.Dialogs.ShowMessage(
                Text.QuarantineAlertFailedTitle,
                Text.QuarantineAlertFailedBody,
                MessageSeverity.Warning);
        }
    }

    private void UpdateBadges()
    {
        var count = _services.Quarantine.GetItems().Count;
        var item = NavigationItems.FirstOrDefault(candidate => candidate.Key == "quarantine");
        if (item is not null) item.BadgeCount = count;
    }

    private void UpdateHeader()
    {
        if (Scan.IsQuarantining)
        {
            HeaderStatusText = Text.StatusQuarantining;
            HeaderStatusDetail = Text.StatusQuarantiningDetail;
            IsBusy = true;
            return;
        }

        if (Scan.IsScanning)
        {
            HeaderStatusText = Text.StatusScanning;
            HeaderStatusDetail = Text.StatusScanningDetail(Scan.FilesScannedText);
            IsBusy = true;
            return;
        }

        HeaderStatusText = Text.StatusReady;

        var detail = _services.Realtime.IsRunning
            ? Text.StatusRealtimeActive
            : Text.StatusOnDemand;

        // A detection that was recorded without a loud alert is still a detection.
        // The status line says how many there were, so nothing is silently dropped.
        if (_quietDetections > 0)
        {
            var strings = AlertService.BuildStrings(_services.Language);
            var quiet = _quietDetections == 1
                ? strings.QuietDetailOne
                : string.Format(CultureInfo.CurrentCulture, strings.QuietDetailMany, _quietDetections);
            detail = detail + " · " + quiet;
        }

        HeaderStatusDetail = detail;
        IsBusy = false;
    }

    private void UpdateThemeState()
    {
        var preference = _services.Settings.Theme;

        OnPropertyChanged(nameof(IsDarkTheme), nameof(UsesSystemTheme));

        CanToggleTheme = !_services.Theme.IsSystemHighContrast;

        ThemeTooltip = _services.Theme.IsSystemHighContrast
            ? Text.ThemeTooltipHighContrast
            : preference switch
            {
                AppTheme.Light => Text.ThemeTooltipDark,
                AppTheme.Dark => Text.ThemeTooltipSystem,
                AppTheme.HighContrast => Text.ThemeTooltipHighContrastChosen,
                _ => Text.ThemeTooltipLight
            };
    }

    /// <summary>
    /// Cycles the theme: System, then Light, then Dark, then back to System. It is a
    /// no-op while Windows owns the palette through its own high-contrast setting,
    /// and the button is disabled in that case.
    /// </summary>
    private void ToggleTheme()
    {
        if (!CanToggleTheme) return;

        var next = _services.Settings.Theme switch
        {
            AppTheme.System => AppTheme.Light,
            AppTheme.Light => AppTheme.Dark,
            _ => AppTheme.System
        };

        var result = _services.UpdateSettings(settings => settings with { Theme = next });
        if (!result.Ok)
        {
            _services.Dialogs.ShowMessage(
                Text.SettingsAppearanceTitle,
                result.Message ?? Text.SettingsSaveFailed,
                MessageSeverity.Warning);
        }

        UpdateThemeState();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Scan.PropertyChanged -= OnScanPropertyChanged;
        _services.DataChanged -= OnDataChanged;
        _services.SettingsChanged -= OnSettingsChanged;
        _services.RealtimeDetected -= OnRealtimeDetected;
        _services.Alerts.QuarantineRequested -= OnQuarantineRequested;
        _services.Alerts.AlertSuppressed -= OnAlertSuppressed;
        Text.LanguageChanged -= OnLanguageChanged;

        Dashboard.Dispose();
        Scan.Dispose();
        Quarantine.Dispose();
        History.Dispose();
        Settings.Dispose();
    }
}

/// <summary>One entry of the sidebar navigation.</summary>
public sealed class NavigationItemViewModel : ObservableObject
{
    private bool _isSelected;
    private int _badgeCount;
    private string _title;

    public NavigationItemViewModel(
        string key,
        string title,
        object page,
        Action<string> navigate)
    {
        Key = key;
        _title = title;
        Page = page;
        SelectCommand = new RelayCommand(() => navigate(key));
    }

    public string Key { get; }
    public object Page { get; }
    public RelayCommand SelectCommand { get; }

    /// <summary>The visible label. It follows the interface language.</summary>
    public string Title
    {
        get => _title;
        set
        {
            if (!SetProperty(ref _title, value)) return;
            OnPropertyChanged(nameof(AutomationName));
        }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (!SetProperty(ref _isSelected, value)) return;
            OnPropertyChanged(nameof(AutomationName));
        }
    }

    public int BadgeCount
    {
        get => _badgeCount;
        set
        {
            if (!SetProperty(ref _badgeCount, value)) return;
            OnPropertyChanged(nameof(HasBadge), nameof(BadgeText), nameof(AutomationName));
        }
    }

    public bool HasBadge => _badgeCount > 0;
    public string BadgeText => _badgeCount > 99 ? "99+" : _badgeCount.ToString("N0");
    public string AutomationName => HasBadge ? Text.NavBadge(Title, _badgeCount) : Title;
}
