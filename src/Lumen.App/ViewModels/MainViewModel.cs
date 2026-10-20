using System.Collections.ObjectModel;
using System.ComponentModel;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Services;
using Lumen.Core.Models;

namespace Lumen.App.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly AppServices _services;
    private object _currentPage;
    private string _currentTitle = "Dashboard";
    private string _headerStatusText = "Ready";
    private string _headerStatusDetail = "Real-time protection active";
    private bool _isBusy;
    private string _themeGlyph = "\uE708";
    private string _themeTooltip = "Switch theme";
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
            new NavigationItemViewModel("dashboard", "Dashboard", "\uE80F", Dashboard, Navigate),
            new NavigationItemViewModel("scan", "Scan", "\uE721", Scan, Navigate),
            new NavigationItemViewModel("quarantine", "Quarantine", "\uE72E", Quarantine, Navigate),
            new NavigationItemViewModel("history", "History", "\uE81C", History, Navigate),
            new NavigationItemViewModel("settings", "Settings", "\uE713", Settings, Navigate)
        ];

        NavigateCommand = new RelayCommand<string>(key => Navigate(key ?? string.Empty));
        QuickScanCommand = new RelayCommand(StartQuickScan);
        ToggleThemeCommand = new RelayCommand(ToggleTheme);
        OpenSettingsCommand = new RelayCommand(() => Navigate("settings"));

        _currentPage = Dashboard;
        NavigationItems[0].IsSelected = true;

        Scan.PropertyChanged += OnScanPropertyChanged;
        _services.DataChanged += OnDataChanged;
        _services.SettingsChanged += OnSettingsChanged;

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

    public object CurrentPage
    {
        get => _currentPage;
        private set => SetProperty(ref _currentPage, value);
    }

    public string CurrentTitle
    {
        get => _currentTitle;
        private set => SetProperty(ref _currentTitle, value);
    }

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

    public string ThemeGlyph
    {
        get => _themeGlyph;
        private set => SetProperty(ref _themeGlyph, value);
    }

    public string ThemeTooltip
    {
        get => _themeTooltip;
        private set => SetProperty(ref _themeTooltip, value);
    }

    public bool IsScanning => Scan.IsScanning;

    public void Navigate(string key)
    {
        var item = NavigationItems.FirstOrDefault(
            candidate => string.Equals(candidate.Key, key, StringComparison.OrdinalIgnoreCase));
        if (item is null) return;

        foreach (var candidate in NavigationItems) candidate.IsSelected = ReferenceEquals(candidate, item);
        CurrentPage = item.Page;
        CurrentTitle = item.Title;
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
        UpdateThemeState();
        UpdateHeader();
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
            HeaderStatusText = "Quarantining";
            HeaderStatusDetail = "Encrypting files locally";
            IsBusy = true;
            return;
        }

        if (Scan.IsScanning)
        {
            HeaderStatusText = "Scanning";
            HeaderStatusDetail = Scan.FilesScannedText + " files inspected";
            IsBusy = true;
            return;
        }

        HeaderStatusText = "Ready";
        HeaderStatusDetail = _services.Realtime.IsRunning
            ? "Real-time protection active"
            : "On-demand scanning";
        IsBusy = false;
    }

    private void UpdateThemeState()
    {
        ThemeGlyph = _services.Theme.IsDark ? "\uE706" : "\uE708";
        ThemeTooltip = _services.Theme.IsHighContrast
            ? "High contrast is active. Theme preference: " + _services.Settings.Theme
            : _services.Theme.IsDark
                ? "Switch to light theme"
                : "Switch to dark theme";
    }

    private void ToggleTheme()
    {
        var next = _services.Theme.IsDark ? AppTheme.Light : AppTheme.Dark;
        var result = _services.UpdateSettings(settings => settings with { Theme = next });
        if (!result.Ok)
        {
            _services.Dialogs.ShowMessage(
                "Theme could not be saved",
                result.Message ?? "The settings file could not be updated.",
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
    }
}

public sealed class NavigationItemViewModel : ObservableObject
{
    private bool _isSelected;
    private int _badgeCount;

    public NavigationItemViewModel(
        string key,
        string title,
        string glyph,
        object page,
        Action<string> navigate)
    {
        Key = key;
        Title = title;
        Glyph = glyph;
        Page = page;
        SelectCommand = new RelayCommand(() => navigate(key));
    }

    public string Key { get; }
    public string Title { get; }
    public string Glyph { get; }
    public object Page { get; }
    public RelayCommand SelectCommand { get; }

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
    public string AutomationName => HasBadge ? $"{Title}, {_badgeCount} quarantined items" : Title;
}
