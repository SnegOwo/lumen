using System.Collections.ObjectModel;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

public sealed class HistoryViewModel : ObservableObject, IPageViewModel
{
    private readonly AppServices _services;
    private readonly Action _startQuickScan;
    private HistoryRowViewModel? _selectedRow;
    private bool _hasEntries;
    private bool _hasBanner;
    private string _bannerTitle = string.Empty;
    private string _bannerMessage = string.Empty;
    private MessageSeverity _bannerSeverity = MessageSeverity.Info;
    private string _detailTitle = string.Empty;
    private string _detailWhen = string.Empty;
    private string _detailStatus = string.Empty;
    private string _detailScope = string.Empty;
    private string _detailCounts = string.Empty;
    private string _detailDuration = string.Empty;
    private string _detailRoots = string.Empty;

    public HistoryViewModel(AppServices services, Action startQuickScan)
    {
        _services = services;
        _startQuickScan = startQuickScan;

        ClearHistoryCommand = new RelayCommand(ClearHistory, () => HasEntries);
        DismissBannerCommand = new RelayCommand(() => HasBanner = false);
        StartQuickScanCommand = new RelayCommand(() => _startQuickScan());
        RefreshCommand = new RelayCommand(Refresh);
        LoadWarning = services.HistoryStore.LoadWarning;
    }

    public ObservableCollection<HistoryRowViewModel> Rows { get; } = [];
    public ObservableCollection<ScanErrorItemViewModel> DetailErrors { get; } = [];

    public RelayCommand ClearHistoryCommand { get; }
    public RelayCommand DismissBannerCommand { get; }
    public RelayCommand StartQuickScanCommand { get; }
    public RelayCommand RefreshCommand { get; }

    public string? LoadWarning { get; }

    public bool HasEntries
    {
        get => _hasEntries;
        private set
        {
            if (!SetProperty(ref _hasEntries, value)) return;
            ClearHistoryCommand.RaiseCanExecuteChanged();
            OnPropertyChanged(nameof(SummaryText));
        }
    }

    public string SummaryText => _hasEntries
        ? $"{Rows.Count:N0} scan(s) stored locally on this device"
        : "No scan history yet.";

    public HistoryRowViewModel? SelectedRow
    {
        get => _selectedRow;
        set
        {
            if (!SetProperty(ref _selectedRow, value)) return;
            UpdateDetails();
        }
    }

    public bool HasSelection => SelectedRow is not null;

    public bool HasBanner
    {
        get => _hasBanner;
        private set => SetProperty(ref _hasBanner, value);
    }

    public string BannerTitle
    {
        get => _bannerTitle;
        private set => SetProperty(ref _bannerTitle, value);
    }

    public string BannerMessage
    {
        get => _bannerMessage;
        private set => SetProperty(ref _bannerMessage, value);
    }

    public MessageSeverity BannerSeverity
    {
        get => _bannerSeverity;
        private set => SetProperty(ref _bannerSeverity, value);
    }

    public string DetailTitle
    {
        get => _detailTitle;
        private set => SetProperty(ref _detailTitle, value);
    }

    public string DetailWhen
    {
        get => _detailWhen;
        private set => SetProperty(ref _detailWhen, value);
    }

    public string DetailStatus
    {
        get => _detailStatus;
        private set => SetProperty(ref _detailStatus, value);
    }

    public string DetailScope
    {
        get => _detailScope;
        private set => SetProperty(ref _detailScope, value);
    }

    public string DetailCounts
    {
        get => _detailCounts;
        private set => SetProperty(ref _detailCounts, value);
    }

    public string DetailDuration
    {
        get => _detailDuration;
        private set => SetProperty(ref _detailDuration, value);
    }

    public string DetailRoots
    {
        get => _detailRoots;
        private set => SetProperty(ref _detailRoots, value);
    }

    public bool HasDetailErrors => DetailErrors.Count > 0;

    public string DetailErrorsCaption => DetailErrors.Count == 0
        ? "No skipped items were recorded."
        : $"{DetailErrors.Count:N0} skipped or unreadable item(s)";

    public void OnNavigatedTo() => Refresh();

    public void Refresh()
    {
        var selectedId = SelectedRow?.Id;
        var entries = _services.HistoryStore.GetEntries();

        Rows.Clear();
        foreach (var entry in entries) Rows.Add(new HistoryRowViewModel(entry, _services.Clock.UtcNow));
        HasEntries = Rows.Count > 0;
        OnPropertyChanged(nameof(SummaryText));

        SelectedRow = selectedId is null
            ? Rows.FirstOrDefault()
            : Rows.FirstOrDefault(row => row.Id == selectedId) ?? Rows.FirstOrDefault();
    }

    private void UpdateDetails()
    {
        DetailErrors.Clear();

        if (SelectedRow is null)
        {
            DetailTitle = string.Empty;
            DetailWhen = string.Empty;
            DetailStatus = string.Empty;
            DetailScope = string.Empty;
            DetailCounts = string.Empty;
            DetailDuration = string.Empty;
            DetailRoots = string.Empty;
            OnPropertyChanged(nameof(HasSelection), nameof(HasDetailErrors), nameof(DetailErrorsCaption));
            return;
        }

        var source = SelectedRow.Source;
        DetailTitle = SelectedRow.Title;
        DetailWhen = TimeFormatter.DateTime(source.StartedUtc);
        DetailStatus = source.StatusText;
        DetailScope = Presentation.Scope(source.Scope);
        DetailCounts =
            $"{Presentation.Count(source.FilesScanned, "file")} inspected \u00B7 " +
            $"{Presentation.Count(source.DetectionCount, "finding")} \u00B7 " +
            $"{Presentation.Count(source.ErrorCount, "warning")}";
        DetailDuration = TimeFormatter.Duration(source.Duration);
        DetailRoots = source.Roots.Count == 0
            ? "No locations recorded."
            : string.Join(Environment.NewLine, source.Roots.Select(Presentation.SanitizePath));

        foreach (var error in source.Errors) DetailErrors.Add(new ScanErrorItemViewModel(error));
        OnPropertyChanged(nameof(HasSelection), nameof(HasDetailErrors), nameof(DetailErrorsCaption));
    }

    private void ClearHistory()
    {
        if (!HasEntries) return;

        var proceed = _services.Dialogs.Confirm(
            "Clear scan history?",
            "This deletes the local scan-history file. Quarantined files and their encrypted copies are not affected.",
            "Clear history",
            danger: true);
        if (!proceed) return;

        var result = _services.HistoryStore.Clear();
        if (!result.Ok)
        {
            BannerTitle = "History could not be cleared";
            BannerMessage = result.Message ?? "The local history file could not be updated.";
            BannerSeverity = MessageSeverity.Warning;
            HasBanner = true;
            return;
        }

        Refresh();
        BannerTitle = "Scan history cleared";
        BannerMessage = "Local scan history was removed. Quarantined files were not changed.";
        BannerSeverity = MessageSeverity.Success;
        HasBanner = true;
        _services.NotifyDataChanged();
    }
}
