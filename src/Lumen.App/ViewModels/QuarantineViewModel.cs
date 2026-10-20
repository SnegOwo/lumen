using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Localization;
using Lumen.App.Remediation;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

/// <summary>
/// The quarantine page: the encrypted vault and what can be done with it.
/// </summary>
public sealed class QuarantineViewModel : ObservableObject, IPageViewModel, IDisposable
{
    private readonly AppServices _services;
    private readonly RemediationCoordinator _remediation;
    private QuarantineItemViewModel? _selectedItem;
    private bool _hasItems;
    private bool _isWorking;
    private bool _hasBanner;
    private string _bannerTitle = string.Empty;
    private string _bannerMessage = string.Empty;
    private MessageSeverity _bannerSeverity = MessageSeverity.Info;
    private bool _isRemediationEnabled;
    private string _workingLabel = string.Empty;
    private bool _disposed;

    /// <summary>Creates the quarantine view model.</summary>
    public QuarantineViewModel(AppServices services, Action goToScan)
    {
        _services = services;
        _remediation = new RemediationCoordinator(services);

        GoToScanCommand = new RelayCommand(goToScan);
        RefreshCommand = new RelayCommand(Refresh, () => !IsWorking);
        RestoreCommand = new AsyncRelayCommand(RestoreAsync, () => HasSelection && !IsWorking);
        RestoreToCommand = new AsyncRelayCommand(RestoreToAsync, () => HasSelection && !IsWorking);
        DeleteCommand = new AsyncRelayCommand(DeleteAsync, () => HasSelection && !IsWorking);
        CleanFileCommand = new AsyncRelayCommand(
            CleanFileAsync,
            () => HasSelection && IsRemediationEnabled && !IsWorking);
        RevealOriginalCommand = new RelayCommand(RevealOriginal, () => HasSelection && !IsWorking && SelectedItem?.OriginalExists == true);
        OpenVaultCommand = new RelayCommand(OpenVault);
        CopyPathCommand = new RelayCommand(CopyPath, () => HasSelection);
        DismissBannerCommand = new RelayCommand(() => HasBanner = false);

        WarningText = services.Quarantine.LoadWarning;
        _isRemediationEnabled = services.Settings.RemediationEnabled;

        services.SettingsChanged += OnServicesSettingsChanged;
        Text.LanguageChanged += OnLanguageChanged;
    }

    public ObservableCollection<QuarantineItemViewModel> Items { get; } = [];

    public RelayCommand GoToScanCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public AsyncRelayCommand RestoreCommand { get; }
    public AsyncRelayCommand RestoreToCommand { get; }
    public AsyncRelayCommand DeleteCommand { get; }

    /// <summary>
    /// Cleans up the file behind the selected quarantine item. It is only enabled
    /// when the user allowed remediation actions in Settings.
    /// </summary>
    public AsyncRelayCommand CleanFileCommand { get; }

    public RelayCommand RevealOriginalCommand { get; }
    public RelayCommand OpenVaultCommand { get; }
    public RelayCommand CopyPathCommand { get; }
    public RelayCommand DismissBannerCommand { get; }

    public string? WarningText { get; }
    public bool HasWarning => !string.IsNullOrWhiteSpace(WarningText);

    public bool HasItems
    {
        get => _hasItems;
        private set
        {
            if (!SetProperty(ref _hasItems, value)) return;
            OnPropertyChanged(nameof(CountText), nameof(EmptyDetail), nameof(VaultSummary));
        }
    }

    public string CountText => Text.QuarantineCountChip(Items.Count);

    public string VaultSummary => Items.Count == 0
        ? Text.QuarantineSummaryEmpty
        : Text.QuarantineSummary(Items.Count);

    public string EmptyDetail => Text.QuarantineEmptyBody;

    public QuarantineItemViewModel? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (!SetProperty(ref _selectedItem, value)) return;
            OnPropertyChanged(nameof(HasSelection));
            RevealOriginalCommand.RaiseCanExecuteChanged();
            CopyPathCommand.RaiseCanExecuteChanged();
            RaiseCommandStates();
        }
    }

    public bool HasSelection => SelectedItem is not null;

    public bool IsWorking
    {
        get => _isWorking;
        private set
        {
            if (!SetProperty(ref _isWorking, value)) return;
            OnPropertyChanged(nameof(HasWorkProgress), nameof(WorkingLabel));
            RaiseCommandStates();
        }
    }

    /// <summary>True while a long vault operation is running.</summary>
    public bool HasWorkProgress => IsWorking;

    /// <summary>What the vault is busy with, shown next to the progress strip.</summary>
    public string WorkingLabel
    {
        get => _workingLabel;
        private set => SetProperty(ref _workingLabel, value);
    }

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

    /// <summary>
    /// The banner, in one line. It is announced by the live region of the page, so
    /// a screen reader reports what the banner says.
    /// </summary>
    public string BannerAnnouncement => _hasBanner
        ? BannerTitle + ". " + BannerMessage
        : string.Empty;

    /// <summary>
    /// True when the user allowed remediation actions. The Clean action stays disabled
    /// while it is off.
    /// </summary>
    public bool IsRemediationEnabled
    {
        get => _isRemediationEnabled;
        private set
        {
            if (!SetProperty(ref _isRemediationEnabled, value)) return;
            RaiseCommandStates();
        }
    }

    public void OnNavigatedTo() => Refresh();

    public void Refresh()
    {
        var selectedId = SelectedItem?.Id;
        Items.Clear();
        foreach (var item in _services.Quarantine.GetItems())
            Items.Add(new QuarantineItemViewModel(item, _services.Clock.UtcNow));

        HasItems = Items.Count > 0;
        SelectedItem = selectedId is null
            ? Items.FirstOrDefault()
            : Items.FirstOrDefault(item => item.Id == selectedId) ?? Items.FirstOrDefault();
        OnPropertyChanged(nameof(CountText), nameof(VaultSummary), nameof(EmptyDetail));
    }

    private async Task RestoreAsync()
    {
        if (SelectedItem is null) return;
        var item = SelectedItem;
        var proceed = _services.Dialogs.Confirm(
            Text.RestoreTitle,
            Text.RestoreBody,
            Text.QuarantineRestore,
            details: Text.RestoreOriginalPrefix + item.OriginalPath + Environment.NewLine +
                      "SHA-256: " + item.Source.Sha256);
        if (!proceed) return;

        IsWorking = true;
        WorkingLabel = item.FileName;
        try
        {
            var result = await _services.Quarantine.RestoreAsync(
                new RestoreRequest { Id = item.Id },
                CancellationToken.None);
            await HandleRestoreResultAsync(result, item, attempt: 0);
        }
        catch (Exception ex)
        {
            _services.Log.Error("Quarantine", "Restore failed unexpectedly.", ex);
            SetBanner(Text.RestoreFailedTitle, Text.RestoreFailedBody, MessageSeverity.Danger);
        }
        finally
        {
            IsWorking = false;
            WorkingLabel = string.Empty;
        }
    }

    private async Task RestoreToAsync()
    {
        if (SelectedItem is null) return;
        var item = SelectedItem;

        var folder = _services.Dialogs.PickFolder(
            Text.RestoreFolderPickerTitle,
            item.OriginalFolder);
        if (string.IsNullOrWhiteSpace(folder)) return;

        var fileName = Path.GetFileName(item.Source.OriginalPath);
        if (string.IsNullOrWhiteSpace(fileName)) fileName = "restored-file";
        var destination = Path.Combine(folder, fileName);
        var overwrite = false;

        if (File.Exists(destination))
        {
            overwrite = _services.Dialogs.Confirm(
                Text.RestoreReplaceTitle,
                Text.RestoreReplaceBody,
                Text.RestoreReplaceFileConfirm,
                danger: true,
                details: Text.RestoreOriginalPrefix + Presentation.SanitizePath(destination));
            if (!overwrite) return;
        }

        IsWorking = true;
        WorkingLabel = item.FileName;
        try
        {
            var result = await _services.Quarantine.RestoreAsync(
                new RestoreRequest
                {
                    Id = item.Id,
                    DestinationPath = destination,
                    Overwrite = overwrite
                },
                CancellationToken.None);
            await HandleRestoreResultAsync(result, item, attempt: 1);
        }
        catch (Exception ex)
        {
            _services.Log.Error("Quarantine", "Restore-to-folder failed unexpectedly.", ex);
            SetBanner(Text.RestoreFailedTitle, Text.RestoreFailedBody, MessageSeverity.Danger);
        }
        finally
        {
            IsWorking = false;
            WorkingLabel = string.Empty;
        }
    }

    private async Task HandleRestoreResultAsync(
        RestoreResult result,
        QuarantineItemViewModel item,
        int attempt)
    {
        switch (result.Status)
        {
            case RestoreStatus.Restored:
                SetBanner(
                    Text.RestoreDoneTitle,
                    Text.RestoreDoneBody(Presentation.SanitizePath(result.RestoredPath)),
                    MessageSeverity.Success);
                Refresh();
                _services.NotifyDataChanged();
                return;

            case RestoreStatus.TargetExists:
                if (attempt >= 2) break;

                var replace = _services.Dialogs.Confirm(
                    Text.RestoreTargetExistsTitle,
                    Text.RestoreTargetExistsBody,
                    Text.RestoreReplaceConfirm,
                    danger: true,
                    details: Text.RestoreOriginalPrefix + Presentation.SanitizePath(result.RestoredPath));
                if (!replace)
                {
                    SetBanner(
                        Text.RestoreCancelledTitle,
                        Text.RestoreCancelledKeptBody,
                        MessageSeverity.Info);
                    return;
                }

                var retry = await _services.Quarantine.RestoreAsync(
                    new RestoreRequest { Id = item.Id, Overwrite = true },
                    CancellationToken.None);
                await HandleRestoreResultAsync(retry, item, attempt + 1);
                return;

            case RestoreStatus.DestinationMissing:
                if (attempt >= 2) break;

                var chooseFolder = _services.Dialogs.Confirm(
                    Text.RestoreFolderGoneTitle,
                    Text.RestoreFolderGoneBody,
                    Text.RestoreChooseFolder,
                    details: Text.RestoreOriginalPrefix + item.OriginalPath);
                if (!chooseFolder)
                {
                    SetBanner(
                        Text.RestoreCancelledTitle,
                        Text.RestoreKeptBody,
                        MessageSeverity.Info);
                    return;
                }

                var folder = _services.Dialogs.PickFolder(
                    Text.RestoreFolderPickerTitle,
                    _services.UserProfile);
                if (string.IsNullOrWhiteSpace(folder))
                {
                    SetBanner(
                        Text.RestoreCancelledTitle,
                        Text.RestoreKeptBody,
                        MessageSeverity.Info);
                    return;
                }

                var fileName = Path.GetFileName(item.Source.OriginalPath);
                if (string.IsNullOrWhiteSpace(fileName)) fileName = "restored-file";
                var destination = Path.Combine(folder, fileName);
                var overwrite = false;
                if (File.Exists(destination))
                {
                    overwrite = _services.Dialogs.Confirm(
                        Text.RestoreReplaceTitle,
                        Text.RestoreReplaceBody,
                        Text.RestoreReplaceFileConfirm,
                        danger: true,
                        details: Text.RestoreOriginalPrefix + Presentation.SanitizePath(destination));
                    if (!overwrite)
                    {
                        SetBanner(Text.RestoreCancelledTitle, Text.RestoreKeptBody, MessageSeverity.Info);
                        return;
                    }
                }

                var retryTo = await _services.Quarantine.RestoreAsync(
                    new RestoreRequest
                    {
                        Id = item.Id,
                        DestinationPath = destination,
                        Overwrite = overwrite
                    },
                    CancellationToken.None);
                await HandleRestoreResultAsync(retryTo, item, attempt + 1);
                return;

            case RestoreStatus.Corrupt:
                _services.Dialogs.ShowMessage(
                    Text.RestoreCorruptTitle,
                    Text.RestoreCorruptBody,
                    MessageSeverity.Danger,
                    Text.RestoreStatusPrefix + result.Message);
                SetBanner(
                    Text.RestoreIntegrityTitle,
                    Text.RestoreIntegrityBody,
                    MessageSeverity.Danger);
                return;

            case RestoreStatus.NotFound:
                SetBanner(Text.QuarantineItemNotFoundTitle, result.Message, MessageSeverity.Warning);
                Refresh();
                return;

            case RestoreStatus.Cancelled:
                SetBanner(Text.RestoreCancelledTitle, Text.RestoreCancelledBody, MessageSeverity.Info);
                return;

            default:
                SetBanner(Text.RestoreFailedTitle, result.Message, MessageSeverity.Danger);
                return;
        }

        SetBanner(Text.RestoreFailedTitle, result.Message, MessageSeverity.Danger);
    }

    private async Task DeleteAsync()
    {
        if (SelectedItem is null) return;
        var item = SelectedItem;

        var details = Text.RestoreOriginalPrefix + item.OriginalPath + Environment.NewLine +
                      "SHA-256: " + item.Source.Sha256;
        if (item.OriginalExists)
        {
            details += Environment.NewLine + Text.QuarantineOriginalPresentDetail;
        }

        var proceed = _services.Dialogs.Confirm(
            Text.QuarantineDeleteTitle,
            Text.QuarantineDeleteBody,
            Text.QuarantineDeleteConfirm,
            danger: true,
            details: details);
        if (!proceed) return;

        IsWorking = true;
        WorkingLabel = item.FileName;
        try
        {
            var result = await _services.Quarantine.DeleteAsync(item.Id, CancellationToken.None);
            if (result.Deleted)
            {
                SetBanner(Text.QuarantineDeletedTitle, result.Message, MessageSeverity.Success);
                Refresh();
                _services.NotifyDataChanged();
            }
            else
            {
                SetBanner(Text.QuarantineDeleteFailedTitle, result.Message, MessageSeverity.Danger);
            }
        }
        catch (Exception ex)
        {
            _services.Log.Error("Quarantine", "Permanent deletion failed unexpectedly.", ex);
            SetBanner(Text.QuarantineDeleteFailedTitle, Text.QuarantineDeleteFailedBody, MessageSeverity.Danger);
        }
        finally
        {
            IsWorking = false;
            WorkingLabel = string.Empty;
        }
    }

    /// <summary>
    /// Cleans up the file behind the selected quarantine item. The flow is plan, then
    /// review, then confirm, then execute.
    /// </summary>
    private async Task CleanFileAsync()
    {
        if (IsWorking) return;
        if (!IsRemediationEnabled) return;
        var item = SelectedItem;
        if (item is null) return;

        var target = new RemediationTarget
        {
            FilePath = item.Source.OriginalPath,
            Sha256 = item.Source.Sha256,
            SizeBytes = item.Source.SizeBytes,
            FindingTitle = item.FindingTitle,
            FindingDetail = item.FindingDetail,
            QuarantineItemId = item.Id
        };

        await _remediation.RunAsync(target, CancellationToken.None);
        Refresh();
        _services.NotifyDataChanged();
    }

    private void RevealOriginal()
    {
        if (SelectedItem is null) return;
        if (!_services.RevealFile(SelectedItem.Source.OriginalPath))
        {
            _services.Dialogs.ShowMessage(
                Text.QuarantineOriginalMissingTitle,
                Text.QuarantineOriginalMissingBody,
                MessageSeverity.Info);
        }
    }

    private void OpenVault()
    {
        if (!_services.OpenFolder(_services.Paths.QuarantineDirectory))
        {
            SetBanner(Text.QuarantineFolderFailedTitle, Text.QuarantineFolderFailedBody, MessageSeverity.Warning);
        }
    }

    private void CopyPath()
    {
        if (SelectedItem is null) return;
        try
        {
            Clipboard.SetText(SelectedItem.Source.OriginalPath);
            SetBanner(Text.QuarantinePathCopiedTitle, Text.QuarantinePathCopiedBody, MessageSeverity.Info);
        }
        catch (Exception ex)
        {
            _services.Log.Warn("Shell", "The path could not be copied.", ex);
            SetBanner(Text.QuarantinePathCopyFailedTitle, Text.QuarantinePathCopyFailedBody, MessageSeverity.Warning);
        }
    }

    private void SetBanner(string title, string message, MessageSeverity severity)
    {
        BannerTitle = title;
        BannerMessage = message;
        BannerSeverity = severity;
        HasBanner = true;
        OnPropertyChanged(nameof(BannerAnnouncement));
    }

    private void OnServicesSettingsChanged(object? sender, EventArgs e)
    {
        IsRemediationEnabled = _services.Settings.RemediationEnabled;
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(
            nameof(CountText),
            nameof(VaultSummary),
            nameof(EmptyDetail),
            nameof(WorkingLabel));

        foreach (var item in Items) item.Refresh();
    }

    private void RaiseCommandStates()
    {
        RefreshCommand.RaiseCanExecuteChanged();
        RestoreCommand.RaiseCanExecuteChanged();
        RestoreToCommand.RaiseCanExecuteChanged();
        DeleteCommand.RaiseCanExecuteChanged();
        CleanFileCommand.RaiseCanExecuteChanged();
        RevealOriginalCommand.RaiseCanExecuteChanged();
        CopyPathCommand.RaiseCanExecuteChanged();
    }

    /// <summary>Unsubscribes from the events this view model listens to.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _services.SettingsChanged -= OnServicesSettingsChanged;
        Text.LanguageChanged -= OnLanguageChanged;
    }
}
