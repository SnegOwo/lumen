using System.Collections.ObjectModel;
using System.Windows;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

public sealed class QuarantineViewModel : ObservableObject, IPageViewModel
{
    private readonly AppServices _services;
    private QuarantineItemViewModel? _selectedItem;
    private bool _hasItems;
    private bool _isWorking;
    private bool _hasBanner;
    private string _bannerTitle = string.Empty;
    private string _bannerMessage = string.Empty;
    private MessageSeverity _bannerSeverity = MessageSeverity.Info;

    public QuarantineViewModel(AppServices services, Action goToScan)
    {
        _services = services;

        GoToScanCommand = new RelayCommand(goToScan);
        RefreshCommand = new RelayCommand(Refresh, () => !IsWorking);
        RestoreCommand = new AsyncRelayCommand(RestoreAsync, () => HasSelection && !IsWorking);
        RestoreToCommand = new AsyncRelayCommand(RestoreToAsync, () => HasSelection && !IsWorking);
        DeleteCommand = new AsyncRelayCommand(DeleteAsync, () => HasSelection && !IsWorking);
        RevealOriginalCommand = new RelayCommand(RevealOriginal, () => HasSelection && !IsWorking && SelectedItem?.OriginalExists == true);
        OpenVaultCommand = new RelayCommand(OpenVault);
        CopyPathCommand = new RelayCommand(CopyPath, () => HasSelection);
        DismissBannerCommand = new RelayCommand(() => HasBanner = false);

        WarningText = services.Quarantine.LoadWarning;
    }

    public ObservableCollection<QuarantineItemViewModel> Items { get; } = [];

    public RelayCommand GoToScanCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public AsyncRelayCommand RestoreCommand { get; }
    public AsyncRelayCommand RestoreToCommand { get; }
    public AsyncRelayCommand DeleteCommand { get; }
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

    public string CountText => Items.Count == 1 ? "1 encrypted file" : $"{Items.Count:N0} encrypted files";

    public string VaultSummary => Items.Count == 0
        ? "Nothing is quarantined."
        : CountText + " isolated in this account's encrypted vault.";

    public string EmptyDetail =>
        "Files you choose to quarantine are encrypted with AES-256, integrity-checked, and kept here until you restore or delete them.";

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
            RaiseCommandStates();
        }
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
            "Restore this file?",
            "Lumen will decrypt the encrypted copy, verify its SHA-256 hash, and write it back. " +
            "If the original folder no longer exists, you will be asked where to put the file.",
            "Restore",
            details: "Original location: " + item.OriginalPath + Environment.NewLine + "SHA-256: " + item.Source.Sha256);
        if (!proceed) return;

        IsWorking = true;
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
            SetBanner("Restore failed", "The file could not be restored. The encrypted copy was kept.", MessageSeverity.Danger);
        }
        finally
        {
            IsWorking = false;
        }
    }

    private async Task RestoreToAsync()
    {
        if (SelectedItem is null) return;
        var item = SelectedItem;

        var folder = _services.Dialogs.PickFolder(
            "Choose a folder for the restored file",
            item.OriginalFolder);
        if (string.IsNullOrWhiteSpace(folder)) return;

        var fileName = Path.GetFileName(item.Source.OriginalPath);
        if (string.IsNullOrWhiteSpace(fileName)) fileName = "restored-file";
        var destination = Path.Combine(folder, fileName);
        var overwrite = false;

        if (File.Exists(destination))
        {
            overwrite = _services.Dialogs.Confirm(
                "Replace the existing file?",
                "A file with this name already exists in the folder you chose. " +
                "Restoring will replace it with the quarantined copy. This cannot be undone.",
                "Replace file",
                danger: true,
                details: "Existing file: " + Presentation.SanitizePath(destination));
            if (!overwrite) return;
        }

        IsWorking = true;
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
            SetBanner("Restore failed", "The file could not be restored. The encrypted copy was kept.", MessageSeverity.Danger);
        }
        finally
        {
            IsWorking = false;
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
                    "File restored",
                    "The file was decrypted and verified at " + Presentation.SanitizePath(result.RestoredPath),
                    MessageSeverity.Success);
                Refresh();
                _services.NotifyDataChanged();
                return;

            case RestoreStatus.TargetExists:
                if (attempt >= 2) break;

                var replace = _services.Dialogs.Confirm(
                    "A file already exists at the original location",
                    "Restoring will replace the current file with the verified quarantined copy. " +
                    "The current file cannot be recovered by Lumen.",
                    "Replace existing file",
                    danger: true,
                    details: "Existing file: " + Presentation.SanitizePath(result.RestoredPath));
                if (!replace)
                {
                    SetBanner(
                        "Restore cancelled",
                        "The existing file was left in place. The quarantine item was not changed.",
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
                    "The original folder no longer exists",
                    "The folder this file came from is gone. Choose another folder to restore the file into.",
                    "Choose folder",
                    details: "Original location: " + item.OriginalPath);
                if (!chooseFolder)
                {
                    SetBanner(
                        "Restore cancelled",
                        "The encrypted copy was kept. You can restore it later to a folder you choose.",
                        MessageSeverity.Info);
                    return;
                }

                var folder = _services.Dialogs.PickFolder(
                    "Choose a folder for the restored file",
                    _services.UserProfile);
                if (string.IsNullOrWhiteSpace(folder))
                {
                    SetBanner(
                        "Restore cancelled",
                        "The encrypted copy was kept.",
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
                        "Replace the existing file?",
                        "A file with this name already exists in the chosen folder. Replace it with the quarantined copy?",
                        "Replace file",
                        danger: true,
                        details: "Existing file: " + Presentation.SanitizePath(destination));
                    if (!overwrite)
                    {
                        SetBanner("Restore cancelled", "The encrypted copy was kept.", MessageSeverity.Info);
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
                    "The encrypted copy failed verification",
                    "Lumen did not restore the file because the encrypted copy is incomplete or was modified. " +
                    "The quarantine item remains in the vault so the evidence is preserved. " +
                    "Do not delete it if you may need support.",
                    MessageSeverity.Danger,
                    "Status: " + result.Message);
                SetBanner(
                    "Restore failed integrity check",
                    "Nothing was written. The quarantine item remains in the vault.",
                    MessageSeverity.Danger);
                return;

            case RestoreStatus.NotFound:
                SetBanner("Item not found", result.Message, MessageSeverity.Warning);
                Refresh();
                return;

            case RestoreStatus.Cancelled:
                SetBanner("Restore cancelled", "Nothing was written.", MessageSeverity.Info);
                return;

            default:
                SetBanner("Restore failed", result.Message, MessageSeverity.Danger);
                return;
        }

        SetBanner("Restore failed", result.Message, MessageSeverity.Danger);
    }

    private async Task DeleteAsync()
    {
        if (SelectedItem is null) return;
        var item = SelectedItem;

        var details = "Original location: " + item.OriginalPath + Environment.NewLine +
                      "SHA-256: " + item.Source.Sha256;
        if (item.OriginalExists)
        {
            details += Environment.NewLine +
                       "The original file still exists at its original location because it could not be removed.";
        }

        var proceed = _services.Dialogs.Confirm(
            "Permanently delete this encrypted copy?",
            "This deletes the encrypted vault file and its index entry. It cannot be undone. " +
            "If the original file was removed when it was quarantined, the file will be gone permanently.",
            "Delete permanently",
            danger: true,
            details: details);
        if (!proceed) return;

        IsWorking = true;
        try
        {
            var result = await _services.Quarantine.DeleteAsync(item.Id, CancellationToken.None);
            if (result.Deleted)
            {
                SetBanner("Quarantine item deleted", result.Message, MessageSeverity.Success);
                Refresh();
                _services.NotifyDataChanged();
            }
            else
            {
                SetBanner("Delete failed", result.Message, MessageSeverity.Danger);
            }
        }
        catch (Exception ex)
        {
            _services.Log.Error("Quarantine", "Permanent deletion failed unexpectedly.", ex);
            SetBanner("Delete failed", "The item could not be deleted.", MessageSeverity.Danger);
        }
        finally
        {
            IsWorking = false;
        }
    }

    private void RevealOriginal()
    {
        if (SelectedItem is null) return;
        if (!_services.RevealFile(SelectedItem.Source.OriginalPath))
        {
            _services.Dialogs.ShowMessage(
                "Original file not found",
                "The original file is no longer at that location. Use Restore to write the quarantined copy to a folder you choose.",
                MessageSeverity.Info);
        }
    }

    private void OpenVault()
    {
        if (!_services.OpenFolder(_services.Paths.QuarantineDirectory))
        {
            SetBanner("Folder could not be opened", "The quarantine folder could not be opened.", MessageSeverity.Warning);
        }
    }

    private void CopyPath()
    {
        if (SelectedItem is null) return;
        try
        {
            Clipboard.SetText(SelectedItem.Source.OriginalPath);
            SetBanner("Path copied", "The original path was copied to the clipboard.", MessageSeverity.Info);
        }
        catch (Exception ex)
        {
            _services.Log.Warn("Shell", "The path could not be copied.", ex);
            SetBanner("Could not copy the path", "The clipboard is unavailable right now.", MessageSeverity.Warning);
        }
    }

    private void SetBanner(string title, string message, MessageSeverity severity)
    {
        BannerTitle = title;
        BannerMessage = message;
        BannerSeverity = severity;
        HasBanner = true;
    }

    private void RaiseCommandStates()
    {
        RefreshCommand.RaiseCanExecuteChanged();
        RestoreCommand.RaiseCanExecuteChanged();
        RestoreToCommand.RaiseCanExecuteChanged();
        DeleteCommand.RaiseCanExecuteChanged();
        RevealOriginalCommand.RaiseCanExecuteChanged();
        CopyPathCommand.RaiseCanExecuteChanged();
    }
}
