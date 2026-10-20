using System.Collections.ObjectModel;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Services;
using Lumen.Core.Detection;
using Lumen.Core.Models;

namespace Lumen.App.ViewModels;

public sealed class SettingsViewModel : ObservableObject, IPageViewModel
{
    private readonly AppServices _services;
    private readonly Action<string> _scanFolder;
    private bool _hasSaveError;
    private string _saveErrorText = string.Empty;

    public SettingsViewModel(AppServices services, Action<string> scanFolder)
    {
        _services = services;
        _scanFolder = scanFolder;

        Defender = new DefenderStatusViewModel(services);
        Rules = new ObservableCollection<DetectionRuleViewModel>(
            DetectionCatalog.Rules.Select(rule => new DetectionRuleViewModel(rule)));

        OpenDataFolderCommand = new RelayCommand(() => OpenFolder(_services.DataDirectory));
        OpenQuarantineFolderCommand = new RelayCommand(() => OpenFolder(_services.Paths.QuarantineDirectory));
        OpenLogFolderCommand = new RelayCommand(() => OpenFolder(_services.Paths.LogDirectory));
        OpenWindowsSecurityCommand = new RelayCommand(OpenWindowsSecurity);
        CreateSamplesCommand = new RelayCommand(CreateSamples);
        CreateEicarCommand = new RelayCommand(CreateEicar);
        ResetDefaultsCommand = new RelayCommand(ResetDefaults);
        RefreshDefenderCommand = Defender.RefreshCommand;
        DismissSaveErrorCommand = new RelayCommand(() => HasSaveError = false);

        _services.SettingsChanged += (_, _) => RaiseSettings();
    }

    public DefenderStatusViewModel Defender { get; }
    public ObservableCollection<DetectionRuleViewModel> Rules { get; }

    public RelayCommand OpenDataFolderCommand { get; }
    public RelayCommand OpenQuarantineFolderCommand { get; }
    public RelayCommand OpenLogFolderCommand { get; }
    public RelayCommand OpenWindowsSecurityCommand { get; }
    public RelayCommand CreateSamplesCommand { get; }
    public RelayCommand CreateEicarCommand { get; }
    public RelayCommand ResetDefaultsCommand { get; }
    public AsyncRelayCommand RefreshDefenderCommand { get; }
    public RelayCommand DismissSaveErrorCommand { get; }

    public AppTheme Theme
    {
        get => _services.Settings.Theme;
        set
        {
            if (value == Theme) return;
            Save(settings => settings with { Theme = value });
            OnPropertyChanged();
        }
    }

    public bool LoggingEnabled
    {
        get => _services.Settings.LoggingEnabled;
        set
        {
            if (value == LoggingEnabled) return;
            Save(settings => settings with { LoggingEnabled = value });
            OnPropertyChanged();
        }
    }

    public bool MinimizeToTray
    {
        get => _services.Settings.MinimizeToTray;
        set
        {
            if (value == MinimizeToTray) return;
            Save(settings => settings with { MinimizeToTray = value });
            OnPropertyChanged();
        }
    }

    public bool ShowTrayNotifications
    {
        get => _services.Settings.ShowTrayNotifications;
        set
        {
            if (value == ShowTrayNotifications) return;
            Save(settings => settings with { ShowTrayNotifications = value });
            OnPropertyChanged();
        }
    }

    public bool RealtimeProtectionEnabled
    {
        get => _services.Settings.RealtimeProtectionEnabled;
        set
        {
            if (value == RealtimeProtectionEnabled) return;
            Save(settings => settings with { RealtimeProtectionEnabled = value });
            OnPropertyChanged();
            OnPropertyChanged(nameof(RealtimeStatusText));
        }
    }

    public bool RealtimeAutoQuarantine
    {
        get => _services.Settings.RealtimeAutoQuarantine;
        set
        {
            if (value == RealtimeAutoQuarantine) return;
            Save(settings => settings with { RealtimeAutoQuarantine = value });
            OnPropertyChanged();
        }
    }

    public string RealtimeStatusText => RealtimeProtectionEnabled
        ? "Watching Desktop, Documents and Downloads while Lumen runs."
        : "Paused. New and changed files are only checked during scans.";

    public double MaxInspectMegabytes
    {
        get => _services.Settings.MaxInspectMegabytes;
        set
        {
            var rounded = Math.Clamp((int)Math.Round(value), AppSettings.MinAllowedInspectMegabytes, AppSettings.MaxAllowedInspectMegabytes);
            if (rounded == _services.Settings.MaxInspectMegabytes) return;

            Save(settings => settings with { MaxInspectMegabytes = rounded });
            OnPropertyChanged();
            OnPropertyChanged(nameof(MaxInspectText), nameof(InspectLimitDetail));
        }
    }

    public string MaxInspectText => _services.Settings.MaxInspectMegabytes + " MB";

    public string InspectLimitDetail =>
        $"Lumen reads at most {_services.Settings.MaxInspectMegabytes} MB from the start of each file for content checks. " +
        "File-name rules still examine the full name. Contents are never uploaded or written to the log.";

    public string DataPathText => _services.SanitizePath(_services.DataDirectory);
    public string QuarantinePathText => _services.SanitizePath(_services.Paths.QuarantineDirectory);
    public string LogPathText => _services.SanitizePath(_services.Paths.LogDirectory);
    public string VersionText => "Version " + _services.Version;
    public string RulesCountText => $"{Rules.Count:N0} documented rules";
    public string SettingsNote => "Changes are saved automatically on this device.";

    public string AboutText =>
        "Lumen is a transparent, local file inspector. It runs on-demand scans and, when real-time protection is on, " +
        "re-checks new and changed files in your Desktop, Documents and Downloads folders while the app is open. " +
        "It does not install a driver, monitor system folders, upload files, or change Microsoft Defender settings. " +
        "Its rules are intentionally small and documented, so a clean result is not proof that a file is safe.";

    public bool HasSaveError
    {
        get => _hasSaveError;
        private set => SetProperty(ref _hasSaveError, value);
    }

    public string SaveErrorText
    {
        get => _saveErrorText;
        private set => SetProperty(ref _saveErrorText, value);
    }

    public void OnNavigatedTo()
    {
        RaiseSettings();
        _ = Defender.RefreshAsync(false);
    }

    private void Save(Func<AppSettings, AppSettings> update)
    {
        var result = _services.UpdateSettings(update);
        if (result.Ok)
        {
            HasSaveError = false;
            SaveErrorText = string.Empty;
            return;
        }

        SaveErrorText = result.Message ?? "The setting could not be saved.";
        HasSaveError = true;
    }

    private void RaiseSettings()
    {
        OnPropertyChanged(
            nameof(Theme),
            nameof(LoggingEnabled),
            nameof(MinimizeToTray),
            nameof(ShowTrayNotifications),
            nameof(RealtimeProtectionEnabled),
            nameof(RealtimeAutoQuarantine),
            nameof(RealtimeStatusText),
            nameof(MaxInspectMegabytes),
            nameof(MaxInspectText),
            nameof(InspectLimitDetail),
            nameof(DataPathText),
            nameof(QuarantinePathText),
            nameof(LogPathText));
    }

    private void OpenFolder(string path)
    {
        if (_services.OpenFolder(path)) return;
        SaveErrorText = "That folder could not be opened.";
        HasSaveError = true;
    }

    private void OpenWindowsSecurity()
    {
        if (_services.OpenWindowsSecurity()) return;
        _services.Dialogs.ShowMessage(
            "Windows Security could not be opened",
            "This system may not include the Windows Security app.",
            MessageSeverity.Info);
    }

    private void CreateSamples()
    {
        var folder = _services.Dialogs.PickFolder(
            "Choose a folder for harmless test files",
            Path.Combine(_services.UserProfile, "Documents"));
        if (string.IsNullOrWhiteSpace(folder)) return;

        var result = _services.TestFiles.CreateBenignSamples(folder);
        if (!result.Ok)
        {
            _services.Dialogs.ShowMessage("Test files could not be created", result.Message, MessageSeverity.Warning);
            return;
        }

        var details = string.Join(Environment.NewLine, result.Created.Select(_services.SanitizePath));
        var scanNow = _services.Dialogs.Confirm(
            "Harmless test files created",
            "The folder now contains plain-text files plus one deceptive double-extension name for testing Lumen's file-name rule. " +
            "None of them is executable or malicious. Do you want to open a folder scan for this location?",
            "Scan test folder",
            details: details);
        if (scanNow) _scanFolder(folder);
    }

    private void CreateEicar()
    {
        var proceed = _services.Dialogs.Confirm(
            "Create the EICAR test file?",
            "EICAR is a harmless, industry-standard antivirus test string, not malware. " +
            "Microsoft Defender may quarantine the file immediately and record an event. " +
            "Only create it in a folder you control, preferably inside a test VM.",
            "Create EICAR file",
            danger: true);
        if (!proceed) return;

        var folder = _services.Dialogs.PickFolder(
            "Choose a folder for the EICAR test file",
            Path.Combine(_services.UserProfile, "Documents"));
        if (string.IsNullOrWhiteSpace(folder)) return;

        var result = _services.TestFiles.CreateEicarSample(folder);
        if (!result.Ok)
        {
            _services.Dialogs.ShowMessage("EICAR test file could not be created", result.Message, MessageSeverity.Warning);
            return;
        }

        var scanNow = _services.Dialogs.Confirm(
            "EICAR test file created",
            "If Microsoft Defender did not remove the file, a Lumen scan should report the EICAR test signature. " +
            "This verifies scanner plumbing only and says nothing about real malware. Open a folder scan now?",
            "Scan test folder",
            details: string.Join(Environment.NewLine, result.Created.Select(_services.SanitizePath)));
        if (scanNow) _scanFolder(folder);
    }

    private void ResetDefaults()
    {
        var proceed = _services.Dialogs.Confirm(
            "Restore default settings?",
            "Theme, logging, tray behavior and content-inspection size will return to their defaults. " +
            "Scan history and quarantined files are not affected.",
            "Restore defaults");
        if (!proceed) return;

        var result = _services.UpdateSettings(_ => AppSettings.Default);
        if (!result.Ok)
        {
            SaveErrorText = result.Message ?? "Settings could not be restored.";
            HasSaveError = true;
            return;
        }

        RaiseSettings();
        HasSaveError = false;
    }
}
