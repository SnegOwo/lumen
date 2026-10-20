using System.Collections.ObjectModel;
using System.ComponentModel;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Localization;
using Lumen.App.Services;
using Lumen.Core.Detection;
using Lumen.Core.Models;

namespace Lumen.App.ViewModels;

/// <summary>
/// A group of detection rules that share a category.
/// </summary>
public sealed class DetectionRuleGroupViewModel
{
    /// <summary>Creates a group of rules.</summary>
    public DetectionRuleGroupViewModel(
        FindingCategory category,
        string label,
        string hint,
        IEnumerable<DetectionRuleViewModel> rules)
    {
        Category = category;
        Label = label;
        Hint = hint;
        Rules = new ObservableCollection<DetectionRuleViewModel>(rules);
    }

    /// <summary>The category the group stands for.</summary>
    public FindingCategory Category { get; }

    /// <summary>The name of the category.</summary>
    public string Label { get; }

    /// <summary>What a rule in this category means.</summary>
    public string Hint { get; }

    /// <summary>The rules in this category.</summary>
    public ObservableCollection<DetectionRuleViewModel> Rules { get; }
}

/// <summary>
/// The settings page: appearance, language, scanning, real-time protection,
/// remediation, alerts, the rule catalogue and the test tools.
/// </summary>
public sealed class SettingsViewModel : ObservableObject, IPageViewModel, IDisposable
{
    private readonly AppServices _services;
    private readonly Action<string> _scanFolder;
    private bool _hasSaveError;
    private string _saveErrorText = string.Empty;
    private bool _disposed;

    /// <summary>Creates the settings view model.</summary>
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
        AddWatchedFolderCommand = new RelayCommand(AddWatchedFolder);
        RemoveWatchedFolderCommand = new RelayCommand<string>(RemoveWatchedFolder);
        AddExcludedFolderCommand = new RelayCommand(AddExcludedFolder);
        RemoveExcludedFolderCommand = new RelayCommand<string>(RemoveExcludedFolder);

        Text.LanguageChanged += OnLanguageChanged;
        _services.SettingsChanged += OnServicesSettingsChanged;

        RaiseSettings();
        RebuildRuleGroups();
    }

    public DefenderStatusViewModel Defender { get; }

    /// <summary>Every rule Lumen can report.</summary>
    public ObservableCollection<DetectionRuleViewModel> Rules { get; }

    /// <summary>The same rules, grouped by category so that 51 entries stay readable.</summary>
    public ObservableCollection<DetectionRuleGroupViewModel> RuleGroups { get; } = [];

    public RelayCommand OpenDataFolderCommand { get; }
    public RelayCommand OpenQuarantineFolderCommand { get; }
    public RelayCommand OpenLogFolderCommand { get; }
    public RelayCommand OpenWindowsSecurityCommand { get; }
    public RelayCommand CreateSamplesCommand { get; }
    public RelayCommand CreateEicarCommand { get; }
    public RelayCommand ResetDefaultsCommand { get; }
    public AsyncRelayCommand RefreshDefenderCommand { get; }
    public RelayCommand DismissSaveErrorCommand { get; }

    /// <summary>Adds a folder to the real-time watch list.</summary>
    public RelayCommand AddWatchedFolderCommand { get; }

    /// <summary>Removes a folder from the real-time watch list.</summary>
    public RelayCommand<string> RemoveWatchedFolderCommand { get; }

    /// <summary>Adds a folder to the real-time exclusion list.</summary>
    public RelayCommand AddExcludedFolderCommand { get; }

    /// <summary>Removes a folder from the real-time exclusion list.</summary>
    public RelayCommand<string> RemoveExcludedFolderCommand { get; }

    /// <summary>The theme the user picked.</summary>
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

    /// <summary>The interface language.</summary>
    public AppLanguage Language
    {
        get => _services.Settings.Language;
        set
        {
            if (value == Language) return;
            Save(settings => settings with { Language = value });
            Text.Set(value);
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

    /// <summary>
    /// Aggressive mode: the extra detection rules, the folders a dropper lands in,
    /// no waiting before an inspection, and the automatic quarantine of a
    /// high-confidence match.
    /// </summary>
    public bool AggressiveMode
    {
        get => _services.Settings.AggressiveMode;
        set
        {
            if (value == AggressiveMode) return;
            Save(settings => settings with { AggressiveMode = value });
            OnPropertyChanged();
        }
    }

    /// <summary>
    /// How long the real-time monitor waits for a file to stop changing before it
    /// inspects it. Lower means a faster answer.
    /// </summary>
    public int RealtimeSettleDelayMs
    {
        get => _services.Settings.RealtimeSettleDelayMs;
        set
        {
            var clamped = Math.Clamp(value, 0, 2000);
            if (clamped == RealtimeSettleDelayMs) return;
            Save(settings => settings with { RealtimeSettleDelayMs = clamped });
            OnPropertyChanged();
            OnPropertyChanged(nameof(RealtimeSettleDelayText));
        }
    }

    /// <summary>The settle delay, shown in a form a person can read.</summary>
    public string RealtimeSettleDelayText =>
        RealtimeSettleDelayMs == 0
            ? Text.SettleDelayNone
            : Text.SettleDelayMs(RealtimeSettleDelayMs);

    /// <summary>
    /// How many files the real-time monitor may inspect at the same time. More workers
    /// mean a faster answer on a busy folder.
    /// </summary>
    public int RealtimeWorkerCount
    {
        get => _services.Settings.RealtimeWorkerCount;
        set
        {
            var clamped = Math.Clamp(value, 1, 8);
            if (clamped == RealtimeWorkerCount) return;
            Save(settings => settings with { RealtimeWorkerCount = clamped });
            OnPropertyChanged();
        }
    }

    /// <summary>
    /// Stop the processes that are using a file the real-time monitor flagged. It
    /// needs the remediation switch as well, and it never stops a protected process.
    /// </summary>
    public bool RealtimeAutoKill
    {
        get => _services.Settings.RealtimeAutoKill;
        set
        {
            if (value == RealtimeAutoKill) return;
            Save(settings => settings with { RealtimeAutoKill = value });
            OnPropertyChanged();
        }
    }

    /// <summary>
    /// How long Lumen stays quiet about a file it has already raised the alert for.
    /// </summary>
    public int AlertCooldownSeconds
    {
        get => _services.Settings.AlertCooldownSeconds;
        set
        {
            var clamped = Math.Clamp(value, 0, 3600);
            if (clamped == AlertCooldownSeconds) return;
            Save(settings => settings with { AlertCooldownSeconds = clamped });
            OnPropertyChanged();
            OnPropertyChanged(nameof(AlertCooldownText));
        }
    }

    /// <summary>The alert cooldown, shown in a form a person can read.</summary>
    public string AlertCooldownText =>
        AlertCooldownSeconds == 0
            ? Text.AlertCooldownAlways
            : Text.AlertCooldownMinutes(Math.Max(1, AlertCooldownSeconds / 60));

    public bool RealtimeAutoQuarantine
    {
        get => _services.Settings.RealtimeAutoQuarantine;
        set        {
            if (value == RealtimeAutoQuarantine) return;
            Save(settings => settings with { RealtimeAutoQuarantine = value });
            OnPropertyChanged();
        }
    }

    public string RealtimeStatusText => RealtimeProtectionEnabled
        ? Text.SettingsRealtimeOnBody
        : Text.SettingsRealtimeOffBody;

    /// <summary>
    /// The master switch for the remediation engine. It is off by default: with it off,
    /// Lumen can only detect and quarantine.
    /// </summary>
    public bool RemediationEnabled
    {
        get => _services.Settings.RemediationEnabled;
        set
        {
            if (value == RemediationEnabled) return;
            Save(settings => settings with { RemediationEnabled = value });
            OnPropertyChanged();
        }
    }

    /// <summary>Whether the full-screen detection alert is shown.</summary>
    public bool DetectionAlertEnabled
    {
        get => _services.Settings.DetectionAlertEnabled;
        set
        {
            if (value == DetectionAlertEnabled) return;
            Save(settings => settings with { DetectionAlertEnabled = value });
            OnPropertyChanged();
        }
    }

    /// <summary>Whether the detection alert plays a sound.</summary>
    public bool DetectionAlertSoundEnabled
    {
        get => _services.Settings.DetectionAlertSoundEnabled;
        set
        {
            if (value == DetectionAlertSoundEnabled) return;
            Save(settings => settings with { DetectionAlertSoundEnabled = value });
            OnPropertyChanged();
        }
    }

    /// <summary>Whether the detection alert draws the cat.</summary>
    public bool DetectionAlertCatEnabled
    {
        get => _services.Settings.DetectionAlertCatEnabled;
        set
        {
            if (value == DetectionAlertCatEnabled) return;
            Save(settings => settings with { DetectionAlertCatEnabled = value });
            OnPropertyChanged();
        }
    }

    /// <summary>The folders the real-time monitor watches, on top of the standard ones.</summary>
    public ObservableCollection<string> WatchedFolders { get; } = [];

    /// <summary>The folders the real-time monitor skips.</summary>
    public ObservableCollection<string> ExcludedFolders { get; } = [];

    /// <summary>True when no extra folder is watched.</summary>
    public bool HasNoWatchedFolders => WatchedFolders.Count == 0;

    /// <summary>True when no folder is excluded.</summary>
    public bool HasNoExcludedFolders => ExcludedFolders.Count == 0;

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

    public string InspectLimitDetail => Text.SettingsInspectLimit(_services.Settings.MaxInspectMegabytes);

    public string DataPathText => _services.SanitizePath(_services.DataDirectory);
    public string QuarantinePathText => _services.SanitizePath(_services.Paths.QuarantineDirectory);
    public string LogPathText => _services.SanitizePath(_services.Paths.LogDirectory);
    public string VersionText => Text.SettingsVersion(_services.Version);
    public string RulesCountText => Text.SettingsRulesCount(Rules.Count);

    /// <summary>The "about" paragraph.</summary>
    public string AboutText => Text.SettingsAboutBody;

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

        SaveErrorText = result.Message ?? Text.SettingsSaveFailed;
        HasSaveError = true;
    }

    private void RaiseSettings()
    {
        OnPropertyChanged(
            nameof(Theme),
            nameof(Language),
            nameof(LoggingEnabled),
            nameof(MinimizeToTray),
            nameof(ShowTrayNotifications),
            nameof(RealtimeProtectionEnabled),
            nameof(RealtimeAutoQuarantine),
            nameof(RealtimeSettleDelayMs),
            nameof(RealtimeSettleDelayText),
            nameof(RealtimeWorkerCount),
            nameof(RealtimeAutoKill),
            nameof(AlertCooldownSeconds),
            nameof(AlertCooldownText),
            nameof(AggressiveMode),
            nameof(RealtimeStatusText),
            nameof(RemediationEnabled),
            nameof(DetectionAlertEnabled),
            nameof(DetectionAlertSoundEnabled),
            nameof(DetectionAlertCatEnabled),
            nameof(MaxInspectMegabytes),
            nameof(MaxInspectText),
            nameof(InspectLimitDetail),
            nameof(DataPathText),
            nameof(QuarantinePathText),
            nameof(LogPathText),
            nameof(VersionText),
            nameof(RulesCountText),
            nameof(AboutText));

        RefreshFolderLists();
    }

    private void RefreshFolderLists()
    {
        SyncFolderList(WatchedFolders, _services.Settings.RealtimeWatchFolders);
        SyncFolderList(ExcludedFolders, _services.Settings.RealtimeExcludedFolders);
        OnPropertyChanged(nameof(HasNoWatchedFolders), nameof(HasNoExcludedFolders));
    }

    private static void SyncFolderList(ObservableCollection<string> target, IReadOnlyList<string> source)
    {
        target.Clear();
        foreach (var folder in source) target.Add(folder);
    }

    private void AddWatchedFolder()
    {
        var folder = _services.Dialogs.PickFolder(
            Text.SettingsPickWatchedTitle,
            _services.UserProfile);
        if (string.IsNullOrWhiteSpace(folder)) return;

        var current = _services.Settings.RealtimeWatchFolders.ToList();
        if (current.Contains(folder, StringComparer.OrdinalIgnoreCase)) return;

        current.Add(folder);
        Save(settings => settings with { RealtimeWatchFolders = current });
        RefreshFolderLists();
    }

    private void RemoveWatchedFolder(string? folder)
    {
        if (string.IsNullOrWhiteSpace(folder)) return;

        var current = _services.Settings.RealtimeWatchFolders
            .Where(candidate => !string.Equals(candidate, folder, StringComparison.OrdinalIgnoreCase))
            .ToList();

        Save(settings => settings with { RealtimeWatchFolders = current });
        RefreshFolderLists();
    }

    private void AddExcludedFolder()
    {
        var folder = _services.Dialogs.PickFolder(
            Text.SettingsPickExcludedTitle,
            _services.UserProfile);
        if (string.IsNullOrWhiteSpace(folder)) return;

        var current = _services.Settings.RealtimeExcludedFolders.ToList();
        if (current.Contains(folder, StringComparer.OrdinalIgnoreCase)) return;

        current.Add(folder);
        Save(settings => settings with { RealtimeExcludedFolders = current });
        RefreshFolderLists();
    }

    private void RemoveExcludedFolder(string? folder)
    {
        if (string.IsNullOrWhiteSpace(folder)) return;

        var current = _services.Settings.RealtimeExcludedFolders
            .Where(candidate => !string.Equals(candidate, folder, StringComparison.OrdinalIgnoreCase))
            .ToList();

        Save(settings => settings with { RealtimeExcludedFolders = current });
        RefreshFolderLists();
    }

    private void OpenFolder(string path)
    {
        if (_services.OpenFolder(path)) return;
        SaveErrorText = Text.SettingsFolderFailed;
        HasSaveError = true;
    }

    private void OpenWindowsSecurity()
    {
        if (_services.OpenWindowsSecurity()) return;
        _services.Dialogs.ShowMessage(
            Text.WindowsSecurityFailedTitle,
            Text.WindowsSecurityFailedBodyShort,
            MessageSeverity.Info);
    }

    private void CreateSamples()
    {
        var folder = _services.Dialogs.PickFolder(
            Text.SamplesFolderTitle,
            Path.Combine(_services.UserProfile, "Documents"));
        if (string.IsNullOrWhiteSpace(folder)) return;

        var result = _services.TestFiles.CreateBenignSamples(folder);
        if (!result.Ok)
        {
            _services.Dialogs.ShowMessage(Text.SamplesFailedTitle, result.Message, MessageSeverity.Warning);
            return;
        }

        var details = string.Join(Environment.NewLine, result.Created.Select(_services.SanitizePath));
        var scanNow = _services.Dialogs.Confirm(
            Text.SamplesCreatedTitle,
            Text.SamplesCreatedBody,
            Text.SamplesCreatedConfirm,
            details: details);
        if (scanNow) _scanFolder(folder);
    }

    private void CreateEicar()
    {
        var proceed = _services.Dialogs.Confirm(
            Text.EicarCreateTitle,
            Text.EicarCreateBody,
            Text.EicarCreateConfirm,
            danger: true);
        if (!proceed) return;

        var folder = _services.Dialogs.PickFolder(
            Text.EicarFolderTitle,
            Path.Combine(_services.UserProfile, "Documents"));
        if (string.IsNullOrWhiteSpace(folder)) return;

        var result = _services.TestFiles.CreateEicarSample(folder);
        if (!result.Ok)
        {
            _services.Dialogs.ShowMessage(Text.EicarFailedTitle, result.Message, MessageSeverity.Warning);
            return;
        }

        var scanNow = _services.Dialogs.Confirm(
            Text.EicarCreatedTitle,
            Text.EicarCreatedBody,
            Text.SamplesCreatedConfirm,
            details: string.Join(Environment.NewLine, result.Created.Select(_services.SanitizePath)));
        if (scanNow) _scanFolder(folder);
    }

    private void ResetDefaults()
    {
        var proceed = _services.Dialogs.Confirm(
            Text.SettingsResetTitle,
            Text.SettingsResetBody,
            Text.SettingsResetConfirm);
        if (!proceed) return;

        var result = _services.UpdateSettings(_ => AppSettings.Default);
        if (!result.Ok)
        {
            SaveErrorText = result.Message ?? Text.SettingsSaveFailed;
            HasSaveError = true;
            return;
        }

        Text.Set(_services.Language);
        RaiseSettings();
        RebuildRuleGroups();
        HasSaveError = false;
    }

    /// <summary>
    /// Rebuilds the category groups of the rule catalogue. With 51 rules a flat list is
    /// hard to scan, so the rules are grouped by the kind of signal they use.
    /// </summary>
    private void RebuildRuleGroups()
    {
        RuleGroups.Clear();

        foreach (var category in new[]
                 {
                     FindingCategory.TestSignature,
                     FindingCategory.Signature,
                     FindingCategory.Behavior,
                     FindingCategory.Heuristic,
                     FindingCategory.Reputation
                 })
        {
            var rules = Rules.Where(rule => rule.Source.Category == category).ToArray();
            if (rules.Length == 0) continue;

            RuleGroups.Add(new DetectionRuleGroupViewModel(
                category,
                Presentation.Category(category),
                Presentation.CategoryHint(category),
                rules));
        }
    }

    private void OnServicesSettingsChanged(object? sender, EventArgs e) => RaiseSettings();

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(
            nameof(RulesCountText),
            nameof(InspectLimitDetail),
            nameof(VersionText),
            nameof(AboutText));

        RebuildRuleGroups();
    }

    /// <summary>Unsubscribes from the events this view model listens to.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Text.LanguageChanged -= OnLanguageChanged;
        _services.SettingsChanged -= OnServicesSettingsChanged;
        Defender.Dispose();
    }
}
