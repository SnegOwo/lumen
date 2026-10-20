using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Localization;
using Lumen.App.Remediation;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Quarantine;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

/// <summary>
/// One of the four scan scopes, shown as a choice card.
/// </summary>
public sealed class ScanScopeOptionViewModel : ObservableObject
{
    private readonly Action<ScanScopeKind> _select;
    private bool _isSelected;

    /// <summary>Creates a scope option.</summary>
    public ScanScopeOptionViewModel(
        ScanScopeKind scope,
        string title,
        string body,
        string glyph,
        string automationName,
        Action<ScanScopeKind> select)
    {
        Scope = scope;
        Title = title;
        Body = body;
        Glyph = glyph;
        AutomationName = automationName;
        _select = select;
    }

    /// <summary>The scope this card stands for.</summary>
    public ScanScopeKind Scope { get; }

    /// <summary>The card title.</summary>
    public string Title { get; }

    /// <summary>The one-line explanation under the title.</summary>
    public string Body { get; }

    /// <summary>The icon glyph.</summary>
    public string Glyph { get; }

    /// <summary>The accessible name of the card.</summary>
    public string AutomationName { get; }

    /// <summary>True when this scope is the selected one.</summary>
    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (!SetProperty(ref _isSelected, value)) return;
            if (value) _select(Scope);
        }
    }

    /// <summary>Rebuilds the wording after the interface language changed.</summary>
    public void Refresh()
    {
        OnPropertyChanged(nameof(Title), nameof(Body), nameof(AutomationName));
    }
}

/// <summary>
/// The scan page: scope selection, the live progress strip and the results.
/// </summary>
public sealed class ScanViewModel : ObservableObject, IPageViewModel, IDisposable
{
    private const int MaxDetailsInConfirm = 8;
    private const int MaxFailedDetails = 12;

    private readonly AppServices _services;
    private readonly RemediationCoordinator _remediation;
    private readonly DispatcherTimer _timer;
    private readonly Stopwatch _stopwatch = new();
    private readonly HashSet<string> _detectionPaths = new(StringComparer.OrdinalIgnoreCase);

    private ScanScopeKind _scope = ScanScopeKind.Quick;
    private string? _selectedFolder;
    private string? _selectedFile;
    private bool _isScanning;
    private bool _isCancelling;
    private bool _isQuarantining;
    private bool _hasCompleted;
    private long _filesScanned;
    private long _filesSkipped;
    private long _errorCount;
    private long _detectionCount;
    private string _phaseText = string.Empty;
    private string _currentFileDisplay = string.Empty;
    private string _elapsedText = "0s";
    private bool _isErrorsExpanded;
    private bool _updatingSelection;
    private DetectionItemViewModel? _selectedDetection;
    private bool _hasSummary;
    private string _summaryTitle = string.Empty;
    private string _summaryMessage = string.Empty;
    private MessageSeverity _summarySeverity = MessageSeverity.Info;
    private bool _hasAction;
    private string _actionTitle = string.Empty;
    private string _actionMessage = string.Empty;
    private MessageSeverity _actionSeverity = MessageSeverity.Info;
    private CancellationTokenSource? _cts;
    private string? _lastScanId;
    private bool _isRemediationEnabled;
    private bool _updatingScopeSelection;

    private double _quarantineProgress;
    private string _quarantineCurrentFile = string.Empty;
    private long _quarantineTotalBytes;
    private long _quarantineCompletedBytes;
    private bool _disposed;

    /// <summary>Creates the scan view model.</summary>
    public ScanViewModel(AppServices services)
    {
        _services = services;
        _remediation = new RemediationCoordinator(services);
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _timer.Tick += (_, _) =>
        {
            if (_stopwatch.IsRunning) ElapsedText = TimeFormatter.Duration(_stopwatch.Elapsed);
        };

        StartScanCommand = new AsyncRelayCommand(StartScanAsync, () => CanStartScan);
        CancelScanCommand = new RelayCommand(CancelScan, () => IsScanning && !IsCancelling);
        BrowseCommand = new RelayCommand(Browse, () => CanBrowse);
        QuarantineSelectedCommand = new AsyncRelayCommand(
            QuarantineSelectedAsync,
            () => HasSelection && !IsScanning && !IsQuarantining);
        CleanSelectedCommand = new AsyncRelayCommand(
            CleanSelectedAsync,
            () => HasSelection && IsRemediationEnabled && !IsScanning && !IsQuarantining);
        ToggleErrorsCommand = new RelayCommand(
            () => IsErrorsExpanded = !IsErrorsExpanded,
            () => Errors.Count > 0);
        CopySelectedPathCommand = new RelayCommand(CopySelectedPath, () => SelectedDetection is not null);
        RevealSelectedCommand = new RelayCommand(RevealSelected, () => SelectedDetection is not null);
        ClearResultsCommand = new RelayCommand(ClearResults, () => HasCompleted && !IsScanning && !IsQuarantining);
        DismissActionCommand = new RelayCommand(() => HasAction = false);

        ScopeOptions =
        [
            new ScanScopeOptionViewModel(
                ScanScopeKind.Quick,
                Text.ScanScopeQuickTitle,
                Text.ScanScopeQuickBody,
                "\uE721",
                Text.ScanScopeQuickName,
                SelectScopeFromOption),
            new ScanScopeOptionViewModel(
                ScanScopeKind.FullUserProfile,
                Text.ScanScopeFullTitle,
                Text.ScanScopeFullBody,
                "\uE77B",
                Text.ScanScopeFullName,
                SelectScopeFromOption),
            new ScanScopeOptionViewModel(
                ScanScopeKind.Folder,
                Text.ScanScopeFolderTitle,
                Text.ScanScopeFolderBody,
                "\uE8B7",
                Text.ScanScopeFolderName,
                SelectScopeFromOption),
            new ScanScopeOptionViewModel(
                ScanScopeKind.File,
                Text.ScanScopeFileTitle,
                Text.ScanScopeFileBody,
                "\uE7C3",
                Text.ScanScopeFileName,
                SelectScopeFromOption)
        ];

        _phaseText = Text.ScanPhaseReady;
        _isRemediationEnabled = services.Settings.RemediationEnabled;

        services.SettingsChanged += OnServicesSettingsChanged;
        Text.LanguageChanged += OnLanguageChanged;

        UpdateScopeSelection();
    }

    public ObservableCollection<DetectionItemViewModel> Detections { get; } = [];
    public ObservableCollection<ScanErrorItemViewModel> Errors { get; } = [];

    /// <summary>The four scope cards, rendered from one reusable template.</summary>
    public ObservableCollection<ScanScopeOptionViewModel> ScopeOptions { get; }

    public AsyncRelayCommand StartScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand BrowseCommand { get; }
    public AsyncRelayCommand QuarantineSelectedCommand { get; }

    /// <summary>
    /// Cleans up the selected findings. It is only enabled when the user allowed
    /// remediation actions in Settings, and even then it only produces a plan.
    /// </summary>
    public AsyncRelayCommand CleanSelectedCommand { get; }

    public RelayCommand ToggleErrorsCommand { get; }
    public RelayCommand CopySelectedPathCommand { get; }
    public RelayCommand RevealSelectedCommand { get; }
    public RelayCommand ClearResultsCommand { get; }
    public RelayCommand DismissActionCommand { get; }

    public ScanScopeKind Scope
    {
        get => _scope;
        set
        {
            if (!SetProperty(ref _scope, value)) return;
            OnPropertyChanged(
                nameof(IsCustomScope),
                nameof(SelectedPathDisplay),
                nameof(ScopeDescription),
                nameof(CanStartScan),
                nameof(CanBrowse));
            UpdateScopeSelection();
            RaiseCommandStates();
        }
    }

    public string? SelectedFolder
    {
        get => _selectedFolder;
        set
        {
            if (!SetProperty(ref _selectedFolder, value)) return;
            PathSelectionChanged();
        }
    }

    public string? SelectedFile
    {
        get => _selectedFile;
        set
        {
            if (!SetProperty(ref _selectedFile, value)) return;
            PathSelectionChanged();
        }
    }

    /// <summary>True when the scope is a folder or a single file.</summary>
    public bool IsCustomScope => Scope is ScanScopeKind.Folder or ScanScopeKind.File;

    public string SelectedPathDisplay => Scope switch
    {
        ScanScopeKind.Quick => Text.ScanPathQuick,
        ScanScopeKind.FullUserProfile => Text.ScanPathFull,
        ScanScopeKind.Folder => string.IsNullOrWhiteSpace(SelectedFolder)
            ? Text.ScanPathNoFolder
            : Presentation.SanitizePath(SelectedFolder),
        _ => string.IsNullOrWhiteSpace(SelectedFile)
            ? Text.ScanPathNoFile
            : Presentation.SanitizePath(SelectedFile)
    };

    public string ScopeDescription => Scope switch
    {
        ScanScopeKind.Quick => Text.ScanScopeQuickDescription,
        ScanScopeKind.FullUserProfile => Text.ScanScopeFullDescription,
        ScanScopeKind.Folder => Text.ScanScopeFolderDescription,
        _ => Text.ScanScopeFileDescription
    };

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (!SetProperty(ref _isScanning, value)) return;
            OnPropertyChanged(nameof(IsNotScanning), nameof(ScanButtonText), nameof(CanStartScan), nameof(CanBrowse));
            RaiseCommandStates();
        }
    }

    public bool IsNotScanning => !IsScanning;

    public bool IsCancelling
    {
        get => _isCancelling;
        private set
        {
            if (!SetProperty(ref _isCancelling, value)) return;
            OnPropertyChanged(nameof(CancelButtonText), nameof(CanCancel));
            RaiseCommandStates();
        }
    }

    public bool CanCancel => IsScanning && !IsCancelling;

    public bool IsQuarantining
    {
        get => _isQuarantining;
        private set
        {
            if (!SetProperty(ref _isQuarantining, value)) return;
            OnPropertyChanged(nameof(CanStartScan), nameof(CanBrowse), nameof(HasQuarantineProgress));
            RaiseCommandStates();
        }
    }

    public bool CanStartScan => !IsScanning && !IsQuarantining && Scope switch
    {
        ScanScopeKind.Quick or ScanScopeKind.FullUserProfile => true,
        ScanScopeKind.Folder => !string.IsNullOrWhiteSpace(SelectedFolder),
        _ => !string.IsNullOrWhiteSpace(SelectedFile)
    };

    public bool CanBrowse => IsCustomScope && !IsScanning && !IsQuarantining;

    public string ScanButtonText => IsScanning ? Text.ScanRunning : Text.ScanStart;
    public string CancelButtonText => IsCancelling ? Text.ScanCancelling : Text.ScanCancel;

    public long FilesScanned
    {
        get => _filesScanned;
        private set
        {
            if (SetProperty(ref _filesScanned, value)) OnPropertyChanged(nameof(FilesScannedText));
        }
    }

    public string FilesScannedText => _filesScanned.ToString("N0");

    /// <summary>
    /// The files that were deliberately not inspected, for example because they were
    /// links, cloud placeholders or outside the inspected prefix.
    /// </summary>
    public long FilesSkipped
    {
        get => _filesSkipped;
        private set
        {
            if (SetProperty(ref _filesSkipped, value)) OnPropertyChanged(nameof(FilesSkippedText));
        }
    }

    public string FilesSkippedText => _filesSkipped.ToString("N0");

    /// <summary>The items that could not be inspected at all.</summary>
    public long ErrorCount
    {
        get => _errorCount;
        private set
        {
            if (SetProperty(ref _errorCount, value)) OnPropertyChanged(nameof(ErrorCountText));
        }
    }

    public string ErrorCountText => _errorCount.ToString("N0");

    public long DetectionCount
    {
        get => _detectionCount;
        private set
        {
            if (!SetProperty(ref _detectionCount, value)) return;
            OnPropertyChanged(
                nameof(DetectionCountText),
                nameof(HasFindings),
                nameof(HasNoFindings),
                nameof(FindingsCaption));
        }
    }

    public string DetectionCountText => _detectionCount.ToString("N0");
    public string FindingsCaption => Text.FindingCaption(_detectionCount);
    public bool HasFindings => _detectionCount > 0;
    public bool HasNoFindings => HasCompleted && _detectionCount == 0;

    /// <summary>The phase of the running scan.</summary>
    public string PhaseText
    {
        get => _phaseText;
        private set => SetProperty(ref _phaseText, value);
    }

    /// <summary>The file that is being inspected right now.</summary>
    public string CurrentFileDisplay
    {
        get => _currentFileDisplay;
        private set => SetProperty(ref _currentFileDisplay, value);
    }

    public string ElapsedText
    {
        get => _elapsedText;
        private set => SetProperty(ref _elapsedText, value);
    }

    public bool HasCompleted
    {
        get => _hasCompleted;
        private set
        {
            if (!SetProperty(ref _hasCompleted, value)) return;
            OnPropertyChanged(nameof(HasNoFindings));
            RaiseCommandStates();
        }
    }

    public bool IsErrorsExpanded
    {
        get => _isErrorsExpanded;
        set
        {
            if (!SetProperty(ref _isErrorsExpanded, value)) return;
            OnPropertyChanged(nameof(ErrorsToggleText));
        }
    }

    public string ErrorsToggleText => IsErrorsExpanded
        ? Text.ScanHideSkipped
        : Text.ScanShowSkipped(Errors.Count);

    public DetectionItemViewModel? SelectedDetection
    {
        get => _selectedDetection;
        set
        {
            if (!SetProperty(ref _selectedDetection, value)) return;
            OnPropertyChanged(nameof(HasSelectedDetection));
            CopySelectedPathCommand.RaiseCanExecuteChanged();
            RevealSelectedCommand.RaiseCanExecuteChanged();
        }
    }

    public bool HasSelectedDetection => SelectedDetection is not null;

    public bool HasSelection => Detections.Any(item => item.IsSelected);
    public int SelectedCount => Detections.Count(item => item.IsSelected);

    public string QuarantineButtonText => SelectedCount switch
    {
        0 => Text.ScanQuarantineNone,
        1 => Text.ScanQuarantineOne,
        _ => Text.ScanQuarantineMany(SelectedCount)
    };

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

    public bool AreAllSelected
    {
        get => Detections.Count > 0 && Detections.All(item => item.IsSelected);
        set
        {
            if (Detections.Count == 0) return;
            if (!value && !HasSelection) return;

            _updatingSelection = true;
            try
            {
                foreach (var item in Detections) item.IsSelected = value;
            }
            finally
            {
                _updatingSelection = false;
            }

            RaiseSelectionProperties();
        }
    }

    public bool HasSummary
    {
        get => _hasSummary;
        private set => SetProperty(ref _hasSummary, value);
    }

    public string SummaryTitle
    {
        get => _summaryTitle;
        private set => SetProperty(ref _summaryTitle, value);
    }

    public string SummaryMessage
    {
        get => _summaryMessage;
        private set => SetProperty(ref _summaryMessage, value);
    }

    public MessageSeverity SummarySeverity
    {
        get => _summarySeverity;
        private set => SetProperty(ref _summarySeverity, value);
    }

    public bool HasAction
    {
        get => _hasAction;
        private set => SetProperty(ref _hasAction, value);
    }

    public string ActionTitle
    {
        get => _actionTitle;
        private set => SetProperty(ref _actionTitle, value);
    }

    public string ActionMessage
    {
        get => _actionMessage;
        private set => SetProperty(ref _actionMessage, value);
    }

    public MessageSeverity ActionSeverity
    {
        get => _actionSeverity;
        private set => SetProperty(ref _actionSeverity, value);
    }

    // ----------------------------------------------------------------------
    // Quarantine progress
    // ----------------------------------------------------------------------

    /// <summary>True while files are being encrypted into the vault.</summary>
    public bool HasQuarantineProgress => IsQuarantining;

    /// <summary>The determinate progress of the running quarantine, from 0 to 1.</summary>
    public double QuarantineProgress
    {
        get => _quarantineProgress;
        private set => SetProperty(ref _quarantineProgress, value);
    }

    /// <summary>The file that is being encrypted right now.</summary>
    public string QuarantineCurrentFile
    {
        get => _quarantineCurrentFile;
        private set => SetProperty(ref _quarantineCurrentFile, value);
    }

    /// <summary>The progress of the running quarantine, as a percentage.</summary>
    public string QuarantineProgressText
    {
        get => _quarantineTotalBytes <= 0
            ? string.Empty
            : (QuarantineProgress * 100).ToString("N0") + "%";
    }

    public void OnNavigatedTo()
    {
        // Scan state intentionally survives navigation so a running scan is never lost.
    }

    public void SetScope(ScanScopeKind scope) => Scope = scope;

    public void CancelScan()
    {
        if (!IsScanning || IsCancelling) return;

        IsCancelling = true;
        PhaseText = Text.ScanPhaseCancelling;
        try
        {
            _cts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The scan finished at the same moment.
        }
    }

    private void SelectScopeFromOption(ScanScopeKind scope)
    {
        if (_updatingScopeSelection) return;
        if (Scope != scope) Scope = scope;
    }

    private void UpdateScopeSelection()
    {
        _updatingScopeSelection = true;
        try
        {
            foreach (var option in ScopeOptions) option.IsSelected = option.Scope == Scope;
        }
        finally
        {
            _updatingScopeSelection = false;
        }
    }

    private void PathSelectionChanged()
    {
        OnPropertyChanged(
            nameof(SelectedPathDisplay),
            nameof(CanStartScan),
            nameof(CanBrowse));
        RaiseCommandStates();
    }

    private void Browse()
    {
        if (!CanBrowse) return;

        if (Scope == ScanScopeKind.Folder)
        {
            var folder = _services.Dialogs.PickFolder(
                Text.ScanScopeFolderName,
                SelectedFolder ?? _services.UserProfile);
            if (!string.IsNullOrWhiteSpace(folder)) SelectedFolder = folder;
            return;
        }

        var startFolder = SelectedFile is not null
            ? Path.GetDirectoryName(SelectedFile)
            : _services.UserProfile;
        var file = _services.Dialogs.PickFile(Text.ScanScopeFileName, startFolder);
        if (!string.IsNullOrWhiteSpace(file)) SelectedFile = file;
    }

    private ScanRequest BuildRequest()
    {
        var planner = _services.CreatePlanner();
        return Scope switch
        {
            ScanScopeKind.Quick => planner.CreateQuick(),
            ScanScopeKind.FullUserProfile => planner.CreateFullProfile(),
            ScanScopeKind.Folder => planner.CreateFolder(SelectedFolder ?? string.Empty),
            _ => planner.CreateFile(SelectedFile ?? string.Empty)
        };
    }

    private async Task StartScanAsync()
    {
        if (!CanStartScan) return;

        ScanRequest request;
        try
        {
            request = BuildRequest();
        }
        catch (ArgumentException ex)
        {
            _services.Dialogs.ShowMessage(Text.ScanChooseLocation, ex.Message, MessageSeverity.Warning);
            return;
        }

        if (request.Roots.Count == 0)
        {
            _services.Dialogs.ShowMessage(
                Text.ScanNoStandardFolders,
                Text.ScanNoStandardFoldersBody,
                MessageSeverity.Info);
            Scope = ScanScopeKind.Folder;
            Browse();
            return;
        }

        var critical = request.Roots.FirstOrDefault(PathRules.IsSystemCritical);
        if (critical is not null)
        {
            var proceed = _services.Dialogs.Confirm(
                Text.ScanProtectedLocationTitle,
                Text.ScanProtectedLocationBody,
                Text.ScanProtectedLocationConfirm,
                danger: true,
                details: Text.ScanLocationPrefix + Presentation.SanitizePath(critical));
            if (!proceed) return;
        }

        var network = request.Roots.FirstOrDefault(PathRules.IsNetworkPath);
        if (network is not null)
        {
            var proceed = _services.Dialogs.Confirm(
                Text.ScanNetworkLocationTitle,
                Text.ScanNetworkLocationBody,
                Text.ScanNetworkLocationConfirm,
                details: Text.ScanLocationPrefix + Presentation.SanitizePath(network));
            if (!proceed) return;
        }

        ResetResults();
        IsScanning = true;
        IsCancelling = false;
        IsQuarantining = false;
        HasCompleted = false;
        PhaseText = Text.ScanPhasePreparing;
        CurrentFileDisplay = Text.ScanWaitingForFile;
        _stopwatch.Restart();
        _timer.Start();
        _services.Tray?.SetStatus("scanning…");
        _cts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<ScanProgress>(OnProgress);
            var outcome = await _services.ScanEngine.ScanAsync(request, progress, _cts.Token);
            ApplyOutcome(outcome);
        }
        catch (OperationCanceledException)
        {
            HasCompleted = true;
            PhaseText = Text.ScanPhaseCancelled;
            SummaryTitle = Text.ScanSummaryCancelled;
            SummaryMessage = Text.ScanSummaryCancelledBody;
            SummarySeverity = MessageSeverity.Warning;
            HasSummary = true;
        }
        catch (Exception ex)
        {
            _services.Log.Error("Scan", "The scan could not be completed.", ex);
            HasCompleted = true;
            PhaseText = Text.ScanPhaseFailed;
            SummaryTitle = Text.ScanSummaryFailed;
            SummaryMessage = Text.ScanSummaryFailedBody;
            SummarySeverity = MessageSeverity.Danger;
            HasSummary = true;
        }
        finally
        {
            _stopwatch.Stop();
            _timer.Stop();
            ElapsedText = TimeFormatter.Duration(_stopwatch.Elapsed);
            IsCancelling = false;
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;
            _services.Tray?.SetStatus(null);
        }
    }

    private void OnProgress(ScanProgress progress)
    {
        FilesScanned = progress.FilesScanned;
        FilesSkipped = progress.FilesSkipped;
        ErrorCount = progress.ErrorCount;
        DetectionCount = progress.DetectionCount;
        ElapsedText = TimeFormatter.Duration(progress.Elapsed);
        PhaseText = progress.Phase switch
        {
            ScanPhase.Enumerating => Text.ScanPhaseEnumerating,
            ScanPhase.Inspecting => Text.ScanPhaseInspecting,
            _ => Text.ScanPhaseFinishing
        };
        CurrentFileDisplay = string.IsNullOrWhiteSpace(progress.CurrentFile)
            ? Text.ScanPhasePreparingList
            : Presentation.SanitizePath(progress.CurrentFile);

        foreach (var detection in progress.NewDetections) AddDetection(detection);
    }

    private void AddDetection(ScanDetection detection)
    {
        if (!_detectionPaths.Add(detection.FilePath)) return;

        var item = new DetectionItemViewModel(detection);
        item.PropertyChanged += OnDetectionPropertyChanged;
        Detections.Add(item);

        if (SelectedDetection is null) SelectedDetection = item;
        RaiseSelectionProperties();

        RaiseAlert(detection);
    }

    /// <summary>
    /// Raises the loud detection alert. It is only raised for a real detection, never
    /// for a clean scan.
    /// </summary>
    private void RaiseAlert(ScanDetection detection)
    {
        var primary = detection.PrimaryFinding;
        _services.Alerts.Show(
            detection,
            detection.FileName,
            primary?.Title ?? Text.FindingCaption(1),
            Presentation.ConfidenceText(primary?.Confidence ?? Confidence.Low));
    }

    private void OnDetectionPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(DetectionItemViewModel.IsSelected) || _updatingSelection) return;
        RaiseSelectionProperties();
    }

    private void RaiseSelectionProperties()
    {
        OnPropertyChanged(
            nameof(HasSelection),
            nameof(SelectedCount),
            nameof(AreAllSelected),
            nameof(QuarantineButtonText));
        QuarantineSelectedCommand.RaiseCanExecuteChanged();
        CleanSelectedCommand.RaiseCanExecuteChanged();
    }

    private void ApplyOutcome(ScanOutcome outcome)
    {
        FilesScanned = outcome.FilesScanned;
        FilesSkipped = outcome.FilesSkipped;
        ErrorCount = outcome.ErrorCount;
        DetectionCount = outcome.Detections.Count;
        ElapsedText = TimeFormatter.Duration(outcome.Duration);
        HasCompleted = true;
        _lastScanId = outcome.ScanId;

        var expected = new HashSet<string>(
            outcome.Detections.Select(detection => detection.FilePath),
            StringComparer.OrdinalIgnoreCase);

        for (var index = Detections.Count - 1; index >= 0; index--)
        {
            if (expected.Contains(Detections[index].Source.FilePath)) continue;
            RemoveDetectionAt(index);
        }

        foreach (var detection in outcome.Detections) AddDetection(detection);

        Errors.Clear();
        foreach (var error in outcome.Errors) Errors.Add(new ScanErrorItemViewModel(error));
        OnPropertyChanged(nameof(ErrorsToggleText), nameof(HasErrors));
        ToggleErrorsCommand.RaiseCanExecuteChanged();
        if (Errors.Count == 0) IsErrorsExpanded = false;

        PhaseText = outcome.Cancelled ? Text.ScanPhaseCancelled : Text.ScanPhaseComplete;
        CurrentFileDisplay = string.Empty;

        if (outcome.Cancelled)
        {
            SummaryTitle = Text.ScanSummaryCancelled;
            SummaryMessage = Text.ScanSummaryCancelledBody;
            SummarySeverity = MessageSeverity.Warning;
        }
        else if (outcome.HasFindings)
        {
            SummaryTitle = Text.ScanSummaryFound(outcome.Detections.Count);
            SummaryMessage = outcome.ErrorCount > 0
                ? Text.ScanSummaryFoundBody
                : Text.ScanSummaryFoundCleanBody;
            SummarySeverity = MessageSeverity.Warning;
        }
        else if (outcome.ErrorCount > 0)
        {
            SummaryTitle = Text.ScanSummaryWarnings;
            SummaryMessage = Text.ScanSummaryWarningsBody;
            SummarySeverity = MessageSeverity.Warning;
        }
        else
        {
            SummaryTitle = Text.ScanSummaryClean;
            SummaryMessage = Text.ScanSummaryCleanBody;
            SummarySeverity = MessageSeverity.Success;
        }

        HasSummary = true;

        var history = new ScanHistoryEntry
        {
            Id = outcome.ScanId,
            StartedUtc = outcome.StartedUtc,
            FinishedUtc = outcome.FinishedUtc,
            Scope = outcome.Request.Scope,
            ScopeDescription = outcome.Request.Description,
            Roots = outcome.Request.Roots,
            FilesScanned = outcome.FilesScanned,
            FilesSkipped = outcome.FilesSkipped,
            ErrorCount = outcome.ErrorCount,
            DetectionCount = outcome.Detections.Count,
            Cancelled = outcome.Cancelled,
            Errors = outcome.Errors
        };

        var saved = _services.HistoryStore.Add(history);
        if (!saved.Ok)
        {
            SetAction(
                Text.ScanHistorySaveFailedTitle,
                saved.Message ?? Text.ScanHistorySaveFailedBody,
                MessageSeverity.Warning);
        }

        _services.NotifyDataChanged();
        NotifyScanComplete(outcome);
        _services.Log.Info(
            "Scan",
            $"UI scan completed. findings={outcome.Detections.Count} errors={outcome.ErrorCount} cancelled={outcome.Cancelled}");
    }

    private void RemoveDetectionAt(int index)
    {
        var item = Detections[index];
        item.PropertyChanged -= OnDetectionPropertyChanged;
        Detections.RemoveAt(index);
        _detectionPaths.Remove(item.Source.FilePath);

        if (ReferenceEquals(SelectedDetection, item))
            SelectedDetection = Detections.FirstOrDefault();
    }

    private void RemoveDetection(DetectionItemViewModel item)
    {
        var index = Detections.IndexOf(item);
        if (index >= 0) RemoveDetectionAt(index);
    }

    private void ResetResults()
    {
        foreach (var item in Detections) item.PropertyChanged -= OnDetectionPropertyChanged;
        Detections.Clear();
        _detectionPaths.Clear();
        Errors.Clear();
        SelectedDetection = null;
        _lastScanId = null;
        FilesScanned = 0;
        FilesSkipped = 0;
        ErrorCount = 0;
        DetectionCount = 0;
        ElapsedText = "0s";
        IsErrorsExpanded = false;
        HasSummary = false;
        HasAction = false;
        SummaryTitle = string.Empty;
        SummaryMessage = string.Empty;
        ActionTitle = string.Empty;
        ActionMessage = string.Empty;
        HasCompleted = false;
        PhaseText = Text.ScanPhaseReady;
        CurrentFileDisplay = string.Empty;
        QuarantineProgress = 0;
        QuarantineCurrentFile = string.Empty;
        RaiseSelectionProperties();
        OnPropertyChanged(nameof(ErrorsToggleText), nameof(HasErrors), nameof(Errors));
        ToggleErrorsCommand.RaiseCanExecuteChanged();
    }

    private async Task QuarantineSelectedAsync()
    {
        if (IsScanning || IsQuarantining) return;

        var items = Detections.Where(item => item.IsSelected).ToArray();
        if (items.Length == 0) return;

        var details = string.Join(
            Environment.NewLine,
            items.Take(MaxDetailsInConfirm).Select(item => item.FilePath));
        if (items.Length > MaxDetailsInConfirm)
            details += Environment.NewLine + Text.ScanAndMore(items.Length - MaxDetailsInConfirm);

        var proceed = _services.Dialogs.Confirm(
            Text.ScanQuarantineTitle,
            Text.ScanQuarantineBody,
            items.Length == 1 ? Text.ScanQuarantineConfirmOne : Text.ScanQuarantineConfirmMany(items.Length),
            danger: true,
            details: details);
        if (!proceed) return;

        IsQuarantining = true;
        _quarantineTotalBytes = items.Sum(item => Math.Max(0, item.Source.SizeBytes));
        _quarantineCompletedBytes = 0;
        QuarantineProgress = 0;
        QuarantineCurrentFile = string.Empty;
        SetAction(
            Text.ScanQuarantineRunningTitle,
            Text.ScanQuarantineRunningBody(items.Length),
            MessageSeverity.Info);

        var quarantined = 0;
        var retained = 0;
        var skipped = 0;
        var failures = new List<string>();
        var retainedNames = new List<string>();

        try
        {
            foreach (var item in items)
            {
                var request = new QuarantineRequest
                {
                    FilePath = item.Source.FilePath,
                    FindingTitle = item.Title,
                    Category = item.Category,
                    FindingDetail = item.Detail,
                    ExpectedSha256 = item.Source.Sha256,
                    SourceScanId = _lastScanId,
                    DetectedUtc = item.Source.DetectedUtc
                };

                QuarantineCurrentFile = item.FileName;
                OnPropertyChanged(nameof(QuarantineProgressText));

                var size = Math.Max(0, item.Source.SizeBytes);
                var progress = new Progress<long>(copied =>
                {
                    var done = Math.Min(size, Math.Max(0, copied));
                    QuarantineProgress = _quarantineTotalBytes <= 0
                        ? 0
                        : Math.Clamp((_quarantineCompletedBytes + done) / (double)_quarantineTotalBytes, 0, 1);
                    OnPropertyChanged(nameof(QuarantineProgressText));
                });

                var result = await _services.Quarantine.QuarantineAsync(
                    request,
                    progress,
                    CancellationToken.None);

                if (result.Status == QuarantineStatus.ChangedSinceScan)
                {
                    var allow = _services.Dialogs.Confirm(
                        Text.ScanChangedTitle,
                        Text.ScanChangedBody,
                        Text.ScanChangedConfirm,
                        danger: true,
                        details: Text.ScanLocationPrefix + item.FilePath);
                    if (!allow)
                    {
                        skipped++;
                        _quarantineCompletedBytes += size;
                        continue;
                    }

                    request = request with { AllowChangedFile = true };
                    result = await _services.Quarantine.QuarantineAsync(
                        request,
                        progress,
                        CancellationToken.None);
                }

                _quarantineCompletedBytes += size;
                QuarantineProgress = _quarantineTotalBytes <= 0
                    ? 1
                    : Math.Clamp(_quarantineCompletedBytes / (double)_quarantineTotalBytes, 0, 1);
                OnPropertyChanged(nameof(QuarantineProgressText));

                switch (result.Status)
                {
                    case QuarantineStatus.Quarantined:
                        quarantined++;
                        RemoveDetection(item);
                        break;

                    case QuarantineStatus.QuarantinedOriginalRetained:
                        quarantined++;
                        retained++;
                        retainedNames.Add(item.FileName);
                        RemoveDetection(item);
                        break;

                    case QuarantineStatus.Cancelled:
                        skipped++;
                        break;

                    default:
                        failures.Add(item.FileName + ": " + result.Message);
                        break;
                }
            }
        }
        finally
        {
            IsQuarantining = false;
            QuarantineCurrentFile = string.Empty;
        }

        RaiseSelectionProperties();

        if (failures.Count == 0 && skipped == 0)
        {
            var message = Text.ScanQuarantineDoneBody(quarantined);
            if (retained > 0) message += " " + Text.ScanQuarantineRetainedBody(retained);

            SetAction(Text.ScanQuarantineDoneTitle, message, retained > 0 ? MessageSeverity.Warning : MessageSeverity.Success);
        }
        else
        {
            var message = Text.ScanQuarantineWarnBody(quarantined, skipped, failures.Count);

            SetAction(Text.ScanQuarantineWarnTitle, message, MessageSeverity.Warning);

            if (failures.Count > 0 || retainedNames.Count > 0)
            {
                var failureDetails = new List<string>();
                if (retainedNames.Count > 0)
                {
                    failureDetails.Add(Text.ScanRetainedDetail);
                    failureDetails.AddRange(retainedNames.Select(name => "  • " + name));
                }

                if (failures.Count > 0)
                {
                    if (failureDetails.Count > 0) failureDetails.Add(string.Empty);
                    failureDetails.Add(Text.ScanFailedDetail);
                    failureDetails.AddRange(failures.Take(MaxFailedDetails).Select(failure => "  • " + failure));
                    if (failures.Count > MaxFailedDetails)
                        failureDetails.Add("  " + Text.ScanAndMore(failures.Count - MaxFailedDetails));
                }

                _services.Dialogs.ShowMessage(
                    Text.ScanQuarantineResultsTitle,
                    message,
                    MessageSeverity.Warning,
                    string.Join(Environment.NewLine, failureDetails));
            }
        }

        _services.NotifyDataChanged();
    }

    /// <summary>
    /// Cleans up the selected findings. The flow is plan, then review, then confirm,
    /// then execute: nothing is stopped and nothing is deleted before the user has
    /// confirmed the plan.
    /// </summary>
    private async Task CleanSelectedAsync()
    {
        if (IsScanning || IsQuarantining) return;
        if (!IsRemediationEnabled) return;

        var items = Detections.Where(item => item.IsSelected).ToArray();
        if (items.Length == 0) return;

        var ran = false;
        foreach (var item in items)
        {
            var target = new RemediationTarget
            {
                FilePath = item.Source.FilePath,
                Sha256 = item.Source.Sha256,
                SizeBytes = item.Source.SizeBytes,
                FindingTitle = item.Title,
                FindingDetail = item.Detail
            };

            var executed = await _remediation.RunAsync(target, CancellationToken.None);
            if (!executed) break;
            ran = true;
        }

        if (!ran) return;

        _services.NotifyDataChanged();
    }

    private void CopySelectedPath()
    {
        if (SelectedDetection is null) return;

        try
        {
            Clipboard.SetText(SelectedDetection.Source.FilePath);
            SetAction(Text.ScanPathCopiedTitle, Text.ScanPathCopiedBody, MessageSeverity.Info);
        }
        catch (Exception ex)
        {
            _services.Log.Warn("Shell", "The file path could not be copied.", ex);
            SetAction(Text.ScanPathCopyFailedTitle, Text.ScanPathCopyFailedBody, MessageSeverity.Warning);
        }
    }

    private void RevealSelected()
    {
        if (SelectedDetection is null) return;

        if (!_services.RevealFile(SelectedDetection.Source.FilePath))
        {
            _services.Dialogs.ShowMessage(
                Text.ScanFileNotFoundTitle,
                Text.ScanFileNotFoundBody,
                MessageSeverity.Info);
        }
    }

    private void ClearResults()
    {
        if (IsScanning || IsQuarantining) return;
        ResetResults();
    }

    private void SetAction(string title, string message, MessageSeverity severity)
    {
        ActionTitle = title;
        ActionMessage = message;
        ActionSeverity = severity;
        HasAction = true;
    }

    private void NotifyScanComplete(ScanOutcome outcome)
    {
        if (_services.Tray is null || !_services.Settings.ShowTrayNotifications) return;

        var main = Application.Current?.MainWindow;
        var windowIsActive = main is { IsVisible: true, WindowState: not WindowState.Minimized } && main.IsActive;
        if (windowIsActive) return;

        var title = outcome.Cancelled
            ? Text.ScanTrayCancelled
            : outcome.HasFindings
                ? Text.ScanTrayReview
                : Text.ScanTrayComplete;
        var message = outcome.Cancelled
            ? Text.ScanTrayCancelledBody
            : outcome.HasFindings
                ? Text.ScanTrayFoundBody(outcome.Detections.Count)
                : Text.ScanTrayCleanBody;

        _services.Tray.Notify(title, message);
    }

    private void OnServicesSettingsChanged(object? sender, EventArgs e)
    {
        IsRemediationEnabled = _services.Settings.RemediationEnabled;
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(
            nameof(PhaseText),
            nameof(ScanButtonText),
            nameof(CancelButtonText),
            nameof(ScopeDescription),
            nameof(SelectedPathDisplay),
            nameof(ErrorsToggleText),
            nameof(QuarantineButtonText),
            nameof(FindingsCaption),
            nameof(QuarantineProgressText));

        foreach (var option in ScopeOptions) option.Refresh();
        UpdateScopeSelection();
    }

    private void RaiseCommandStates()
    {
        StartScanCommand.RaiseCanExecuteChanged();
        CancelScanCommand.RaiseCanExecuteChanged();
        BrowseCommand.RaiseCanExecuteChanged();
        QuarantineSelectedCommand.RaiseCanExecuteChanged();
        CleanSelectedCommand.RaiseCanExecuteChanged();
        ClearResultsCommand.RaiseCanExecuteChanged();
    }

    /// <summary>True when at least one item could not be inspected.</summary>
    public bool HasErrors => Errors.Count > 0;

    /// <summary>Unsubscribes from the events this view model listens to.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _timer.Stop();
        _services.SettingsChanged -= OnServicesSettingsChanged;
        Text.LanguageChanged -= OnLanguageChanged;
    }
}
