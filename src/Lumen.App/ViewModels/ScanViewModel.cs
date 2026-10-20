using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using Lumen.App.Dialogs;
using Lumen.App.Infrastructure;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Quarantine;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

public sealed class ScanViewModel : ObservableObject, IPageViewModel
{
    private const int MaxDetailsInConfirm = 8;
    private const int MaxFailedDetails = 12;

    private readonly AppServices _services;
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
    private bool _wasCancelled;
    private long _filesScanned;
    private long _filesSkipped;
    private long _errorCount;
    private long _detectionCount;
    private string _phaseText = "Ready when you are";
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

    public ScanViewModel(AppServices services)
    {
        _services = services;
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
        ToggleErrorsCommand = new RelayCommand(
            () => IsErrorsExpanded = !IsErrorsExpanded,
            () => Errors.Count > 0);
        CopySelectedPathCommand = new RelayCommand(CopySelectedPath, () => SelectedDetection is not null);
        RevealSelectedCommand = new RelayCommand(RevealSelected, () => SelectedDetection is not null);
        ClearResultsCommand = new RelayCommand(ClearResults, () => HasCompleted && !IsScanning && !IsQuarantining);
        DismissActionCommand = new RelayCommand(() => HasAction = false);
    }

    public ObservableCollection<DetectionItemViewModel> Detections { get; } = [];
    public ObservableCollection<ScanErrorItemViewModel> Errors { get; } = [];

    public AsyncRelayCommand StartScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand BrowseCommand { get; }
    public AsyncRelayCommand QuarantineSelectedCommand { get; }
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
                nameof(CustomScopeLabel),
                nameof(SelectedPathDisplay),
                nameof(ScopeHeadline),
                nameof(ScopeDescription),
                nameof(CanStartScan),
                nameof(CanBrowse));
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

    public bool IsCustomScope => Scope is ScanScopeKind.Folder or ScanScopeKind.File;

    public string CustomScopeLabel => Scope == ScanScopeKind.File ? "File to scan" : "Folder to scan";

    public string SelectedPathDisplay => Scope switch
    {
        ScanScopeKind.Quick => "Desktop, Documents and Downloads",
        ScanScopeKind.FullUserProfile => "Your user profile \u2014 app data, caches and Lumen's vault are excluded",
        ScanScopeKind.Folder => string.IsNullOrWhiteSpace(SelectedFolder)
            ? "No folder selected yet"
            : Presentation.SanitizePath(SelectedFolder),
        _ => string.IsNullOrWhiteSpace(SelectedFile)
            ? "No file selected yet"
            : Presentation.SanitizePath(SelectedFile)
    };

    public string ScopeHeadline => Scope switch
    {
        ScanScopeKind.Quick => "Quick scan",
        ScanScopeKind.FullUserProfile => "Full profile scan",
        ScanScopeKind.Folder => "Folder scan",
        _ => "Single-file scan"
    };

    public string ScopeDescription => Scope switch
    {
        ScanScopeKind.Quick =>
            "Checks Desktop, Documents and Downloads with Lumen's small set of transparent rules.",
        ScanScopeKind.FullUserProfile =>
            "Walks your user profile while skipping AppData, caches, reparse points and Lumen's own data.",
        ScanScopeKind.Folder =>
            "Checks one folder you choose. Links and cloud placeholders are skipped, never followed.",
        _ => "Checks one file you choose. Nothing is uploaded, changed or removed."
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
            OnPropertyChanged(nameof(CanStartScan), nameof(CanBrowse));
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

    public string ScanButtonText => IsScanning ? "Scanning\u2026" : "Start scan";
    public string CancelButtonText => IsCancelling ? "Cancelling\u2026" : "Cancel scan";

    public long FilesScanned
    {
        get => _filesScanned;
        private set
        {
            if (SetProperty(ref _filesScanned, value)) OnPropertyChanged(nameof(FilesScannedText));
        }
    }

    public string FilesScannedText => _filesScanned.ToString("N0");

    public long FilesSkipped
    {
        get => _filesSkipped;
        private set
        {
            if (SetProperty(ref _filesSkipped, value)) OnPropertyChanged(nameof(FilesSkippedText));
        }
    }

    public string FilesSkippedText => _filesSkipped.ToString("N0");

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
    public string FindingsCaption => _detectionCount == 1 ? "finding" : "findings";
    public bool HasFindings => _detectionCount > 0;
    public bool HasNoFindings => HasCompleted && _detectionCount == 0;

    public string PhaseText
    {
        get => _phaseText;
        private set => SetProperty(ref _phaseText, value);
    }

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

    public bool WasCancelled
    {
        get => _wasCancelled;
        private set => SetProperty(ref _wasCancelled, value);
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
        ? "Hide skipped items"
        : $"Show {Errors.Count:N0} skipped item(s)";

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
    public string QuarantineButtonText => SelectedCount == 0
        ? "Quarantine selected"
        : SelectedCount == 1
            ? "Quarantine 1 file"
            : $"Quarantine {SelectedCount} files";

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

    public void OnNavigatedTo()
    {
        // Scan state intentionally survives navigation so a running scan is never lost.
    }

    public void SetScope(ScanScopeKind scope) => Scope = scope;

    public void CancelScan()
    {
        if (!IsScanning || IsCancelling) return;

        IsCancelling = true;
        PhaseText = "Cancelling\u2026";
        try
        {
            _cts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The scan finished at the same moment.
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
                "Choose a folder to scan",
                SelectedFolder ?? _services.UserProfile);
            if (!string.IsNullOrWhiteSpace(folder)) SelectedFolder = folder;
            return;
        }

        var startFolder = SelectedFile is not null
            ? Path.GetDirectoryName(SelectedFile)
            : _services.UserProfile;
        var file = _services.Dialogs.PickFile("Choose a file to scan", startFolder);
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
            _services.Dialogs.ShowMessage("Choose a scan location", ex.Message, MessageSeverity.Warning);
            return;
        }

        if (request.Roots.Count == 0)
        {
            _services.Dialogs.ShowMessage(
                "No standard folders found",
                "None of the usual quick-scan folders exist for this account. Choose a folder instead.",
                MessageSeverity.Info);
            Scope = ScanScopeKind.Folder;
            Browse();
            return;
        }

        var critical = request.Roots.FirstOrDefault(PathRules.IsSystemCritical);
        if (critical is not null)
        {
            var proceed = _services.Dialogs.Confirm(
                "Scan a protected system location?",
                "Lumen would normally never scan Windows, Program Files or a drive root. " +
                "This scan is read-only, but many files will return access-denied results. " +
                "Lumen does not bypass Windows permissions. Only continue if you have a specific reason.",
                "Scan anyway",
                danger: true,
                details: "Location: " + Presentation.SanitizePath(critical));
            if (!proceed) return;
        }

        var network = request.Roots.FirstOrDefault(PathRules.IsNetworkPath);
        if (network is not null)
        {
            var proceed = _services.Dialogs.Confirm(
                "Scan a network location?",
                "Scanning a network share can be slow and may be logged by the remote computer. " +
                "Lumen reads files directly from this device and does not upload anything.",
                "Scan network location",
                details: "Location: " + Presentation.SanitizePath(network));
            if (!proceed) return;
        }

        ResetResults();
        IsScanning = true;
        IsCancelling = false;
        IsQuarantining = false;
        HasCompleted = false;
        WasCancelled = false;
        PhaseText = "Preparing scan\u2026";
        CurrentFileDisplay = "Waiting for the first file\u2026";
        _stopwatch.Restart();
        _timer.Start();
        _services.Tray?.SetStatus("scanning\u2026");
        _cts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<ScanProgress>(OnProgress);
            var outcome = await _services.ScanEngine.ScanAsync(request, progress, _cts.Token);
            ApplyOutcome(outcome);
        }
        catch (OperationCanceledException)
        {
            WasCancelled = true;
            HasCompleted = true;
            PhaseText = "Cancelled";
            SummaryTitle = "Scan cancelled";
            SummaryMessage = "The scan stopped before finishing. Partial results, if any, are shown. No files were changed.";
            SummarySeverity = MessageSeverity.Warning;
            HasSummary = true;
        }
        catch (Exception ex)
        {
            _services.Log.Error("Scan", "The scan could not be completed.", ex);
            HasCompleted = true;
            PhaseText = "Scan failed";
            SummaryTitle = "The scan could not be completed";
            SummaryMessage = "An unexpected error stopped the scan. No files were changed. Details were written to the local log.";
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
            ScanPhase.Enumerating => "Finding files\u2026",
            ScanPhase.Inspecting => "Inspecting files\u2026",
            _ => "Finishing\u2026"
        };
        CurrentFileDisplay = string.IsNullOrWhiteSpace(progress.CurrentFile)
            ? "Preparing the file list\u2026"
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
    }

    private void ApplyOutcome(ScanOutcome outcome)
    {
        FilesScanned = outcome.FilesScanned;
        FilesSkipped = outcome.FilesSkipped;
        ErrorCount = outcome.ErrorCount;
        DetectionCount = outcome.Detections.Count;
        ElapsedText = TimeFormatter.Duration(outcome.Duration);
        WasCancelled = outcome.Cancelled;
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

        PhaseText = outcome.Cancelled ? "Cancelled" : "Scan complete";
        CurrentFileDisplay = string.Empty;

        if (outcome.Cancelled)
        {
            SummaryTitle = "Scan cancelled";
            SummaryMessage =
                "The scan stopped early. Results collected before cancellation are shown. " +
                "No files were changed, and nothing is quarantined until you choose it.";
            SummarySeverity = MessageSeverity.Warning;
        }
        else if (outcome.HasFindings)
        {
            SummaryTitle = Presentation.Count(outcome.Detections.Count, "potential issue") + " found";
            SummaryMessage = outcome.ErrorCount > 0
                ? "Review each finding before deciding what to quarantine. Some items could not be inspected, so this result is incomplete."
                : "Lumen has not changed or removed anything. Review the findings and quarantine only what you understand.";
            SummarySeverity = MessageSeverity.Warning;
        }
        else if (outcome.ErrorCount > 0)
        {
            SummaryTitle = "Scan completed with warnings";
            SummaryMessage =
                "No matches for Lumen's limited rules were found, but some files could not be inspected. " +
                "This does not prove the uninspected files are safe.";
            SummarySeverity = MessageSeverity.Warning;
        }
        else
        {
            SummaryTitle = "No matches found";
            SummaryMessage =
                "No matches for Lumen's limited rules (EICAR, script heuristics and deceptive file names). " +
                "This does not prove the files are safe. Keep Microsoft Defender enabled.";
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
                "Scan history could not be saved",
                saved.Message ?? "The result is shown here, but it may not appear in History.",
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
        WasCancelled = false;
        PhaseText = "Ready when you are";
        CurrentFileDisplay = string.Empty;
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
            details += Environment.NewLine + $"\u2026and {items.Length - MaxDetailsInConfirm} more";

        var proceed = _services.Dialogs.Confirm(
            "Quarantine selected files?",
            $"Lumen will copy {Presentation.Count(items.Length, "file")} into the encrypted quarantine vault, " +
            "verify the encrypted copy, and then remove the original. You can restore each file later. " +
            "Files are never uploaded.",
            items.Length == 1 ? "Quarantine file" : $"Quarantine {items.Length} files",
            danger: true,
            details: details);
        if (!proceed) return;

        IsQuarantining = true;
        SetAction(
            "Quarantining files",
            $"Encrypting {Presentation.Count(items.Length, "file")}. Keep Lumen open until this finishes.",
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

                var result = await _services.Quarantine.QuarantineAsync(
                    request,
                    null,
                    CancellationToken.None);

                if (result.Status == QuarantineStatus.ChangedSinceScan)
                {
                    var allow = _services.Dialogs.Confirm(
                        "This file changed since the scan",
                        $"\"{item.FileName}\" no longer matches the content Lumen inspected. " +
                        "Quarantining now would preserve the unreviewed current content. " +
                        "Do you want to quarantine the current content anyway?",
                        "Quarantine current content",
                        danger: true,
                        details: "Path: " + item.FilePath);
                    if (!allow)
                    {
                        skipped++;
                        continue;
                    }

                    request = request with { AllowChangedFile = true };
                    result = await _services.Quarantine.QuarantineAsync(
                        request,
                        null,
                        CancellationToken.None);
                }

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
        }

        RaiseSelectionProperties();

        if (failures.Count == 0 && skipped == 0)
        {
            var message = Presentation.Count(quarantined, "file") + " moved into the encrypted vault.";
            if (retained > 0)
            {
                message += " " + Presentation.Count(retained, "encrypted copy", "encrypted copies") +
                           " was preserved, but the original could not be removed. Close any program using it and delete it manually.";
            }

            SetAction("Quarantine finished", message, retained > 0 ? MessageSeverity.Warning : MessageSeverity.Success);
        }
        else
        {
            var message = $"{Presentation.Count(quarantined, "file")} quarantined";
            if (skipped > 0) message += $", {skipped} skipped";
            if (failures.Count > 0) message += $", {failures.Count} failed";
            message += ". Originals were kept for every item that was not quarantined.";

            SetAction("Quarantine finished with warnings", message, MessageSeverity.Warning);

            if (failures.Count > 0 || retainedNames.Count > 0)
            {
                var failureDetails = new List<string>();
                if (retainedNames.Count > 0)
                {
                    failureDetails.Add("Encrypted copy created, original still present:");
                    failureDetails.AddRange(retainedNames.Select(name => "  \u2022 " + name));
                }

                if (failures.Count > 0)
                {
                    if (failureDetails.Count > 0) failureDetails.Add(string.Empty);
                    failureDetails.Add("Could not be quarantined:");
                    failureDetails.AddRange(failures.Take(MaxFailedDetails).Select(failure => "  \u2022 " + failure));
                    if (failures.Count > MaxFailedDetails)
                        failureDetails.Add($"  \u2026and {failures.Count - MaxFailedDetails} more. See the local log.");
                }

                _services.Dialogs.ShowMessage(
                    "Quarantine results",
                    message,
                    MessageSeverity.Warning,
                    string.Join(Environment.NewLine, failureDetails));
            }
        }

        _services.NotifyDataChanged();
    }

    private void CopySelectedPath()
    {
        if (SelectedDetection is null) return;

        try
        {
            Clipboard.SetText(SelectedDetection.Source.FilePath);
            SetAction("Path copied", "The full file path was copied to the clipboard.", MessageSeverity.Info);
        }
        catch (Exception ex)
        {
            _services.Log.Warn("Shell", "The file path could not be copied.", ex);
            SetAction("Could not copy the path", "The clipboard is unavailable right now.", MessageSeverity.Warning);
        }
    }

    private void RevealSelected()
    {
        if (SelectedDetection is null) return;

        if (!_services.RevealFile(SelectedDetection.Source.FilePath))
        {
            _services.Dialogs.ShowMessage(
                "File not found",
                "That file is no longer at its original location. If you quarantined it, use the Quarantine page to restore it.",
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
            ? "Scan cancelled"
            : outcome.HasFindings
                ? "Scan complete \u2014 review needed"
                : "Scan complete";
        var message = outcome.Cancelled
            ? "The scan stopped early. Open Lumen to review partial results."
            : outcome.HasFindings
                ? $"{Presentation.Count(outcome.Detections.Count, "potential issue")} found. Nothing was changed."
                : "No matches for Lumen's limited rules. Open Lumen for details.";

        _services.Tray.Notify(title, message);
    }

    private void RaiseCommandStates()
    {
        StartScanCommand.RaiseCanExecuteChanged();
        CancelScanCommand.RaiseCanExecuteChanged();
        BrowseCommand.RaiseCanExecuteChanged();
        QuarantineSelectedCommand.RaiseCanExecuteChanged();
        ClearResultsCommand.RaiseCanExecuteChanged();
    }

    public bool HasErrors => Errors.Count > 0;
}
