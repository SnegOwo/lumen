using System.Collections.ObjectModel;
using Lumen.App.Infrastructure;
using Lumen.App.Localization;
using Lumen.App.Services;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

/// <summary>
/// The Microsoft Defender status, shown on the dashboard and in the settings.
/// </summary>
public sealed class DefenderStatusViewModel : ObservableObject, IDisposable
{
    private readonly AppServices _services;
    private DefenderStatus? _status;
    private bool _isChecking;
    private bool _disposed;

    /// <summary>Creates the Defender status view model.</summary>
    public DefenderStatusViewModel(AppServices services)
    {
        _services = services;
        RefreshCommand = new AsyncRelayCommand(() => RefreshAsync(force: true), () => !IsChecking);
        Text.LanguageChanged += OnLanguageChanged;
    }

    public AsyncRelayCommand RefreshCommand { get; }

    public bool IsChecking
    {
        get => _isChecking;
        private set
        {
            if (!SetProperty(ref _isChecking, value)) return;
            RaiseStatusProperties();
        }
    }

    public bool IsAvailable => _status?.IsAvailable == true;
    public bool IsProtected => _status?.RealTimeProtectionEnabled == true;
    public bool IsOff => IsAvailable && !IsProtected;
    public bool IsUnavailable => _status is null || !IsAvailable;
    public bool IsReady => _status is not null && !_isChecking;

    public string Title => IsChecking
        ? Text.DefenderChecking
        : IsUnavailable
            ? Text.DefenderUnavailable
            : IsProtected
                ? Text.DefenderOn
                : Text.DefenderOff;

    public string Detail => _status?.Message ?? Text.DefenderDetailFallback;

    public string Signature => _status?.SignatureText ?? "Microsoft Defender";
    public string Updated => _status?.UpdatedText ?? string.Empty;
    public string BadgeText => IsChecking ? Text.DefenderBadgeChecking : IsUnavailable ? Text.DefenderBadgeUnknown : IsProtected ? Text.DefenderBadgeOn : Text.DefenderBadgeOff;
    public string CheckedText => _status is null
        ? string.Empty
        : Text.DefenderChecked(TimeFormatter.Relative(_status.CheckedUtc, _services.Clock.UtcNow));

    /// <summary>Refreshes the Defender status.</summary>
    public async Task RefreshAsync(bool force = false)
    {
        if (IsChecking) return;

        IsChecking = true;
        try
        {
            _status = await _services.Defender.GetAsync(force);
        }
        catch (OperationCanceledException)
        {
            _status = DefenderStatus.Unavailable(
                Text.DefenderCancelled,
                _services.Clock.UtcNow);
        }
        catch (Exception ex)
        {
            _services.Log.Warn("Defender", "Defender status could not be read.", ex);
            _status = DefenderStatus.Unavailable(
                Text.DefenderUnavailableBody,
                _services.Clock.UtcNow);
        }
        finally
        {
            IsChecking = false;
            RaiseStatusProperties();
        }
    }

    private void OnLanguageChanged(object? sender, EventArgs e) => RaiseStatusProperties();

    /// <summary>Unsubscribes from the language event.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Text.LanguageChanged -= OnLanguageChanged;
    }

    private void RaiseStatusProperties() => OnPropertyChanged(
        nameof(IsAvailable),
        nameof(IsProtected),
        nameof(IsOff),
        nameof(IsUnavailable),
        nameof(IsReady),
        nameof(Title),
        nameof(Detail),
        nameof(Signature),
        nameof(Updated),
        nameof(BadgeText),
        nameof(CheckedText));
}

/// <summary>
/// One finding of a detection, as the detail pane shows it.
/// </summary>
public sealed class FindingViewModel
{
    /// <summary>Wraps a finding.</summary>
    public FindingViewModel(Finding finding)
    {
        Source = finding;
    }

    public Finding Source { get; }
    public string Title => Source.Title;
    public string Summary => Source.Summary;
    public string Detail => Source.Detail;
    public string Advice => Source.Advice;
    public string CategoryLabel => Presentation.Category(Source.Category);
    public string ConfidenceLabel => Presentation.ConfidenceText(Source.Confidence);
    public Confidence Confidence => Source.Confidence;
}

/// <summary>
/// One detection of a scan, as the results list shows it.
/// </summary>
public sealed class DetectionItemViewModel : ObservableObject
{
    private bool _isSelected;

    /// <summary>Wraps a detection.</summary>
    public DetectionItemViewModel(ScanDetection source)
    {
        Source = source;
        Findings = source.Findings.Select(finding => new FindingViewModel(finding)).ToArray();
    }

    public ScanDetection Source { get; }
    public IReadOnlyList<FindingViewModel> Findings { get; }
    public FindingViewModel? PrimaryFinding => Findings.Count > 0 ? Findings[0] : null;

    public string FileName => Presentation.Sanitize(Source.FileName, 160);
    public string FilePath => Presentation.SanitizePath(Source.FilePath);
    public string Folder => Presentation.SanitizePath(Path.GetDirectoryName(Source.FilePath), 260);
    public string Title => PrimaryFinding?.Title ?? Text.PotentialIssueTitle;
    public string Summary => PrimaryFinding?.Summary ?? string.Empty;
    public string Detail => PrimaryFinding?.Detail ?? string.Empty;
    public string Advice => PrimaryFinding?.Advice ?? string.Empty;
    public FindingCategory Category => PrimaryFinding?.Source.Category ?? FindingCategory.Heuristic;
    public Confidence Confidence => PrimaryFinding?.Source.Confidence ?? Confidence.Low;
    public string CategoryLabel => Presentation.Category(Category);
    public string ConfidenceLabel => Presentation.ConfidenceText(Confidence);
    public string SizeText => SizeFormatter.Format(Source.SizeBytes);
    public string HashShort => string.IsNullOrWhiteSpace(Source.Sha256)
        ? Text.HashUnavailable
        : Source.Sha256[..16].ToUpperInvariant() + "…";
    public string DetectedText => TimeFormatter.DateTime(Source.DetectedUtc);
    public string AdditionalText => Findings.Count > 1 ? Text.AdditionalFindings(Findings.Count - 1) : string.Empty;
    public bool HasAdditional => Findings.Count > 1;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (!SetProperty(ref _isSelected, value)) return;
            OnPropertyChanged(nameof(SelectionName));
        }
    }

    /// <summary>The accessible name of the tick box that selects this detection.</summary>
    public string SelectionName => Text.SelectFileName(FileName);

    /// <summary>Re-raises the wording that depends on the interface language.</summary>
    public void Refresh()
    {
        OnPropertyChanged(
            nameof(Title),
            nameof(CategoryLabel),
            nameof(ConfidenceLabel),
            nameof(HashShort),
            nameof(AdditionalText),
            nameof(SelectionName));
    }
}

/// <summary>
/// One item that could not be inspected.
/// </summary>
public sealed class ScanErrorItemViewModel : ObservableObject
{
    /// <summary>Wraps a scan error.</summary>
    public ScanErrorItemViewModel(ScanError source)
    {
        Source = source;
    }

    public ScanError Source { get; }
    public string Path => Presentation.SanitizePath(Source.Path);
    public string Message => Presentation.Sanitize(Source.Message, 300);
    public string KindLabel => Presentation.ErrorKind(Source.Kind);
    public string Technical => Presentation.Sanitize(Source.Technical, 80);

    /// <summary>Re-raises the wording that depends on the interface language.</summary>
    public void Refresh() => OnPropertyChanged(nameof(KindLabel));
}

/// <summary>
/// One scan in the history list.
/// </summary>
public sealed class HistoryRowViewModel : ObservableObject
{
    /// <summary>Wraps a history entry.</summary>
    public HistoryRowViewModel(ScanHistoryEntry source, DateTimeOffset now)
    {
        Source = source;
        Now = now;
    }

    public ScanHistoryEntry Source { get; }
    public DateTimeOffset Now { get; }
    public string Id => Source.Id;
    public string Title => Presentation.Sanitize(Source.ScopeDescription, 180);
    public string WhenText => TimeFormatter.Relative(Source.StartedUtc, Now);
    public string DateText => TimeFormatter.DateTime(Source.StartedUtc);
    public string DurationText => TimeFormatter.Duration(Source.Duration);
    public string MetaText => Text.Count(Source.FilesScanned, Text.File) + " · " + DurationText;
    public bool Cancelled => Source.Cancelled;
    public bool HasDetections => Source.DetectionCount > 0;
    public bool HasErrors => Source.ErrorCount > 0;

    /// <summary>The status of the scan, in the current language.</summary>
    public string StatusText => Cancelled
        ? Text.HistoryStatusCancelled
        : Source.ErrorCount > 0
            ? Text.HistoryStatusErrors
            : Text.HistoryStatusCompleted;

    public string DetectionText => Text.Count(Source.DetectionCount, Text.Finding);
    public string ErrorText => Text.Count(Source.ErrorCount, Text.Warning);
    public string ScopeLabel => Presentation.Scope(Source.Scope);

    /// <summary>Re-raises the wording that depends on the interface language.</summary>
    public void Refresh()
    {
        OnPropertyChanged(nameof(MetaText), nameof(StatusText), nameof(DetectionText), nameof(ErrorText), nameof(ScopeLabel));
    }
}

/// <summary>
/// One item of the encrypted quarantine vault.
/// </summary>
public sealed class QuarantineItemViewModel : ObservableObject
{
    /// <summary>Wraps a vault item.</summary>
    public QuarantineItemViewModel(QuarantineItem source, DateTimeOffset now)
    {
        Source = source;
        Now = now;
    }

    public QuarantineItem Source { get; }
    public DateTimeOffset Now { get; }
    public string Id => Source.Id;
    public string FileName => Presentation.Sanitize(Source.FileName, 160);
    public string OriginalPath => Presentation.SanitizePath(Source.OriginalPath);
    public string OriginalFolder => Presentation.SanitizePath(Path.GetDirectoryName(Source.OriginalPath), 260);
    public string DateText => TimeFormatter.DateTime(Source.QuarantinedUtc);
    public string RelativeText => TimeFormatter.Relative(Source.QuarantinedUtc, Now);
    public string SizeText => SizeFormatter.Format(Source.SizeBytes);
    public string HashShort => Source.Sha256[..16].ToUpperInvariant() + "…";
    public string CategoryLabel => Presentation.Category(Source.Category);
    public string FindingTitle => Presentation.Sanitize(Source.FindingTitle, 180);
    public string FindingDetail => Presentation.Sanitize(Source.FindingDetail, 500);
    public string? Note => string.IsNullOrWhiteSpace(Source.Note) ? null : Presentation.Sanitize(Source.Note, 400);
    public bool HasNote => Note is not null;
    public bool OriginalExists => File.Exists(Source.OriginalPath);

    /// <summary>Re-raises the wording that depends on the interface language.</summary>
    public void Refresh() => OnPropertyChanged(nameof(CategoryLabel));
}

/// <summary>
/// One rule of the detection catalogue.
/// </summary>
public sealed class DetectionRuleViewModel
{
    /// <summary>Wraps a rule summary.</summary>
    public DetectionRuleViewModel(DetectionRuleSummary source)
    {
        Source = source;
    }

    public DetectionRuleSummary Source { get; }
    public string Name => Source.Name;
    public string Description => Source.Description;
    public string CategoryLabel => Presentation.Category(Source.Category);
    public string ConfidenceLabel => Presentation.ConfidenceText(Source.Confidence);
    public Confidence Confidence => Source.Confidence;
    public bool IsTestSignature => Source.Category == FindingCategory.TestSignature;

    /// <summary>
    /// True when the rule only runs in aggressive mode. The rule is still documented and
    /// still tested; the tier only decides WHEN it runs.
    /// </summary>
    public bool IsAggressive => DetectionCatalog.IsAggressive(Source.Id);
}
