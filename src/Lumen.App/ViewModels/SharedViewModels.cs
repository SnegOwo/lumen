using System.Collections.ObjectModel;
using Lumen.App.Infrastructure;
using Lumen.App.Services;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

public sealed class DefenderStatusViewModel : ObservableObject
{
    private readonly AppServices _services;
    private DefenderStatus? _status;
    private bool _isChecking;

    public DefenderStatusViewModel(AppServices services)
    {
        _services = services;
        RefreshCommand = new AsyncRelayCommand(() => RefreshAsync(force: true), () => !IsChecking);
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
        ? "Checking Windows Security\u2026"
        : IsUnavailable
            ? "Status unavailable"
            : IsProtected
                ? "Real-time protection is on"
                : "Real-time protection is off";

    public string Detail => _status?.Message ??
        "Lumen reads Microsoft Defender status but never changes it.";

    public string Signature => _status?.SignatureText ?? "Microsoft Defender";
    public string Updated => _status?.UpdatedText ?? string.Empty;
    public string BadgeText => IsChecking ? "Checking" : IsUnavailable ? "Unknown" : IsProtected ? "On" : "Off";
    public string CheckedText => _status is null
        ? string.Empty
        : "Read-only status checked " + TimeFormatter.Relative(_status.CheckedUtc, _services.Clock.UtcNow);

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
                "The status check was cancelled.",
                _services.Clock.UtcNow);
        }
        catch (Exception ex)
        {
            _services.Log.Warn("Defender", "Defender status could not be read.", ex);
            _status = DefenderStatus.Unavailable(
                "Windows Security status is unavailable on this system.",
                _services.Clock.UtcNow);
        }
        finally
        {
            IsChecking = false;
            RaiseStatusProperties();
        }
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

public sealed class FindingViewModel
{
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

public sealed class DetectionItemViewModel : ObservableObject
{
    private bool _isSelected;

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
    public string Title => PrimaryFinding?.Title ?? "Potential issue";
    public string Summary => PrimaryFinding?.Summary ?? string.Empty;
    public string Detail => PrimaryFinding?.Detail ?? string.Empty;
    public string Advice => PrimaryFinding?.Advice ?? string.Empty;
    public FindingCategory Category => PrimaryFinding?.Source.Category ?? FindingCategory.Heuristic;
    public Confidence Confidence => PrimaryFinding?.Source.Confidence ?? Confidence.Low;
    public string CategoryLabel => Presentation.Category(Category);
    public string ConfidenceLabel => Presentation.ConfidenceText(Confidence);
    public string SizeText => SizeFormatter.Format(Source.SizeBytes);
    public string HashShort => string.IsNullOrWhiteSpace(Source.Sha256)
        ? "SHA-256 unavailable"
        : Source.Sha256[..16].ToUpperInvariant() + "\u2026";
    public string DetectedText => TimeFormatter.DateTime(Source.DetectedUtc);
    public string AdditionalText => Findings.Count > 1 ? $"+{Findings.Count - 1} more finding(s)" : string.Empty;
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

    public string SelectionName => "Select " + FileName;
}

public sealed class ScanErrorItemViewModel
{
    public ScanErrorItemViewModel(ScanError source)
    {
        Source = source;
    }

    public ScanError Source { get; }
    public string Path => Presentation.SanitizePath(Source.Path);
    public string Message => Presentation.Sanitize(Source.Message, 300);
    public string KindLabel => Presentation.ErrorKind(Source.Kind);
    public string Technical => Presentation.Sanitize(Source.Technical, 80);
}

public sealed class HistoryRowViewModel
{
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
    public string MetaText => Presentation.Count(Source.FilesScanned, "file") + " \u00B7 " + DurationText;
    public string StatusText => Source.StatusText;
    public bool Cancelled => Source.Cancelled;
    public bool HasDetections => Source.DetectionCount > 0;
    public bool HasErrors => Source.ErrorCount > 0;
    public string DetectionText => Presentation.Count(Source.DetectionCount, "finding");
    public string ErrorText => Presentation.Count(Source.ErrorCount, "warning");
    public string Glyph => Source.Cancelled ? "\uE711" : HasDetections ? "\uE7BA" : HasErrors ? "\uE7BA" : "\uE73E";
    public string ScopeLabel => Presentation.Scope(Source.Scope);
}

public sealed class QuarantineItemViewModel
{
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
    public string HashShort => Source.Sha256[..16].ToUpperInvariant() + "\u2026";
    public string CategoryLabel => Presentation.Category(Source.Category);
    public string FindingTitle => Presentation.Sanitize(Source.FindingTitle, 180);
    public string FindingDetail => Presentation.Sanitize(Source.FindingDetail, 500);
    public string? Note => string.IsNullOrWhiteSpace(Source.Note) ? null : Presentation.Sanitize(Source.Note, 400);
    public bool HasNote => Note is not null;
    public bool OriginalExists => File.Exists(Source.OriginalPath);
}

public sealed class DetectionRuleViewModel
{
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
}
