using Lumen.App.Infrastructure;
using Lumen.App.Localization;
using Lumen.Core.Models;

namespace Lumen.App.Remediation;

/// <summary>
/// One step of a remediation plan, as the plan window shows it. The step itself is
/// immutable data produced by the engine; this type only adds the tick box, the
/// wording around it and the outcome that the run reported.
/// </summary>
public sealed class RemediationStepViewModel : ObservableObject
{
    private bool _isSelected = true;
    private RemediationStepStatus _status;
    private string _outcome = string.Empty;

    /// <summary>Wraps a planned step.</summary>
    public RemediationStepViewModel(RemediationStep step)
    {
        Step = step;
        _status = step.Status;
        _outcome = step.Outcome ?? string.Empty;
    }

    /// <summary>The planned step, exactly as the engine produced it.</summary>
    public RemediationStep Step { get; }

    /// <summary>The stable id used to select the step for execution.</summary>
    public string Id => Step.Id;

    /// <summary>What kind of action the step performs.</summary>
    public string KindLabel => Step.Kind switch
    {
        RemediationStepKind.TerminateProcess => Text.RemediationKindTerminate,
        RemediationStepKind.RemoveFile => Text.RemediationKindRemoveFile,
        _ => Text.RemediationKindRemovePersistence
    };

    /// <summary>The engine's own description of the step.</summary>
    public string Description => Step.Description;

    /// <summary>The path the step acts on, when it acts on a path.</summary>
    public string? PathText => Step.TargetPath;

    /// <summary>The process the step stops, when it stops one.</summary>
    public string? ProcessText => Step.ProcessName is null
        ? null
        : $"{Step.ProcessName} (PID {Step.ProcessId})";

    /// <summary>Where an autostart entry lives.</summary>
    public string? LocationText => Step.PersistenceEntry?.Location;

    /// <summary>The path an autostart entry points at.</summary>
    public string? EntryTargetText => Step.PersistenceEntry?.TargetPath;

    /// <summary>True when the step carries a process signature fact.</summary>
    public bool HasSignature => Step.ProcessIsSigned.HasValue;

    /// <summary>The wording about the digital signature of the process.</summary>
    public string SignatureText => Step.ProcessIsSigned == true
        ? Text.RemediationSigned
        : Text.RemediationUnsigned;

    /// <summary>The outcome of the step, once it has run.</summary>
    public string OutcomeText
    {
        get => _outcome;
        private set => SetProperty(ref _outcome, value);
    }

    /// <summary>True when the step reported an outcome.</summary>
    public bool HasOutcome => !string.IsNullOrWhiteSpace(_outcome);

    /// <summary>The state of the step, in the current language.</summary>
    public string StatusLabel => _status switch
    {
        RemediationStepStatus.Succeeded => Text.RemediationSucceeded,
        RemediationStepStatus.Failed => Text.RemediationFailed,
        RemediationStepStatus.Skipped => Text.RemediationSkipped,
        RemediationStepStatus.Refused => Text.RemediationRefused,
        _ => Text.RemediationPending
    };

    /// <summary>True when the step failed, so the window can colour it.</summary>
    public bool IsFailure => _status == RemediationStepStatus.Failed;

    /// <summary>True when the step succeeded.</summary>
    public bool IsSuccess => _status == RemediationStepStatus.Succeeded;

    /// <summary>Whether the user wants this step to run.</summary>
    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }

    /// <summary>Applies the outcome that the run reported for this step.</summary>
    public void ApplyOutcome(RemediationStep outcome)
    {
        _status = outcome.Status;
        OutcomeText = outcome.Outcome ?? string.Empty;
        OnPropertyChanged(
            nameof(StatusLabel),
            nameof(IsFailure),
            nameof(IsSuccess),
            nameof(HasOutcome));
    }

    /// <summary>Re-raises the wording that depends on the interface language.</summary>
    public void Refresh()
    {
        OnPropertyChanged(
            nameof(KindLabel),
            nameof(StatusLabel),
            nameof(SignatureText));
    }
}
