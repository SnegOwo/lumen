using System.Collections.ObjectModel;
using System.ComponentModel;
using Lumen.App.Infrastructure;
using Lumen.App.Localization;
using Lumen.Core.Models;

namespace Lumen.App.Remediation;

/// <summary>
/// The state of the remediation plan window. It shows a plan that has not been executed
/// yet, and afterwards the outcome of every step that ran.
/// </summary>
public sealed class RemediationPlanViewModel : ObservableObject, IDisposable
{
    private bool _isExecuting;
    private bool _hasResult;
    private string _resultTitle = string.Empty;
    private string _resultMessage = string.Empty;
    private bool _allSelected = true;
    private bool _hasError;
    private string _errorText = string.Empty;
    private bool _disposed;

    /// <summary>Creates the view model for a plan that has been produced but not run.</summary>
    public RemediationPlanViewModel(RemediationPlan plan)
    {
        Plan = plan;
        Steps = new ObservableCollection<RemediationStepViewModel>(
            plan.Steps.Select(step => new RemediationStepViewModel(step)));

        Text.LanguageChanged += OnLanguageChanged;
    }

    /// <summary>The plan the window is about.</summary>
    public RemediationPlan Plan { get; }

    /// <summary>The steps, in the order they would run.</summary>
    public ObservableCollection<RemediationStepViewModel> Steps { get; }

    /// <summary>The name of the file the plan is about.</summary>
    public string FileName => Path.GetFileName(Plan.Target.FilePath);

    /// <summary>The full path of the file the plan is about.</summary>
    public string FilePath => Plan.Target.FilePath;

    /// <summary>The title of the finding that produced the plan.</summary>
    public string FindingTitle => Plan.Target.FindingTitle;

    /// <summary>The extra detail of the finding.</summary>
    public string FindingDetail => Plan.Target.FindingDetail ?? string.Empty;

    /// <summary>True when the finding carries an extra detail line.</summary>
    public bool HasFindingDetail => !string.IsNullOrWhiteSpace(FindingDetail);

    /// <summary>The title of the window.</summary>
    public string TitleText => Text.RemediationPlanTitleFor(FileName);

    /// <summary>The short reminder shown next to the buttons.</summary>
    public string PlanHint => Text.RemediationNothingChangedYet;

    /// <summary>True when the run reported an error the user has to know about.</summary>
    public bool HasError
    {
        get => _hasError;
        private set => SetProperty(ref _hasError, value);
    }

    /// <summary>The error the run reported.</summary>
    public string ErrorText
    {
        get => _errorText;
        private set => SetProperty(ref _errorText, value);
    }

    /// <summary>True when the plan has at least one step.</summary>
    public bool HasSteps => Steps.Count > 0;

    /// <summary>True when the steps can still be selected.</summary>
    public bool CanSelectSteps => Steps.Count > 0 && !HasResult;

    /// <summary>True while the selected steps are running.</summary>
    public bool IsExecuting
    {
        get => _isExecuting;
        set => SetProperty(ref _isExecuting, value);
    }

    /// <summary>True once the outcome of the run is on screen.</summary>
    public bool HasResult
    {
        get => _hasResult;
        private set
        {
            if (!SetProperty(ref _hasResult, value)) return;
            OnPropertyChanged(nameof(CanSelectSteps));
        }
    }

    /// <summary>The headline of the outcome.</summary>
    public string ResultTitle
    {
        get => _resultTitle;
        private set => SetProperty(ref _resultTitle, value);
    }

    /// <summary>The overall outcome, in plain language.</summary>
    public string ResultMessage
    {
        get => _resultMessage;
        private set => SetProperty(ref _resultMessage, value);
    }

    /// <summary>
    /// Ticks or unticks every step at once. It stops working once the run has started.
    /// </summary>
    public bool AllSelected
    {
        get => _allSelected;
        set
        {
            if (!SetProperty(ref _allSelected, value)) return;
            if (HasResult) return;
            foreach (var step in Steps) step.IsSelected = value;
        }
    }

    /// <summary>The ids of the steps the user ticked.</summary>
    public IReadOnlyCollection<string> SelectedStepIds =>
        Steps.Where(step => step.IsSelected).Select(step => step.Id).ToArray();

    /// <summary>Replaces the plan steps with the outcome of the run.</summary>
    public void ApplyResult(RemediationResult result)
    {
        foreach (var step in Steps)
        {
            var updated = result.Steps.FirstOrDefault(candidate =>
                string.Equals(candidate.Id, step.Id, StringComparison.OrdinalIgnoreCase));
            if (updated is null) continue;

            step.ApplyOutcome(updated);
        }

        ResultTitle = result.Status switch
        {
            RemediationStatus.Executed => Text.RemediationDoneTitle,
            RemediationStatus.PartiallyExecuted => Text.RemediationWarnTitle,
            RemediationStatus.Failed => Text.RemediationWarnTitle,
            RemediationStatus.Cancelled => Text.RemediationStatusCancelled,
            _ => Text.RemediationStatusRefused
        };

        ResultMessage = result.Status switch
        {
            RemediationStatus.Executed => Text.RemediationStatusExecuted,
            RemediationStatus.PartiallyExecuted => Text.RemediationStatusPartial,
            RemediationStatus.Failed => Text.RemediationStatusFailed,
            RemediationStatus.Cancelled => Text.RemediationStatusCancelled,
            _ => Text.RemediationStatusRefused
        };

        HasResult = true;
        AllSelected = false;
    }

    /// <summary>Shows an error that stopped the run.</summary>
    public void SetError(string message)
    {
        ErrorText = message;
        HasError = !string.IsNullOrWhiteSpace(message);
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(
            nameof(FindingTitle),
            nameof(FindingDetail),
            nameof(AllSelected),
            nameof(ResultTitle),
            nameof(ResultMessage));

        foreach (var step in Steps) step.Refresh();
    }

    /// <summary>Unsubscribes from the language event.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Text.LanguageChanged -= OnLanguageChanged;
    }
}
