using System.Windows;
using Lumen.Core.Models;

namespace Lumen.App.Remediation;

/// <summary>
/// The remediation plan window. It shows what Lumen <em>would</em> do, lets the user
/// tick the steps they want, and only then runs them. Nothing is changed before the
/// user presses the execute button.
/// </summary>
public partial class RemediationPlanWindow : Window
{
    private readonly RemediationPlanViewModel _viewModel;
    private readonly Func<IReadOnlyCollection<string>, Task<RemediationResult>> _executor;

    /// <summary>
    /// Creates the window for a plan.
    /// </summary>
    /// <param name="plan">The plan the engine produced. It has not been executed.</param>
    /// <param name="executor">Runs the steps the user confirmed and returns the outcome.</param>
    public RemediationPlanWindow(
        RemediationPlan plan,
        Func<IReadOnlyCollection<string>, Task<RemediationResult>> executor)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(executor);

        InitializeComponent();

        _executor = executor;
        _viewModel = new RemediationPlanViewModel(plan);
        DataContext = _viewModel;

        Closed += (_, _) => _viewModel.Dispose();
    }

    private async void OnExecuteClicked(object sender, RoutedEventArgs e)
    {
        var stepIds = _viewModel.SelectedStepIds;
        if (stepIds.Count == 0) return;

        _viewModel.IsExecuting = true;
        ExecuteButton.IsEnabled = false;

        try
        {
            var result = await _executor(stepIds);
            _viewModel.ApplyResult(result);
        }
        catch (Exception ex)
        {
            _viewModel.SetError(ex.Message);
        }
        finally
        {
            _viewModel.IsExecuting = false;
            ExecuteButton.IsEnabled = true;
        }
    }

    private void OnCancelClicked(object sender, RoutedEventArgs e) => Close();
}
