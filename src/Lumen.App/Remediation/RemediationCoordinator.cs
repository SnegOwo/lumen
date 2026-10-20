using System.Windows;
using Lumen.App.Dialogs;
using Lumen.App.Localization;
using Lumen.Core.Models;

namespace Lumen.App.Remediation;

/// <summary>
/// Drives the remediation flow: plan, then review, then confirm, then execute.
///
/// <para>
/// The order is the whole point. <see cref="RemediationEngine.PlanAsync"/> only reads
/// the world, the plan window shows what would happen, and only the user's
/// confirmation leads to <see cref="RemediationEngine.ExecuteAsync"/>. Nothing is
/// stopped and nothing is deleted before that.
/// </para>
/// </summary>
public sealed class RemediationCoordinator
{
    private readonly global::Lumen.App.Services.AppServices _services;

    /// <summary>Creates the coordinator for the running application.</summary>
    public RemediationCoordinator(global::Lumen.App.Services.AppServices services)
    {
        _services = services;
    }

    /// <summary>
    /// True when the user allowed remediation actions. The master switch is off by
    /// default, and the UI hides the action entirely while it is off.
    /// </summary>
    public bool IsEnabled => _services.Settings.RemediationEnabled;

    /// <summary>
    /// Runs the full flow for one file. The plan window is shown modally and stays
    /// open with the outcome once the steps have run.
    /// </summary>
    /// <returns>True when steps actually ran; false when the user cancelled.</returns>
    public async Task<bool> RunAsync(RemediationTarget target, CancellationToken cancellationToken)
    {
        if (!IsEnabled)
        {
            _services.Dialogs.ShowMessage(
                Text.RemediationDisabledTitle,
                Text.RemediationDisabledBody,
                MessageSeverity.Warning);
            return false;
        }

        RemediationPlan plan;
        try
        {
            plan = await _services.Remediation.PlanAsync(target, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _services.Log.Error("Remediation", "The remediation plan could not be produced.", ex);
            _services.Dialogs.ShowMessage(
                Text.RemediationPlanFailedTitle,
                Text.RemediationPlanFailedBody,
                MessageSeverity.Warning,
                ex.Message);
            return false;
        }

        if (plan.Status == RemediationStatus.Refused || plan.Steps.Count == 0)
        {
            _services.Dialogs.ShowMessage(
                Text.RemediationPlanFailedTitle,
                string.IsNullOrWhiteSpace(plan.Message)
                    ? Text.RemediationPlanFailedBody
                    : plan.Message,
                MessageSeverity.Warning);
            return false;
        }

        var window = new RemediationPlanWindow(
            plan,
            ids => _services.Remediation.ExecuteAsync(plan, ids, cancellationToken));

        var owner = Application.Current?.MainWindow;
        if (owner is { IsVisible: true }) window.Owner = owner;

        window.ShowDialog();
        return true;
    }
}
