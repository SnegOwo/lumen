using System.Media;
using System.Windows;
using System.Windows.Threading;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.Alerts;

/// <summary>
/// Shows the loud detection alert and plays the noise.
///
/// Everything here is optional and every switch is in the Settings page. The alert is
/// a demonstration feature: Lumen's job is to make sure a detection is never missed,
/// and a quiet line of text in a corner is easy to miss.
/// </summary>
public sealed class AlertService
{
    private readonly global::Lumen.App.Services.AppServices _services;
    private bool _showing;

    public AlertService(global::Lumen.App.Services.AppServices services)
    {
        _services = services;
    }

    /// <summary>Raised when the user asks for the alerted file to be quarantined.</summary>
    public event EventHandler<string>? QuarantineRequested;

    /// <summary>
    /// Shows the alert for a detection. The call returns immediately; the alert window
    /// owns itself until the user dismisses it.
    /// </summary>
    public void Show(ScanDetection detection, string fileName, string ruleTitle, string confidence)
    {
        var settings = _services.Settings;
        if (!settings.DetectionAlertEnabled) return;
        if (_showing) return;

        var strings = BuildStrings(settings.Language);

        RunOnUI(() =>
        {
            if (_showing) return;
            _showing = true;

            try
            {
                if (settings.DetectionAlertSoundEnabled) PlayAlertSound();

                var window = new DetectionAlertWindow(
                    strings,
                    DisplayText.Sanitize(fileName, 120),
                    DisplayText.Sanitize(ruleTitle, 120),
                    DisplayText.Sanitize(confidence, 40),
                    settings.DetectionAlertCatEnabled);

                window.QuarantineRequested += (_, _) =>
                {
                    var path = detection.FilePath;
                    RunOnUI(() => QuarantineRequested?.Invoke(this, path));
                };

                window.Closed += (_, _) => _showing = false;
                window.Show();
                window.Activate();
            }
            catch (Exception ex)
            {
                _showing = false;
                _services.Log.Warn("Alert", "The detection alert could not be shown.", ex);
            }
        });
    }

    /// <summary>
    /// The alert wording, in the language the user selected.
    /// </summary>
    public static AlertStrings BuildStrings(AppLanguage language) =>
        language == AppLanguage.Francais
            ? new AlertStrings
            {
                Headline = "MALWARE DÉTECTÉ",
                Subhead = "Un fichier correspond à une règle de Lumen.",
                Quarantine = "Mettre en quarantaine",
                Dismiss = "Fermer",
                FileLabel = "Fichier",
                RuleLabel = "Règle",
                ConfidenceLabel = "Confiance",
                NothingChanged = "Rien n'a été modifié."
            }
            : new AlertStrings
            {
                Headline = "MALWARE DETECTED",
                Subhead = "A file matched a Lumen rule.",
                Quarantine = "Quarantine",
                Dismiss = "Dismiss",
                FileLabel = "File",
                RuleLabel = "Rule",
                ConfidenceLabel = "Confidence",
                NothingChanged = "Nothing was changed."
            };

    /// <summary>
    /// Plays the alert noise. It uses only sounds that ship with Windows, so there is
    /// no audio file to ship, download or fail to load.
    /// </summary>
    private static void PlayAlertSound()
    {
        try
        {
            SystemSounds.Exclamation.Play();
        }
        catch
        {
            // Audio is a nicety. A machine with no sound card must still work.
        }

        try
        {
            // A short two-tone siren, because one beep is not alarming enough.
            for (var index = 0; index < 2; index++)
            {
                Console.Beep(880, 180);
                Console.Beep(660, 180);
            }
        }
        catch
        {
            // Some sessions have no console attached.
        }
    }

    private static void RunOnUI(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess()) action();
        else dispatcher.BeginInvoke(action, DispatcherPriority.Normal);
    }
}
