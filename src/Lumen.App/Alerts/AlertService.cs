using System.Media;
using System.Windows;
using System.Windows.Threading;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.Alerts;

/// <summary>
/// Where a detection came from. It decides who tells the user about it, so that a
/// detection is never announced twice.
/// </summary>
public enum AlertOrigin
{
    /// <summary>
    /// An on-demand scan. Nothing else tells the user about a single scan finding,
    /// so the alert service does it.
    /// </summary>
    Scan,

    /// <summary>
    /// The real-time monitor. It has already put a message in the notification
    /// area, so the alert service does not repeat it.
    /// </summary>
    Realtime
}

/// <summary>
/// A detection that was recorded but not announced. The detection itself is never
/// lost: it is in the results list and in the history, whatever happened here.
/// </summary>
public sealed record AlertSuppression
{
    /// <summary>The name of the file, without its folder.</summary>
    public required string FileName { get; init; }

    /// <summary>Why the alert was not shown, in English.</summary>
    public required string Reason { get; init; }

    /// <summary>Where the detection came from.</summary>
    public required AlertOrigin Origin { get; init; }
}

/// <summary>
/// Shows the loud detection alert and plays the noise.
///
/// <para>
/// Everything here is optional and every switch is in the Settings page. The alert
/// is a demonstration feature: Lumen's job is to make sure a detection is never
/// missed, and a quiet line of text in a corner is easy to miss.
/// </para>
///
/// <para>
/// Loud is not the same as constant. A busy folder can produce dozens of findings
/// in a second, and a window that takes over the screen for every one of them is
/// how the whole application came to feel slow. Three rules keep the noise down,
/// and none of them ever loses a detection:
/// </para>
///
/// <list type="number">
/// <item><description>
/// <see cref="AlertPolicy"/> decides whether a finding is strong enough to be
/// worth the screen. A medium or low finding is listed, not announced.
/// </description></item>
/// <item><description>
/// The same file is not announced twice in a row. The cooldown is the same two
/// minutes the real-time monitor already uses for the same rule.
/// </description></item>
/// <item><description>
/// There is never more than one alert window. A finding that arrives while a
/// window is open is recorded and reported quietly.
/// </description></item>
/// </list>
/// </summary>
public sealed class AlertService
{
    /// <summary>
    /// How many announced paths are remembered. The map is bounded so it cannot
    /// grow without limit, whatever the machine finds.
    /// </summary>
    private const int MaxAnnouncedPaths = 512;

    private readonly global::Lumen.App.Services.AppServices _services;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _announced = new(StringComparer.OrdinalIgnoreCase);
    private int _alertWindowOpen;
    private DateTimeOffset _lastQuietNotification = DateTimeOffset.MinValue;

    public AlertService(global::Lumen.App.Services.AppServices services)
    {
        _services = services;
    }

    /// <summary>
    /// How long the same file stays quiet after it has been announced.
    ///
    /// <para>
    /// The real-time monitor already refuses to report the same path twice within
    /// two minutes, and the alert follows the same rule so that both agree on what
    /// "the same detection" means. A value of zero or less turns the cooldown off,
    /// which is useful when a single file is deliberately tested again and again.
    /// </para>
    /// </summary>
    public TimeSpan Cooldown { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// How long the notification area stays quiet after a "recorded without an
    /// alert" message.
    ///
    /// <para>
    /// A busy folder can produce dozens of findings in a second. Every one of them
    /// is in the results list, and the notification area only needs to say it once
    /// in a while — otherwise the tray becomes the next thing that lags the
    /// machine. A value of zero or less posts a message for every finding.
    /// </para>
    /// </summary>
    public TimeSpan QuietNotificationInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Raised when the user asks for the alerted file to be quarantined.</summary>
    public event EventHandler<string>? QuarantineRequested;

    /// <summary>
    /// Raised when a detection was recorded but no alert window was shown.
    ///
    /// <para>
    /// The shell uses this to tell the user that something was seen. The detection
    /// itself is never dropped: it stays in the results list and in the history, and
    /// nothing is moved, deleted or quarantined because of it.
    /// </para>
    /// </summary>
    public event EventHandler<AlertSuppression>? AlertSuppressed;

    /// <summary>
    /// Shows the alert for a detection. The call returns immediately; the alert
    /// window owns itself until the user dismisses it.
    ///
    /// <para>
    /// The alert is only shown when it is worth the screen: a strong finding, a
    /// test signature, a file that was not announced recently, and no other alert
    /// window already open. Everything else is recorded and reported quietly.
    /// </para>
    /// </summary>
    /// <param name="detection">The detection that was recorded.</param>
    /// <param name="fileName">The name of the file, for the window.</param>
    /// <param name="ruleTitle">The name of the rule that matched, for the window.</param>
    /// <param name="confidence">The confidence, already in the interface language.</param>
    /// <param name="origin">Where the detection came from.</param>
    public void Show(
        ScanDetection detection,
        string fileName,
        string ruleTitle,
        string confidence,
        AlertOrigin origin = AlertOrigin.Scan)
    {
        var settings = _services.Settings;
        if (!settings.DetectionAlertEnabled) return;

        // Lumen's own demonstration file exists to show the alert, and the user
        // asked for it explicitly. It is never filtered and never cooled down.
        var demonstration = IsDemonstrationSample(detection.FilePath);
        if (!demonstration && !AlertPolicy.ShouldAlert(detection.Findings, out var reason))
        {
            Suppress(
                detection,
                fileName,
                reason,
                origin);
            return;
        }

        RunOnUI(() => Present(detection, fileName, ruleTitle, confidence, settings, origin, demonstration));
    }

    /// <summary>
    /// Puts the window on the screen. Only one alert window may exist at a time.
    /// </summary>
    private void Present(
        ScanDetection detection,
        string fileName,
        string ruleTitle,
        string confidence,
        AppSettings settings,
        AlertOrigin origin,
        bool demonstration)
    {
        if (Interlocked.CompareExchange(ref _alertWindowOpen, 1, 0) != 0)
        {
            Suppress(
                detection,
                fileName,
                "Another alert window is already open, so this one was not shown.",
                origin);
            return;
        }

        try
        {
            if (!demonstration && IsOnCooldown(detection.FilePath, out var cooldownReason))
            {
                // The window was never opened, so the place is free again.
                Interlocked.Exchange(ref _alertWindowOpen, 0);
                Suppress(detection, fileName, cooldownReason, origin);
                return;
            }

            RecordAnnouncement(detection.FilePath);

            if (settings.DetectionAlertSoundEnabled) PlayAlertSound();

            var window = new DetectionAlertWindow(
                BuildStrings(settings.Language),
                DisplayText.Sanitize(fileName, 120),
                DisplayText.Sanitize(ruleTitle, 120),
                DisplayText.Sanitize(confidence, 40),
                settings.DetectionAlertCatEnabled);

            window.QuarantineRequested += (_, _) =>
            {
                var path = detection.FilePath;
                RunOnUI(() => QuarantineRequested?.Invoke(this, path));
            };

            window.Closed += (_, _) => Interlocked.Exchange(ref _alertWindowOpen, 0);
            window.Show();
            window.Activate();
        }
        catch (Exception ex)
        {
            Interlocked.Exchange(ref _alertWindowOpen, 0);
            _services.Log.Warn("Alert", "The detection alert could not be shown.", ex);
        }
    }

    /// <summary>
    /// Records a detection that was not announced and tells the user about it.
    ///
    /// <para>
    /// Nothing is lost. The detection is in the results list and in the history, the
    /// notification area says that something was seen, and the shell is told through
    /// <see cref="AlertSuppressed"/>.
    /// </para>
    /// </summary>
    private void Suppress(ScanDetection detection, string fileName, string reason, AlertOrigin origin)
    {
        _services.Log.Info(
            "Alert",
            "No alert window for " + DisplayText.SanitizePath(detection.FilePath) + ": " + reason);

        // The real-time monitor has already put a message in the notification area,
        // so a second one would only be noise.
        if (origin == AlertOrigin.Scan) NotifyQuietly(fileName, reason);

        var suppression = new AlertSuppression
        {
            FileName = DisplayText.Sanitize(fileName, 160),
            Reason = reason,
            Origin = origin
        };

        RunOnUI(() => AlertSuppressed?.Invoke(this, suppression));
    }

    /// <summary>
    /// Puts a short message in the notification area. The message is rate limited,
    /// so a busy folder cannot turn the notification area into a firehose.
    /// </summary>
    private void NotifyQuietly(string fileName, string reason)
    {
        var tray = _services.Tray;
        if (tray is null) return;

        var now = _services.Clock.UtcNow;
        lock (_gate)
        {
            if (now - _lastQuietNotification < QuietNotificationInterval) return;
            _lastQuietNotification = now;
        }

        tray.Notify(
            "Detection recorded",
            DisplayText.Sanitize(fileName, 120) + " was recorded without an alert: " + reason +
            " Nothing was changed.");
    }

    /// <summary>
    /// True when the same file was announced recently enough to stay quiet.
    /// </summary>
    private bool IsOnCooldown(string path, out string reason)
    {
        reason = "The same file was announced recently, so it was not announced twice.";
        if (Cooldown <= TimeSpan.Zero) return false;
        if (string.IsNullOrWhiteSpace(path)) return false;

        lock (_gate)
        {
            PruneAnnouncements();
            if (!_announced.TryGetValue(path, out var last)) return false;
            if (_services.Clock.UtcNow - last >= Cooldown) return false;
        }

        return true;
    }

    /// <summary>
    /// Remembers that a file has been announced, so it stays quiet for the
    /// cooldown.
    /// </summary>
    private void RecordAnnouncement(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;

        lock (_gate)
        {
            _announced[path] = _services.Clock.UtcNow;
            PruneAnnouncements();
        }
    }

    /// <summary>
    /// Drops the paths that are no longer in the cooldown, and keeps the map within
    /// its bound whatever happens.
    /// </summary>
    private void PruneAnnouncements()
    {
        if (_announced.Count == 0) return;

        var window = Cooldown > TimeSpan.Zero ? Cooldown : TimeSpan.FromMinutes(10);
        var cutoff = _services.Clock.UtcNow - window;

        var expired = new List<string>();
        foreach (var pair in _announced)
        {
            if (pair.Value < cutoff) expired.Add(pair.Key);
        }

        foreach (var key in expired) _announced.Remove(key);

        while (_announced.Count > MaxAnnouncedPaths)
        {
            var oldest = string.Empty;
            var oldestAt = DateTimeOffset.MaxValue;
            foreach (var pair in _announced)
            {
                if (pair.Value >= oldestAt) continue;
                oldest = pair.Key;
                oldestAt = pair.Value;
            }

            if (oldest.Length == 0) return;
            _announced.Remove(oldest);
        }
    }

    /// <summary>
    /// True when the path is Lumen's own demonstration file.
    ///
    /// <para>
    /// The demonstration file is harmless text that Lumen wrote itself, and the
    /// rules that match it are only heuristics. The user asked for the
    /// demonstration, so the alert is always shown for it.
    /// </para>
    /// </summary>
    private static bool IsDemonstrationSample(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        var name = Path.GetFileName(path);
        return string.Equals(
            name,
            global::Lumen.Core.Detection.DemoSample.FileName,
            StringComparison.OrdinalIgnoreCase);
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
                NothingChanged = "Rien n'a été modifié.",
                QuietTitle = "Détection enregistrée",
                QuietDetailOne = "1 détection a été enregistrée sans alerte.",
                QuietDetailMany = "{0} détections ont été enregistrées sans alerte."
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
                NothingChanged = "Nothing was changed.",
                QuietTitle = "Detection recorded",
                QuietDetailOne = "1 detection was recorded without an alert.",
                QuietDetailMany = "{0} detections were recorded without an alert."
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
