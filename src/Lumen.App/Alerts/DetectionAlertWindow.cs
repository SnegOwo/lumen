using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace Lumen.App.Alerts;

/// <summary>
/// The wording of the detection alert. It is passed in rather than hard-coded so the
/// alert can speak the same language as the rest of the application.
/// </summary>
public sealed record AlertStrings
{
    public string Headline { get; init; } = "MALWARE DETECTED";
    public string Subhead { get; init; } = "A file matched a Lumen rule.";
    public string Quarantine { get; init; } = "Quarantine";
    public string Dismiss { get; init; } = "Dismiss";
    public string FileLabel { get; init; } = "File";
    public string RuleLabel { get; init; } = "Rule";
    public string ConfidenceLabel { get; init; } = "Confidence";
    public string NothingChanged { get; init; } = "Nothing was changed.";

    /// <summary>
    /// The headline of the status line when a detection was recorded without a loud
    /// alert. It says that something was seen, so the user is never left guessing.
    /// </summary>
    public string QuietTitle { get; init; } = "Detection recorded";

    /// <summary>
    /// The status line when exactly one detection was recorded without a loud alert.
    /// </summary>
    public string QuietDetailOne { get; init; } = "1 detection was recorded without an alert.";

    /// <summary>
    /// The status line when several detections were recorded without a loud alert.
    /// {0} is the number of detections.
    /// </summary>
    public string QuietDetailMany { get; init; } = "{0} detections were recorded without an alert.";
}

/// <summary>
/// A deliberately loud, deliberately unserious window that appears when Lumen flags
/// something. It is a demonstration build: the point is that the user SEES the
/// detection, and a quiet corner of the interface does not achieve that.
///
/// <para>
/// Loud does not mean endless. The window keeps itself on top and pulses for a few
/// seconds, then settles: it drops the "always on top" claim and stops the pulsing
/// border. A window that never stops drawing is a window that keeps the interface
/// busy long after the user has read it, and it is the reason a busy folder used to
/// make the whole machine feel slow.
/// </para>
///
/// <para>
/// The window is built entirely in code, so it never collides with the theme
/// dictionaries and always works even if a resource is missing.
/// </para>
/// </summary>
public sealed class DetectionAlertWindow : Window
{
    /// <summary>
    /// How many seconds the window pulses and keeps itself on top before it settles.
    /// Eight seconds is long enough to catch the eye of somebody who is looking at
    /// the screen, and short enough that the window does not shout at somebody who
    /// is working in another program.
    /// </summary>
    private const int SettleSeconds = 8;

    private Storyboard? _pulse;
    private readonly Border _border;
    private readonly DispatcherTimer _settle;
    private readonly CatArt? _cat;
    private bool _pulseAllowed = true;

    public DetectionAlertWindow(AlertStrings strings, string fileName, string rule, string confidence, bool showCat)
    {
        Strings = strings;

        Title = strings.Headline;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        Topmost = true;
        Width = 560;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        var root = new Grid();
        Content = root;

        // The pulsing danger border.
        _border = new Border
        {
            CornerRadius = new CornerRadius(20),
            BorderThickness = new Thickness(4),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),
            Background = new SolidColorBrush(Color.FromArgb(0xFA, 0x14, 0x14, 0x18)),
            Padding = new Thickness(28),
            Margin = new Thickness(18),
            Effect = new DropShadowEffect
            {
                BlurRadius = 40,
                ShadowDepth = 0,
                Opacity = 0.65,
                Color = Color.FromRgb(0xDC, 0x26, 0x26)
            }
        };

        StartPulse();

        // The window settles after a while: it stops pulsing and gives up the "always
        // on top" claim, so an alert that nobody acted on does not keep the machine
        // busy for the rest of the session.
        _settle = new DispatcherTimer { Interval = TimeSpan.FromSeconds(SettleSeconds) };
        _settle.Tick += (_, _) => Settle();

        var content = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
        _border.Child = content;
        root.Children.Add(_border);

        // The headline.
        content.Children.Add(new TextBlock
        {
            Text = strings.Headline,
            FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI"),
            FontWeight = FontWeights.Black,
            FontSize = 40,
            Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71)),
            HorizontalAlignment = HorizontalAlignment.Center,
            TextAlignment = TextAlignment.Center
        });

        content.Children.Add(new TextBlock
        {
            Text = strings.Subhead,
            FontFamily = new FontFamily("Segoe UI, Tahoma"),
            FontSize = 14,
            Foreground = new SolidColorBrush(Color.FromRgb(0xB4, 0xB4, 0xC4)),
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 2, 0, 14)
        });

        if (showCat)
        {
            var cat = new CatArt
            {
                Mood = CatMood.Alarmed,
                Width = 150,
                Height = 150,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 12),
                // The alert card is always dark, so the cat uses its own palette
                // instead of the application's surface colours.
                Fur = new SolidColorBrush(Color.FromRgb(0x3A, 0x44, 0x5C)),
                FurLight = new SolidColorBrush(Color.FromRgb(0x5A, 0x66, 0x80)),
                Accent = new SolidColorBrush(Color.FromRgb(0x5E, 0xEA, 0xD4))
            };
            _cat = cat;
            content.Children.Add(cat);
        }

        content.Children.Add(BuildDetails(strings, fileName, rule, confidence));

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 18, 0, 0)
        };

        var quarantine = new Button
        {
            Content = strings.Quarantine,
            Padding = new Thickness(22, 10, 22, 10),
            Margin = new Thickness(0, 0, 10, 0),
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Cursor = Cursors.Hand,
            Background = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),
            Foreground = Brushes.White,
            BorderThickness = new Thickness(0)
        };

        var dismiss = new Button
        {
            Content = strings.Dismiss,
            Padding = new Thickness(22, 10, 22, 10),
            FontSize = 14,
            Cursor = Cursors.Hand,
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush(Color.FromRgb(0xD4, 0xD4, 0xDC)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x3A, 0x3A, 0x44)),
            BorderThickness = new Thickness(1)
        };

        buttons.Children.Add(quarantine);
        buttons.Children.Add(dismiss);
        content.Children.Add(buttons);

        dismiss.Click += (_, _) => Close();
        quarantine.Click += (_, _) =>
        {
            QuarantineRequested?.Invoke(this, EventArgs.Empty);
            Close();
        };

        // The destructive action must never hold the keyboard focus. If it did, a
        // stray Enter key would quarantine a file that nobody had confirmed.
        dismiss.Focus();

        KeyDown += (_, args) =>
        {
            if (args.Key == Key.Escape) Close();
        };

        Loaded += (_, _) => _settle.Start();
        Activated += OnActivated;
        Deactivated += OnDeactivated;
    }

    public AlertStrings Strings { get; }

    /// <summary>Raised when the user asks for the file to be quarantined.</summary>
    public event EventHandler? QuarantineRequested;

    private static StackPanel BuildDetails(AlertStrings strings, string fileName, string rule, string confidence)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 4, 0, 0) };
        panel.Children.Add(BuildRow(strings.FileLabel, fileName));
        panel.Children.Add(BuildRow(strings.RuleLabel, rule));
        panel.Children.Add(BuildRow(strings.ConfidenceLabel, confidence));
        panel.Children.Add(new TextBlock
        {
            Text = strings.NothingChanged,
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromRgb(0x8B, 0x8B, 0x9B)),
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 12, 0, 0)
        });
        return panel;
    }

    private static UIElement BuildRow(string label, string value)
    {
        var grid = new Grid { Margin = new Thickness(0, 2, 0, 2) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        grid.Children.Add(new TextBlock
        {
            Text = label,
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromRgb(0x8B, 0x8B, 0x9B)),
            VerticalAlignment = VerticalAlignment.Center
        });

        var text = new TextBlock
        {
            Text = value,
            FontSize = 13,
            Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0xED, 0xF7)),
            TextTrimming = TextTrimming.CharacterEllipsis,
            ToolTip = value
        };
        Grid.SetColumn(text, 1);
        grid.Children.Add(text);

        return grid;
    }

    /// <summary>
    /// Builds the pulsing border. The storyboard is built fresh every time the
    /// pulse starts, so restarting it never depends on what a stopped storyboard
    /// remembers.
    /// </summary>
    private Storyboard CreatePulse()
    {
        var thicknessAnimation = new ThicknessAnimation
        {
            From = new Thickness(4),
            To = new Thickness(9),
            Duration = new Duration(TimeSpan.FromMilliseconds(700)),
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever
        };

        Storyboard.SetTarget(thicknessAnimation, _border);
        Storyboard.SetTargetProperty(thicknessAnimation, new PropertyPath(Border.BorderThicknessProperty));

        var storyboard = new Storyboard();
        storyboard.Children.Add(thicknessAnimation);
        return storyboard;
    }

    /// <summary>Starts the pulsing border.</summary>
    private void StartPulse()
    {
        // The previous pulse is stopped first, so two borders never animate at once.
        StopPulse();
        _pulse = CreatePulse();
        _pulse.Begin(_border, true);
    }

    /// <summary>Stops the pulsing border.</summary>
    private void StopPulse() => _pulse?.Stop();

    /// <summary>
    /// Stops the pulsing border and gives up the "always on top" claim. The window
    /// stays on screen until the user dismisses it, but it stops asking for
    /// attention and it stops redrawing itself.
    /// </summary>
    private void Settle()
    {
        _settle.Stop();
        _pulseAllowed = false;
        StopPulse();
        if (Topmost) Topmost = false;
    }

    /// <summary>
    /// The window became the active window again. The pulsing starts once more, but
    /// only while the window is still young enough to deserve it.
    /// </summary>
    private void OnActivated(object? sender, EventArgs e)
    {
        if (_pulseAllowed) StartPulse();
        _cat?.ResumeAnimation();
    }

    /// <summary>
    /// The window lost the focus. A background alert must not keep the interface
    /// busy, so the pulsing stops and the cat stops moving until the user comes
    /// back.
    /// </summary>
    private void OnDeactivated(object? sender, EventArgs e)
    {
        StopPulse();
        _cat?.SuspendAnimation();
    }

    protected override void OnClosed(EventArgs e)
    {
        _settle.Stop();
        StopPulse();
        _cat?.SuspendAnimation();
        base.OnClosed(e);
    }
}
