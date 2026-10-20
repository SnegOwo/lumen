using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Shapes;

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
}

/// <summary>
/// A deliberately loud, deliberately unserious window that appears when Lumen flags
/// something. It is a demonstration build: the point is that the user SEES the
/// detection, and a quiet corner of the interface does not achieve that.
///
/// The window is built entirely in code, so it never collides with the theme
/// dictionaries and always works even if a resource is missing.
/// </summary>
public sealed class DetectionAlertWindow : Window
{
    private readonly Storyboard _pulse;

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
        var border = new Border
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

        _pulse = new Storyboard();
        var thicknessAnimation = new ThicknessAnimation
        {
            From = new Thickness(4),
            To = new Thickness(9),
            Duration = new Duration(TimeSpan.FromMilliseconds(700)),
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever
        };
        Storyboard.SetTarget(thicknessAnimation, border);
        Storyboard.SetTargetProperty(thicknessAnimation, new PropertyPath(Border.BorderThicknessProperty));
        _pulse.Children.Add(thicknessAnimation);
        _pulse.Begin(border, true);

        var content = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
        border.Child = content;
        root.Children.Add(border);

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

        KeyDown += (_, args) =>
        {
            if (args.Key == Key.Escape) Close();
        };
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

    protected override void OnClosed(EventArgs e)
    {
        _pulse.Stop();
        base.OnClosed(e);
    }
}
