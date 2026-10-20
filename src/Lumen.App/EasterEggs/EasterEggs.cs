using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Lumen.App.Alerts;
using Lumen.App.Dialogs;
using Lumen.Core.Models;

namespace Lumen.App.EasterEggs;

/// <summary>
/// The joke layer.
///
/// Lumen is a serious piece of software that happens to contain a cat, and these are
/// the places where the cat is allowed to take the controls. Nothing here changes how
/// a file is inspected, a match is reported or a quarantine is performed: the worst a
/// joke can do is change a colour, move a picture or say something silly.
///
/// - The Konami code puts Lumen into CAT MODE.
/// - F9 raises a demonstration detection, so the alert can be shown on camera without
///   preparing a file first.
/// - Ctrl+Alt+C sends a cat across the bottom of the window.
/// - Clicking the cat in CAT MODE produces a completely fictional bug report.
/// </summary>
public sealed class EasterEggs : IDisposable
{
    private static readonly Key[] Konami =
    [
        Key.Up, Key.Up, Key.Down, Key.Down,
        Key.Left, Key.Right, Key.Left, Key.Right,
        Key.B, Key.A
    ];

    private static readonly string[] CatPalette = ["Accent.Primary", "Accent.PrimaryHover", "Accent.PrimaryPressed", "Accent.Text", "Accent.Soft", "Accent.SoftBorder"];
    private static readonly Brush[] CatBrushes =
    [
        new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)),
        new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24)),
        new SolidColorBrush(Color.FromRgb(0xD9, 0x77, 0x06)),
        new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24)),
        new SolidColorBrush(Color.FromRgb(0x3B, 0x2A, 0x10)),
        new SolidColorBrush(Color.FromRgb(0x78, 0x4F, 0x0C))
    ];

    private readonly Window _window;
    private readonly global::Lumen.App.Services.AppServices _services;
    private readonly KeySequenceWatcher _watcher = new(Konami);
    private readonly DispatcherTimer _walker;
    private Panel? _root;
    private FrameworkElement? _overlay;
    private FrameworkElement? _walkerCat;
    private double _walkX;
    private bool _catMode;

    public EasterEggs(Window window, global::Lumen.App.Services.AppServices services)
    {
        _window = window;
        _services = services;

        _walker = new DispatcherTimer(DispatcherPriority.Render) { Interval = TimeSpan.FromMilliseconds(16) };
        _walker.Tick += (_, _) => AdvanceWalker();
    }

    /// <summary>True while CAT MODE is on.</summary>
    public bool CatMode => _catMode;

    /// <summary>True when the interface is in French, so the jokes can be too.</summary>
    private bool French => _services.Language == AppLanguage.Francais;

    public void Install()
    {
        _window.PreviewKeyDown += OnPreviewKeyDown;
        _window.Loaded += (_, _) =>
        {
            _root = _window.Content as Panel;
        };

        // The window may already be loaded by the time this runs, in which case the
        // Loaded event will never fire and the overlay would have nowhere to go.
        if (_window.IsLoaded) _root = _window.Content as Panel;
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && _catMode)
        {
            SetCatMode(false);
            e.Handled = true;
            return;
        }

        // F9 raises the demonstration detection. It is the fastest way to show the
        // alert on camera without a test file, a scan, or any explanation.
        if (e.Key == Key.F9)
        {
            _services.TriggerDemoDetection();
            e.Handled = true;
            return;
        }

        // Ctrl+Alt+C sends a cat across the bottom of the window.
        if (e.Key == Key.C && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Alt))
        {
            WalkTheCat();
            e.Handled = true;
            return;
        }

        if (_watcher.Observe(e.Key))
        {
            _services.Log.Info("EasterEgg", "The Konami code was entered. Cat mode is now " + (!_catMode) + ".");
            SetCatMode(!_catMode);
        }
    }

    /// <summary>
    /// CAT MODE: the accent colour becomes a cat colour and a very smug cat appears.
    /// The scanner is unchanged; only the mood is.
    /// </summary>
    private void SetCatMode(bool enabled)
    {
        _catMode = enabled;

        if (enabled)
        {
            for (var index = 0; index < CatPalette.Length; index++)
            {
                var brush = CatBrushes[index];
                brush.Freeze();
                _window.Resources[CatPalette[index]] = brush;
            }

            ShowOverlay(
                "CAT MODE",
                French
                    ? "Lumen est maintenant 100 % plus précis. Cette affirmation est décorative."
                    : "Lumen is now 100% more accurate. This claim is decorative.",
                mood: CatMood.Content);
        }
        else
        {
            foreach (var key in CatPalette) _window.Resources.Remove(key);
            HideOverlay();
        }
    }

    /// <summary>
    /// Sends a cat across the bottom of the window. It has never been near a file.
    /// </summary>
    private void WalkTheCat()
    {
        if (_root is null) return;
        if (_walkerCat is not null) return;

        var cat = new CatArt
        {
            Mood = CatMood.Alarmed,
            Width = 90,
            Height = 90,
            Fur = new SolidColorBrush(Color.FromRgb(0x3A, 0x44, 0x5C)),
            FurLight = new SolidColorBrush(Color.FromRgb(0x5A, 0x66, 0x80)),
            Accent = new SolidColorBrush(Color.FromRgb(0x5E, 0xEA, 0xD4))
        };
        cat.SetValue(System.Windows.Controls.Panel.ZIndexProperty, 9999);

        var canvas = new Canvas();
        canvas.SetValue(System.Windows.Controls.Panel.ZIndexProperty, 9999);
        canvas.Children.Add(cat);
        _root.Children.Add(canvas);

        _walkerCat = cat;
        _walkX = -100;
        _walker.Start();
    }

    private void AdvanceWalker()
    {
        if (_walkerCat is null || _root is null) return;

        _walkX += 6;
        var width = _root.ActualWidth;
        Canvas.SetLeft(_walkerCat, _walkX);
        Canvas.SetTop(_walkerCat, Math.Max(0, _root.ActualHeight - 110));

        if (_walkX > width + 100)
        {
            _walker.Stop();
            var canvas = _walkerCat.Parent as Panel;
            canvas?.Children.Remove(_walkerCat);
            _walkerCat = null;
        }
    }

    private void ShowOverlay(string title, string message, CatMood mood)
    {
        if (_root is null) return;
        HideOverlay();

        var stack = new StackPanel
        {
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        };

        stack.Children.Add(new TextBlock
        {
            Text = title,
            FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI"),
            FontWeight = FontWeights.Black,
            FontSize = 56,
            Foreground = new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24)),
            HorizontalAlignment = HorizontalAlignment.Center
        });

        var cat = new CatArt
        {
            Mood = mood,
            Width = 220,
            Height = 220,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 10, 0, 10),
            Fur = new SolidColorBrush(Color.FromRgb(0x3A, 0x44, 0x5C)),
            FurLight = new SolidColorBrush(Color.FromRgb(0x5A, 0x66, 0x80)),
            Accent = new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24))
        };
        stack.Children.Add(cat);

        stack.Children.Add(new TextBlock
        {
            Text = message,
            FontSize = 16,
            Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0xED, 0xF7)),
            HorizontalAlignment = HorizontalAlignment.Center,
            TextAlignment = TextAlignment.Center,
            MaxWidth = 520
        });

        var card = new Border
        {
            CornerRadius = new CornerRadius(20),
            Background = new SolidColorBrush(Color.FromArgb(0xF2, 0x14, 0x14, 0x18)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)),
            BorderThickness = new Thickness(3),
            Padding = new Thickness(40, 32, 40, 32),
            Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                BlurRadius = 40,
                Opacity = 0.6,
                Color = Color.FromRgb(0xF5, 0x9E, 0x0B)
            },
            Child = stack
        };

        card.MouseLeftButtonUp += (_, _) => ReportTheFakeBug();

        var host = new Grid { Opacity = 0 };
        host.Children.Add(card);
        Grid.SetColumnSpan(host, 20);
        Grid.SetRowSpan(host, 20);
        host.SetValue(System.Windows.Controls.Panel.ZIndexProperty, 5000);

        _root.Children.Add(host);
        _overlay = host;

        host.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
    }

    private void HideOverlay()
    {
        if (_overlay is null) return;
        var element = _overlay;
        _overlay = null;

        var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(160));
        fade.Completed += (_, _) =>
        {
            if (element.Parent is Panel parent) parent.Children.Remove(element);
        };
        element.BeginAnimation(UIElement.OpacityProperty, fade);
    }

    /// <summary>
    /// A completely fictional bug report. It reports a problem that does not exist,
    /// which is the only kind of bug report this feature can produce.
    /// </summary>
    private void ReportTheFakeBug()
    {
        _services.Dialogs.ShowMessage(
            "Lumen has stopped responding",
            "The scan was interrupted by a cat. No files were affected, because no scan was " +
            "running. Error code 0xC0FFEE. Please try again, ideally without the cat.",
            MessageSeverity.Warning,            "Stack trace:\n" +
            "   at Lumen.Core.Scanning.ScanEngine.ScanCore(ScanRequest request)\n" +
            "   at Lumen.Core.Detection.CatDetector.Inspect(FileProbe probe)\n" +
            "   at Lumen.App.Alerts.CatArt.OnRender(DrawingContext context)");
    }

    public void Dispose()
    {
        _window.PreviewKeyDown -= OnPreviewKeyDown;
        _walker.Stop();
    }
}
