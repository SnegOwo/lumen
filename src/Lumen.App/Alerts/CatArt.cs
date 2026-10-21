using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Lumen.App.Alerts;

/// <summary>
/// How the cat is feeling. It has no effect on any detection; it exists because a
/// security tool that takes itself too seriously is a security tool nobody opens.
/// </summary>
public enum CatMood
{
    /// <summary>Wide eyes and an arched back. Something was detected.</summary>
    Alarmed,

    /// <summary>Calm, eyes closed, tail curled. Nothing is happening.</summary>
    Calm,

    /// <summary>Grinning. A detection was dealt with.</summary>
    Content
}

/// <summary>
/// The cat.
///
/// It is a PHOTO, not a drawing. The picture lives in the application resources
/// (<c>Assets/cat.jpg</c> or <c>Assets/cat.png</c>) so it travels inside the
/// executable and needs no file next to it. When no picture is present the control
/// falls back to a simple drawn cat, so the alert always looks like something.
///
/// The only animation is a gentle bob, and it is deliberately cheap: a timer moves a
/// transform, so nothing is redrawn and nothing is allocated. The timer only runs while
/// the cat is on screen and loaded, so a cat that nobody can see costs nothing.
/// </summary>
public sealed class CatArt : Image
{
    private static readonly string[] CandidateResources =
    [
        "pack://application:,,,/Lumen;component/Assets/cat.jpg",
        "pack://application:,,,/Lumen;component/Assets/cat.png"
    ];

    private static readonly string[] CandidateFiles =
    [
        "Assets\\cat.jpg",
        "Assets\\cat.png"
    ];

    private readonly DispatcherTimer _timer;
    private readonly TranslateTransform _bob;
    private double _phase;

    public CatArt()
    {
        _bob = new TranslateTransform();
        RenderTransform = _bob;
        Stretch = Stretch.Uniform;
        SnapsToDevicePixels = true;
        IsHitTestVisible = false;
        Focusable = false;

        Source = LoadPhoto();
        HasPhoto = Source is not null;
        if (!HasPhoto) Source = BuildFallback();

        _timer = new DispatcherTimer(DispatcherPriority.Render)
        {
            Interval = TimeSpan.FromMilliseconds(60)
        };
        _timer.Tick += (_, _) => Advance();

        Loaded += (_, _) => UpdateAnimationState();
        Unloaded += (_, _) => _timer.Stop();
        IsVisibleChanged += (_, _) => UpdateAnimationState();
    }

    /// <summary>
    /// True when a real photograph was found. The drawn cat is only a placeholder for
    /// the case where the picture has not been added to the project yet.
    /// </summary>
    public bool HasPhoto { get; private set; }

    /// <summary>The mood the cat is in.</summary>
    public CatMood Mood
    {
        get => (CatMood)GetValue(MoodProperty);
        set => SetValue(MoodProperty, value);
    }

    public static readonly DependencyProperty MoodProperty = DependencyProperty.Register(
        nameof(Mood),
        typeof(CatMood),
        typeof(CatArt),
        new FrameworkPropertyMetadata(CatMood.Alarmed));

    /// <summary>Stops the bob for a moment, for example while the alert is being read.</summary>
    public void SuspendAnimation() => _timer.Stop();

    /// <summary>Starts the bob again.</summary>
    public void ResumeAnimation() => UpdateAnimationState();

    protected override void OnRenderSizeChanged(SizeChangedInfo info)
    {
        base.OnRenderSizeChanged(info);
        UpdateAnimationState();
    }

    private void UpdateAnimationState()
    {
        if (IsVisible && IsLoaded) _timer.Start();
        else _timer.Stop();
    }

    private void Advance()
    {
        // A slow, shallow bob. It is a transform change, so the picture is never
        // redrawn and nothing is allocated.
        _phase += 0.05;
        if (_phase > 200) _phase -= 200;
        _bob.Y = Math.Sin(_phase * 0.5) * 3.0;
    }

    private static ImageSource? LoadPhoto()
    {
        foreach (var uri in CandidateResources)
        {
            var source = TryLoad(uri);
            if (source is not null) return source;
        }

        foreach (var relative in CandidateFiles)
        {
            var path = Path.Combine(AppContext.BaseDirectory, relative);
            if (!File.Exists(path)) continue;
            var source = TryLoad(path);
            if (source is not null) return source;
        }

        return null;
    }

    private static ImageSource? TryLoad(string location)
    {
        try
        {
            var source = new BitmapImage();
            source.BeginInit();
            source.UriSource = new Uri(location, UriKind.Absolute);
            source.CacheOption = BitmapCacheOption.OnLoad;
            source.EndInit();
            source.Freeze();
            return source;
        }
        catch (Exception ex) when (ex is IOException or UriFormatException or NotSupportedException or ArgumentException)
        {
            // Not usable. Try the next one.
            return null;
        }
    }

    /// <summary>
    /// A plain drawn cat, used only when the photograph has not been added to the
    /// project. It is built once and frozen, so it costs nothing to display.
    /// </summary>
    private static ImageSource BuildFallback()
    {
        var group = new DrawingGroup();

        var body = new EllipseGeometry(new Rect(26, 58, 68, 62));
        var head = new EllipseGeometry(new Rect(30, 18, 60, 54));
        var chest = new EllipseGeometry(new Rect(44, 78, 32, 34));
        var eye = new EllipseGeometry(new Rect(46, 38, 10, 12));
        var eye2 = new EllipseGeometry(new Rect(64, 38, 10, 12));

        var nose = new StreamGeometry();
        using (var ctx = nose.Open())
        {
            ctx.BeginFigure(new Point(56, 52), isFilled: true, isClosed: true);
            ctx.LineTo(new Point(64, 52), isStroked: false, isSmoothJoin: false);
            ctx.LineTo(new Point(60, 58), isStroked: false, isSmoothJoin: false);
        }
        nose.Freeze();

        var fur = new SolidColorBrush(Color.FromRgb(0x3A, 0x44, 0x5C));
        var light = new SolidColorBrush(Color.FromRgb(0x5A, 0x66, 0x80));
        var accent = new SolidColorBrush(Color.FromRgb(0x5E, 0xEA, 0xD4));

        group.Children.Add(new GeometryDrawing(fur, null, body));
        group.Children.Add(new GeometryDrawing(light, null, chest));
        group.Children.Add(new GeometryDrawing(fur, null, head));
        group.Children.Add(new GeometryDrawing(accent, null, eye));
        group.Children.Add(new GeometryDrawing(accent, null, eye2));
        group.Children.Add(new GeometryDrawing(accent, null, nose));

        group.Freeze();

        var drawing = new DrawingImage(group);
        drawing.Freeze();
        return drawing;
    }
}
