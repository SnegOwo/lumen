using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

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
/// A cat, drawn entirely with WPF vector primitives — no image assets, no fonts, no
/// downloads. It blinks on its own, its tail sways, and it can look alarmed, calm or
/// content.
///
/// <para>
/// Everything is drawn in the supplied brushes so it follows the current theme.
/// </para>
///
/// <para>
/// The drawing is deliberately cheap, because a cat that redraws itself twenty-five
/// times a second on a machine that is already busy is a nuisance rather than a
/// joke. Everything that does not move — the body, the chest, the head, the ears,
/// the face, the whiskers — is built once, frozen and reused, and the thirteen
/// positions of the tail are built once as well. The animation is a storyboard that
/// advances a single number, so the cat costs a re-render thirteen times a second,
/// and it costs nothing at all while it is hidden, unloaded or in the background.
/// </para>
/// </summary>
public sealed class CatArt : FrameworkElement
{
    /// <summary>
    /// The size of the drawing coordinate system. The cat is drawn once in a square
    /// of this size and then scaled to the element, so one set of geometry serves
    /// every size the cat is used at.
    /// </summary>
    private const double Unit = 120.0;

    /// <summary>
    /// How many times a second the tail moves. The tail is a small detail; thirteen
    /// frames a second is enough to read as alive, and it costs a little over half
    /// of the twenty-five frames a second the cat used to redraw itself at.
    /// </summary>
    private const int FramesPerSecond = 13;

    /// <summary>How many frames make one full sway of the tail: three seconds.</summary>
    private const int FramesPerCycle = FramesPerSecond * 3;

    /// <summary>
    /// How many frames at the start of a cycle the cat keeps its eyes closed. Two
    /// frames is about a tenth of a second, which is long enough to read as a blink.
    /// </summary>
    private const int BlinkFrames = 2;

    /// <summary>The two sides of the cat, from left to right.</summary>
    private static readonly int[] Sides = [-1, 1];

    private Storyboard? _animation;
    private CatCache? _cache;
    private double _cacheWidth;
    private double _cacheHeight;
    private CatMood _cacheMood;
    private Brush? _cacheFur;
    private Brush? _cacheFurLight;
    private Brush? _cacheAccent;
    private bool _suspended;

    public CatArt()
    {
        IsHitTestVisible = false;
        Focusable = false;

        IsVisibleChanged += OnIsVisibleChanged;
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

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

    /// <summary>The main fur colour.</summary>
    public Brush Fur
    {
        get => (Brush)GetValue(FurProperty);
        set => SetValue(FurProperty, value);
    }

    public static readonly DependencyProperty FurProperty = DependencyProperty.Register(
        nameof(Fur),
        typeof(Brush),
        typeof(CatArt),
        new FrameworkPropertyMetadata(Brushes.SlateGray));

    /// <summary>The inner-ear and chest colour.</summary>
    public Brush FurLight
    {
        get => (Brush)GetValue(FurLightProperty);
        set => SetValue(FurLightProperty, value);
    }

    public static readonly DependencyProperty FurLightProperty = DependencyProperty.Register(
        nameof(FurLight),
        typeof(Brush),
        typeof(CatArt),
        new FrameworkPropertyMetadata(Brushes.Silver));

    /// <summary>The colour of the eyes and the outlines.</summary>
    public Brush Accent
    {
        get => (Brush)GetValue(AccentProperty);
        set => SetValue(AccentProperty, value);
    }

    public static readonly DependencyProperty AccentProperty = DependencyProperty.Register(
        nameof(Accent),
        typeof(Brush),
        typeof(CatArt),
        new FrameworkPropertyMetadata(Brushes.Teal));

    /// <summary>
    /// The frame of the tail animation that is on screen. The storyboard advances
    /// this number and does nothing else; the drawing reads it and picks the shape
    /// that belongs to it.
    /// </summary>
    private static readonly DependencyProperty FrameIndexProperty = DependencyProperty.Register(
        "FrameIndex",
        typeof(double),
        typeof(CatArt),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>
    /// Stops the animation while the cat stays on screen.
    ///
    /// <para>
    /// The alert window uses this when the user moves to another window: a cat that
    /// keeps waving in the background is a small waste of somebody else's machine.
    /// The cat is still drawn, it simply stops moving.
    /// </para>
    /// </summary>
    public void SuspendAnimation()
    {
        _suspended = true;
        StopAnimation();
    }

    /// <summary>
    /// Starts the animation again, but only if the cat is actually on screen. A cat
    /// that is hidden or not loaded never runs.
    /// </summary>
    public void ResumeAnimation()
    {
        _suspended = false;
        UpdateAnimationState();
    }

    private void OnLoaded(object sender, RoutedEventArgs args) => UpdateAnimationState();

    private void OnUnloaded(object sender, RoutedEventArgs args)
    {
        // A cat that is no longer on screen must not keep a timer or a clock alive.
        StopAnimation();
    }

    protected override void OnRender(DrawingContext context)
    {
        var width = ActualWidth <= 0 ? Unit : ActualWidth;
        var height = ActualHeight <= 0 ? Unit : ActualHeight;
        var scale = Math.Min(width, height) / Unit;

        var cache = EnsureCache(width, height, scale);
        var frame = CurrentFrame();

        context.DrawGeometry(null, cache.TailPen, cache.Tails[frame]);

        foreach (var part in cache.Parts)
        {
            context.DrawGeometry(part.Fill, part.Stroke, part.Geometry);
        }

        if (IsBlinking(frame))
        {
            foreach (var part in cache.Lids)
            {
                context.DrawGeometry(part.Fill, part.Stroke, part.Geometry);
            }
        }

        context.PushOpacity(0.75);
        context.DrawGeometry(cache.Whiskers.Fill, cache.Whiskers.Stroke, cache.Whiskers.Geometry);
        context.Pop();
    }

    /// <summary>
    /// Builds the geometry of the cat, once, and keeps it until something that
    /// changes it happens.
    ///
    /// <para>
    /// This is the whole point of the cat: the body, the head, the ears, the face and
    /// the whiskers never move, so they are built once, frozen and drawn again and
    /// again. Only the tail moves, and its positions are built once too, one per
    /// frame of the animation. A frame therefore allocates nothing at all.
    /// </para>
    /// </summary>
    private CatCache EnsureCache(double width, double height, double scale)
    {
        if (_cache is not null &&
            _cacheWidth == width &&
            _cacheHeight == height &&
            _cacheMood == Mood &&
            ReferenceEquals(_cacheFur, Fur) &&
            ReferenceEquals(_cacheFurLight, FurLight) &&
            ReferenceEquals(_cacheAccent, Accent))
        {
            return _cache;
        }

        _cache = BuildCache(width, height, scale);
        _cacheWidth = width;
        _cacheHeight = height;
        _cacheMood = Mood;
        _cacheFur = Fur;
        _cacheFurLight = FurLight;
        _cacheAccent = Accent;
        return _cache;
    }

    private CatCache BuildCache(double width, double height, double scale)
    {
        var cx = width / 2.0;
        var cy = height / 2.0;

        var parts = new List<Part>();
        var lids = new List<Part>();

        var tailPen = new Pen(Accent, 5 * scale) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        var eyePen = new Pen(Accent, 3 * scale) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        var mouthPen = new Pen(Accent, 2 * scale) { StartLineCap = PenLineCap.Round };
        var whiskerPen = new Pen(Accent, 1.6 * scale) { StartLineCap = PenLineCap.Round };

        // The body and the chest.
        parts.Add(new Part(Fur, null, Frozen(new EllipseGeometry(
            new Rect(cx - 26 * scale, cy - 4 * scale, 52 * scale, 46 * scale)))));
        parts.Add(new Part(FurLight, null, Frozen(new EllipseGeometry(
            new Rect(cx - 13 * scale, cy + 4 * scale, 26 * scale, 30 * scale)))));

        // The head.
        parts.Add(new Part(Fur, null, Frozen(new EllipseGeometry(
            new Rect(cx - 30 * scale, cy - 28 * scale, 60 * scale, 54 * scale)))));

        // The ears, outer and inner.
        foreach (var side in Sides)
        {
            var left = cx + side * 26 * scale - 11 * scale;
            var right = cx + side * 26 * scale + 11 * scale;
            var tip = cy - 44 * scale;

            var outer = new StreamGeometry();
            using (var ctx = outer.Open())
            {
                ctx.BeginFigure(new Point(left, cy - 22 * scale), isFilled: true, isClosed: true);
                ctx.LineTo(new Point(cx + side * 28 * scale, tip), isStroked: false, isSmoothJoin: false);
                ctx.LineTo(new Point(right, cy - 18 * scale), isStroked: false, isSmoothJoin: false);
            }
            parts.Add(new Part(Fur, null, Frozen(outer)));

            var inner = new StreamGeometry();
            using (var ctx = inner.Open())
            {
                ctx.BeginFigure(new Point(left + 3 * scale, cy - 23 * scale), isFilled: true, isClosed: true);
                ctx.LineTo(new Point(cx + side * 27 * scale, tip + 6 * scale), isStroked: false, isSmoothJoin: false);
                ctx.LineTo(new Point(right - 3 * scale, cy - 20 * scale), isStroked: false, isSmoothJoin: false);
            }
            parts.Add(new Part(FurLight, null, Frozen(inner)));
        }

        // The eyes. The lids that close them are kept apart, because they are only
        // drawn while the cat blinks.
        var eyeY = cy - 6 * scale;
        var eyeOffset = 13 * scale;
        var eyeWidth = Mood == CatMood.Alarmed ? 8 * scale : 6 * scale;
        var eyeHeight = Mood == CatMood.Alarmed ? 10 * scale : 5 * scale;

        if (Mood == CatMood.Content)
        {
            // Closed, contented arcs.
            foreach (var side in Sides)
            {
                var arc = new StreamGeometry();
                using (var ctx = arc.Open())
                {
                    ctx.BeginFigure(new Point(cx + side * eyeOffset - eyeWidth, eyeY), isFilled: false, isClosed: false);
                    ctx.QuadraticBezierTo(
                        new Point(cx + side * eyeOffset, eyeY + 6 * scale),
                        new Point(cx + side * eyeOffset + eyeWidth, eyeY),
                        isStroked: true,
                        isSmoothJoin: true);
                }
                parts.Add(new Part(null, eyePen, Frozen(arc)));
            }
        }
        else
        {
            foreach (var side in Sides)
            {
                parts.Add(new Part(Accent, null, Frozen(new EllipseGeometry(
                    new Rect(cx + side * eyeOffset - eyeWidth / 2, eyeY - eyeHeight / 2, eyeWidth, eyeHeight)))));

                lids.Add(new Part(Fur, null, Frozen(new RectangleGeometry(
                    new Rect(cx + side * eyeOffset - eyeWidth, eyeY - eyeHeight, eyeWidth * 2, eyeHeight * 2)))));
            }
        }

        // The nose.
        var nose = new StreamGeometry();
        using (var ctx = nose.Open())
        {
            ctx.BeginFigure(new Point(cx - 4 * scale, cy + 6 * scale), isFilled: true, isClosed: true);
            ctx.LineTo(new Point(cx + 4 * scale, cy + 6 * scale), isStroked: false, isSmoothJoin: false);
            ctx.LineTo(new Point(cx, cy + 11 * scale), isStroked: false, isSmoothJoin: false);
        }
        parts.Add(new Part(Accent, null, Frozen(nose)));

        // The mouth.
        var mouth = new StreamGeometry();
        using (var ctx = mouth.Open())
        {
            ctx.BeginFigure(new Point(cx, cy + 11 * scale), isFilled: false, isClosed: false);
            if (Mood == CatMood.Alarmed)
            {
                ctx.QuadraticBezierTo(new Point(cx - 8 * scale, cy + 20 * scale), new Point(cx - 12 * scale, cy + 12 * scale), isStroked: true, isSmoothJoin: true);
                ctx.QuadraticBezierTo(new Point(cx, cy + 14 * scale), new Point(cx + 12 * scale, cy + 12 * scale), isStroked: true, isSmoothJoin: true);
                ctx.QuadraticBezierTo(new Point(cx + 8 * scale, cy + 20 * scale), new Point(cx, cy + 11 * scale), isStroked: true, isSmoothJoin: true);
            }
            else
            {
                ctx.QuadraticBezierTo(new Point(cx - 7 * scale, cy + 18 * scale), new Point(cx - 13 * scale, cy + 12 * scale), isStroked: true, isSmoothJoin: true);
                ctx.QuadraticBezierTo(new Point(cx, cy + 15 * scale), new Point(cx + 13 * scale, cy + 12 * scale), isStroked: true, isSmoothJoin: true);
                ctx.QuadraticBezierTo(new Point(cx + 7 * scale, cy + 18 * scale), new Point(cx, cy + 11 * scale), isStroked: true, isSmoothJoin: true);
            }
        }
        parts.Add(new Part(null, mouthPen, Frozen(mouth)));

        // The whiskers: one geometry for all six lines.
        var whiskers = new StreamGeometry();
        using (var ctx = whiskers.Open())
        {
            foreach (var side in Sides)
            {
                for (var row = -1; row <= 1; row++)
                {
                    var start = new Point(cx + side * 16 * scale, cy + 8 * scale + row * 4 * scale);
                    var end = new Point(cx + side * 40 * scale, cy + 4 * scale + row * 7 * scale);
                    ctx.BeginFigure(start, isFilled: false, isClosed: false);
                    ctx.LineTo(end, isStroked: true, isSmoothJoin: true);
                }
            }
        }

        // The tail: one frozen shape per frame of the animation, so that moving the
        // tail costs a lookup rather than a new geometry.
        var amplitude = (Mood == CatMood.Alarmed ? 4.0 : 2.5) * scale;
        var tails = new Geometry[FramesPerCycle];
        for (var frame = 0; frame < FramesPerCycle; frame++)
        {
            var sway = Math.Sin(2 * Math.PI * frame / FramesPerCycle) * amplitude;

            var tail = new StreamGeometry();
            using (var ctx = tail.Open())
            {
                ctx.BeginFigure(new Point(cx + 22 * scale, cy + 26 * scale), isFilled: false, isClosed: false);
                ctx.BezierTo(
                    new Point(cx + 48 * scale, cy + 30 * scale + sway),
                    new Point(cx + 52 * scale, cy - 4 * scale + sway),
                    new Point(cx + 34 * scale, cy - 12 * scale + sway),
                    isStroked: true,
                    isSmoothJoin: true);
            }
            tails[frame] = Frozen(tail);
        }

        return new CatCache(
            parts,
            lids,
            new Part(null, whiskerPen, Frozen(whiskers)),
            tails,
            tailPen);
    }

    /// <summary>
    /// Freezes a geometry so it can be shared and drawn without being checked for
    /// changes on every frame.
    /// </summary>
    private static Geometry Frozen(Geometry geometry)
    {
        geometry.Freeze();
        return geometry;
    }

    private int CurrentFrame()
    {
        var frame = (int)Math.Round((double)GetValue(FrameIndexProperty), MidpointRounding.AwayFromZero);
        if (frame < 0) return 0;
        if (frame >= FramesPerCycle) return FramesPerCycle - 1;
        return frame;
    }

    private bool IsBlinking(int frame) => Mood != CatMood.Content && frame < BlinkFrames;

    private void OnIsVisibleChanged(object sender, DependencyPropertyChangedEventArgs args) =>
        UpdateAnimationState();

    /// <summary>
    /// The animation runs only while the cat is on screen and loaded. A storyboard
    /// stops on its own when it is removed from the tree, but it does not stop when
    /// the element is merely hidden, so the state is checked here.
    /// </summary>
    private void UpdateAnimationState()
    {
        if (IsVisible && IsLoaded && !_suspended) StartAnimation();
        else StopAnimation();
    }

    private void StartAnimation()
    {
        // Nothing to do when the tail is already moving.
        if (_animation is not null && _animation.GetCurrentState() == ClockState.Active) return;

        // The old clock is stopped first and a fresh storyboard is built, so starting
        // the animation can never depend on what a stopped storyboard remembers.
        StopAnimation();
        _animation = CreateAnimation();

        // The storyboard is started as a controllable one, so it can be stopped and
        // started again without the tail jumping.
        _animation.Begin(this, true);
    }

    private void StopAnimation() => _animation?.Stop();

    /// <summary>
    /// Builds the animation. It advances a single number through discrete key
    /// frames: a discrete key frame holds its value until the next one, so the
    /// number — and with it the drawing — changes thirteen times a second rather
    /// than sixty times a second.
    /// </summary>
    private Storyboard CreateAnimation()
    {
        var frames = new DoubleAnimationUsingKeyFrames
        {
            Duration = new Duration(TimeSpan.FromSeconds(FramesPerCycle / (double)FramesPerSecond)),
            RepeatBehavior = RepeatBehavior.Forever
        };

        for (var frame = 0; frame < FramesPerCycle; frame++)
        {
            frames.KeyFrames.Add(new DiscreteDoubleKeyFrame(
                frame,
                KeyTime.FromPercent(frame / (double)FramesPerCycle)));
        }

        var storyboard = new Storyboard();
        storyboard.Children.Add(frames);
        Storyboard.SetTarget(frames, this);
        Storyboard.SetTargetProperty(frames, new PropertyPath(FrameIndexProperty));
        return storyboard;
    }

    /// <summary>One drawn piece of the cat: a fill, a stroke and a shape.</summary>
    private sealed record Part(Brush? Fill, Pen? Stroke, Geometry Geometry);

    /// <summary>
    /// Everything the cat is made of, built once. The tail is the only part that
    /// changes from frame to frame, and its shapes are all here as well.
    /// </summary>
    private sealed record CatCache(
        IReadOnlyList<Part> Parts,
        IReadOnlyList<Part> Lids,
        Part Whiskers,
        IReadOnlyList<Geometry> Tails,
        Pen TailPen);
}
