using System.Windows;
using System.Windows.Media;
using System.Windows.Shapes;
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
/// A cat, drawn entirely with WPF vector primitives — no image assets, no fonts, no
/// downloads. It blinks on its own, its tail sways, and it can look alarmed, calm or
/// content.
///
/// Everything is drawn in the supplied brushes so it follows the current theme.
/// </summary>
public sealed class CatArt : FrameworkElement
{
    private readonly DispatcherTimer _timer;
    private double _phase;
    private bool _blinking;

    public CatArt()
    {
        IsHitTestVisible = false;
        Focusable = false;

        _timer = new DispatcherTimer(DispatcherPriority.Render)
        {
            Interval = TimeSpan.FromMilliseconds(40)
        };
        _timer.Tick += (_, _) =>
        {
            _phase += 0.045;
            if (_phase > 200) _phase -= 200;

            // A blink every few seconds.
            var slot = _phase % 4.0;
            if (slot >= 0.0 && slot < 0.04) _blinking = true;
            else if (slot >= 0.30) _blinking = false;

            InvalidateVisual();
        };
        _timer.Start();
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

    protected override void OnRender(DrawingContext context)
    {
        var width = ActualWidth <= 0 ? 120 : ActualWidth;
        var height = ActualHeight <= 0 ? 120 : ActualHeight;
        var scale = Math.Min(width, height) / 120.0;

        var cx = width / 2;
        var cy = height / 2;

        var sway = Mood == CatMood.Alarmed
            ? Math.Sin(_phase * 3.2) * 4 * scale
            : Math.Sin(_phase * 0.8) * 2.5 * scale;

        DrawTail(context, cx, cy, scale, sway);
        DrawBody(context, cx, cy, scale);
        DrawHead(context, cx, cy - 20 * scale, scale);
        DrawEars(context, cx, cy - 20 * scale, scale);
        DrawFace(context, cx, cy - 20 * scale, scale);
        DrawWhiskers(context, cx, cy - 20 * scale, scale);
    }

    private void DrawTail(DrawingContext context, double cx, double cy, double scale, double sway)
    {
        var pen = new Pen(Accent, 5 * scale) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(new Point(cx + 22 * scale, cy + 26 * scale), isFilled: false, isClosed: false);
            ctx.BezierTo(
                new Point(cx + 48 * scale, cy + 30 * scale + sway),
                new Point(cx + 52 * scale, cy - 4 * scale + sway),
                new Point(cx + 34 * scale, cy - 12 * scale + sway),
                isStroked: true,
                isSmoothJoin: true);
        }
        geometry.Freeze();
        context.DrawGeometry(null, pen, geometry);
    }

    private void DrawBody(DrawingContext context, double cx, double cy, double scale)
    {
        var body = new EllipseGeometry(new Rect(cx - 26 * scale, cy - 4 * scale, 52 * scale, 46 * scale));
        body.Freeze();
        context.DrawGeometry(Fur, null, body);

        var chest = new EllipseGeometry(new Rect(cx - 13 * scale, cy + 4 * scale, 26 * scale, 30 * scale));
        chest.Freeze();
        context.DrawGeometry(FurLight, null, chest);
    }

    private void DrawHead(DrawingContext context, double cx, double cy, double scale)
    {
        var head = new EllipseGeometry(new Rect(cx - 30 * scale, cy - 28 * scale, 60 * scale, 54 * scale));
        head.Freeze();
        context.DrawGeometry(Fur, null, head);
    }

    private void DrawEars(DrawingContext context, double cx, double cy, double scale)
    {
        foreach (var side in new[] { -1, 1 })
        {
            var left = cx + side * 26 * scale - 11 * scale;
            var right = cx + side * 26 * scale + 11 * scale;
            var tip = cy - 44 * scale;

            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                ctx.BeginFigure(new Point(left, cy - 22 * scale), isFilled: true, isClosed: true);
                ctx.LineTo(new Point(cx + side * 28 * scale, tip), isStroked: false, isSmoothJoin: false);
                ctx.LineTo(new Point(right, cy - 18 * scale), isStroked: false, isSmoothJoin: false);
            }
            geometry.Freeze();
            context.DrawGeometry(Fur, null, geometry);

            var inner = new StreamGeometry();
            using (var ctx = inner.Open())
            {
                ctx.BeginFigure(new Point(left + 3 * scale, cy - 23 * scale), isFilled: true, isClosed: true);
                ctx.LineTo(new Point(cx + side * 27 * scale, tip + 6 * scale), isStroked: false, isSmoothJoin: false);
                ctx.LineTo(new Point(right - 3 * scale, cy - 20 * scale), isStroked: false, isSmoothJoin: false);
            }
            inner.Freeze();
            context.DrawGeometry(FurLight, null, inner);
        }
    }

    private void DrawFace(DrawingContext context, double cx, double cy, double scale)
    {
        var eyePen = new Pen(Accent, 3 * scale) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };

        var eyeY = cy - 6 * scale;
        var eyeOffset = 13 * scale;
        var eyeWidth = Mood == CatMood.Alarmed ? 8 * scale : 6 * scale;
        var eyeHeight = Mood == CatMood.Alarmed ? 10 * scale : 5 * scale;

        if (Mood == CatMood.Content)
        {
            // Closed, contented arcs.
            foreach (var side in new[] { -1, 1 })
            {
                var geometry = new StreamGeometry();
                using (var ctx = geometry.Open())
                {
                    ctx.BeginFigure(new Point(cx + side * eyeOffset - eyeWidth, eyeY), isFilled: false, isClosed: false);
                    ctx.QuadraticBezierTo(
                        new Point(cx + side * eyeOffset, eyeY + 6 * scale),
                        new Point(cx + side * eyeOffset + eyeWidth, eyeY),
                        isStroked: true,
                        isSmoothJoin: true);
                }
                geometry.Freeze();
                context.DrawGeometry(null, eyePen, geometry);
            }
        }
        else
        {
            foreach (var side in new[] { -1, 1 })
            {
                var eye = new EllipseGeometry(
                    new Rect(cx + side * eyeOffset - eyeWidth / 2, eyeY - eyeHeight / 2, eyeWidth, eyeHeight));
                eye.Freeze();
                context.DrawGeometry(Accent, null, eye);
            }
        }

        if (_blinking && Mood != CatMood.Content)
        {
            foreach (var side in new[] { -1, 1 })
            {
                var lid = new RectangleGeometry(
                    new Rect(cx + side * eyeOffset - eyeWidth, eyeY - eyeHeight, eyeWidth * 2, eyeHeight * 2));
                lid.Freeze();
                context.DrawGeometry(Fur, null, lid);
            }
        }

        // Nose.
        var nose = new StreamGeometry();
        using (var ctx = nose.Open())
        {
            ctx.BeginFigure(new Point(cx - 4 * scale, cy + 6 * scale), isFilled: true, isClosed: true);
            ctx.LineTo(new Point(cx + 4 * scale, cy + 6 * scale), isStroked: false, isSmoothJoin: false);
            ctx.LineTo(new Point(cx, cy + 11 * scale), isStroked: false, isSmoothJoin: false);
        }
        nose.Freeze();
        context.DrawGeometry(Accent, null, nose);

        // Mouth.
        var mouthPen = new Pen(Accent, 2 * scale) { StartLineCap = PenLineCap.Round };
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
        mouth.Freeze();
        context.DrawGeometry(null, mouthPen, mouth);
    }

    private void DrawWhiskers(DrawingContext context, double cx, double cy, double scale)
    {
        var pen = new Pen(Accent, 1.6 * scale) { StartLineCap = PenLineCap.Round };

        context.PushOpacity(0.75);
        for (var side = -1; side <= 1; side += 2)
        {
            for (var row = -1; row <= 1; row++)
            {
                var start = new Point(cx + side * 16 * scale, cy + 8 * scale + row * 4 * scale);
                var end = new Point(cx + side * 40 * scale, cy + 4 * scale + row * 7 * scale);
                var geometry = new StreamGeometry();
                using (var ctx = geometry.Open())
                {
                    ctx.BeginFigure(start, isFilled: false, isClosed: false);
                    ctx.LineTo(end, isStroked: true, isSmoothJoin: true);
                }
                geometry.Freeze();
                context.DrawGeometry(null, pen, geometry);
            }
        }
        context.Pop();
    }
}
