using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using WpfPath = System.Windows.Shapes.Path;

namespace Lumen.App.Views.Charts;

/// <summary>
/// A sparkline: the number of detections of every recent scan, drawn with a
/// Polyline and a filled Path.
///
/// <para>
/// The control owns no chart library and no image asset. It rebuilds its shapes
/// whenever the values or the available size change, and it reads its colours
/// through resource references so the palette swap reaches it.
/// </para>
/// </summary>
public partial class SparklineView : UserControl
{
    /// <summary>The values that are drawn, oldest first.</summary>
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values),
        typeof(IReadOnlyList<double>),
        typeof(SparklineView),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnValuesChanged));

    /// <summary>The resource key of the stroke colour.</summary>
    public static readonly DependencyProperty StrokeKeyProperty = DependencyProperty.Register(
        nameof(StrokeKey),
        typeof(string),
        typeof(SparklineView),
        new FrameworkPropertyMetadata("Accent.Primary", FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>The resource key of the fill colour.</summary>
    public static readonly DependencyProperty FillKeyProperty = DependencyProperty.Register(
        nameof(FillKey),
        typeof(string),
        typeof(SparklineView),
        new FrameworkPropertyMetadata("Accent.Soft", FrameworkPropertyMetadataOptions.AffectsRender));

    public SparklineView()
    {
        InitializeComponent();
        SizeChanged += (_, _) => Redraw();
    }

    /// <summary>The values that are drawn, oldest first.</summary>
    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    /// <summary>The resource key of the stroke colour.</summary>
    public string StrokeKey
    {
        get => (string)GetValue(StrokeKeyProperty);
        set => SetValue(StrokeKeyProperty, value);
    }

    /// <summary>The resource key of the fill colour.</summary>
    public string FillKey
    {
        get => (string)GetValue(FillKeyProperty);
        set => SetValue(FillKeyProperty, value);
    }

    private static void OnValuesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SparklineView view) view.Redraw();
    }

    private void OnRootSizeChanged(object sender, SizeChangedEventArgs e) => Redraw();

    private void Redraw()
    {
        Root.Children.Clear();

        var values = Values;
        var width = Root.ActualWidth;
        var height = Root.ActualHeight;
        if (values is null || values.Count == 0 || width <= 1 || height <= 1) return;

        var maximum = Math.Max(1d, values.Max());
        var step = values.Count > 1 ? width / (values.Count - 1) : width;
        var usable = Math.Max(1d, height - 4);

        var points = new PointCollection();
        for (var index = 0; index < values.Count; index++)
        {
            var x = index * step;
            var ratio = values[index] / maximum;
            var y = height - 2 - (ratio * usable);
            points.Add(new Point(x, y));
        }

        // The filled area under the line.
        var area = new WpfPath
        {
            Data = BuildArea(points, height)
        };
        area.SetResourceReference(WpfPath.FillProperty, FillKey);
        Root.Children.Add(area);

        var line = new Polyline
        {
            Points = points,
            StrokeThickness = 2,
            StrokeLineJoin = PenLineJoin.Round,
            StrokeStartLineCap = PenLineCap.Round,
            StrokeEndLineCap = PenLineCap.Round
        };
        line.SetResourceReference(Polyline.StrokeProperty, StrokeKey);
        Root.Children.Add(line);

        // A dot on the most recent value, so the reader knows where "now" is.
        var last = points[points.Count - 1];
        var dot = new Ellipse
        {
            Width = 6,
            Height = 6,
            Margin = new Thickness(last.X - 3, last.Y - 3, 0, 0)
        };
        dot.SetResourceReference(Ellipse.FillProperty, StrokeKey);
        Root.Children.Add(dot);
    }

    private static Geometry BuildArea(PointCollection points, double height)
    {
        if (points.Count == 0) return Geometry.Empty;

        var geometry = new StreamGeometry();
        using (var context = geometry.Open())
        {
            context.BeginFigure(new Point(points[0].X, height), true, true);
            foreach (var point in points) context.LineTo(point, true, false);
            context.LineTo(new Point(points[points.Count - 1].X, height), true, false);
        }

        geometry.Freeze();
        return geometry;
    }
}
