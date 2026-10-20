using System.Windows;
using System.Windows.Controls;
using System.Windows.Shapes;

namespace Lumen.App.Views.Charts;

/// <summary>
/// A small bar chart: a handful of counts drawn as Rectangles with a label under
/// each of them.
///
/// <para>
/// Like the sparkline, it uses no chart library and no image asset. The bars are
/// rebuilt whenever the values or the available size change.
/// </para>
/// </summary>
public partial class BarChartView : UserControl
{
    /// <summary>The values that are drawn.</summary>
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values),
        typeof(IReadOnlyList<double>),
        typeof(BarChartView),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnValuesChanged));

    /// <summary>The label under each bar.</summary>
    public static readonly DependencyProperty LabelsProperty = DependencyProperty.Register(
        nameof(Labels),
        typeof(IReadOnlyList<string>),
        typeof(BarChartView),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnValuesChanged));

    /// <summary>The resource keys of the bar colours, one per bar.</summary>
    public static readonly DependencyProperty BrushKeysProperty = DependencyProperty.Register(
        nameof(BrushKeys),
        typeof(IReadOnlyList<string>),
        typeof(BarChartView),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnValuesChanged));

    private const double LabelHeight = 20;

    public BarChartView()
    {
        InitializeComponent();
    }

    /// <summary>The values that are drawn.</summary>
    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    /// <summary>The label under each bar.</summary>
    public IReadOnlyList<string>? Labels
    {
        get => (IReadOnlyList<string>?)GetValue(LabelsProperty);
        set => SetValue(LabelsProperty, value);
    }

    /// <summary>The resource keys of the bar colours, one per bar.</summary>
    public IReadOnlyList<string>? BrushKeys
    {
        get => (IReadOnlyList<string>?)GetValue(BrushKeysProperty);
        set => SetValue(BrushKeysProperty, value);
    }

    private static void OnValuesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is BarChartView view) view.Redraw();
    }

    private void OnBarsSizeChanged(object sender, SizeChangedEventArgs e) => Redraw();

    private void Redraw()
    {
        Bars.Children.Clear();
        LabelItems.Items.Clear();

        var values = Values;
        if (values is null || values.Count == 0) return;

        var width = Bars.ActualWidth;
        var height = Bars.ActualHeight;
        if (width <= 1 || height <= 1) return;

        var maximum = Math.Max(1d, values.Max());
        var slot = width / values.Count;
        var barWidth = Math.Max(8d, Math.Min(56d, slot * 0.5));
        var usable = Math.Max(1d, height - LabelHeight);

        for (var index = 0; index < values.Count; index++)
        {
            var ratio = values[index] / maximum;
            var barHeight = Math.Max(2d, ratio * usable);
            var left = (index * slot) + ((slot - barWidth) / 2);
            var top = usable - barHeight;

            var bar = new Rectangle
            {
                Width = barWidth,
                Height = barHeight,
                RadiusX = 4,
                RadiusY = 4,
                Margin = new Thickness(left, top, 0, 0)
            };

            var key = BrushKeys is not null && index < BrushKeys.Count
                ? BrushKeys[index]
                : "Accent.Primary";
            bar.SetResourceReference(Rectangle.FillProperty, key);
            Bars.Children.Add(bar);

            if (Labels is not null && index < Labels.Count)
            {
                LabelItems.Items.Add(Labels[index]);
            }
        }
    }
}
