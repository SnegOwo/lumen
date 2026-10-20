using System.Globalization;
using System.Windows;
using System.Windows.Data;
using Lumen.App.Infrastructure;

namespace Lumen.App.Tests;

public sealed class ConverterTests
{
    private static readonly CultureInfo Culture = CultureInfo.InvariantCulture;

    /// <summary>Every converter the application currently ships.</summary>
    private static IReadOnlyList<Type> ConverterTypes() =>
        typeof(EnumEqualsConverter).Assembly
            .GetTypes()
            .Where(type => typeof(IValueConverter).IsAssignableFrom(type) && type is { IsAbstract: false, IsInterface: false })
            .Where(type => type.GetConstructor(Type.EmptyTypes) is not null)
            .OrderBy(type => type.Name, StringComparer.Ordinal)
            .ToArray();

    private static IValueConverter? TryCreate(string typeName)
    {
        var type = typeof(EnumEqualsConverter).Assembly.GetType("Lumen.App.Infrastructure." + typeName);
        return type is null ? null : (IValueConverter)Activator.CreateInstance(type)!;
    }

    [Fact]
    public void Converters_theCoreConvertersArePresent()
    {
        var names = ConverterTypes().Select(type => type.Name).ToArray();

        Assert.Contains("EnumEqualsConverter", names);
        Assert.Contains("InverseBooleanToVisibilityConverter", names);
        Assert.Contains("NullToVisibilityConverter", names);
        Assert.Contains("EmptyStringToVisibilityConverter", names);
    }

    [Fact]
    public void Converters_everyConverter_livesInTheInfrastructureNamespace()
    {
        var misplaced = ConverterTypes()
            .Where(type => type.Namespace != "Lumen.App.Infrastructure")
            .Select(type => type.FullName!)
            .ToArray();

        Assert.Empty(misplaced);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [InlineData(null)]
    public void Converters_convert_neverReturnsNull(bool? value)
    {
        foreach (var type in ConverterTypes())
        {
            var converter = (IValueConverter)Activator.CreateInstance(type)!;

            var result = converter.Convert(value, typeof(object), null, Culture);

            Assert.NotNull(result);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [InlineData(null)]
    public void Converters_convertBack_neverThrows(bool? value)
    {
        foreach (var type in ConverterTypes())
        {
            var converter = (IValueConverter)Activator.CreateInstance(type)!;

            var exception = Record.Exception(() => converter.ConvertBack(value, typeof(object), null, Culture));

            Assert.Null(exception);
        }
    }

    [Fact]
    public void EnumEqualsConverter_convert_withAMatchingValue_returnsTrue()
    {
        var converter = new EnumEqualsConverter();

        Assert.True((bool)converter.Convert(DayOfWeek.Monday, typeof(bool), "Monday", Culture));
        Assert.True((bool)converter.Convert(DayOfWeek.Monday, typeof(bool), "monday", Culture));
    }

    [Fact]
    public void EnumEqualsConverter_convert_withADifferentValue_returnsFalse()
    {
        var converter = new EnumEqualsConverter();

        Assert.False((bool)converter.Convert(DayOfWeek.Monday, typeof(bool), "Tuesday", Culture));
    }

    [Fact]
    public void EnumEqualsConverter_convert_withNull_returnsFalse()
    {
        var converter = new EnumEqualsConverter();

        Assert.False((bool)converter.Convert(null, typeof(bool), "Monday", Culture));
        Assert.False((bool)converter.Convert(DayOfWeek.Monday, typeof(bool), null, Culture));
    }

    [Fact]
    public void EnumEqualsConverter_convertBack_withTrue_returnsTheParsedEnumValue()
    {
        var converter = new EnumEqualsConverter();

        var result = converter.ConvertBack(true, typeof(DayOfWeek), "Monday", Culture);

        Assert.Equal(DayOfWeek.Monday, (DayOfWeek)result);
    }

    [Fact]
    public void EnumEqualsConverter_convertBack_withFalse_returnsBindingDoNothing()
    {
        var converter = new EnumEqualsConverter();

        var result = converter.ConvertBack(false, typeof(DayOfWeek), "Monday", Culture);

        Assert.Equal(Binding.DoNothing, result);
    }

    [Fact]
    public void EnumEqualsConverter_convertBack_withANonEnumTarget_returnsBindingDoNothing()
    {
        var converter = new EnumEqualsConverter();

        var result = converter.ConvertBack(true, typeof(string), "Monday", Culture);

        Assert.Equal(Binding.DoNothing, result);
    }

    [Fact]
    public void EnumEqualsConverter_convertBack_withAnUnknownMember_returnsBindingDoNothing()
    {
        var converter = new EnumEqualsConverter();

        var result = converter.ConvertBack(true, typeof(DayOfWeek), "NotADay", Culture);

        Assert.Equal(Binding.DoNothing, result);
    }

    [Fact]
    public void InverseBooleanToVisibilityConverter_convert_withTrue_returnsCollapsed()
    {
        var converter = new InverseBooleanToVisibilityConverter();

        Assert.Equal(Visibility.Collapsed, converter.Convert(true, typeof(Visibility), null, Culture));
    }

    [Fact]
    public void InverseBooleanToVisibilityConverter_convert_withFalse_returnsVisible()
    {
        var converter = new InverseBooleanToVisibilityConverter();

        Assert.Equal(Visibility.Visible, converter.Convert(false, typeof(Visibility), null, Culture));
    }

    [Fact]
    public void InverseBooleanToVisibilityConverter_convertBack_returnsBindingDoNothing()
    {
        var converter = new InverseBooleanToVisibilityConverter();

        Assert.Equal(Binding.DoNothing, converter.ConvertBack(Visibility.Visible, typeof(Visibility), null, Culture));
    }

    [Fact]
    public void NullToVisibilityConverter_convert_withNull_returnsCollapsed()
    {
        var converter = new NullToVisibilityConverter();

        Assert.Equal(Visibility.Collapsed, converter.Convert(null, typeof(Visibility), null, Culture));
    }

    [Fact]
    public void NullToVisibilityConverter_convert_withAValue_returnsVisible()
    {
        var converter = new NullToVisibilityConverter();

        Assert.Equal(Visibility.Visible, converter.Convert("text", typeof(Visibility), null, Culture));
    }

    [Fact]
    public void NullToVisibilityConverter_convert_withTheInverseParameter_invertsTheResult()
    {
        var converter = new NullToVisibilityConverter();

        Assert.Equal(Visibility.Visible, converter.Convert(null, typeof(Visibility), "Inverse", Culture));
        Assert.Equal(Visibility.Collapsed, converter.Convert("text", typeof(Visibility), "Inverse", Culture));
    }

    [Fact]
    public void NullToVisibilityConverter_convertBack_returnsBindingDoNothing()
    {
        var converter = new NullToVisibilityConverter();

        Assert.Equal(Binding.DoNothing, converter.ConvertBack(Visibility.Visible, typeof(Visibility), null, Culture));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void EmptyStringToVisibilityConverter_convert_withBlankText_returnsCollapsed(string? value)
    {
        var converter = new EmptyStringToVisibilityConverter();

        Assert.Equal(Visibility.Collapsed, converter.Convert(value, typeof(Visibility), null, Culture));
    }

    [Fact]
    public void EmptyStringToVisibilityConverter_convert_withText_returnsVisible()
    {
        var converter = new EmptyStringToVisibilityConverter();

        Assert.Equal(Visibility.Visible, converter.Convert("text", typeof(Visibility), null, Culture));
    }

    [Fact]
    public void EmptyStringToVisibilityConverter_convertBack_returnsBindingDoNothing()
    {
        var converter = new EmptyStringToVisibilityConverter();

        Assert.Equal(Binding.DoNothing, converter.ConvertBack(Visibility.Visible, typeof(Visibility), null, Culture));
    }

    [Fact]
    public void CountToVisibilityConverter_convert_withANonZeroCount_returnsVisible()
    {
        var converter = TryCreate("CountToVisibilityConverter");
        if (converter is null) return;

        Assert.Equal(Visibility.Visible, converter.Convert(3, typeof(Visibility), null, Culture));
    }

    [Fact]
    public void CountToVisibilityConverter_convert_withAZeroCount_returnsCollapsed()
    {
        var converter = TryCreate("CountToVisibilityConverter");
        if (converter is null) return;

        Assert.Equal(Visibility.Collapsed, converter.Convert(0, typeof(Visibility), null, Culture));
    }

    [Fact]
    public void CountToVisibilityConverter_convert_withTheZeroParameter_invertsTheResult()
    {
        var converter = TryCreate("CountToVisibilityConverter");
        if (converter is null) return;

        Assert.Equal(Visibility.Visible, converter.Convert(0, typeof(Visibility), "Zero", Culture));
        Assert.Equal(Visibility.Collapsed, converter.Convert(3, typeof(Visibility), "Zero", Culture));
    }

    [Fact]
    public void InverseBooleanConverter_convert_invertsTheValue()
    {
        var converter = TryCreate("InverseBooleanConverter");
        if (converter is null) return;

        Assert.False((bool)converter.Convert(true, typeof(bool), null, Culture));
        Assert.True((bool)converter.Convert(false, typeof(bool), null, Culture));
    }

    [Fact]
    public void InverseBooleanConverter_convertBack_invertsTheValue()
    {
        var converter = TryCreate("InverseBooleanConverter");
        if (converter is null) return;

        Assert.False((bool)converter.ConvertBack(true, typeof(bool), null, Culture));
        Assert.True((bool)converter.ConvertBack(false, typeof(bool), null, Culture));
    }
}
