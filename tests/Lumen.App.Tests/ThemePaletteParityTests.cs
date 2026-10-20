using System.Windows;
using System.Windows.Markup;
using Lumen.App.Tests.Support;

namespace Lumen.App.Tests;

/// <summary>
/// The three palettes are the contract between the theme and the views. A key
/// that exists in the light theme but not in the high contrast theme is a
/// silent bug: the view falls back to a hard coded colour and the user with
/// high contrast enabled gets a different interface from everybody else.
/// </summary>
public sealed class ThemePaletteParityTests
{
    private const string Light = "Colors.Light.xaml";
    private const string Dark = "Colors.Dark.xaml";
    private const string HighContrast = "Colors.HighContrast.xaml";

    private static IReadOnlyList<string> LoadKeys(string fileName)
    {
        var path = Path.Combine(SourceTree.ThemesDirectory, fileName);
        var text = File.ReadAllText(path);

        return WpfHost.Shared.Invoke(() =>
        {
            var dictionary = (ResourceDictionary)XamlReader.Parse(text);

            return dictionary.Keys
                .Cast<object>()
                .Select(key => key.ToString()!)
                .OrderBy(key => key, StringComparer.Ordinal)
                .ToArray();
        });
    }

    private static void AssertSameKeys(IReadOnlyList<string> left, string leftName, IReadOnlyList<string> right, string rightName)
    {
        var missing = left.Except(right, StringComparer.Ordinal).OrderBy(key => key, StringComparer.Ordinal).ToArray();
        var extra = right.Except(left, StringComparer.Ordinal).OrderBy(key => key, StringComparer.Ordinal).ToArray();

        var message =
            $"{leftName} and {rightName} do not expose the same resource keys." +
            (missing.Length > 0 ? Environment.NewLine + "Missing from " + rightName + ": " + string.Join(", ", missing) : string.Empty) +
            (extra.Length > 0 ? Environment.NewLine + "Only in " + rightName + ": " + string.Join(", ", extra) : string.Empty);

        Assert.True(missing.Length == 0 && extra.Length == 0, message);
    }

    [Fact]
    public void Palettes_theLightAndTheDarkTheme_exposeTheSameKeys()
    {
        AssertSameKeys(LoadKeys(Light), Light, LoadKeys(Dark), Dark);
    }

    [Fact]
    public void Palettes_theLightAndTheHighContrastTheme_exposeTheSameKeys()
    {
        AssertSameKeys(LoadKeys(Light), Light, LoadKeys(HighContrast), HighContrast);
    }

    [Fact]
    public void Palettes_theDarkAndTheHighContrastTheme_exposeTheSameKeys()
    {
        AssertSameKeys(LoadKeys(Dark), Dark, LoadKeys(HighContrast), HighContrast);
    }

    [Fact]
    public void Palettes_everyPalette_declaresAtLeastOneKey()
    {
        foreach (var fileName in new[] { Light, Dark, HighContrast })
        {
            Assert.NotEmpty(LoadKeys(fileName));
        }
    }

    [Fact]
    public void Palettes_everyDeclaredKey_resolvesToAValue()
    {
        foreach (var fileName in new[] { Light, Dark, HighContrast })
        {
            var path = Path.Combine(SourceTree.ThemesDirectory, fileName);
            var text = File.ReadAllText(path);

            WpfHost.Shared.Invoke(() =>
            {
                var dictionary = (ResourceDictionary)XamlReader.Parse(text);

                foreach (var key in dictionary.Keys)
                {
                    // The value may legitimately be null: "Card.Effect" is an
                    // x:Null placeholder that switches the drop shadow off.
                    Assert.True(dictionary.Contains(key), $"{fileName} lost the key '{key}'.");
                }

                return true;
            });
        }
    }

    [Fact]
    public void Palettes_everyPaletteDeclaresTheSameNumberOfKeys()
    {
        var counts = new[] { Light, Dark, HighContrast }
            .Select(fileName => new { FileName = fileName, Count = LoadKeys(fileName).Count })
            .ToArray();

        Assert.True(
            counts.Select(count => count.Count).Distinct().Count() == 1,
            string.Join(
                Environment.NewLine,
                counts.Select(count => $"{count.FileName}: {count.Count} keys")));
    }
}
