using Lumen.App.Tests.Support;

namespace Lumen.App.Tests;

/// <summary>
/// The icon glyphs are published as named string resources so that the views
/// never repeat a magic number. Every value has to be exactly one character:
/// a glyph that is empty is invisible and a glyph that is two characters wide
/// breaks the layout of every button that uses it.
/// </summary>
public sealed class IconResourceTests
{
    private static string IconsPath => Path.Combine(SourceTree.ThemesDirectory, "Icons.xaml");

    private static IReadOnlyDictionary<string, string> DeclaredIcons() =>
        Xaml.KeyedElementValues(IconsPath);

    [Fact]
    public void Icons_theFileExists()
    {
        Assert.True(File.Exists(IconsPath), "Themes/Icons.xaml is missing.");
    }

    [Fact]
    public void Icons_everyDeclaredValue_isASingleNonEmptyCharacter()
    {
        var failures = new List<string>();

        foreach (var (key, value) in DeclaredIcons())
        {
            if (string.IsNullOrEmpty(value) || value.Length != 1 || char.IsWhiteSpace(value[0]))
            {
                failures.Add($"  {key}: '{value}'");
            }
        }

        Assert.True(
            failures.Count == 0,
            "These icon resources are not a single character:" + Environment.NewLine +
            string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public void Icons_everyDeclaredKey_startsWithTheIconPrefix()
    {
        var wrong = DeclaredIcons().Keys
            .Where(key => !key.StartsWith("Icon.", StringComparison.Ordinal))
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToArray();

        Assert.True(wrong.Length == 0, "These icon keys do not start with 'Icon.': " + string.Join(", ", wrong));
    }

    [Fact]
    public void Icons_everyIconKeyTheApplicationUses_isDeclared()
    {
        var declared = DeclaredIcons();
        var used = new HashSet<string>(StringComparer.Ordinal);

        foreach (var file in SourceTree.XamlFiles)
        {
            foreach (var reference in Xaml.ResourceReferences(file))
            {
                if (reference.StartsWith("Icon.", StringComparison.Ordinal)) used.Add(reference);
            }
        }

        var missing = used.Where(key => !declared.ContainsKey(key)).OrderBy(key => key, StringComparer.Ordinal).ToArray();

        Assert.True(
            missing.Length == 0,
            "These icon keys are used but not declared in Themes/Icons.xaml: " + string.Join(", ", missing));
    }

    [Fact]
    public void Icons_theFileDeclaresAtLeastOneGlyph()
    {
        Assert.NotEmpty(DeclaredIcons());
    }
}
