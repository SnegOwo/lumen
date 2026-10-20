using Lumen.App.Tests.Support;

namespace Lumen.App.Tests;

/// <summary>
/// A <c>{StaticResource}</c> or <c>{DynamicResource}</c> reference that points
/// at a key nobody declares is a broken reference. WPF only reports it when the
/// element is loaded, so in practice it shows up as a silent fallback to the
/// default colour or as an exception on a screen the user rarely opens.
/// </summary>
public sealed class ThemeResourceReferenceTests
{
    private static IReadOnlySet<string> DeclaredKeys(IEnumerable<string> files)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);

        foreach (var file in files)
        {
            foreach (var key in Xaml.DeclaredKeys(file)) keys.Add(key);
        }

        return keys;
    }

    private static string Describe(IReadOnlyCollection<string> missing, string file) =>
        string.Join(Environment.NewLine, missing.Select(key => $"  {file}: '{key}'"));

    [Fact]
    public void ThemeFiles_everyResourceReference_resolvesToADeclaredKey()
    {
        var declared = DeclaredKeys(SourceTree.ThemeFiles);
        var failures = new List<string>();

        foreach (var file in SourceTree.ThemeFiles)
        {
            var missing = Xaml.ResourceReferences(file)
                .Where(key => !declared.Contains(key))
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (missing.Length > 0) failures.Add(Describe(missing, SourceTree.Relative(file)));
        }

        Assert.True(
            failures.Count == 0,
            "These theme resources are referenced but never declared:" + Environment.NewLine +
            string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public void AppFiles_everyResourceReference_resolvesToADeclaredKey()
    {
        var declared = DeclaredKeys(SourceTree.XamlFiles);
        var failures = new List<string>();

        foreach (var file in SourceTree.XamlFiles)
        {
            var missing = Xaml.ResourceReferences(file)
                .Where(key => !declared.Contains(key))
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (missing.Length > 0) failures.Add(Describe(missing, SourceTree.Relative(file)));
        }

        Assert.True(
            failures.Count == 0,
            "These resources are referenced but never declared:" + Environment.NewLine +
            string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public void ThemeFiles_everyThemeControlFile_isCoveredByTheThemeScan()
    {
        var controls = SourceTree.ThemeFiles
            .Where(path => path.Contains($"{Path.DirectorySeparatorChar}Controls{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        Assert.NotEmpty(controls);
        Assert.Contains(controls, path => path.EndsWith("Buttons.xaml", StringComparison.OrdinalIgnoreCase));
    }
}
