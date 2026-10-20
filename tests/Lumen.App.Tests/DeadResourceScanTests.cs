using System.Text.RegularExpressions;
using Lumen.App.Tests.Support;

namespace Lumen.App.Tests;

/// <summary>
/// A resource that nobody uses is dead weight, and worse, it hides the fact
/// that a view still paints a hard coded colour instead of using the token
/// that was designed for it. The scan therefore fails when a theme key is
/// declared but never referenced anywhere in the application.
/// </summary>
public sealed class DeadResourceScanTests
{
    private sealed record Declaration(string Key, string File);

    private static IReadOnlyList<Declaration> Declarations()
    {
        var declarations = new List<Declaration>();

        foreach (var file in SourceTree.ThemeFiles)
        {
            foreach (var key in Xaml.DeclaredKeys(file))
            {
                declarations.Add(new Declaration(key, SourceTree.Relative(file)));
            }
        }

        return declarations;
    }

    /// <summary>How often the key is used outside of its own declaration.</summary>
    private static int CountUsages(string key, IReadOnlyDictionary<string, string> sources)
    {
        var pattern = Xaml.KeyPattern(key);
        var usages = 0;

        foreach (var (file, text) in sources)
        {
            var matches = pattern.Matches(text).Count;
            var declarations = Regex.Matches(text, "x:Key=\"" + Regex.Escape(key) + "\"").Count;
            usages += Math.Max(0, matches - declarations);
        }

        return usages;
    }

    [Fact]
    public void ThemeFiles_everyDeclaredKey_isReferencedSomewhereInTheApplication()
    {
        var sources = SourceTree.SourceFiles.ToDictionary(
            path => path,
            path => Xaml.StripComments(
                File.ReadAllText(path),
                isXaml: path.EndsWith(".xaml", StringComparison.OrdinalIgnoreCase)),
            StringComparer.OrdinalIgnoreCase);

        var unused = new List<string>();

        foreach (var declaration in Declarations().DistinctBy(item => item.Key, StringComparer.Ordinal))
        {
            if (CountUsages(declaration.Key, sources) == 0)
            {
                unused.Add($"{declaration.Key} (declared in {declaration.File})");
            }
        }

        Assert.True(
            unused.Count == 0,
            "These theme resources are declared but never used:" + Environment.NewLine +
            string.Join(Environment.NewLine, unused.Select(item => "  " + item)));
    }

    [Fact]
    public void ThemeFiles_theScanFindsAtLeastOneDeclaredKey()
    {
        // Guards the scan itself: if the theme folder were empty the test above
        // would pass without checking anything.
        Assert.NotEmpty(Declarations());
    }
}
