using System.Windows.Controls;
using System.Xml.Linq;
using Lumen.App.Tests.Support;

namespace Lumen.App.Tests;

/// <summary>
/// Every XAML file has to be valid: a malformed file breaks the build, a bad
/// resource reference breaks the screen that uses it. The checks here read the
/// files from the source tree, so they also cover files that the application
/// only loads at runtime.
/// </summary>
public sealed class XamlWellFormednessTests
{
    [Fact]
    public void XamlFiles_everyFile_isWellFormedXml()
    {
        var failures = new List<string>();

        foreach (var file in SourceTree.XamlFiles)
        {
            try
            {
                XDocument.Load(file, LoadOptions.SetLineInfo);
            }
            catch (Exception exception)
            {
                failures.Add($"{SourceTree.Relative(file)}: {exception.Message}");
            }
        }

        Assert.True(
            failures.Count == 0,
            "These XAML files are not well formed:" + Environment.NewLine +
            string.Join(Environment.NewLine, failures.Select(failure => "  " + failure)));
    }

    [Fact]
    public void XamlFiles_theProjectContainsXamlFiles()
    {
        Assert.NotEmpty(SourceTree.XamlFiles);
        Assert.True(SourceTree.XamlFiles.Count > 10);
    }

    [Fact]
    public void ThemeFiles_theWholeThemeTree_loadsWithoutErrors()
    {
        LumenApplication.Ensure();

        var exception = Record.Exception(() => LumenApplication.LoadDictionary("themes/controls.xaml"));

        Assert.Null(exception);
    }

    [Fact]
    public void ThemeFiles_everyThemeDictionary_loadsWithoutErrors()
    {
        LumenApplication.Ensure();

        var failures = new List<string>();

        foreach (var file in SourceTree.ThemeFiles)
        {
            var relative = SourceTree.Relative(file);
            if (!relative.EndsWith(".xaml", StringComparison.OrdinalIgnoreCase)) continue;

            try
            {
                var dictionary = LumenApplication.LoadDictionary(relative);
                Assert.NotNull(dictionary);
            }
            catch (Exception exception)
            {
                failures.Add($"{relative}: {exception.GetBaseException().Message}");
            }
        }

        Assert.True(
            failures.Count == 0,
            "These theme dictionaries do not load:" + Environment.NewLine +
            string.Join(Environment.NewLine, failures.Select(failure => "  " + failure)));
    }

    [Fact]
    public void XamlFiles_everyUserControlView_loadsWithoutErrors()
    {
        LumenApplication.InstallResources();

        var failures = new List<string>();
        var loaded = 0;

        foreach (var (file, type) in UserControlViews())
        {
            try
            {
                WpfHost.Shared.Invoke(() => Activator.CreateInstance(type));
                loaded++;
            }
            catch (Exception exception)
            {
                failures.Add($"{file}: {exception.GetBaseException().Message}");
            }
        }

        Assert.True(loaded > 0, "No user control view was found to load.");

        Assert.True(
            failures.Count == 0,
            "These views do not load:" + Environment.NewLine +
            string.Join(Environment.NewLine, failures.Select(failure => "  " + failure)));
    }

    private static IEnumerable<(string File, Type Type)> UserControlViews()
    {
        foreach (var file in SourceTree.XamlFiles)
        {
            var relative = SourceTree.Relative(file);
            var type = LumenApplication.TypeFor(relative);

            if (type is null) continue;
            if (!typeof(UserControl).IsAssignableFrom(type)) continue;
            if (type.GetConstructor(Type.EmptyTypes) is null) continue;

            yield return (relative, type);
        }
    }
}
