using System.Text.RegularExpressions;
using Lumen.App.Tests.Support;

namespace Lumen.App.Tests;

/// <summary>
/// Guards against a mistake that is invisible in the source and expensive at run time.
/// </summary>
public sealed class AnimationBudgetTests
{
    /// <summary>
    /// A progress bar whose <c>IsIndeterminate</c> is set statically starts a storyboard
    /// that repeats forever, and the storyboard only stops when the property goes back
    /// to false. A bar inside a collapsed panel still animates: the panel being
    /// invisible does not stop the clock.
    ///
    /// That cost Lumen about eleven percent of a core, permanently, and it was only
    /// visible because the idle CPU was measured. This test makes sure no view ever
    /// does it again.
    /// </summary>
    [Fact]
    public void No_view_sets_IsIndeterminate_statically()
    {
        var offenders = new List<string>();

        foreach (var file in SourceTree.XamlFiles)
        {
            var text = File.ReadAllText(file);
            var matches = Regex.Matches(text, "IsIndeterminate\\s*=\\s*\"(?<value>[^\"]*)\"");
            foreach (Match match in matches)
            {
                var value = match.Groups["value"].Value;
                if (value.Equals("True", StringComparison.OrdinalIgnoreCase))
                {
                    offenders.Add(SourceTree.Relative(file) + ": IsIndeterminate=\"True\" is set statically");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "An indeterminate progress bar must bind IsIndeterminate to a property, " +
            "or its forever-repeating storyboard burns CPU for the whole life of the app:" +
            Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The same trap one level down: a VIEW must not start a forever-repeating
    /// animation of its own. The theme is allowed to contain one, because the theme
    /// knows how to stop it; a view does not.
    /// </summary>
    [Fact]
    public void No_view_starts_a_forever_repeating_storyboard()
    {
        var offenders = new List<string>();

        foreach (var file in SourceTree.XamlFiles)
        {
            var relative = SourceTree.Relative(file);
            if (relative.StartsWith("Themes/", StringComparison.OrdinalIgnoreCase)) continue;

            var text = File.ReadAllText(file);
            if (text.Contains("RepeatBehavior=\"Forever\"", StringComparison.Ordinal))
            {
                offenders.Add(relative);
            }
        }

        Assert.True(
            offenders.Count == 0,
            "A forever-repeating storyboard belongs in the theme, where it can be stopped " +
            "when the control is not visible:" + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }
}
