using Lumen.App.ViewModels;
using Lumen.Core.Models;

namespace Lumen.App.Tests;

public sealed class PresentationTests
{
    [Theory]
    [InlineData(1L, "1 file")]
    [InlineData(0L, "0 files")]
    [InlineData(12L, "12 files")]
    [InlineData(2L, "2 files")]
    public void Count_withAFileCount_formatsTheCountAndTheNoun(long value, string expected)
    {
        Assert.Equal(expected, Presentation.Count(value, "file"));
    }

    [Fact]
    public void Count_withAnExplicitPlural_usesTheGivenPlural()
    {
        Assert.Equal("0 items", Presentation.Count(0, "item", "items"));
        Assert.Equal("1 item", Presentation.Count(1, "item", "items"));
        Assert.Equal("3 items", Presentation.Count(3, "item", "items"));
    }

    [Fact]
    public void Count_withThousands_groupsTheDigits()
    {
        var expected = 1500.ToString("N0") + " files";

        Assert.Equal(expected, Presentation.Count(1500, "file"));
    }

    [Theory]
    [InlineData("file", "files")]
    [InlineData("scan", "scans")]
    [InlineData("box", "boxes")]
    [InlineData("buzz", "buzzes")]
    [InlineData("match", "matches")]
    [InlineData("dish", "dishes")]
    [InlineData("policy", "policies")]
    [InlineData("city", "cities")]
    [InlineData("day", "days")]
    [InlineData("key", "keys")]
    public void Plural_pluralisesTheNoun(string singular, string expected)
    {
        Assert.Equal(expected, Presentation.Plural(singular));
    }

    [Fact]
    public void Plural_withBlankText_returnsAnEmptyString()
    {
        Assert.Equal(string.Empty, Presentation.Plural(string.Empty));
        Assert.Equal(string.Empty, Presentation.Plural("   "));
    }

    [Fact]
    public void Category_everyCategory_hasALabel()
    {
        foreach (var category in Enum.GetValues<FindingCategory>())
        {
            var label = Presentation.Category(category);

            Assert.False(string.IsNullOrWhiteSpace(label), $"{category} has no label.");
        }
    }

    [Fact]
    public void CategoryHint_everyCategoryHasAHint()
    {
        foreach (var category in Enum.GetValues<FindingCategory>())
        {
            var hint = Presentation.CategoryHint(category);

            Assert.False(string.IsNullOrWhiteSpace(hint), $"{category} has no hint.");
        }
    }

    [Fact]
    public void Category_theTestSignatureIsNamedDistinctly()
    {
        Assert.Equal("Test signature", Presentation.Category(FindingCategory.TestSignature));
    }

    [Fact]
    public void ConfidenceText_everyConfidenceHasALabel()
    {
        foreach (var confidence in Enum.GetValues<Confidence>())
        {
            var label = Presentation.ConfidenceText(confidence);

            Assert.False(string.IsNullOrWhiteSpace(label), $"{confidence} has no label.");
        }
    }

    [Fact]
    public void Scope_everyScopeHasALabel()
    {
        foreach (var scope in Enum.GetValues<ScanScopeKind>())
        {
            var label = Presentation.Scope(scope);

            Assert.False(string.IsNullOrWhiteSpace(label), $"{scope} has no label.");
        }
    }

    [Fact]
    public void ErrorKind_everyErrorKindHasALabel()
    {
        foreach (var kind in Enum.GetValues<ScanErrorKind>())
        {
            var label = Presentation.ErrorKind(kind);

            Assert.False(string.IsNullOrWhiteSpace(label), $"{kind} has no label.");
        }
    }

    [Fact]
    public void Sanitize_withControlCharacters_replacesThemWithSpaces()
    {
        var sanitized = Presentation.Sanitize("before\u0007after");

        Assert.DoesNotContain('\u0007', sanitized);
        Assert.Equal("before after", sanitized);
    }

    [Fact]
    public void Sanitize_withLineBreaks_flattensThemIntoSpaces()
    {
        var sanitized = Presentation.Sanitize("line one\r\nline two");

        Assert.DoesNotContain('\r', sanitized);
        Assert.DoesNotContain('\n', sanitized);
        Assert.Contains("line one", sanitized);
        Assert.Contains("line two", sanitized);
    }

    [Theory]
    [InlineData('\u202A')]
    [InlineData('\u202B')]
    [InlineData('\u202C')]
    [InlineData('\u202D')]
    [InlineData('\u202E')]
    [InlineData('\u2066')]
    [InlineData('\u2069')]
    [InlineData('\u200E')]
    [InlineData('\u200F')]
    public void Sanitize_withBidiCharacters_neutralisesThem(char bidi)
    {
        var sanitized = Presentation.Sanitize("a" + bidi + "b");

        Assert.DoesNotContain(bidi, sanitized);
        Assert.Contains("\\u", sanitized, StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitize_withNull_returnsAnEmptyString()
    {
        Assert.Equal(string.Empty, Presentation.Sanitize(null));
    }

    [Fact]
    public void Sanitize_withText_longerThanTheLimit_truncatesIt()
    {
        var sanitized = Presentation.Sanitize(new string('x', 500), 50);

        Assert.Equal(50, sanitized.Length);
        Assert.EndsWith("\u2026", sanitized, StringComparison.Ordinal);
    }

    [Fact]
    public void SanitizePath_withControlCharacters_replacesThemWithSpaces()
    {
        var sanitized = Presentation.SanitizePath("C:\\temp\u0000file.txt");

        Assert.DoesNotContain('\u0000', sanitized);
        Assert.Contains("file.txt", sanitized);
    }
}
