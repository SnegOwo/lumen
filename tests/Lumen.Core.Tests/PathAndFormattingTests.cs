using System.Text;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.Core.Tests;

public sealed class PathAndFormattingTests
{
    [Fact]
    public void IsWithin_matches_children_but_not_siblings_or_prefixes()
    {
        using var temp = new TempDirectory();
        var parent = temp.CreateDirectory("parent");
        var child = temp.CreateDirectory("parent/child");
        var sibling = temp.CreateDirectory("parent-child");
        var file = temp.File("parent/child/file.txt", "x");

        Assert.True(PathRules.IsWithin(child, parent));
        Assert.True(PathRules.IsWithin(file, parent));
        Assert.True(PathRules.IsWithin(parent, parent));
        Assert.False(PathRules.IsWithin(sibling, parent));
        Assert.False(PathRules.IsWithin(parent, child));
    }

    [Fact]
    public void Exclusions_cover_the_whole_subtree()
    {
        using var temp = new TempDirectory();
        var cache = temp.CreateDirectory("cache");
        var file = temp.File("cache/deep/file.txt", "x");
        var other = temp.File("other/file.txt", "x");

        Assert.True(PathRules.IsExcluded(file, [cache]));
        Assert.False(PathRules.IsExcluded(other, [cache]));
    }

    [Fact]
    public void System_critical_and_network_paths_are_recognized()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windows))
        {
            Assert.True(PathRules.IsSystemCritical(Path.Combine(windows, "System32")));
        }

        using var temp = new TempDirectory();
        Assert.True(PathRules.IsDriveRoot(Path.GetPathRoot(temp.Root)!));
        Assert.True(PathRules.IsNetworkPath(@"\\server\share"));
        Assert.False(PathRules.IsNetworkPath(temp.Root));
    }

    [Fact]
    public void ValidateTarget_reports_files_folders_and_missing_paths()
    {
        using var temp = new TempDirectory();
        var file = temp.File("file.txt", "x");
        var folder = temp.CreateDirectory("folder");

        var fileResult = PathRules.ValidateTarget(file);
        var folderResult = PathRules.ValidateTarget(folder);
        var missing = PathRules.ValidateTarget(Path.Combine(temp.Root, "missing"));

        Assert.True(fileResult.IsValid);
        Assert.False(fileResult.IsDirectory);
        Assert.True(folderResult.IsValid);
        Assert.True(folderResult.IsDirectory);
        Assert.False(missing.IsValid);
        Assert.False(string.IsNullOrWhiteSpace(missing.Error));
    }

    [Fact]
    public void Display_text_hides_control_and_bidi_characters_and_truncates()
    {
        var sanitized = DisplayText.Sanitize("bad\u0001name\u202Eexe", 100);

        Assert.DoesNotContain('\u0001', sanitized);
        Assert.Contains("\\u202E", sanitized);

        var longText = new string('a', 600);
        Assert.Equal(300, DisplayText.Sanitize(longText).Length);
    }

    [Fact]
    public void Size_and_time_formatting_is_readable()
    {
        Assert.Equal("0 B", SizeFormatter.Format(0));
        Assert.Equal("1.5 KB", SizeFormatter.Format(1536));
        Assert.Equal("1 MB", SizeFormatter.Format(1024 * 1024));
        Assert.Equal("1m 15s", TimeFormatter.Duration(TimeSpan.FromSeconds(75)));

        var now = new DateTimeOffset(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal("just now", TimeFormatter.Relative(now.AddSeconds(-10), now));
        Assert.Equal("5 minutes ago", TimeFormatter.Relative(now.AddMinutes(-5), now));
    }

    [Fact]
    public void Sha256_matches_known_vector()
    {
        const string expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        Assert.Equal(expected, HashUtil.Sha256Bytes(Encoding.ASCII.GetBytes("abc")));

        using var temp = new TempDirectory();
        var path = temp.File("abc.txt", "abc");
        Assert.Equal(expected, HashUtil.Sha256File(path, CancellationToken.None));
    }

    [Fact]
    public void Settings_normalize_handles_bad_values()
    {
        var normalized = (AppSettings.Default with
        {
            Theme = (AppTheme)99,
            MaxInspectMegabytes = -5
        }).Normalize();

        Assert.Equal(AppTheme.System, normalized.Theme);
        Assert.Equal(AppSettings.MinAllowedInspectMegabytes, normalized.MaxInspectMegabytes);
    }
}
