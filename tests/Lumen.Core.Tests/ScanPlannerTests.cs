using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Tests;

public sealed class ScanPlannerTests
{
    [Fact]
    public void Quick_scan_uses_existing_standard_folders()
    {
        using var temp = new TempDirectory();
        var profile = temp.CreateDirectory("profile");
        temp.CreateDirectory("profile/Desktop");
        temp.CreateDirectory("profile/Documents");
        temp.CreateDirectory("profile/Downloads");
        var planner = CreatePlanner(temp, profile);

        var request = planner.CreateQuick();

        Assert.Equal(ScanScopeKind.Quick, request.Scope);
        Assert.Equal(3, request.Roots.Count);
        Assert.Contains(request.Roots, path => path.EndsWith("Desktop", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(request.Roots, path => path.EndsWith("Documents", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(request.Roots, path => path.EndsWith("Downloads", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Quick scan", request.Description);
    }

    [Fact]
    public void Quick_scan_with_no_standard_folders_returns_empty_roots()
    {
        using var temp = new TempDirectory();
        var profile = temp.CreateDirectory("empty-profile");
        var planner = CreatePlanner(temp, profile);

        var request = planner.CreateQuick();

        Assert.Empty(request.Roots);
    }

    [Fact]
    public void Full_scan_excludes_appdata_and_caches_and_uses_configured_limit()
    {
        using var temp = new TempDirectory();
        var profile = temp.CreateDirectory("profile");
        var planner = new ScanPlanner(
            profile,
            Path.Combine(temp.Root, "lumen-data"),
            AppSettings.Default with { MaxInspectMegabytes = 2 });

        var request = planner.CreateFullProfile();

        Assert.Equal(ScanScopeKind.FullUserProfile, request.Scope);
        Assert.Single(request.Roots);
        Assert.Contains(
            request.ExcludedDirectories,
            path => string.Equals(path, Path.Combine(profile, "AppData"), StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2 * 1024 * 1024, request.MaxInspectBytes);
        Assert.Contains("Full scan", request.Description);
    }

    [Fact]
    public void Custom_folder_and_file_requests_are_typed_and_validated()
    {
        using var temp = new TempDirectory();
        var profile = temp.CreateDirectory("profile");
        var folder = temp.CreateDirectory("custom/folder");
        var file = temp.File("custom/folder/file.txt", "x");
        var planner = CreatePlanner(temp, profile);

        var folderRequest = planner.CreateFolder(folder);
        var fileRequest = planner.CreateFile(file);

        Assert.Equal(ScanScopeKind.Folder, folderRequest.Scope);
        Assert.Equal(PathRules.NormalizeDirectory(folder), Assert.Single(folderRequest.Roots));
        Assert.Equal(ScanScopeKind.File, fileRequest.Scope);
        Assert.Equal(PathRules.NormalizeFile(file), Assert.Single(fileRequest.Roots));
        Assert.Throws<ArgumentException>(() => planner.CreateFolder(file));
        Assert.Throws<ArgumentException>(() => planner.CreateFile(folder));
        Assert.Throws<ArgumentException>(() => planner.CreateFile(Path.Combine(temp.Root, "missing.txt")));
    }

    [Fact]
    public void MaxInspect_bytes_are_clamped_to_safe_range()
    {
        using var temp = new TempDirectory();
        var profile = temp.CreateDirectory("profile");
        var tooSmall = new ScanPlanner(
            profile,
            Path.Combine(temp.Root, "data"),
            AppSettings.Default with { MaxInspectMegabytes = 0 });
        var tooLarge = new ScanPlanner(
            profile,
            Path.Combine(temp.Root, "data"),
            AppSettings.Default with { MaxInspectMegabytes = 999 });

        Assert.Equal(1 * 1024 * 1024, tooSmall.CreateFullProfile().MaxInspectBytes);
        Assert.Equal(16L * 1024 * 1024, tooLarge.CreateFullProfile().MaxInspectBytes);
    }

    private static ScanPlanner CreatePlanner(TempDirectory temp, string profile) =>
        new(profile, Path.Combine(temp.Root, "lumen-data"), AppSettings.Default);
}
