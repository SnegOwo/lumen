using System.Reflection;

namespace Lumen.App.Tests.Support;

/// <summary>
/// Locates the Lumen source tree at runtime so the theme scans can read the
/// real XAML files. Nothing in this project may hard-code an absolute path:
/// the walk-up from the test binaries finds the solution, and the build-time
/// <c>LumenRepositoryRoot</c> assembly metadata is only a fallback for the
/// case where the binaries were emitted outside the repository (for example
/// into a separate <c>--artifacts-path</c>).
/// </summary>
internal static class SourceTree
{
    private const string SolutionFileName = "Lumen.slnx";

    public static string RepositoryRoot { get; } = FindRepositoryRoot();

    public static string AppProjectDirectory => Path.Combine(RepositoryRoot, "src", "Lumen.App");

    public static string ThemesDirectory => Path.Combine(AppProjectDirectory, "Themes");

    /// <summary>Every XAML file that belongs to the application project.</summary>
    public static IReadOnlyList<string> XamlFiles { get; } = FindFiles(".xaml");

    /// <summary>Every XAML file that belongs to the theme folder.</summary>
    public static IReadOnlyList<string> ThemeFiles { get; } =
        XamlFiles.Where(path => path.StartsWith(ThemesDirectory, StringComparison.OrdinalIgnoreCase)).ToArray();

    /// <summary>Every source file (XAML and C#) of the application project.</summary>
    public static IReadOnlyList<string> SourceFiles { get; } = FindFiles(".xaml", ".cs");

    public static string Relative(string path) =>
        Path.GetRelativePath(AppProjectDirectory, path).Replace('\\', '/');

    private static IReadOnlyList<string> FindFiles(params string[] extensions) =>
        Directory.EnumerateFiles(AppProjectDirectory, "*.*", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => extensions.Any(extension => path.EndsWith(extension, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();

    private static bool IsBuildOutput(string path)
    {
        var relative = Path.GetRelativePath(AppProjectDirectory, path).Replace('\\', '/');
        return relative.StartsWith("obj/", StringComparison.OrdinalIgnoreCase)
            || relative.StartsWith("bin/", StringComparison.OrdinalIgnoreCase)
            || relative.Contains("/obj/", StringComparison.OrdinalIgnoreCase)
            || relative.Contains("/bin/", StringComparison.OrdinalIgnoreCase);
    }

    private static string FindRepositoryRoot()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            var found = SearchUpwards(start);
            if (found is not null) return found;
        }

        var baked = typeof(SourceTree).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => attribute.Key == "LumenRepositoryRoot")?.Value;

        if (!string.IsNullOrWhiteSpace(baked) && File.Exists(Path.Combine(baked, SolutionFileName)))
        {
            return Path.GetFullPath(baked);
        }

        throw new InvalidOperationException(
            "Could not locate the Lumen repository root (a directory containing '" + SolutionFileName + "').");
    }

    private static string? SearchUpwards(string start)
    {
        var directory = new DirectoryInfo(start);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, SolutionFileName))) return directory.FullName;
            directory = directory.Parent;
        }

        return null;
    }
}
