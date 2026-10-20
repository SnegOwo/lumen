using Lumen.Core.Util;

namespace Lumen.Core.Abstractions;

/// <summary>
/// Decides whether a path lies in a place the signed-in user can freely write to and run
/// programs from.
/// </summary>
/// <remarks>
/// <para>
/// The question matters because most software a person owns is not signed. A missing
/// signature on its own says almost nothing, so Lumen does not report it on its own. The
/// combination of "nothing says who published this" and "any program running as this user
/// can replace it" is worth a second look.
/// </para>
/// <para>
/// Implementations must stay pure: they answer from a set of known folders and must not
/// touch the file system while a scan is running. They are injected rather than looked up
/// so a test can decide what counts as a suspicious location and so the answer does not
/// depend on the machine the tests run on.
/// </para>
/// </remarks>
public interface ISuspiciousLocation
{
    /// <summary>
    /// Returns true when the path lies inside a location the user can freely write to and
    /// execute from.
    /// </summary>
    /// <param name="path">
    /// The path to classify. It may be relative; a path that names no folder at all carries
    /// no location and is treated as worth a look rather than quietly cleared.
    /// </param>
    bool IsSuspicious(string path);
}

/// <summary>
/// The default answer: the temporary folder, the user's local and roaming application data,
/// the Downloads folder and the Desktop.
/// </summary>
/// <remarks>
/// <para>
/// Everything else is ordinary. Program Files, the Windows folder and the drive roots are
/// places a normal user cannot replace, so an unsigned file there is the normal state of
/// the world and is not reported.
/// </para>
/// <para>
/// The set of folders is resolved once when the object is created and can be replaced with
/// an explicit list, which is what the tests do so that their answer does not depend on
/// where they happen to run.
/// </para>
/// </remarks>
public sealed class DefaultSuspiciousLocation : ISuspiciousLocation
{
    private readonly IReadOnlyList<string> _roots;

    /// <summary>
    /// Creates the implementation over the folders of the machine it runs on: the temporary
    /// folder, the local and roaming application data folders, the Downloads folder and the
    /// Desktop.
    /// </summary>
    public DefaultSuspiciousLocation() : this(DefaultRoots())
    {
    }

    /// <summary>
    /// Creates the implementation over an explicit set of folders. A folder that cannot be
    /// understood is dropped rather than guessed at.
    /// </summary>
    /// <param name="roots">The folders the user can freely write to and execute from.</param>
    public DefaultSuspiciousLocation(IEnumerable<string> roots)
    {
        _roots = roots
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Select(Normalize)
            .Where(root => root is not null)
            .Select(root => root!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>The folders this implementation treats as user writable.</summary>
    public IReadOnlyList<string> Roots => _roots;

    /// <inheritdoc />
    public bool IsSuspicious(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        var trimmed = path.Trim();

        // A path that names no folder cannot be placed. We cannot show that it sits in a
        // protected location, so it is not cleared either.
        if (!CarriesLocation(trimmed)) return true;

        try
        {
            foreach (var root in _roots)
            {
                // PathRules does the containment test, so "C:\Temp2" is not inside "C:\Temp".
                if (PathRules.IsWithin(trimmed, root)) return true;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            // A path Windows cannot even parse is not placed in a user writable folder.
            return false;
        }

        return false;
    }

    /// <summary>
    /// True when the path names a folder at all. A bare file name carries no location, and
    /// a rooted path does.
    /// </summary>
    private static bool CarriesLocation(string path) =>
        Path.IsPathFullyQualified(path) || LooksLikeWindowsPath(path);

    /// <summary>
    /// True for a path that starts with a drive letter. The product only runs on Windows,
    /// but the core library is also exercised by tests on other hosts, and the answer must
    /// not change with the host.
    /// </summary>
    private static bool LooksLikeWindowsPath(string path) =>
        path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':';

    private static string? Normalize(string root)
    {
        try
        {
            return PathRules.NormalizeDirectory(root);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            // A folder that cannot be resolved is simply not part of the answer.
            return null;
        }
    }

    /// <summary>
    /// The folders of the current machine that a user can freely write to and run from.
    /// </summary>
    private static IReadOnlyList<string> DefaultRoots()
    {
        var candidates = new List<string>();

        Add(candidates, Path.GetTempPath());
        Add(candidates, Environment.GetEnvironmentVariable("TEMP"));
        Add(candidates, Environment.GetEnvironmentVariable("TMP"));
        Add(candidates, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
        Add(candidates, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        Add(candidates, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        Add(candidates, Environment.GetFolderPath(Environment.SpecialFolder.Desktop));

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(profile))
        {
            Add(candidates, Path.Combine(profile, "Downloads"));
        }

        return candidates;
    }

    private static void Add(List<string> candidates, string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return;
        candidates.Add(candidate);
    }
}
