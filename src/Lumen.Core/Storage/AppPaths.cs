namespace Lumen.Core.Storage;

/// <summary>
/// Per-user, non-roaming application data locations. Nothing is written to the install
/// folder, ProgramData or the registry.
/// </summary>
public sealed class AppPaths
{
    public AppPaths(string root)
    {
        Root = Path.GetFullPath(root);
    }

    public string Root { get; }
    public string SettingsFile => Path.Combine(Root, "settings.json");
    public string HistoryFile => Path.Combine(Root, "history.json");
    public string QuarantineDirectory => Path.Combine(Root, "quarantine");
    public string QuarantineManifestFile => Path.Combine(QuarantineDirectory, "manifest.json");
    public string LogDirectory => Path.Combine(Root, "logs");
    public string LogFile => Path.Combine(LogDirectory, "lumen.log");

    /// <summary>
    /// The per-user data folder.
    ///
    /// Set the <c>LUMEN_DATA_DIR</c> environment variable to put Lumen's data somewhere
    /// else entirely. That is how the sandbox mode works: point it at a folder inside
    /// the project, and deleting that folder removes every trace of a test run.
    /// </summary>
    public static AppPaths ForCurrentUser()
    {
        var overridePath = Environment.GetEnvironmentVariable("LUMEN_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            try
            {
                return new AppPaths(Path.GetFullPath(overridePath.Trim()));
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // An unusable override falls back to the normal location rather than
                // refusing to start.
            }
        }

        return new AppPaths(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Lumen"));
    }

    public void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(QuarantineDirectory);
        Directory.CreateDirectory(LogDirectory);
    }
}
