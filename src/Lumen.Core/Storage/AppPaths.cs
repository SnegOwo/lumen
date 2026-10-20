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

    public static AppPaths ForCurrentUser() =>
        new(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Lumen"));

    public void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(QuarantineDirectory);
        Directory.CreateDirectory(LogDirectory);
    }
}
