using System.Text.Json;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Storage;

namespace Lumen.Core.Storage;

public sealed class SettingsStore
{
    private readonly JsonFileStore<AppSettings> _store;

    public SettingsStore(AppPaths paths, ILog log)
    {
        _store = new JsonFileStore<AppSettings>(paths.SettingsFile, log);
    }

    public string? LoadWarning { get; private set; }

    /// <summary>
    /// Reads the settings. A file that is missing or unreadable yields the built-in
    /// defaults and a warning; a file that can be read is normalized so that hand-edited
    /// values cannot break the application.
    /// </summary>
    public AppSettings Load()
    {
        var settings = _store.Load(out var warning);
        LoadWarning = warning;

        // A settings file that is missing or cannot be read leaves the built-in defaults
        // in place, and those defaults are already valid. They are returned unchanged:
        // normalizing them would replace the empty folder lists with new (equal) arrays,
        // and a record compares those lists by reference, which would make "the settings
        // are the defaults" false.
        if (warning is not null || !File.Exists(_store.FilePath))
            return settings;

        return settings.Normalize();
    }

    /// <summary>
    /// Writes the settings. The file is replaced atomically, so a crash cannot leave a
    /// half-written settings file behind.
    /// </summary>
    public OperationResult Save(AppSettings settings)
    {
        try
        {
            _store.Save(settings.Normalize());
            return OperationResult.Success();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException or ArgumentException)
        {
            return OperationResult.Failure("Settings could not be saved: " + ex.Message);
        }
    }
}
