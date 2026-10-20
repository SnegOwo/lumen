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

    public AppSettings Load()
    {
        var settings = _store.Load(out var warning);
        LoadWarning = warning;
        return settings.Normalize();
    }

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
