using System.Text.Json;
using Lumen.Core.Abstractions;
using Lumen.Core.Util;

namespace Lumen.Core.Storage;

/// <summary>
/// Loads a JSON file and turns corruption into a warning plus a preserved backup instead of
/// an exception. Saves are atomic.
/// </summary>
public sealed class JsonFileStore<T> where T : class, new()
{
    private readonly string _path;
    private readonly ILog _log;
    private readonly long _maxBytes;

    public JsonFileStore(string path, ILog log, long maxBytes = 8 * 1024 * 1024)
    {
        _path = path;
        _log = log;
        _maxBytes = maxBytes;
    }

    public string FilePath => _path;

    public T Load(out string? warning)
    {
        warning = null;
        if (!File.Exists(_path)) return new T();

        try
        {
            var info = new FileInfo(_path);
            if (info.Length > _maxBytes)
            {
                warning = PreserveCorrupt("The data file is unexpectedly large.", null);
                return new T();
            }

            var bytes = File.ReadAllBytes(_path);
            var value = JsonSerializer.Deserialize<T>(bytes, JsonDefaults.Options);
            if (value is null)
            {
                warning = PreserveCorrupt("The data file contained no usable data.", null);
                return new T();
            }

            return value;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException or ArgumentException)
        {
            warning = PreserveCorrupt("The data file could not be read.", ex);
            return new T();
        }
    }

    public void Save(T value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonDefaults.Options);
        AtomicFile.WriteAllBytes(_path, bytes);
    }

    private string PreserveCorrupt(string reason, Exception? exception)
    {
        _log.Error("Storage", $"{reason} File: {DisplayText.SanitizePath(_path)}", exception);

        try
        {
            var backup = _path + ".corrupt-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            File.Move(_path, backup, overwrite: true);
            return $"{reason} The unreadable file was preserved as {DisplayText.SanitizePath(backup)}.";
        }
        catch (Exception ex)
        {
            _log.Error("Storage", "Could not preserve the unreadable data file.", ex);
            return $"{reason} It could not be preserved automatically.";
        }
    }
}
