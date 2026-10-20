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

            // A UTF-8 byte order mark is legal in a text file and editors such as
            // Notepad add one. System.Text.Json rejects it, which would make Lumen
            // throw away a perfectly good settings file just because someone opened it
            // in a text editor and saved it.
            var offset = 0;
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) offset = 3;

            var value = JsonSerializer.Deserialize<T>(bytes.AsSpan(offset), JsonDefaults.Options);
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
            // The name carries milliseconds and a short random suffix so that two
            // corruptions in the same second cannot overwrite each other's backup.
            var stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            var suffix = Guid.NewGuid().ToString("N")[..8];
            var backup = _path + ".corrupt-" + stamp + "-" + suffix;
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
