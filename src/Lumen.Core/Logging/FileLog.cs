using System.Text;
using Lumen.Core.Abstractions;

namespace Lumen.Core.Logging;

/// <summary>
/// Append-only UTF-8 log with size-based rotation. Logging failures are swallowed by design:
/// disk problems must never take down a scan. Messages are sanitized and file contents are
/// never logged.
/// </summary>
public sealed class FileLog : ILog
{
    private const long MaxBytes = 2 * 1024 * 1024;

    /// <summary>
    /// How many rotated files are kept next to the live log (lumen.log.1, .2 and .3).
    /// Older generations are dropped so diagnostics survive a few restarts without the
    /// log folder growing without bound.
    /// </summary>
    private const int MaxGenerations = 3;

    private readonly object _gate = new();
    private readonly string _directory;
    private readonly string _filePath;
    private readonly IClock _clock;
    private readonly string? _userProfile;
    private readonly string? _dataDirectory;
    private readonly long _maxBytes;
    private readonly UTF8Encoding _encoding = new(false);
    private volatile bool _enabled;
    private bool _directoryReady;

    /// <summary>
    /// Creates a log that writes to <c>lumen.log</c> inside the given folder.
    /// </summary>
    /// <param name="directory">Folder that holds the log and its rotated generations.</param>
    /// <param name="clock">Clock used for the timestamp of every line.</param>
    /// <param name="enabled">Whether anything is written at all.</param>
    /// <param name="userProfilePath">User folder that is replaced with %USERPROFILE% in messages.</param>
    /// <param name="dataDirectory">Lumen data folder that is replaced with %LUMEN_DATA% in messages.</param>
    /// <param name="maxBytes">Size at which the log is rotated. Lower values keep the tests fast.</param>
    public FileLog(
        string directory,
        IClock clock,
        bool enabled,
        string? userProfilePath = null,
        string? dataDirectory = null,
        long maxBytes = MaxBytes)
    {
        _directory = directory;
        _filePath = Path.Combine(directory, "lumen.log");
        _clock = clock;
        _enabled = enabled;
        _userProfile = userProfilePath;
        _dataDirectory = dataDirectory;
        _maxBytes = Math.Max(512, maxBytes);
    }

    /// <summary>Whether anything is written to the log at all.</summary>
    public bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    /// <summary>Full path of the live log file.</summary>
    public string LogFilePath => _filePath;

    /// <summary>Writes an informational line.</summary>
    public void Info(string category, string message) => Write("INFO", category, message, null);

    /// <summary>Writes a warning line.</summary>
    public void Warn(string category, string message, Exception? exception = null) =>
        Write("WARN", category, message, exception);

    /// <summary>Writes an error line.</summary>
    public void Error(string category, string message, Exception? exception = null) =>
        Write("ERROR", category, message, exception);

    private void Write(string level, string category, string message, Exception? exception)
    {
        if (!_enabled) return;

        try
        {
            var line = new StringBuilder(256);
            line.Append(_clock.UtcNow.ToString("O"))
                .Append(" [").Append(level).Append("] [")
                .Append(Sanitize(category)).Append("] ")
                .Append(Sanitize(message));

            if (exception is not null)
            {
                line.Append(" | ").Append(exception.GetType().Name);
                if (!string.IsNullOrWhiteSpace(exception.Message))
                    line.Append(": ").Append(Sanitize(exception.Message));
            }

            lock (_gate)
            {
                EnsureDirectory();
                RotateIfNeeded();

                // The handle is opened for the single write and closed again. A handle
                // that stays open for the lifetime of the application would stop the
                // user (and any diagnostic tool) from reading the log, because Windows
                // refuses to open a file for reading while somebody holds it for
                // writing. The directory is only created once, which was the other
                // half of the per-line cost.
                var bytes = _encoding.GetBytes(line.AppendLine().ToString());
                using var stream = new FileStream(
                    _filePath,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.Read,
                    bufferSize: 4096,
                    FileOptions.None);
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush();
            }
        }
        catch (DirectoryNotFoundException)
        {
            _directoryReady = false;
        }
        catch
        {
            // Diagnostics must not break the application.
        }
    }

    /// <summary>
    /// Creates the log folder once instead of on every line.
    /// </summary>
    private void EnsureDirectory()
    {
        if (_directoryReady) return;
        Directory.CreateDirectory(_directory);
        _directoryReady = true;
    }

    private void RotateIfNeeded()
    {
        var info = new FileInfo(_filePath);
        if (!info.Exists || info.Length < _maxBytes) return;

        Rotate();
    }

    /// <summary>
    /// Shifts the existing generations up by one and starts a fresh log file. The oldest
    /// generation is dropped so the number of files stays bounded.
    /// </summary>
    private void Rotate()
    {
        TryDelete($"{_filePath}.{MaxGenerations}");
        for (var generation = MaxGenerations - 1; generation >= 1; generation--)
        {
            TryMove($"{_filePath}.{generation}", $"{_filePath}.{generation + 1}");
        }

        TryMove(_filePath, $"{_filePath}.1");
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // Rotation is best effort; a locked old generation must not stop logging.
        }
    }

    private static void TryMove(string source, string destination)
    {
        try
        {
            if (File.Exists(source)) File.Move(source, destination, overwrite: true);
        }
        catch
        {
            // Rotation is best effort; a locked old generation must not stop logging.
        }
    }

    private string Sanitize(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var sanitized = text
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal);

        if (!string.IsNullOrWhiteSpace(_userProfile))
            sanitized = sanitized.Replace(_userProfile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(_dataDirectory))
            sanitized = sanitized.Replace(_dataDirectory, "%LUMEN_DATA%", StringComparison.OrdinalIgnoreCase);

        if (sanitized.Length > 4000)
            sanitized = string.Concat(sanitized.AsSpan(0, 3999), "\u2026");

        return sanitized;
    }
}
