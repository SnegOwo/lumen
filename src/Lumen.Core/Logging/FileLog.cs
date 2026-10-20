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
    private readonly object _gate = new();
    private readonly string _directory;
    private readonly string _filePath;
    private readonly IClock _clock;
    private readonly string? _userProfile;
    private readonly string? _dataDirectory;
    private volatile bool _enabled;

    public FileLog(
        string directory,
        IClock clock,
        bool enabled,
        string? userProfilePath = null,
        string? dataDirectory = null)
    {
        _directory = directory;
        _filePath = Path.Combine(directory, "lumen.log");
        _clock = clock;
        _enabled = enabled;
        _userProfile = userProfilePath;
        _dataDirectory = dataDirectory;
    }

    public bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    public string LogFilePath => _filePath;

    public void Info(string category, string message) => Write("INFO", category, message, null);
    public void Warn(string category, string message, Exception? exception = null) =>
        Write("WARN", category, message, exception);

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
                Directory.CreateDirectory(_directory);
                RotateIfNeeded();
                File.AppendAllText(_filePath, line.AppendLine().ToString(), new UTF8Encoding(false));
            }
        }
        catch
        {
            // Diagnostics must not break the application.
        }
    }

    private void RotateIfNeeded()
    {
        var info = new FileInfo(_filePath);
        if (!info.Exists || info.Length < MaxBytes) return;

        var backup = _filePath + ".1";
        if (File.Exists(backup)) File.Delete(backup);
        File.Move(_filePath, backup);
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
