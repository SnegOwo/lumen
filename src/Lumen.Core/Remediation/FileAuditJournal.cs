using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;

namespace Lumen.Core.Remediation;

/// <summary>
/// A durable, append-only audit journal stored as one JSON object per line.
///
/// The file is only ever appended to: existing lines are never rewritten, so a crash in
/// the middle of a write can lose the last entry but can never rewrite history. The
/// location is decided by the caller, because Lumen.Core does not decide where the
/// application data lives.
/// </summary>
public sealed class FileAuditJournal : IAuditJournal
{
    /// <summary>The file name Lumen uses inside its application data folder.</summary>
    public const string DefaultFileName = "remediation-journal.jsonl";

    private static readonly JsonSerializerOptions LineOptions = CreateLineOptions();

    private readonly string _path;
    private readonly IClock _clock;
    private readonly ILog _log;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    /// <summary>
    /// Creates a journal that writes to the given file. The file and its folder are
    /// created on the first write; nothing is written at construction time.
    /// </summary>
    public FileAuditJournal(string journalPath, IClock clock, ILog log)
    {
        if (string.IsNullOrWhiteSpace(journalPath))
            throw new ArgumentException("A journal path is required.", nameof(journalPath));

        _path = Path.GetFullPath(journalPath);
        _clock = clock;
        _log = log;
    }

    /// <summary>Creates a journal inside the application's own data folder.</summary>
    public static FileAuditJournal CreateUnder(Storage.AppPaths appPaths, IClock clock, ILog log)
    {
        ArgumentNullException.ThrowIfNull(appPaths);
        return new FileAuditJournal(Path.Combine(appPaths.Root, DefaultFileName), clock, log);
    }

    /// <summary>The full path of the journal file.</summary>
    public string FilePath => _path;

    /// <summary>
    /// Appends one entry and flushes it to disk before returning. A failure to write is
    /// logged and rethrown: the caller must stop rather than act without a record.
    /// </summary>
    public async Task AppendAsync(AuditEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var stamped = entry.TimestampUtc == default
            ? entry with { TimestampUtc = _clock.UtcNow }
            : entry;

        var line = JsonSerializer.Serialize(stamped, LineOptions) + "\n";
        var bytes = Encoding.UTF8.GetBytes(line);

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            using var stream = new FileStream(
                _path,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.WriteThrough);

            await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            _log.Error("Remediation", "The audit journal could not be written; no action was taken.", ex);
            throw;
        }
        finally
        {
            _mutex.Release();
        }
    }

    /// <summary>
    /// Reads the journal back, oldest entry first. A line that cannot be parsed is skipped
    /// and logged: a damaged line must not hide the rest of the record.
    /// </summary>
    public async Task<IReadOnlyList<AuditEntry>> ReadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path)) return [];

        string[] lines;
        try
        {
            lines = await File.ReadAllLinesAsync(_path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Error("Remediation", "The audit journal could not be read.", ex);
            return [];
        }

        var entries = new List<AuditEntry>(lines.Length);
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                var entry = JsonSerializer.Deserialize<AuditEntry>(line, LineOptions);
                if (entry is not null) entries.Add(entry);
            }
            catch (JsonException ex)
            {
                _log.Warn("Remediation", "A damaged line in the audit journal was skipped.", ex);
            }
        }

        return entries;
    }

    private static JsonSerializerOptions CreateLineOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            WriteIndented = false,
            MaxDepth = 16,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }
}
