using Lumen.Core.Abstractions;
using Lumen.Core.Models;

namespace Lumen.Core.Storage;

/// <summary>
/// Bounded local scan history (newest first). The file is capped so it cannot grow without
/// limit; a corrupt file is preserved as a backup rather than silently discarded.
/// </summary>
public sealed class HistoryStore
{
    private readonly JsonFileStore<HistoryFile> _store;
    private readonly ILog _log;
    private readonly object _gate = new();
    private readonly List<ScanHistoryEntry> _entries = [];

    public HistoryStore(AppPaths paths, ILog log, int maxEntries = 200)
    {
        _log = log;
        MaxEntries = Math.Max(10, maxEntries);
        _store = new JsonFileStore<HistoryFile>(paths.HistoryFile, log);

        var file = _store.Load(out var warning);
        LoadWarning = warning;
        if (file.Entries is null) file.Entries = [];

        foreach (var entry in file.Entries
                     .OrderByDescending(candidate => candidate.StartedUtc)
                     .Take(MaxEntries))
        {
            _entries.Add(entry);
        }
    }

    public int MaxEntries { get; }
    public string? LoadWarning { get; }

    public IReadOnlyList<ScanHistoryEntry> GetEntries()
    {
        lock (_gate) return _entries.ToArray();
    }

    public OperationResult Add(ScanHistoryEntry entry)
    {
        lock (_gate)
        {
            _entries.Insert(0, entry);
            if (_entries.Count > MaxEntries) _entries.RemoveRange(MaxEntries, _entries.Count - MaxEntries);
            return SaveLocked();
        }
    }

    public OperationResult Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
            return SaveLocked();
        }
    }

    private OperationResult SaveLocked()
    {
        try
        {
            _store.Save(new HistoryFile
            {
                SchemaVersion = 1,
                Entries = _entries.ToList()
            });
            return OperationResult.Success();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or NotSupportedException or ArgumentException)
        {
            _log.Error("History", "Scan history could not be saved.", ex);
            return OperationResult.Failure("Scan history could not be saved: " + ex.Message);
        }
    }
}
