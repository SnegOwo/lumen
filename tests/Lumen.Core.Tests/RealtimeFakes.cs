using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

/// <summary>
/// A watcher that does nothing on its own. Tests drive it directly, so watcher failures
/// and file-system events are produced on demand instead of depending on real file-system
/// timing.
/// </summary>
internal sealed class FakeWatcher : IFileSystemWatcher
{
    public FakeWatcher(string root) => Root = root;

    public string Root { get; }
    public bool Enabled { get; private set; }
    public bool Disposed { get; private set; }
    public int EnableCount { get; private set; }

    public event EventHandler<FileSystemEventArgs>? Created;
    public event EventHandler<FileSystemEventArgs>? Changed;
    public event EventHandler<FileSystemEventArgs>? Deleted;
    public event EventHandler<RenamedEventArgs>? Renamed;
    public event EventHandler<ErrorEventArgs>? Error;

    public void Enable()
    {
        Enabled = true;
        EnableCount++;
    }

    public void Disable() => Enabled = false;

    public void Dispose()
    {
        Disposed = true;
        Enabled = false;
    }

    public void RaiseCreated(string path) =>
        Created?.Invoke(this, EventArgs(WatcherChangeTypes.Created, path));

    public void RaiseChanged(string path) =>
        Changed?.Invoke(this, EventArgs(WatcherChangeTypes.Changed, path));

    public void RaiseDeleted(string path) =>
        Deleted?.Invoke(this, EventArgs(WatcherChangeTypes.Deleted, path));

    public void RaiseRenamed(string path) =>
        Renamed?.Invoke(
            this,
            new RenamedEventArgs(
                WatcherChangeTypes.Renamed,
                Path.GetDirectoryName(path) ?? string.Empty,
                Path.GetFileName(path),
                Path.GetFileName(path)));

    public void RaiseError(Exception? exception = null) =>
        Error?.Invoke(this, new ErrorEventArgs(exception ?? new IOException("The watcher failed.")));

    /// <summary>
    /// Builds the event arguments the way the operating system does: a directory and a file
    /// name, which the framework combines back into the full path.
    /// </summary>
    private static FileSystemEventArgs EventArgs(WatcherChangeTypes changeType, string path) =>
        new(changeType, Path.GetDirectoryName(path) ?? string.Empty, Path.GetFileName(path));
}

/// <summary>
/// Hands out <see cref="FakeWatcher"/> instances and remembers every one it created, so a
/// test can tell whether the monitor rebuilt a watcher after a failure.
/// </summary>
internal sealed class FakeWatcherFactory : IFileSystemWatcherFactory
{
    private readonly object _gate = new();
    private readonly List<FakeWatcher> _created = [];

    public IReadOnlyList<FakeWatcher> Created
    {
        get { lock (_gate) return _created.ToArray(); }
    }

    public IFileSystemWatcher Create(string root)
    {
        var watcher = new FakeWatcher(root);
        lock (_gate) _created.Add(watcher);
        return watcher;
    }

    public FakeWatcher? Latest
    {
        get { lock (_gate) return _created.Count == 0 ? null : _created[^1]; }
    }

    /// <summary>
    /// The most recent watcher the monitor has actually switched on. A watcher that has
    /// been created but not enabled yet is not yet known to the monitor.
    /// </summary>
    public FakeWatcher? LatestEnabled
    {
        get
        {
            lock (_gate)
            {
                for (var index = _created.Count - 1; index >= 0; index--)
                {
                    if (_created[index].Enabled) return _created[index];
                }

                return null;
            }
        }
    }
}

/// <summary>
/// A hash provider that always fails, standing in for a file that is locked or in use.
/// </summary>
internal sealed class FailingHashProvider : IFileHashProvider
{
    private readonly string _reason;

    public FailingHashProvider(string reason = "The file is in use and could not be hashed.") => _reason = reason;

    public FileHashResult TryComputeSha256(string path, CancellationToken cancellationToken) =>
        new()
        {
            Outcome = FileHashOutcome.Failed,
            Error = _reason
        };
}

/// <summary>
/// A detector that records every probe it sees, so a test can check how much of a file was
/// actually read.
/// </summary>
internal sealed class RecordingDetector : IScanDetector
{
    private readonly Func<FileProbe, bool> _match;
    private readonly object _gate = new();
    private readonly List<FileProbe> _probes = [];

    public RecordingDetector(string id, Func<FileProbe, bool> match)
    {
        Id = id;
        _match = match;
    }

    public string Id { get; }
    public string Name => "Recording detector";
    public string Description => "Test detector";
    public FindingCategory Category => FindingCategory.Heuristic;
    public Confidence Confidence => Confidence.Medium;

    public IReadOnlyList<FileProbe> Probes
    {
        get { lock (_gate) return _probes.ToArray(); }
    }

    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        lock (_gate) _probes.Add(probe);
        if (!_match(probe)) return [];

        return
        [
            new Finding
            {
                RuleId = Id,
                Title = "Test finding",
                Category = Category,
                Confidence = Confidence,
                Summary = "Test summary",
                Detail = "Test detail",
                Advice = "Test advice"
            }
        ];
    }
}
