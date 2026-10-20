namespace Lumen.Core.Protection;

/// <summary>
/// A minimal watcher abstraction over <see cref="FileSystemWatcher"/>. The real watcher is
/// fragile: it dies when its root is renamed or deleted, it drops events when its internal
/// buffer overflows, and it fails silently on a network share that disappears. Keeping the
/// surface behind an interface lets the monitor treat a watcher as a resource it can throw
/// away and rebuild, and lets tests produce a failure on demand instead of hoping the
/// filesystem misbehaves.
/// </summary>
public interface IFileSystemWatcher : IDisposable
{
    /// <summary>The folder this watcher observes. Used for logging and re-scan purposes.</summary>
    string Root { get; }

    /// <summary>
    /// Starts delivering events. Implementations must tolerate being enabled more than once.
    /// </summary>
    void Enable();

    /// <summary>
    /// Stops delivering events. Implementations must tolerate being disabled more than once
    /// and must not throw when the underlying root has already disappeared.
    /// </summary>
    void Disable();

    /// <summary>Raised for a file that appeared.</summary>
    event EventHandler<FileSystemEventArgs>? Created;

    /// <summary>Raised for a file whose contents or metadata changed.</summary>
    event EventHandler<FileSystemEventArgs>? Changed;

    /// <summary>Raised for a file that was removed. The path no longer exists.</summary>
    event EventHandler<FileSystemEventArgs>? Deleted;

    /// <summary>Raised for a file that was renamed or moved inside the watched tree.</summary>
    event EventHandler<RenamedEventArgs>? Renamed;

    /// <summary>
    /// Raised when the watcher itself failed. The monitor treats this as "this folder is no
    /// longer covered" and rebuilds the watcher.
    /// </summary>
    event EventHandler<ErrorEventArgs>? Error;
}

/// <summary>
/// Creates watchers for a folder. The default implementation returns watchers backed by the
/// real <see cref="FileSystemWatcher"/>; tests inject a fake so watcher failures and events
/// can be produced deterministically.
/// </summary>
public interface IFileSystemWatcherFactory
{
    /// <summary>
    /// Creates a watcher for <paramref name="root"/>. The returned watcher is not enabled;
    /// the caller decides when to start receiving events.
    /// </summary>
    IFileSystemWatcher Create(string root);
}

/// <summary>
/// The default <see cref="IFileSystemWatcherFactory"/>, backed by the real
/// <see cref="FileSystemWatcher"/>. This is a user-mode watcher: it observes the folder
/// tree it was given and nothing else, and it stops working when the application stops.
/// </summary>
public sealed class FileSystemWatcherFactory : IFileSystemWatcherFactory
{
    /// <summary>
    /// The internal buffer size requested from the operating system watcher. The Windows
    /// default is 8 KB, which overflows easily on a busy folder; 64 KB is the documented
    /// maximum and drops far fewer events.
    /// </summary>
    internal const int BufferSize = 64 * 1024;

    /// <inheritdoc />
    public IFileSystemWatcher Create(string root) => new RealFileSystemWatcher(root);
}

/// <summary>
/// Wraps the real <see cref="FileSystemWatcher"/> so the rest of the product never depends
/// on that type directly. The wrapper adds nothing to the safety contract: it only observes.
/// </summary>
internal sealed class RealFileSystemWatcher : IFileSystemWatcher
{
    private readonly FileSystemWatcher _watcher;
    private readonly string _root;

    public RealFileSystemWatcher(string root)
    {
        _root = root;
        _watcher = new FileSystemWatcher(root)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                           NotifyFilters.Size | NotifyFilters.DirectoryName,
            EnableRaisingEvents = false
        };

        try
        {
            _watcher.InternalBufferSize = FileSystemWatcherFactory.BufferSize;
        }
        catch (ArgumentOutOfRangeException)
        {
            // A platform with a smaller maximum keeps its default buffer; the monitor
            // still recovers from an overflow, it just has to rebuild more often.
        }

        _watcher.Created += OnCreated;
        _watcher.Changed += OnChanged;
        _watcher.Deleted += OnDeleted;
        _watcher.Renamed += OnRenamed;
        _watcher.Error += OnError;
    }

    public string Root => _root;

    public event EventHandler<FileSystemEventArgs>? Created;
    public event EventHandler<FileSystemEventArgs>? Changed;
    public event EventHandler<FileSystemEventArgs>? Deleted;
    public event EventHandler<RenamedEventArgs>? Renamed;
    public event EventHandler<ErrorEventArgs>? Error;

    public void Enable()
    {
        try
        {
            _watcher.EnableRaisingEvents = true;
        }
        catch (ObjectDisposedException)
        {
            // The watcher was disposed while a rebuild was in flight.
        }
    }

    public void Disable()
    {
        try
        {
            _watcher.EnableRaisingEvents = false;
        }
        catch (ObjectDisposedException)
        {
            // Already disposed; nothing to do.
        }
    }

    public void Dispose()
    {
        _watcher.Created -= OnCreated;
        _watcher.Changed -= OnChanged;
        _watcher.Deleted -= OnDeleted;
        _watcher.Renamed -= OnRenamed;
        _watcher.Error -= OnError;
        _watcher.Dispose();
    }

    // The events are re-raised with this wrapper as the sender, so the monitor can tell
    // which watcher an event came from and ignore a watcher it has already replaced.
    private void OnCreated(object sender, FileSystemEventArgs e) => Created?.Invoke(this, e);
    private void OnChanged(object sender, FileSystemEventArgs e) => Changed?.Invoke(this, e);
    private void OnDeleted(object sender, FileSystemEventArgs e) => Deleted?.Invoke(this, e);
    private void OnRenamed(object sender, RenamedEventArgs e) => Renamed?.Invoke(this, e);
    private void OnError(object sender, ErrorEventArgs e) => Error?.Invoke(this, e);
}
