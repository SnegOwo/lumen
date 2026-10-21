using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Remediation;

namespace Lumen.App.Tests;

/// <summary>
/// A scratch directory for the tests that touch the real file system. It deletes
/// itself, and it makes every file writable again first, because a copy of an
/// executable can still be locked by the antivirus for a moment.
/// </summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Root = Path.Combine(Path.GetTempPath(), "lumen-e2e", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
    }

    public string Root { get; }

    public string CreateDirectory(string relativePath)
    {
        var path = Path.Combine(Root, relativePath);
        Directory.CreateDirectory(path);
        return path;
    }

    public void Dispose()
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                if (!Directory.Exists(Root)) return;
                foreach (var file in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
                {
                    try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
                }

                Directory.Delete(Root, recursive: true);
                return;
            }
            catch
            {
                Thread.Sleep(80);
            }
        }
    }
}

/// <summary>
/// An audit journal that keeps everything in memory. The end-to-end tests are about
/// the watcher and the terminator, not about the file format of the journal.
/// </summary>
internal sealed class NullAuditJournal : IAuditJournal
{
    private readonly List<AuditEntry> _entries = [];

    public IReadOnlyList<AuditEntry> Entries
    {
        get { lock (_entries) return _entries.ToArray(); }
    }

    public Task AppendAsync(AuditEntry entry, CancellationToken cancellationToken)
    {
        lock (_entries) _entries.Add(entry);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditEntry>> ReadAsync(CancellationToken cancellationToken)
    {
        lock (_entries) return Task.FromResult<IReadOnlyList<AuditEntry>>(_entries.ToArray());
    }
}
