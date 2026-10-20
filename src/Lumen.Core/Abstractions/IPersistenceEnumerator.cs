using Lumen.Core.Models;

namespace Lumen.Core.Abstractions;

/// <summary>
/// Lists and removes the autostart entries that make a program run again after a reboot:
/// Run and RunOnce registry values in the user's own hive, Startup-folder items, scheduled
/// tasks and services. Implementations talk to the operating system; the remediation engine
/// only decides what to offer and reports what happened.
/// </summary>
public interface IPersistenceEnumerator
{
    /// <summary>
    /// Lists the autostart entries that reference the given file. Implementations should
    /// return only matching entries, but the engine checks every entry again before it
    /// offers it, so a sloppy implementation cannot widen the blast radius. Implementations
    /// must capture enough data in the returned entries to put an entry back, and must
    /// never remove anything while enumerating.
    /// </summary>
    Task<IReadOnlyList<PersistenceEntry>> EnumerateAsync(string filePath, CancellationToken cancellationToken);

    /// <summary>
    /// Removes a single autostart entry. Implementations must not write outside the user's
    /// own registry hive, must not install or modify services other than the one named in
    /// the entry, and must report honestly whether the entry was removed.
    /// </summary>
    Task<PersistenceRemovalResult> RemoveAsync(PersistenceEntry entry, CancellationToken cancellationToken);
}
