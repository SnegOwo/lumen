using Lumen.Core.Models;

namespace Lumen.Core.Remediation;

/// <summary>
/// The append-only record of what Lumen planned and what it did. Every entry is written
/// before the outcome is known and is never rewritten or removed, so the journal can be
/// trusted as the account of what happened. File contents are never recorded: only
/// paths, hashes, sizes, process names and outcomes.
/// </summary>
public interface IAuditJournal
{
    /// <summary>
    /// Appends one entry to the journal and makes it durable before returning. The engine
    /// treats a failure to write as a reason to stop, because an action without a record
    /// of it is an action nobody can report on.
    /// </summary>
    Task AppendAsync(AuditEntry entry, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the journal back, oldest entry first. Entries that cannot be read are
    /// skipped rather than failing the whole read.
    /// </summary>
    Task<IReadOnlyList<AuditEntry>> ReadAsync(CancellationToken cancellationToken);
}
