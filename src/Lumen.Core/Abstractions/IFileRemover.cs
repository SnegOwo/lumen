using Lumen.Core.Models;

namespace Lumen.Core.Abstractions;

/// <summary>
/// Permanently deletes a file. There is no undo at this level: the caller is expected to
/// have kept a verified copy in the quarantine vault, and to have asked the user first.
/// Implementations must not remove folders, must not follow symbolic links out of the
/// tree, and must not bypass Windows permissions.
/// </summary>
public interface IFileRemover
{
    /// <summary>
    /// Permanently deletes the given file and reports what happened, including why it
    /// failed. A missing file is reported as such rather than treated as success.
    /// </summary>
    Task<FileRemovalResult> RemoveAsync(string filePath, CancellationToken cancellationToken);
}
