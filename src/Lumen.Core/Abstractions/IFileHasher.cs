using Lumen.Core.Models;

namespace Lumen.Core.Abstractions;

/// <summary>
/// Reads the SHA-256 and the size of a file. The remediation engine needs this to check
/// that a file is still the file that was scanned before it is removed. Implementations
/// must not return, log or store the contents of the file.
/// </summary>
public interface IFileHasher
{
    /// <summary>
    /// Hashes the given file and reports the digest and the size, or explains why it could
    /// not be read. The file is only ever read; nothing is changed.
    /// </summary>
    Task<FileHashResult> GetSha256Async(string filePath, CancellationToken cancellationToken);
}
