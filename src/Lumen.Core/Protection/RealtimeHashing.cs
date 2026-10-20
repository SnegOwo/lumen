using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.Core.Protection;

/// <summary>
/// Computes the digest of a file. This exists as a seam for two reasons: hashing is the
/// step that decides whether a detection can be acted on automatically, and a locked or
/// short-lived file can fail it. Tests inject a failing implementation to prove the
/// difference between "detected" and "detected and safely actionable".
/// </summary>
public interface IFileHashProvider
{
    /// <summary>
    /// Attempts to hash the file. Implementations must not throw for ordinary I/O failures;
    /// they report the failure through the returned result instead.
    /// </summary>
    FileHashResult TryComputeSha256(string path, CancellationToken cancellationToken);
}

/// <summary>
/// The default <see cref="IFileHashProvider"/>, backed by <see cref="HashUtil"/>. A file
/// that cannot be opened (locked by another process, deleted, access denied) yields a failed
/// result rather than an exception, so a detection is still reported.
/// </summary>
public sealed class SystemFileHashProvider : IFileHashProvider
{
    /// <inheritdoc />
    public FileHashResult TryComputeSha256(string path, CancellationToken cancellationToken)
    {
        try
        {
            return new FileHashResult
            {
                Outcome = FileHashOutcome.Hashed,
                Sha256 = HashUtil.Sha256File(path, cancellationToken)
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (FileNotFoundException)
        {
            return new FileHashResult
            {
                Outcome = FileHashOutcome.NotFound,
                Error = "The file no longer exists."
            };
        }
        catch (UnauthorizedAccessException)
        {
            return new FileHashResult
            {
                Outcome = FileHashOutcome.AccessDenied,
                Error = "Windows denied access to the file."
            };
        }
        catch (Exception ex)
        {
            // The digest is optional context for the report. A file that cannot be hashed
            // is still a detection; it just cannot be quarantined automatically.
            return new FileHashResult
            {
                Outcome = FileHashOutcome.Failed,
                Error = "The file could not be hashed (" + ex.GetType().Name + ")."
            };
        }
    }
}
