using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.Services;

/// <summary>
/// The real operating-system implementation of <see cref="IFileRemover"/> and
/// <see cref="IFileHasher"/>.
///
/// Both operations are strictly read-then-act on a single path. The remover never
/// recurses into folders, never follows a symbolic link out of the tree, and never
/// touches a system-critical location. Nothing is bypassed: if Windows says no, the
/// answer is reported as no.
/// </summary>
public sealed class WindowsFileOperations : IFileRemover, IFileHasher
{
    /// <summary>
    /// Permanently deletes a single file.
    /// </summary>
    public Task<FileRemovalResult> RemoveAsync(string filePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(filePath))
        {
            return Task.FromResult(Failed("No file was given."));
        }

        string full;
        try
        {
            full = PathRules.NormalizeFile(filePath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Task.FromResult(Failed("That file path is not valid."));
        }

        if (PathRules.IsSystemCritical(full))
        {
            return Task.FromResult(new FileRemovalResult
            {
                Removed = false,
                Outcome = FileRemovalOutcome.SystemCritical,
                Message = "That location is system-critical. Lumen never removes files from Windows or Program Files."
            });
        }

        try
        {
            if (Directory.Exists(full))
            {
                return Task.FromResult(new FileRemovalResult
                {
                    Removed = false,
                    Outcome = FileRemovalOutcome.PathIsDirectory,
                    Message = "That path is a folder. Lumen only removes single files."
                });
            }

            if (!File.Exists(full))
            {
                return Task.FromResult(new FileRemovalResult
                {
                    Removed = false,
                    Outcome = FileRemovalOutcome.NotFound,
                    Message = "The file no longer exists."
                });
            }

            var attributes = File.GetAttributes(full);
            if (PathRules.IsReparsePoint(attributes))
            {
                return Task.FromResult(Failed("Symbolic links and other reparse points are never removed."));
            }

            // Read-only files would otherwise fail deep inside the delete.
            if ((attributes & FileAttributes.ReadOnly) != 0)
                File.SetAttributes(full, attributes & ~FileAttributes.ReadOnly);

            File.Delete(full);

            return Task.FromResult(new FileRemovalResult
            {
                Removed = true,
                Outcome = FileRemovalOutcome.Removed,
                Message = "The file was permanently removed."
            });
        }
        catch (UnauthorizedAccessException)
        {
            return Task.FromResult(new FileRemovalResult
            {
                Removed = false,
                Outcome = FileRemovalOutcome.AccessDenied,
                Message = "Windows denied access. Lumen does not bypass permissions."
            });
        }
        catch (IOException)
        {
            return Task.FromResult(new FileRemovalResult
            {
                Removed = false,
                Outcome = FileRemovalOutcome.InUse,
                Message = "The file is in use by another program and could not be removed."
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(Failed("The file could not be removed: " + ex.GetType().Name));
        }
    }

    /// <summary>
    /// Reads the SHA-256 and the size of a file. The contents are never returned,
    /// logged or stored anywhere else.
    /// </summary>
    public Task<FileHashResult> GetSha256Async(string filePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(filePath))
        {
            return Task.FromResult(new FileHashResult
            {
                Outcome = FileHashOutcome.Failed,
                Error = "No file was given."
            });
        }

        string full;
        try
        {
            full = PathRules.NormalizeFile(filePath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Task.FromResult(new FileHashResult
            {
                Outcome = FileHashOutcome.Failed,
                Error = "That file path is not valid."
            });
        }

        try
        {
            if (!File.Exists(full))
            {
                return Task.FromResult(new FileHashResult
                {
                    Outcome = FileHashOutcome.NotFound,
                    Error = "The file no longer exists."
                });
            }

            var info = new FileInfo(full);
            var hash = HashUtil.Sha256File(full, cancellationToken);

            return Task.FromResult(new FileHashResult
            {
                Outcome = FileHashOutcome.Hashed,
                Sha256 = hash,
                SizeBytes = info.Length
            });
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Task.FromResult(new FileHashResult
            {
                Outcome = FileHashOutcome.AccessDenied,
                Error = "Windows denied access to the file."
            });
        }
        catch (IOException ex)
        {
            return Task.FromResult(new FileHashResult
            {
                Outcome = FileHashOutcome.Failed,
                Error = "The file could not be read: " + ex.Message
            });
        }
    }

    private static FileRemovalResult Failed(string message) =>
        new()
        {
            Removed = false,
            Outcome = FileRemovalOutcome.Failed,
            Message = message
        };
}
