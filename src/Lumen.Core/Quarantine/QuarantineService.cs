using System.Security.Cryptography;
using System.Text;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Storage;
using Lumen.Core.Util;

namespace Lumen.Core.Quarantine;

public sealed class QuarantineManifest
{
    public int SchemaVersion { get; set; } = 1;
    public List<QuarantineItem> Items { get; set; } = [];
}

/// <summary>
/// Encrypted, per-user quarantine. Content is copied into an AES-256-CBC vault file, verified,
/// and indexed before the original is removed. Keys are protected with DPAPI by the caller.
/// Every destructive action happens only after explicit UI confirmation; this service never
/// deletes anything on its own.
/// </summary>
public sealed class QuarantineService : IDisposable
{
    /// <summary>
    /// How long <see cref="Dispose"/> waits for running operations before it leaves the
    /// semaphore alone instead of disposing it under a live waiter.
    /// </summary>
    private const int DisposeGraceMilliseconds = 500;

    /// <summary>
    /// A partially written vault file older than this is left over from an interrupted
    /// run and can be removed. A younger one may still be in flight.
    /// </summary>
    private static readonly TimeSpan StalePartAge = TimeSpan.FromMinutes(5);

    private const string DisposedMessage = "The quarantine service has already been shut down.";

    private readonly string _directory;
    private readonly ISecretProtector _protector;
    private readonly IClock _clock;
    private readonly ILog _log;
    private readonly JsonFileStore<QuarantineManifest> _store;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly object _sync = new();
    private QuarantineManifest _manifest;
    private bool _readOnly;
    private bool _disposed;
    private int _inflight;

    /// <summary>
    /// Opens the encrypted vault. The index is read once; a vault that cannot be read
    /// completely stays read-only so that no record is lost.
    /// </summary>
    /// <param name="quarantineDirectory">Folder that holds the encrypted vault files.</param>
    /// <param name="manifestPath">File that holds the index of the vault.</param>
    /// <param name="protector">Protects the encryption keys, for example with DPAPI.</param>
    /// <param name="clock">Clock used for the timestamps in the index.</param>
    /// <param name="log">Log for diagnostics. File contents are never written to it.</param>
    public QuarantineService(
        string quarantineDirectory,
        string manifestPath,
        ISecretProtector protector,
        IClock clock,
        ILog log)
    {
        _directory = Path.GetFullPath(quarantineDirectory);
        Directory.CreateDirectory(_directory);
        _protector = protector;
        _clock = clock;
        _log = log;
        _store = new JsonFileStore<QuarantineManifest>(manifestPath, log);

        _manifest = _store.Load(out var warning);
        _manifest.Items ??= [];
        LoadWarning = warning;

        if (_manifest.SchemaVersion > 1)
        {
            _readOnly = true;
            LoadWarning = Combine(
                LoadWarning,
                "The quarantine index was written by a newer version of Lumen and is read-only.");
        }

        var broken = _manifest.Items.Where(item => !IsValidItem(item)).ToArray();
        if (broken.Length > 0)
        {
            _readOnly = true;
            LoadWarning = Combine(
                LoadWarning,
                $"Quarantine record(s) {DescribeBrokenItems(broken)} are incomplete, so the vault is read-only to avoid data loss.");
        }

        // A vault file that was never finished is not a recoverable copy of anything, so
        // old leftovers are cleaned up. Fresh ones may belong to a quarantine that is
        // still running and are left alone.
        CleanupStalePartFiles();

        if (LoadWarning is not null)
        {
            var orphanCount = CountVaultFiles();
            if (orphanCount > 0)
            {
                LoadWarning = Combine(
                    LoadWarning,
                    $"{orphanCount} encrypted quarantine file(s) are preserved on disk but are not listed because the index was unreadable.");
            }
        }
    }

    /// <summary>Folder that holds the encrypted vault files.</summary>
    public string DirectoryPath => _directory;

    /// <summary>
    /// Set when the vault could not be read completely. It explains what the user has to
    /// do about it, for example which record is broken.
    /// </summary>
    public string? LoadWarning { get; }

    /// <summary>
    /// The records in the vault, newest first. Empty when the service is closed.
    /// </summary>
    public IReadOnlyList<QuarantineItem> GetItems()
    {
        lock (_sync)
        {
            if (_disposed) return [];
            return _manifest.Items
                .OrderByDescending(item => item.QuarantinedUtc)
                .ToArray();
        }
    }

    /// <summary>
    /// Looks up a single record. Returns null when the record is unknown or the service
    /// is closed.
    /// </summary>
    public QuarantineItem? GetItem(string id)
    {
        lock (_sync)
        {
            if (_disposed) return null;
            return _manifest.Items.FirstOrDefault(item =>
                string.Equals(item.Id, id, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Copies a file into the encrypted vault and, when the copy provably matches what was
    /// inspected, removes the original. The original is only removed after the encrypted
    /// copy and its index entry exist; a failure at any point leaves the original alone
    /// and removes the partial copy.
    /// </summary>
    /// <param name="request">The file, the finding it belongs to and the expected hash.</param>
    /// <param name="progress">Reports the number of bytes copied so far.</param>
    /// <param name="cancellationToken">Cancels the copy. The original is left untouched.</param>
    public async Task<QuarantineResult> QuarantineAsync(
        QuarantineRequest request,
        IProgress<long>? progress,
        CancellationToken cancellationToken)
    {
        if (!TryBeginOperation())
            return new QuarantineResult(QuarantineStatus.Failed, null, DisposedMessage, false);

        var acquired = false;
        byte[]? aesKey = null;
        byte[]? macKey = null;
        string? tempPath = null;
        try
        {
            await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            acquired = true;

            if (_readOnly)
                return new QuarantineResult(QuarantineStatus.Failed, null, LoadWarning ?? "The quarantine vault is read-only.", false);

            if (string.IsNullOrWhiteSpace(request.FilePath))
                return new QuarantineResult(QuarantineStatus.NotFound, null, "The file no longer exists.", false);

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(request.FilePath);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return new QuarantineResult(QuarantineStatus.Failed, null, "That file path is not valid.", false);
            }

            if (PathRules.IsWithin(fullPath, _directory))
                return new QuarantineResult(QuarantineStatus.Failed, null, "Files inside the quarantine vault cannot be quarantined again.", false);

            if (Directory.Exists(fullPath))
                return new QuarantineResult(QuarantineStatus.Failed, null, "That path is a folder, not a file.", false);

            if (!File.Exists(fullPath))
                return new QuarantineResult(QuarantineStatus.NotFound, null, "The file no longer exists.", false);

            var attributes = File.GetAttributes(fullPath);
            if (PathRules.IsReparsePoint(attributes))
                return new QuarantineResult(QuarantineStatus.Failed, null, "Symbolic links and other reparse points are not quarantined.", false);

            // A hash that was supplied but cannot be parsed must not be treated as "no
            // expectation at all": that would quietly turn verification off.
            var expected = NormalizeHash(request.ExpectedSha256);
            if (expected is null && !string.IsNullOrWhiteSpace(request.ExpectedSha256))
            {
                return new QuarantineResult(
                    QuarantineStatus.Failed,
                    null,
                    "The expected SHA-256 hash is not a valid 64-character hash, so the file was not quarantined. The original file was not changed.",
                    false);
            }

            // Remember what the file looked like so that a restore can put it back.
            var info = new FileInfo(fullPath);
            var metadata = CaptureMetadata(attributes, info);
            var sourceLength = info.Length;
            var sourceLastWriteUtc = info.LastWriteTimeUtc;

            var currentHash = await Task.Run(
                () => HashUtil.Sha256File(fullPath, cancellationToken),
                cancellationToken).ConfigureAwait(false);

            if (expected is not null && !HashEquals(expected, currentHash) && !request.AllowChangedFile)
            {
                return new QuarantineResult(
                    QuarantineStatus.ChangedSinceScan,
                    null,
                    "The file changed since it was scanned. Review it again before quarantining.",
                    false);
            }

            var id = Guid.NewGuid().ToString("N");
            var vaultFileName = id + ".qbin";
            tempPath = Path.Combine(_directory, id + ".qbin.part");
            var finalPath = Path.Combine(_directory, vaultFileName);

            aesKey = RandomNumberGenerator.GetBytes(VaultCrypto.AesKeySize);
            macKey = RandomNumberGenerator.GetBytes(VaultCrypto.AesKeySize);
            var iv = RandomNumberGenerator.GetBytes(16);

            // The keys are protected before anything is written into the vault. If the
            // key store is unavailable the file is never copied, because an encrypted
            // file whose key was lost cannot be listed or recovered by anyone.
            string protectedKey;
            string protectedMacKey;
            try
            {
                protectedKey = Convert.ToBase64String(
                    _protector.Protect(aesKey, Entropy(id, "aes")));
                protectedMacKey = Convert.ToBase64String(
                    _protector.Protect(macKey, Entropy(id, "mac")));
            }
            catch (Exception ex)
            {
                _log.Error("Quarantine", "The quarantine keys could not be protected; nothing was quarantined.", ex);
                return new QuarantineResult(
                    QuarantineStatus.Failed,
                    null,
                    "The quarantine keys could not be protected, so the file was not quarantined. The original file was not changed.",
                    false);
            }

            var encrypted = await VaultCrypto.EncryptFileAsync(
                fullPath,
                tempPath,
                aesKey,
                iv,
                progress,
                cancellationToken).ConfigureAwait(false);

            // The copy in the vault must be the same content that was hashed. If it is
            // not, the file changed while it was being read and the original must not
            // be deleted: the vault would hold a different version than the disk.
            if (!HashEquals(currentHash, encrypted.Sha256))
            {
                return new QuarantineResult(
                    QuarantineStatus.ChangedSinceScan,
                    null,
                    "The file changed while it was being quarantined. It was not modified.",
                    false);
            }

            if (expected is not null && !HashEquals(expected, encrypted.Sha256) && !request.AllowChangedFile)
            {
                return new QuarantineResult(
                    QuarantineStatus.ChangedSinceScan,
                    null,
                    "The file changed while it was being quarantined. It was not modified.",
                    false);
            }

            var mac = await VaultCrypto.ComputeHmacAsync(tempPath, macKey, cancellationToken).ConfigureAwait(false);

            var item = new QuarantineItem
            {
                Id = id,
                OriginalPath = fullPath,
                Sha256 = encrypted.Sha256,
                SizeBytes = encrypted.Size,
                DetectedUtc = request.DetectedUtc ?? _clock.UtcNow,
                QuarantinedUtc = _clock.UtcNow,
                FindingTitle = request.FindingTitle,
                Category = request.Category,
                FindingDetail = request.FindingDetail,
                SourceScanId = request.SourceScanId,
                VaultFileName = vaultFileName,
                ProtectedKey = protectedKey,
                ProtectedMacKey = protectedMacKey,
                Mac = mac,
                Iv = Convert.ToBase64String(iv),
                Metadata = metadata
            };

            // The vault file only gets its final name once everything it needs is ready.
            // From here on a failure removes it again, so no unlistable file is left.
            File.Move(tempPath, finalPath);
            tempPath = null;

            try
            {
                lock (_sync) _manifest.Items.Add(item);
                SaveManifest();
            }
            catch (Exception ex)
            {
                lock (_sync) _manifest.Items.RemoveAll(candidate => candidate.Id == id);
                DeleteQuietly(finalPath);
                _log.Error("Quarantine", "The quarantine index could not be saved; the original was left untouched.", ex);
                return new QuarantineResult(
                    QuarantineStatus.Failed,
                    null,
                    "The quarantine index could not be saved. The original file was not changed.",
                    false);
            }

            var originalRemoved = false;
            string? note = null;

            if (!File.Exists(fullPath))
            {
                // Something else already removed the original; there is nothing left to
                // delete and the encrypted copy is the only remaining copy.
                originalRemoved = true;
            }
            else if (!SourceMatchesSnapshot(fullPath, sourceLength, sourceLastWriteUtc))
            {
                // The file changed after it was copied. Deleting it now would remove
                // content that is not in the vault, so it is left in place.
                note = "The file changed while it was being quarantined, so the original was left in place. The encrypted copy in the vault matches the content Lumen inspected.";
                _log.Warn("Quarantine", "The original file changed after it was copied and was not deleted.", null);
            }
            else
            {
                try
                {
                    DeleteOriginal(fullPath, attributes);
                    originalRemoved = true;
                }
                catch (Exception ex)
                {
                    note = "The encrypted copy is preserved, but the original could not be removed. Close any program using it and delete it manually.";
                    _log.Warn("Quarantine", "The original file could not be removed after quarantine.", ex);
                }
            }

            if (note is not null)
            {
                lock (_sync)
                {
                    var index = _manifest.Items.FindIndex(candidate => candidate.Id == id);
                    if (index >= 0)
                    {
                        item = item with { Note = note };
                        _manifest.Items[index] = item;
                    }
                }

                try
                {
                    SaveManifest();
                }
                catch (Exception saveEx)
                {
                    _log.Error("Quarantine", "The quarantine note could not be saved.", saveEx);
                }
            }

            _log.Info(
                "Quarantine",
                $"Quarantined {id} from {fullPath}. originalRemoved={originalRemoved} category={request.Category}");

            return new QuarantineResult(
                originalRemoved ? QuarantineStatus.Quarantined : QuarantineStatus.QuarantinedOriginalRetained,
                item,
                originalRemoved
                    ? "The file was copied into the encrypted quarantine and the original was removed."
                    : note ?? "The encrypted copy is preserved, but the original could not be removed.",
                originalRemoved);
        }
        catch (OperationCanceledException)
        {
            return new QuarantineResult(
                QuarantineStatus.Cancelled,
                null,
                "Quarantine was cancelled. The original file was not changed.",
                false);
        }
        catch (ObjectDisposedException)
        {
            return new QuarantineResult(QuarantineStatus.Failed, null, DisposedMessage, false);
        }
        catch (UnauthorizedAccessException ex)
        {
            _log.Error("Quarantine", "Access was denied while creating the encrypted copy.", ex);
            return new QuarantineResult(
                QuarantineStatus.AccessDenied,
                null,
                "Access was denied. Lumen does not bypass Windows permissions.",
                false);
        }
        catch (IOException ex)
        {
            _log.Error("Quarantine", "The file could not be quarantined.", ex);
            return new QuarantineResult(
                QuarantineStatus.Failed,
                null,
                "The file could not be quarantined. It may be in use, or the disk may be full. The original file was not changed.",
                false);
        }
        catch (Exception ex)
        {
            _log.Error("Quarantine", "An unexpected error occurred while quarantining.", ex);
            return new QuarantineResult(
                QuarantineStatus.Failed,
                null,
                "The file could not be quarantined. The original file was not changed.",
                false);
        }
        finally
        {
            if (tempPath is not null) DeleteQuietly(tempPath);
            if (aesKey is not null) CryptographicOperations.ZeroMemory(aesKey);
            if (macKey is not null) CryptographicOperations.ZeroMemory(macKey);
            if (acquired) ReleaseMutex();
            EndOperation();
        }
    }

    /// <summary>
    /// Decrypts a quarantined file back to disk. The copy is verified against the hash
    /// that was recorded at quarantine time before anything is written, and the original
    /// timestamps and attributes are put back. Protected system locations are refused.
    /// </summary>
    /// <param name="request">The record to restore and where to put it.</param>
    /// <param name="cancellationToken">Cancels the restore. Nothing is written.</param>
    public async Task<RestoreResult> RestoreAsync(RestoreRequest request, CancellationToken cancellationToken)
    {
        if (!TryBeginOperation())
            return new RestoreResult(RestoreStatus.Failed, null, DisposedMessage);

        var acquired = false;
        string? tempPath = null;
        byte[]? aesKey = null;
        byte[]? macKey = null;
        try
        {
            await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            acquired = true;

            if (_readOnly)
                return new RestoreResult(RestoreStatus.Failed, null, LoadWarning ?? "The quarantine vault is read-only.");

            var item = GetItem(request.Id);
            if (item is null)
                return new RestoreResult(RestoreStatus.NotFound, null, "That quarantine item was not found.");

            var vaultPath = GetVaultPath(item);
            if (vaultPath is null || !File.Exists(vaultPath))
                return new RestoreResult(RestoreStatus.Corrupt, null, "The encrypted quarantine file is missing.");

            macKey = Unprotect(item.ProtectedMacKey, item.Id, "mac");
            var actualMac = await VaultCrypto.ComputeHmacAsync(vaultPath, macKey, cancellationToken).ConfigureAwait(false);
            if (!HashEquals(actualMac, item.Mac))
                return new RestoreResult(RestoreStatus.Corrupt, null, "The encrypted quarantine file failed its integrity check.");

            var destination = request.DestinationPath ?? item.OriginalPath;
            if (string.IsNullOrWhiteSpace(destination))
                return new RestoreResult(RestoreStatus.Failed, null, "No restore destination was provided.");

            string fullDestination;
            try
            {
                fullDestination = Path.GetFullPath(destination);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return new RestoreResult(RestoreStatus.Failed, null, "The restore destination is not a valid path.");
            }

            // Lumen does not write into Windows or Program Files. A restore there is
            // refused so the product can never be used to place a file in a protected
            // system location.
            if (PathRules.IsSystemCritical(fullDestination))
            {
                return new RestoreResult(
                    RestoreStatus.DestinationProtected,
                    null,
                    "Lumen does not write to protected system locations. Choose a different folder for the restored file.");
            }

            if (Directory.Exists(fullDestination))
                return new RestoreResult(RestoreStatus.Failed, null, "The restore destination is a folder. Choose a file path.");

            if (PathRules.IsWithin(fullDestination, _directory))
                return new RestoreResult(RestoreStatus.Failed, null, "Choose a restore location outside the quarantine vault.");

            var parent = Path.GetDirectoryName(fullDestination);
            if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
                return new RestoreResult(
                    RestoreStatus.DestinationMissing,
                    null,
                    "The destination folder no longer exists. Restore to a folder you choose instead.");

            if (File.Exists(fullDestination) && !request.Overwrite)
                return new RestoreResult(RestoreStatus.TargetExists, fullDestination, "A file already exists at the restore destination.");

            aesKey = Unprotect(item.ProtectedKey, item.Id, "aes");
            tempPath = Path.Combine(
                parent,
                "." + Path.GetFileName(fullDestination) + "." + Guid.NewGuid().ToString("N") + ".restore.tmp");

            var decrypted = await VaultCrypto.DecryptToFileAsync(
                vaultPath,
                tempPath,
                aesKey,
                item.Sha256,
                cancellationToken).ConfigureAwait(false);

            if (!decrypted)
                return new RestoreResult(
                    RestoreStatus.Corrupt,
                    null,
                    "The restored content failed its SHA-256 check. Nothing was written to the destination.");

            try
            {
                if (File.Exists(fullDestination))
                {
                    try
                    {
                        File.Replace(tempPath, fullDestination, destinationBackupFileName: null, ignoreMetadataErrors: true);
                    }
                    catch (Exception ex) when (ex is IOException or PlatformNotSupportedException)
                    {
                        File.Move(tempPath, fullDestination, overwrite: true);
                    }
                }
                else
                {
                    File.Move(tempPath, fullDestination);
                }

                tempPath = null;
            }
            catch (Exception ex)
            {
                _log.Error("Quarantine", "The restored file could not be written to the destination.", ex);
                return new RestoreResult(
                    RestoreStatus.Failed,
                    null,
                    "Windows could not write the restored file. It may be open in another program.");
            }

            // Give the file back the timestamps and attributes it had before it was
            // quarantined, so a restored file does not look freshly created.
            ApplyOriginalMetadata(item, fullDestination);

            var removed = false;
            lock (_sync)
            {
                removed = _manifest.Items.RemoveAll(candidate => candidate.Id == item.Id) > 0;
            }

            if (removed)
            {
                try
                {
                    SaveManifest();
                }
                catch (Exception ex)
                {
                    lock (_sync) _manifest.Items.Add(item);
                    _log.Error("Quarantine", "The item was restored but the index could not be updated.", ex);
                    return new RestoreResult(
                        RestoreStatus.Restored,
                        fullDestination,
                        "The file was restored, but the quarantine index could not be updated. The encrypted backup was kept.");
                }

                try
                {
                    File.Delete(vaultPath);
                }
                catch (Exception ex)
                {
                    _log.Warn("Quarantine", "The item was restored but the encrypted vault file could not be deleted.", ex);
                    return new RestoreResult(
                        RestoreStatus.Restored,
                        fullDestination,
                        "The file was restored. The encrypted backup could not be deleted and remains in the vault folder.");
                }
            }

            _log.Info("Quarantine", $"Restored item {item.Id} to {fullDestination}.");
            return new RestoreResult(RestoreStatus.Restored, fullDestination, "The file was restored.");
        }
        catch (OperationCanceledException)
        {
            return new RestoreResult(RestoreStatus.Cancelled, null, "Restore was cancelled. Nothing was written to the destination.");
        }
        catch (ObjectDisposedException)
        {
            return new RestoreResult(RestoreStatus.Failed, null, DisposedMessage);
        }
        catch (CryptographicException ex)
        {
            _log.Error("Quarantine", "The quarantine item could not be decrypted.", ex);
            return new RestoreResult(RestoreStatus.Corrupt, null, "The encrypted quarantine file could not be decrypted.");
        }
        catch (UnauthorizedAccessException ex)
        {
            _log.Error("Quarantine", "Access was denied while restoring a file.", ex);
            return new RestoreResult(RestoreStatus.Failed, null, "Access was denied. Lumen does not bypass Windows permissions.");
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or FormatException or NotSupportedException)
        {
            _log.Error("Quarantine", "The file could not be restored.", ex);
            return new RestoreResult(RestoreStatus.Failed, null, "The file could not be restored. The original quarantine copy was kept.");
        }
        finally
        {
            if (tempPath is not null) DeleteQuietly(tempPath);
            if (aesKey is not null) CryptographicOperations.ZeroMemory(aesKey);
            if (macKey is not null) CryptographicOperations.ZeroMemory(macKey);
            if (acquired) ReleaseMutex();
            EndOperation();
        }
    }

    /// <summary>
    /// Removes a record and its encrypted file from the vault. The caller is responsible
    /// for asking the user first; this service never deletes without that confirmation.
    /// </summary>
    /// <param name="id">Id of the record to remove.</param>
    /// <param name="cancellationToken">Cancels the deletion. Nothing is deleted.</param>
    public async Task<DeleteResult> DeleteAsync(string id, CancellationToken cancellationToken)
    {
        if (!TryBeginOperation())
            return new DeleteResult(false, DisposedMessage);

        var acquired = false;
        try
        {
            await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            acquired = true;

            if (_readOnly)
                return new DeleteResult(false, LoadWarning ?? "The quarantine vault is read-only.");

            var item = GetItem(id);
            if (item is null)
                return new DeleteResult(false, "That quarantine item was not found.");

            var vaultPath = GetVaultPath(item);
            var removed = false;
            lock (_sync)
            {
                removed = _manifest.Items.RemoveAll(candidate => candidate.Id == item.Id) > 0;
            }

            if (!removed)
                return new DeleteResult(false, "That quarantine item was not found.");

            try
            {
                SaveManifest();
            }
            catch (Exception ex)
            {
                lock (_sync) _manifest.Items.Add(item);
                _log.Error("Quarantine", "The quarantine index could not be updated for deletion.", ex);
                return new DeleteResult(false, "The quarantine index could not be updated. Nothing was deleted.");
            }

            if (vaultPath is not null && File.Exists(vaultPath))
            {
                try
                {
                    File.Delete(vaultPath);
                }
                catch (Exception ex)
                {
                    lock (_sync) _manifest.Items.Add(item);
                    try { SaveManifest(); } catch { /* best effort */ }
                    _log.Error("Quarantine", "The encrypted quarantine file could not be deleted.", ex);
                    return new DeleteResult(false, "The encrypted file could not be deleted. It may be open in another program.");
                }
            }

            _log.Info("Quarantine", $"Permanently deleted quarantine item {item.Id}.");
            return new DeleteResult(true, "The quarantine item was permanently deleted.");
        }
        catch (OperationCanceledException)
        {
            return new DeleteResult(false, "Deletion was cancelled. Nothing was deleted.");
        }
        catch (ObjectDisposedException)
        {
            return new DeleteResult(false, DisposedMessage);
        }
        catch (UnauthorizedAccessException ex)
        {
            _log.Error("Quarantine", "Access was denied while deleting a quarantine item.", ex);
            return new DeleteResult(false, "Access was denied. Lumen does not bypass Windows permissions.");
        }
        catch (Exception ex) when (ex is IOException or FormatException)
        {
            _log.Error("Quarantine", "The quarantine item could not be deleted.", ex);
            return new DeleteResult(false, "The quarantine item could not be deleted.");
        }
        finally
        {
            if (acquired) ReleaseMutex();
            EndOperation();
        }
    }

    private void SaveManifest()
    {
        QuarantineManifest snapshot;
        lock (_sync)
        {
            snapshot = new QuarantineManifest
            {
                SchemaVersion = 1,
                Items = _manifest.Items.ToList()
            };
        }

        _store.Save(snapshot);
    }

    private string? GetVaultPath(QuarantineItem item)
    {
        if (!IsValidVaultName(item)) return null;
        var path = Path.Combine(_directory, item.VaultFileName);
        return PathRules.IsWithin(path, _directory) ? path : null;
    }

    private bool IsValidItem(QuarantineItem item)
    {
        if (!IsValidVaultName(item)) return false;
        if (string.IsNullOrWhiteSpace(item.OriginalPath)) return false;
        if (!IsHex(item.Sha256, 64)) return false;
        if (!IsHex(item.Mac, 64)) return false;
        if (string.IsNullOrWhiteSpace(item.ProtectedKey) || string.IsNullOrWhiteSpace(item.ProtectedMacKey)) return false;

        try
        {
            return Convert.FromBase64String(item.Iv).Length == 16;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsValidVaultName(QuarantineItem item)
    {
        if (item.Id.Length != 32 || !item.Id.All(Uri.IsHexDigit)) return false;
        return string.Equals(item.VaultFileName, item.Id + ".qbin", StringComparison.Ordinal);
    }

    /// <summary>
    /// Counts the encrypted files in the vault, including partially written ones. They are
    /// reported to the user because a file that is not in the index cannot be restored.
    /// </summary>
    private int CountVaultFiles()
    {
        try
        {
            return Directory.EnumerateFiles(_directory, "*.qbin*", SearchOption.TopDirectoryOnly).Count();
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Removes vault files that were never finished. Only old ones are removed, so a
    /// quarantine that is currently running is never interrupted.
    /// </summary>
    private void CleanupStalePartFiles()
    {
        try
        {
            var cutoff = DateTime.UtcNow - StalePartAge;
            foreach (var path in Directory.EnumerateFiles(_directory, "*.qbin.part", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    var info = new FileInfo(path);
                    if (info.LastWriteTimeUtc >= cutoff) continue;
                    File.Delete(path);
                }
                catch
                {
                    // Best effort: a leftover part file is harmless, it is only clutter.
                }
            }
        }
        catch
        {
            // Best effort cleanup; a failure here must not stop Lumen from starting.
        }
    }

    /// <summary>
    /// Names the records that made the vault read-only so the user can tell which entry
    /// needs attention instead of only being told that something is wrong.
    /// </summary>
    private static string DescribeBrokenItems(IReadOnlyList<QuarantineItem> broken)
    {
        var names = broken.Take(3).Select(DescribeItem).ToArray();
        var listed = string.Join(", ", names);
        return broken.Count > names.Length
            ? $"{listed} (and {broken.Count - names.Length} more)"
            : listed;
    }

    private static string DescribeItem(QuarantineItem item)
    {
        if (!string.IsNullOrWhiteSpace(item.Id)) return item.Id;
        if (!string.IsNullOrWhiteSpace(item.VaultFileName)) return item.VaultFileName;
        if (!string.IsNullOrWhiteSpace(item.OriginalPath)) return item.OriginalPath;
        return "with an unknown id";
    }

    /// <summary>
    /// Records what the original file looked like so that a restore can reproduce it.
    /// </summary>
    private static QuarantinedFileMetadata CaptureMetadata(FileAttributes attributes, FileInfo info)
    {
        return new QuarantinedFileMetadata
        {
            Attributes = attributes,
            LastWriteTimeUtc = new DateTimeOffset(DateTime.SpecifyKind(info.LastWriteTimeUtc, DateTimeKind.Utc)),
            CreationTimeUtc = new DateTimeOffset(DateTime.SpecifyKind(info.CreationTimeUtc, DateTimeKind.Utc))
        };
    }

    /// <summary>
    /// Checks that the file on disk is still the file that was copied into the vault.
    /// The length and the last write time are compared; a different value means the file
    /// was written to after Lumen read it.
    /// </summary>
    private static bool SourceMatchesSnapshot(string path, long length, DateTime lastWriteUtc)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return false;
            if (info.Length != length) return false;
            return File.GetLastWriteTimeUtc(path) == lastWriteUtc;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Removes the original file after it has been copied into the vault. Windows refuses
    /// to delete a read-only file, so that one flag is cleared first; the original value
    /// is kept in the manifest and restored with the file.
    /// </summary>
    private static void DeleteOriginal(string path, FileAttributes attributes)
    {
        if ((attributes & FileAttributes.ReadOnly) != 0)
        {
            try
            {
                File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
            }
            catch
            {
                // The delete below reports the real problem if it still fails.
            }
        }

        File.Delete(path);
    }

    /// <summary>
    /// Puts the original timestamps and attributes back on a restored file. The read-only
    /// flag is applied last so it cannot block writing the timestamps.
    /// </summary>
    private void ApplyOriginalMetadata(QuarantineItem item, string path)
    {
        var metadata = item.Metadata;
        if (metadata is null) return;

        try
        {
            // A reparse point is never restored: the copy is a plain file.
            var attributes = metadata.Attributes & ~FileAttributes.ReparsePoint;
            File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
            File.SetLastWriteTimeUtc(path, metadata.LastWriteTimeUtc.UtcDateTime);
            File.SetCreationTimeUtc(path, metadata.CreationTimeUtc.UtcDateTime);
            File.SetAttributes(path, attributes);
        }
        catch (Exception ex)
        {
            _log.Warn("Quarantine", "The restored file kept new timestamps because the original metadata could not be applied.", ex);
        }
    }

    private byte[] Unprotect(string protectedBase64, string id, string purpose) =>
        _protector.Unprotect(Convert.FromBase64String(protectedBase64), Entropy(id, purpose));

    private static byte[] Entropy(string id, string purpose) =>
        Encoding.UTF8.GetBytes($"Lumen.Quarantine.v1|{id}|{purpose}");

    private static string? NormalizeHash(string? hash)
    {
        if (string.IsNullOrWhiteSpace(hash)) return null;
        var trimmed = hash.Trim();
        return IsHex(trimmed, 64) ? trimmed.ToLowerInvariant() : null;
    }

    private static bool HashEquals(string? left, string? right) =>
        left is not null && right is not null &&
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool IsHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(Uri.IsHexDigit);

    private static string Combine(string? first, string second) =>
        string.IsNullOrWhiteSpace(first) ? second : first + " " + second;

    private static void DeleteQuietly(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // Best effort cleanup of our own partial vault file.
        }
    }

    /// <summary>
    /// Marks the service as closed and records that an operation is running. Operations
    /// that start after this point are refused with a clean result instead of touching a
    /// disposed semaphore.
    /// </summary>
    private bool TryBeginOperation()
    {
        lock (_sync)
        {
            if (_disposed) return false;
            _inflight++;
            return true;
        }
    }

    private void EndOperation()
    {
        lock (_sync)
        {
            if (_inflight > 0) _inflight--;
        }
    }

    /// <summary>
    /// Releases the mutex without letting a disposal race turn into an exception that
    /// hides the real result of the operation.
    /// </summary>
    private void ReleaseMutex()
    {
        try
        {
            _mutex.Release();
        }
        catch (ObjectDisposedException)
        {
            // The service was disposed while the operation was running.
        }
    }

    /// <summary>
    /// Shuts the service down. Running operations are given a short moment to finish; if
    /// one is still running the mutex is left to the garbage collector rather than being
    /// disposed under a live waiter.
    /// </summary>
    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
        }

        var deadline = Environment.TickCount64 + DisposeGraceMilliseconds;
        while (true)
        {
            int running;
            lock (_sync) running = _inflight;
            if (running == 0) break;
            if (Environment.TickCount64 >= deadline) break;
            Thread.Sleep(15);
        }

        int remaining;
        lock (_sync) remaining = _inflight;
        if (remaining > 0) return;

        try
        {
            _mutex.Dispose();
        }
        catch
        {
            // Disposing the mutex must never throw during shutdown.
        }
    }
}
