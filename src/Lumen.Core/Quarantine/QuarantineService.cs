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
    private const int KeySize = 32;
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

        if (_manifest.Items.Any(item => !IsValidItem(item)))
        {
            _readOnly = true;
            LoadWarning = Combine(
                LoadWarning,
                "One or more quarantine records are incomplete. The vault is read-only to avoid data loss.");
        }

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

    public string DirectoryPath => _directory;
    public string? LoadWarning { get; }

    public IReadOnlyList<QuarantineItem> GetItems()
    {
        lock (_sync)
        {
            return _manifest.Items
                .OrderByDescending(item => item.QuarantinedUtc)
                .ToArray();
        }
    }

    public QuarantineItem? GetItem(string id)
    {
        lock (_sync)
        {
            return _manifest.Items.FirstOrDefault(item =>
                string.Equals(item.Id, id, StringComparison.OrdinalIgnoreCase));
        }
    }

    public async Task<QuarantineResult> QuarantineAsync(
        QuarantineRequest request,
        IProgress<long>? progress,
        CancellationToken cancellationToken)
    {
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

            var expected = NormalizeHash(request.ExpectedSha256);
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

            aesKey = RandomNumberGenerator.GetBytes(KeySize);
            macKey = RandomNumberGenerator.GetBytes(KeySize);
            var iv = RandomNumberGenerator.GetBytes(16);

            var encrypted = await VaultCrypto.EncryptFileAsync(
                fullPath,
                tempPath,
                aesKey,
                iv,
                progress,
                cancellationToken).ConfigureAwait(false);

            if (expected is not null && !HashEquals(expected, encrypted.Sha256) && !request.AllowChangedFile)
            {
                return new QuarantineResult(
                    QuarantineStatus.ChangedSinceScan,
                    null,
                    "The file changed while it was being quarantined. It was not modified.",
                    false);
            }

            var mac = await VaultCrypto.ComputeHmacAsync(tempPath, macKey, cancellationToken).ConfigureAwait(false);

            File.Move(tempPath, finalPath);
            tempPath = null;

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
                ProtectedKey = Convert.ToBase64String(
                    _protector.Protect(aesKey, Entropy(id, "aes"))),
                ProtectedMacKey = Convert.ToBase64String(
                    _protector.Protect(macKey, Entropy(id, "mac"))),
                Mac = mac,
                Iv = Convert.ToBase64String(iv)
            };

            lock (_sync) _manifest.Items.Add(item);

            try
            {
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
            try
            {
                File.Delete(fullPath);
                originalRemoved = true;
            }
            catch (Exception ex)
            {
                note = "The encrypted copy is preserved, but the original could not be removed. Close any program using it and delete it manually.";
                _log.Warn("Quarantine", "The original file could not be removed after quarantine.", ex);

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
            if (acquired) _mutex.Release();
        }
    }

    public async Task<RestoreResult> RestoreAsync(RestoreRequest request, CancellationToken cancellationToken)
    {
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
            if (acquired) _mutex.Release();
        }
    }

    public async Task<DeleteResult> DeleteAsync(string id, CancellationToken cancellationToken)
    {
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
            if (acquired) _mutex.Release();
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

    private int CountVaultFiles()
    {
        try
        {
            return Directory.EnumerateFiles(_directory, "*.qbin", SearchOption.TopDirectoryOnly).Count();
        }
        catch
        {
            return 0;
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

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _mutex.Dispose();
    }
}
