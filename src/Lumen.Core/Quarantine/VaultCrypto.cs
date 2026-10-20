using System.Buffers;
using System.Security.Cryptography;

namespace Lumen.Core.Quarantine;

/// <summary>
/// Stream encryption for quarantined files: AES-256-CBC with a per-item key and IV, plus an
/// HMAC-SHA256 over the encrypted vault file. Keys are protected with DPAPI by the caller.
/// </summary>
internal static class VaultCrypto
{
    private const int KeySize = 32;
    private const int IvSize = 16;
    private const int ProgressStep = 4 * 1024 * 1024;
    private static readonly byte[] Magic = "LQ01"u8.ToArray();

    public static async Task<(string Sha256, long Size)> EncryptFileAsync(
        string sourcePath,
        string destinationPath,
        byte[] key,
        byte[] iv,
        IProgress<long>? progress,
        CancellationToken cancellationToken)
    {
        if (key.Length != KeySize) throw new ArgumentException("Invalid encryption key.", nameof(key));
        if (iv.Length != IvSize) throw new ArgumentException("Invalid IV.", nameof(iv));

        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            using var input = new FileStream(
                sourcePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous);

            output.Write(Magic);
            output.Write(iv);

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using (var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
            {
                long total = 0;
                var sinceProgress = 0L;
                int read;
                while ((read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    hash.AppendData(buffer, 0, read);
                    await crypto.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    total += read;
                    sinceProgress += read;

                    if (sinceProgress >= ProgressStep)
                    {
                        progress?.Report(total);
                        sinceProgress = 0;
                    }
                }

                crypto.FlushFinalBlock();
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                progress?.Report(total);
                return (Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(), total);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static async Task<string> ComputeHmacAsync(
        string path,
        byte[] key,
        CancellationToken cancellationToken)
    {
        if (key.Length != KeySize) throw new ArgumentException("Invalid MAC key.", nameof(key));

        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                hmac.AppendData(buffer, 0, read);
            }

            return Convert.ToHexString(hmac.GetHashAndReset()).ToLowerInvariant();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static async Task<bool> DecryptToFileAsync(
        string vaultPath,
        string destinationPath,
        byte[] key,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        if (key.Length != KeySize) throw new ArgumentException("Invalid encryption key.", nameof(key));

        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            using var input = new FileStream(
                vaultPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            var header = new byte[Magic.Length + IvSize];
            var readHeader = 0;
            while (readHeader < header.Length)
            {
                var count = await input.ReadAsync(header.AsMemory(readHeader), cancellationToken).ConfigureAwait(false);
                if (count == 0) return false;
                readHeader += count;
            }

            if (!header.AsSpan(0, Magic.Length).SequenceEqual(Magic)) return false;
            var iv = header.AsSpan(Magic.Length, IvSize).ToArray();

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous);

            using (var crypto = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read, leaveOpen: true))
            {
                int read;
                while ((read = await crypto.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            var actual = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            return string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
