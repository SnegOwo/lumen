namespace Lumen.Core.Storage;

/// <summary>
/// Writes files with a temp-file + atomic replace so a crash cannot leave a half-written
/// settings, history or quarantine manifest.
/// </summary>
public static class AtomicFile
{
    public static void WriteAllBytes(string path, ReadOnlySpan<byte> bytes)
    {
        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory))
            throw new ArgumentException("The destination path has no directory.", nameof(path));

        Directory.CreateDirectory(directory);
        var temp = Path.Combine(
            directory,
            "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");

        try
        {
            using (var stream = new FileStream(
                       temp,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 16 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(path))
            {
                try
                {
                    File.Replace(temp, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
                }
                catch (Exception ex) when (ex is IOException or PlatformNotSupportedException or UnauthorizedAccessException)
                {
                    File.Move(temp, path, overwrite: true);
                }
            }
            else
            {
                File.Move(temp, path);
            }
        }
        finally
        {
            if (File.Exists(temp))
            {
                try { File.Delete(temp); } catch { /* best effort */ }
            }
        }
    }

    public static void WriteAllText(string path, string text) =>
        WriteAllBytes(path, System.Text.Encoding.UTF8.GetBytes(text));
}
