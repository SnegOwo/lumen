using Lumen.Core.Models;

namespace Lumen.Core.Scanning;

public sealed record ProbeReadResult(FileProbe? Probe, ScanError? Error)
{
    public bool Success => Probe is not null;
}

/// <summary>
/// Reads a bounded prefix of a file with sharing enabled. All expected I/O failures are
/// converted into ScanError values so one bad file never aborts a scan.
/// </summary>
public sealed class ProbeReader
{
    private readonly int _maxInspectBytes;

    public ProbeReader(int maxInspectBytes)
    {
        _maxInspectBytes = Math.Clamp(maxInspectBytes, 64 * 1024, 16 * 1024 * 1024);
    }

    public ProbeReadResult Read(string path, FileAttributes attributes, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);

            var length = stream.Length;
            var toRead = (int)Math.Min(length, _maxInspectBytes);
            var buffer = new byte[toRead];
            var read = 0;

            while (read < toRead)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = stream.Read(buffer, read, toRead - read);
                if (count == 0) break;
                read += count;
            }

            if (read != buffer.Length) Array.Resize(ref buffer, read);

            var probe = new FileProbe(path, length, attributes, buffer, contentTruncated: length > read);
            return new ProbeReadResult(probe, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new ProbeReadResult(null, ScanErrors.FromException(path, ex));
        }
    }
}
