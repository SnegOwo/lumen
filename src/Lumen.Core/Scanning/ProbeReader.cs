using System.Buffers;
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
/// <remarks>
/// <para>
/// The reader keeps one buffer per thread and reuses it for every file it reads, so a
/// folder with ten thousand files costs a handful of allocations instead of ten thousand
/// of them. The buffer is taken from <see cref="ArrayPool{T}.Shared"/> and is given back
/// when the thread moves on to a different reader.
/// </para>
/// <para>
/// The bytes of a probe are borrowed from that buffer. They stay valid until the same
/// thread reads the next file. Every caller reads a file and inspects it before it reads
/// the next one, so the bytes are always there while they are needed. A caller that wants
/// to keep a probe for later has to copy what it needs.
/// </para>
/// </remarks>
public sealed class ProbeReader
{
    /// <summary>
    /// The smallest buffer the reader takes from the pool. A buffer of this size is enough
    /// for the many small files that make up a typical folder, and the pool keeps one
    /// bucket for them instead of one per file size.
    /// </summary>
    private const int MinimumBufferBytes = 8 * 1024;

    private readonly int _maxInspectBytes;

    /// <summary>
    /// The buffer of the calling thread. It is thread local on purpose: the real time
    /// monitor runs several workers over one reader, and two workers must never look at
    /// the same bytes.
    /// </summary>
    [ThreadStatic]
    private static ThreadBuffer? _threadBuffer;

    public ProbeReader(int maxInspectBytes)
    {
        _maxInspectBytes = Math.Clamp(maxInspectBytes, 64 * 1024, 16 * 1024 * 1024);
    }

    public ProbeReadResult Read(string path, FileAttributes attributes, CancellationToken cancellationToken)
    {
        try
        {
            // The buffer of the stream is left out on purpose. The reader fills one buffer
            // of its own in a single call, so a second buffer would only be copied into.
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 0,
                FileOptions.SequentialScan);

            var length = stream.Length;
            var toRead = (int)Math.Min(length, _maxInspectBytes);
            var buffer = RentBuffer(toRead);
            var read = 0;

            while (read < toRead)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = stream.Read(buffer, read, toRead - read);
                if (count == 0) break;
                read += count;
            }

            // Only the bytes that were really read are handed out. The rest of the pooled
            // buffer still holds whatever the previous file had in it.
            var probe = new FileProbe(path, length, attributes, buffer.AsMemory(0, read), contentTruncated: length > read);
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

    /// <summary>
    /// Gives the buffer of the calling thread back to the pool. A long operation that read
    /// a lot of files can call this when it is done, so the memory is not kept for
    /// nothing. The next file on that thread takes a buffer from the pool again, which is
    /// normally the very same one.
    /// </summary>
    public static void ReleaseThreadBuffer()
    {
        var slot = _threadBuffer;
        if (slot is null) return;

        slot.Return();
        slot.Owner = null;
    }

    /// <summary>
    /// Returns the buffer of this thread, growing it when the file needs more room.
    /// </summary>
    private byte[] RentBuffer(int needed)
    {
        var slot = _threadBuffer ??= new ThreadBuffer();

        // A buffer that belongs to another reader is given back first. The pool hands out
        // the same array again, so switching readers does not cost an allocation.
        if (!ReferenceEquals(slot.Owner, this))
        {
            slot.Return();
            slot.Owner = this;
        }

        var buffer = slot.Bytes;
        if (buffer is not null && buffer.Length >= needed) return buffer;

        // The file is larger than the buffer: take a bigger one and give the old one back.
        slot.Return();
        buffer = ArrayPool<byte>.Shared.Rent(Math.Max(needed, MinimumBufferBytes));
        slot.Bytes = buffer;
        return buffer;
    }

    /// <summary>
    /// The buffer of one thread. It is returned to the pool as soon as the thread moves on.
    /// </summary>
    private sealed class ThreadBuffer
    {
        public ProbeReader? Owner { get; set; }

        public byte[]? Bytes { get; set; }

        public void Return()
        {
            var buffer = Bytes;
            if (buffer is null) return;

            Bytes = null;

            // The bytes of the last file stay in the pooled array until it is used again.
            // They are not wiped out here: that would mean writing over the whole buffer
            // for every file, and the collector would keep them alive just as long.
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
