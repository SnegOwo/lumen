using System.Diagnostics;
using System.Runtime.InteropServices;
using Lumen.Core.Detection;
using Lumen.Core.Scanning;
using Lumen.Core.Util;
using Xunit.Abstractions;

namespace Lumen.Core.Tests;

/// <summary>Temporary measurement harness. Not part of the product.</summary>
public sealed class TempBaseline
{
    private readonly ITestOutputHelper _output;
    public TempBaseline(ITestOutputHelper output) => _output = output;

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessIoCounters(IntPtr process, out IoCounters counters);

    private static IoCounters ReadIo()
    {
        using var process = Process.GetCurrentProcess();
        GetProcessIoCounters(process.Handle, out var counters);
        return counters;
    }

    private static byte[] SyntheticFile(int size, int seed)
    {
        var bytes = new byte[size];
        var random = new Random(seed);
        for (var index = 0; index < size; index++) bytes[index] = (byte)('a' + random.Next(26));
        return bytes;
    }

    [Fact]
    public void Measure()
    {
        using var temp = new TempDirectory();
        const int fileCount = 200;
        const int fileSize = 4096;
        var paths = new List<string>();
        for (var index = 0; index < fileCount; index++)
        {
            paths.Add(temp.FileBytes($"file-{index}.txt", SyntheticFile(fileSize, index)));
        }

        var reader = new ProbeReader(1024 * 1024);
        var registry = DetectorRegistry.CreateDefault();

        // Warm up so that JIT and one-time allocations do not land in the measurement.
        for (var index = 0; index < 5; index++)
        {
            var warm = reader.Read(paths[index], FileAttributes.Normal, CancellationToken.None);
            registry.Inspect(warm.Probe!, CancellationToken.None);
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        var read = 0L;
        foreach (var path in paths)
        {
            var result = reader.Read(path, FileAttributes.Normal, CancellationToken.None);
            read += result.Probe!.Content.Length;
            registry.Inspect(result.Probe!, CancellationToken.None);
        }
        var after = GC.GetAllocatedBytesForCurrentThread();
        var perFile = (after - before) / (double)fileCount;
        _output.WriteLine($"BASELINE read+inspect: total={after - before} bytes, per file={perFile:F0} bytes, bytesRead={read}");

        // Full scan through the engine.
        var engine = new ScanEngine(registry, new FakeClock(), new FakeLog());
        var request = TestData.Request(temp.Root);
        var ioBefore = ReadIo();
        var scanBefore = GC.GetTotalAllocatedBytes(true);
        var outcome = engine.ScanAsync(request, null, CancellationToken.None).GetAwaiter().GetResult();
        var scanAfter = GC.GetTotalAllocatedBytes(true);
        var ioAfter = ReadIo();
        _output.WriteLine(
            $"BASELINE full scan: files={outcome.FilesScanned} allocated={scanAfter - scanBefore} " +
            $"perFile={(scanAfter - scanBefore) / (double)outcome.FilesScanned:F0} " +
            $"readOps={ioAfter.ReadOperationCount - ioBefore.ReadOperationCount} " +
            $"readBytes={ioAfter.ReadTransferCount - ioBefore.ReadTransferCount}");

        // A matched file: how many times is it read?
        using var temp2 = new TempDirectory();
        var payload = SyntheticFile(4 * 1024 * 1024, 7);
        var marker = System.Text.Encoding.ASCII.GetBytes("WScript.Shell");
        Array.Copy(marker, 0, payload, 1234, marker.Length);
        var big = temp2.FileBytes("big.txt", payload);
        var engine2 = new ScanEngine(registry, new FakeClock(), new FakeLog());
        var ioBefore2 = ReadIo();
        var outcome2 = engine2.ScanAsync(TestData.Request(big), null, CancellationToken.None).GetAwaiter().GetResult();
        var ioAfter2 = ReadIo();
        _output.WriteLine(
            $"BASELINE matched big file: detections={outcome2.Detections.Length} " +
            $"readOps={ioAfter2.ReadOperationCount - ioBefore2.ReadOperationCount} " +
            $"readBytes={ioAfter2.ReadTransferCount - ioBefore2.ReadTransferCount} " +
            $"hash={outcome2.Detections.FirstOrDefault()?.Sha256}");
        _output.WriteLine($"BASELINE expected hash={HashUtil.Sha256File(big, CancellationToken.None)}");
    }
}
