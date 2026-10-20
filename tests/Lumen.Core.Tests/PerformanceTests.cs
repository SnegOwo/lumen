using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Scanning;
using Lumen.Core.Util;
using Xunit.Abstractions;

namespace Lumen.Core.Tests;

/// <summary>
/// Tests that keep Lumen light. They measure how much memory a scan allocates and they
/// compare that against a budget, so a change that starts allocating a buffer per file
/// fails the build instead of quietly making the application heavy.
/// </summary>
/// <remarks>
/// <para>
/// The tests measure allocations and not times. A time limit depends on how busy the
/// machine is, so it fails for the wrong reason; an allocation limit does not.
/// </para>
/// <para>
/// The budgets are deliberately generous. They sit several times above what the code
/// allocates today, so ordinary work does not make them flaky, and they are still far
/// below what the code allocated before the buffers were pooled, so a regression is
/// caught.
/// </para>
/// </remarks>
public sealed class PerformanceTests
{
    /// <summary>
    /// How much memory one file may cost while it is read. Reading a file used to cost
    /// the size of the file plus a 64 KB buffer for every single file.
    /// </summary>
    private const long ReadBudgetPerFile = 4 * 1024;

    /// <summary>
    /// How much memory one file may cost while it is read and inspected. The inspection
    /// itself is the expensive part: the detectors build their findings and the text
    /// rules decode the file as text.
    /// </summary>
    private const long InspectBudgetPerFile = 24 * 1024;

    private readonly ITestOutputHelper _output;

    public PerformanceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void Reading_a_file_does_not_allocate_a_buffer_for_every_file()
    {
        const int fileCount = 64;
        const int fileSize = 64 * 1024;

        using var temp = new TempDirectory();
        var path = temp.FileBytes("sample.bin", SyntheticBytes(fileSize, 3));

        var reader = new ProbeReader(1024 * 1024);

        // The first read fills the pool. It is not part of the measurement.
        var warm = reader.Read(path, FileAttributes.Normal, CancellationToken.None);
        Assert.True(warm.Success);

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < fileCount; index++)
        {
            var result = reader.Read(path, FileAttributes.Normal, CancellationToken.None);
            Assert.True(result.Success);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        var perFile = allocated / fileCount;

        _output.WriteLine($"Reading cost {perFile} bytes per file.");
        Assert.True(
            perFile < ReadBudgetPerFile,
            $"Reading a file may not cost more than {ReadBudgetPerFile} bytes, but it cost {perFile}.");
    }

    [Fact]
    public void Inspecting_a_file_stays_inside_the_memory_budget()
    {
        const int fileCount = 32;
        const int fileSize = 64 * 1024;

        using var temp = new TempDirectory();
        var path = temp.FileBytes("sample.bin", SyntheticBytes(fileSize, 5));

        var reader = new ProbeReader(1024 * 1024);
        var registry = DetectorRegistry.CreateDefault();

        var warm = reader.Read(path, FileAttributes.Normal, CancellationToken.None);
        registry.Inspect(warm.Probe!, CancellationToken.None);

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < fileCount; index++)
        {
            var result = reader.Read(path, FileAttributes.Normal, CancellationToken.None);
            registry.Inspect(result.Probe!, CancellationToken.None);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        var perFile = allocated / fileCount;

        _output.WriteLine($"Reading and inspecting cost {perFile} bytes per file.");
        Assert.True(
            perFile < InspectBudgetPerFile,
            $"Reading and inspecting a file may not cost more than {InspectBudgetPerFile} bytes, but it cost {perFile}.");
    }

    [Fact]
    public void Scanning_the_same_file_again_costs_the_same_and_does_not_grow()
    {
        const int rounds = 20;

        using var temp = new TempDirectory();
        var path = temp.FileBytes("sample.bin", SyntheticBytes(32 * 1024, 11));

        var reader = new ProbeReader(1024 * 1024);
        var registry = DetectorRegistry.CreateDefault();

        var warm = reader.Read(path, FileAttributes.Normal, CancellationToken.None);
        registry.Inspect(warm.Probe!, CancellationToken.None);

        var first = MeasureScan(reader, registry, path, rounds);
        var second = MeasureScan(reader, registry, path, rounds);

        _output.WriteLine($"First round {first} bytes per scan, second round {second} bytes per scan.");
        Assert.True(
            second <= first + (first / 2),
            $"Scanning the same file again may not cost much more than before ({first} then {second} bytes per scan).");
        Assert.True(
            second / rounds < InspectBudgetPerFile,
            $"Scanning the same file again may not cost more than {InspectBudgetPerFile} bytes per file.");
    }

    [Fact]
    public void Scanning_a_folder_allocates_far_less_than_it_reads()
    {
        const int fileCount = 64;
        const int fileSize = 64 * 1024;

        using var temp = new TempDirectory();
        for (var index = 0; index < fileCount; index++)
        {
            temp.FileBytes($"file-{index}.bin", SyntheticBytes(fileSize, index));
        }

        var reader = new ProbeReader(1024 * 1024);
        var registry = DetectorRegistry.CreateDefault();

        var warm = reader.Read(
            Path.Combine(temp.Root, "file-0.bin"),
            FileAttributes.Normal,
            CancellationToken.None);
        registry.Inspect(warm.Probe!, CancellationToken.None);

        var paths = Directory.GetFiles(temp.Root);
        var before = GC.GetAllocatedBytesForCurrentThread();
        long read = 0;
        foreach (var path in paths)
        {
            var result = reader.Read(path, FileAttributes.Normal, CancellationToken.None);
            read += result.Probe!.Content.Length;
            registry.Inspect(result.Probe!, CancellationToken.None);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        _output.WriteLine($"Scanning {paths.Length} files read {read} bytes and allocated {allocated} bytes.");
        Assert.True(
            allocated < read,
            $"Scanning may not allocate more memory than it reads ({allocated} allocated for {read} read).");
    }

    [Fact]
    public void The_buffer_of_the_thread_is_given_back_to_the_pool()
    {
        using var temp = new TempDirectory();
        var path = temp.FileBytes("sample.bin", SyntheticBytes(128 * 1024, 7));

        var reader = new ProbeReader(1024 * 1024);
        var before = GC.GetAllocatedBytesForCurrentThread();
        reader.Read(path, FileAttributes.Normal, CancellationToken.None);
        var after = GC.GetAllocatedBytesForCurrentThread();

        ProbeReader.ReleaseThreadBuffer();

        // Reading the same file again must not need a new buffer, because the pool still
        // has the one that was given back.
        var second = GC.GetAllocatedBytesForCurrentThread();
        reader.Read(path, FileAttributes.Normal, CancellationToken.None);
        var third = GC.GetAllocatedBytesForCurrentThread();

        _output.WriteLine($"First read {(after - before)} bytes, second read {(third - second)} bytes.");
        Assert.True(
            third - second < 128 * 1024,
            "The buffer of the thread must go back to the pool, so that reading again is cheap.");
    }

    [Fact]
    public void Signature_rules_find_the_same_place_as_a_plain_search()
    {
        // The signature engine searches with the vector instructions of the processor. The
        // rules have to fire on exactly the same bytes as a plain byte by byte search.
        var engine = BuildEngine();
        var content = "the quick brown fox jumps over the lazy dog. WScript.Shell and wscript.shell".ToCharArray();

        var text = string.Concat(content);
        var bytes = System.Text.Encoding.ASCII.GetBytes(text);

        var probe = FileProbe.FromBytes("sample.txt", bytes);

        Assert.Equal(ReferenceOffset(bytes, System.Text.Encoding.ASCII.GetBytes("WScript.Shell"), ignoreCase: true), MatchOffset(engine, probe, "test.ascii-ignore-case"));
        Assert.Equal(ReferenceOffset(bytes, System.Text.Encoding.ASCII.GetBytes("WScript.Shell"), ignoreCase: false), MatchOffset(engine, probe, "test.ascii-exact"));
        Assert.Equal(ReferenceOffset(bytes, System.Text.Encoding.ASCII.GetBytes("quick brown"), ignoreCase: false), MatchOffset(engine, probe, "test.ascii-exact-2"));
    }

    [Fact]
    public void Signature_rules_with_wildcards_find_the_same_place_as_a_plain_search()
    {
        var engine = BuildEngine();
        var bytes = new byte[] { 0x11, 0x22, 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x33 };
        var probe = FileProbe.FromBytes("sample.bin", bytes);

        // The pattern is "4D 5A ?? 00 03 00 ?? 00": the wildcards have to match any byte.
        Assert.Equal(2, MatchOffset(engine, probe, "test.hex-wildcard"));
        Assert.Equal(-1, MatchOffset(engine, probe, "test.hex-missing"));
    }

    [Fact]
    public void A_token_rule_fires_on_the_same_text_as_before()
    {
        var engine = BuildEngine();
        var probe = FileProbe.FromText("run.ps1", "powershell -w hidden -enc SQBFAFgA");

        var matches = engine.Match(probe, CancellationToken.None);
        Assert.Contains(matches, match => match.Rule.Id == "test.token-groups");

        var clean = FileProbe.FromText("run.ps1", "Write-Output 'hello'");
        Assert.DoesNotContain(
            engine.Match(clean, CancellationToken.None),
            match => match.Rule.Id == "test.token-groups");
    }

    private static int MatchOffset(SignatureEngine engine, FileProbe probe, string ruleId)
    {
        foreach (var match in engine.Match(probe, CancellationToken.None))
        {
            if (match.Rule.Id == ruleId) return match.Offset;
        }

        return -1;
    }

    /// <summary>
    /// A plain byte by byte search, written the slow way, used as the reference for the
    /// vectorised search of the signature engine.
    /// </summary>
    private static int ReferenceOffset(byte[] haystack, byte[] needle, bool ignoreCase)
    {
        for (var start = 0; start + needle.Length <= haystack.Length; start++)
        {
            var matched = true;
            for (var offset = 0; offset < needle.Length; offset++)
            {
                var left = haystack[start + offset];
                var right = needle[offset];
                if (ignoreCase)
                {
                    if (left is >= (byte)'A' and <= (byte)'Z') left += 32;
                    if (right is >= (byte)'A' and <= (byte)'Z') right += 32;
                }

                if (left == right) continue;
                matched = false;
                break;
            }

            if (matched) return start;
        }

        return -1;
    }

    private static SignatureEngine BuildEngine()
    {
        const string json = """
        {
          "schemaVersion": 1,
          "rules": [
            {
              "id": "test.ascii-ignore-case",
              "title": "Case insensitive text",
              "category": "Signature",
              "confidence": "Medium",
              "description": "d",
              "detail": "d",
              "advice": "a",
              "patterns": [ { "kind": "ascii", "value": "WScript.Shell" } ]
            },
            {
              "id": "test.ascii-exact",
              "title": "Exact text",
              "category": "Signature",
              "confidence": "Medium",
              "description": "d",
              "detail": "d",
              "advice": "a",
              "patterns": [ { "kind": "ascii", "value": "WScript.Shell", "caseSensitive": true } ]
            },
            {
              "id": "test.ascii-exact-2",
              "title": "Exact text",
              "category": "Signature",
              "confidence": "Medium",
              "description": "d",
              "detail": "d",
              "advice": "a",
              "patterns": [ { "kind": "ascii", "value": "quick brown", "caseSensitive": true } ]
            },
            {
              "id": "test.hex-wildcard",
              "title": "Byte pattern",
              "category": "Signature",
              "confidence": "Medium",
              "description": "d",
              "detail": "d",
              "advice": "a",
              "patterns": [ { "kind": "hex", "value": "4D 5A ?? 00 03 00 ?? 00" } ]
            },
            {
              "id": "test.hex-missing",
              "title": "Byte pattern",
              "category": "Signature",
              "confidence": "Medium",
              "description": "d",
              "detail": "d",
              "advice": "a",
              "patterns": [ { "kind": "hex", "value": "4D 5A ?? 03 00 ?? 01" } ]
            },
            {
              "id": "test.token-groups",
              "title": "Token combination",
              "category": "Signature",
              "confidence": "Medium",
              "description": "d",
              "detail": "d",
              "advice": "a",
              "patterns": [ { "kind": "tokenGroups", "value": "powershell,pwsh|-w hidden,-enc " } ]
            }
          ]
        }
        """;

        var parsed = SignatureEngine.Parse(json, "performance test");
        Assert.True(parsed.Ok, parsed.Problem);
        return new SignatureEngine(parsed.RuleSet!);
    }

    private static long MeasureScan(
        ProbeReader reader,
        DetectorRegistry registry,
        string path,
        int rounds)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < rounds; index++)
        {
            var result = reader.Read(path, FileAttributes.Normal, CancellationToken.None);
            registry.Inspect(result.Probe!, CancellationToken.None);
        }

        return (GC.GetAllocatedBytesForCurrentThread() - before) / rounds;
    }

    private static byte[] SyntheticBytes(int size, int seed)
    {
        var bytes = new byte[size];
        var random = new Random(seed);
        for (var index = 0; index < size; index++) bytes[index] = (byte)random.Next(256);
        return bytes;
    }
}
