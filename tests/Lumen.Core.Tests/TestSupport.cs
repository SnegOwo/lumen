using System.Security.Cryptography;
using System.Text;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Root = Path.Combine(Path.GetTempPath(), "lumen-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
    }

    public string Root { get; }

    public string File(string relativePath, string content) =>
        FileBytes(relativePath, Encoding.UTF8.GetBytes(content));

    public string FileBytes(string relativePath, byte[] content)
    {
        var path = Path.Combine(Root, relativePath);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        System.IO.File.WriteAllBytes(path, content);
        return path;
    }

    public string CreateDirectory(string relativePath)
    {
        var path = Path.Combine(Root, relativePath);
        System.IO.Directory.CreateDirectory(path);
        return path;
    }

    public void Dispose()
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                if (!Directory.Exists(Root)) return;
                foreach (var file in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
                {
                    try { System.IO.File.SetAttributes(file, FileAttributes.Normal); } catch { }
                }

                Directory.Delete(Root, recursive: true);
                return;
            }
            catch
            {
                Thread.Sleep(60);
            }
        }
    }
}

internal sealed class FakeClock : IClock
{
    public DateTimeOffset UtcNow { get; set; } = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
}

internal sealed class FakeLog : ILog
{
    private readonly object _gate = new();
    private readonly List<string> _lines = [];

    public IReadOnlyList<string> Lines
    {
        get { lock (_gate) return _lines.ToArray(); }
    }

    public void Info(string category, string message) => Add("INFO", category, message, null);
    public void Warn(string category, string message, Exception? exception = null) => Add("WARN", category, message, exception);
    public void Error(string category, string message, Exception? exception = null) => Add("ERROR", category, message, exception);

    private void Add(string level, string category, string message, Exception? exception)
    {
        lock (_gate)
            _lines.Add($"{level}|{category}|{message}|{exception?.GetType().Name}");
    }
}

/// <summary>Test-only protector; deliberately reversible and not used in the product.</summary>
internal sealed class FakeSecretProtector : ISecretProtector
{
    public byte[] Protect(byte[] plaintext, byte[] entropy) => Transform(plaintext, entropy);
    public byte[] Unprotect(byte[] protectedData, byte[] entropy) => Transform(protectedData, entropy);

    private static byte[] Transform(byte[] data, byte[] entropy)
    {
        var key = SHA256.HashData(entropy);
        var result = new byte[data.Length];
        for (var index = 0; index < data.Length; index++) result[index] = (byte)(data[index] ^ key[index % key.Length]);
        return result;
    }
}

internal sealed class FakeDetector : IScanDetector
{
    private readonly Func<FileProbe, bool> _match;

    public FakeDetector(string id, Func<FileProbe, bool> match, FindingCategory category = FindingCategory.Heuristic)
    {
        Id = id;
        _match = match;
        Category = category;
    }

    public string Id { get; }
    public string Name => "Fake detector";
    public string Description => "Test detector";
    public FindingCategory Category { get; }
    public Confidence Confidence => Confidence.Medium;

    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_match(probe)) return [];
        return
        [
            new Finding
            {
                RuleId = Id,
                Title = "Test finding",
                Category = Category,
                Confidence = Confidence,
                Summary = "Test summary",
                Detail = "Test detail",
                Advice = "Test advice"
            }
        ];
    }
}

internal sealed class CollectingProgress : IProgress<ScanProgress>
{
    private readonly object _gate = new();
    private readonly List<ScanProgress> _reports = [];

    public Action<ScanProgress>? OnReport { get; set; }

    public IReadOnlyList<ScanProgress> Reports
    {
        get { lock (_gate) return _reports.ToArray(); }
    }

    public void Report(ScanProgress value)
    {
        lock (_gate) _reports.Add(value);
        OnReport?.Invoke(value);
    }
}

internal sealed class InlineProgress<T> : IProgress<T>
{
    private readonly Action<T> _action;
    public InlineProgress(Action<T> action) => _action = action;
    public void Report(T value) => _action(value);
}

internal static class TestData
{
    private static readonly int[] EicarCodes =
    [
        88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92, 80, 90, 88, 53, 52, 40, 80, 94,
        41, 55, 67, 67, 41, 55, 125, 36, 69, 73, 67, 65, 82, 45, 83, 84, 65, 78, 68, 65,
        82, 68, 45, 65, 78, 84, 73, 86, 73, 82, 85, 83, 45, 84, 69, 83, 84, 45, 70, 73,
        76, 69, 33, 36, 72, 43, 72, 42
    ];

    public static byte[] EicarBytes()
    {
        var bytes = new byte[EicarCodes.Length];
        for (var index = 0; index < EicarCodes.Length; index++) bytes[index] = (byte)EicarCodes[index];
        return bytes;
    }

    public static ScanRequest Request(params string[] roots) => new()
    {
        Scope = ScanScopeKind.Folder,
        Roots = roots,
        Description = "test scan",
        MaxInspectBytes = 1024 * 1024
    };

    public static QuarantineRequest Quarantine(string path, string? expectedHash = null, bool allowChanged = false) => new()
    {
        FilePath = path,
        FindingTitle = "Test finding",
        Category = FindingCategory.Heuristic,
        FindingDetail = "Test detail",
        ExpectedSha256 = expectedHash,
        AllowChangedFile = allowChanged
    };
}

