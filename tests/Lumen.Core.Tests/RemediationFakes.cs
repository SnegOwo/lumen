using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Remediation;

namespace Lumen.Core.Tests;

/// <summary>
/// Test double for the operating system's process list. It never touches a real process:
/// it only remembers what it was asked to do so a test can assert on it.
/// </summary>
internal sealed class FakeProcessTerminator : IProcessTerminator
{
    private readonly List<ProcessMatch> _matches = [];

    /// <summary>Every process id the engine asked to terminate, in order.</summary>
    public List<int> TerminatedPids { get; } = [];

    /// <summary>Process ids whose termination is made to fail.</summary>
    public HashSet<int> FailTerminationPids { get; } = [];

    /// <summary>How often the engine asked for the process list.</summary>
    public int FindCallCount { get; private set; }

    public FakeProcessTerminator Add(ProcessMatch match)
    {
        _matches.Add(match);
        return this;
    }

    public FakeProcessTerminator AddProcess(
        string name,
        string? executablePath,
        int pid,
        bool isSystemProcess = false,
        bool isSigned = false,
        ProcessMatchKind matchKind = ProcessMatchKind.ExecutablePath)
    {
        var process = new ProcessInfo
        {
            Pid = pid,
            Name = name,
            ExecutablePath = executablePath,
            IsSystemProcess = isSystemProcess,
            IsSigned = isSigned
        };

        return Add(new ProcessMatch
        {
            Process = process,
            MatchKind = matchKind,
            MatchedPath = executablePath ?? name
        });
    }

    public Task<IReadOnlyList<ProcessMatch>> FindByFilePathAsync(string filePath, CancellationToken cancellationToken)
    {
        FindCallCount++;
        var found = _matches
            .Where(match => Matches(match, filePath))
            .ToArray();
        return Task.FromResult<IReadOnlyList<ProcessMatch>>(found);
    }

    public Task<ProcessInfo?> GetAsync(int pid, CancellationToken cancellationToken)
    {
        var process = _matches
            .Select(match => match.Process)
            .FirstOrDefault(candidate => candidate.Pid == pid);
        return Task.FromResult(process);
    }

    public Task<ProcessTerminationResult> TerminateAsync(int pid, CancellationToken cancellationToken)
    {
        TerminatedPids.Add(pid);

        if (FailTerminationPids.Contains(pid))
        {
            return Task.FromResult(new ProcessTerminationResult
            {
                Terminated = false,
                Outcome = ProcessTerminationOutcome.Failed,
                Message = "The process could not be stopped."
            });
        }

        return Task.FromResult(new ProcessTerminationResult
        {
            Terminated = true,
            Outcome = ProcessTerminationOutcome.Terminated,
            Message = "The process was stopped."
        });
    }

    private static bool Matches(ProcessMatch match, string filePath)
    {
        var target = Normalize(filePath);
        if (target is null) return false;

        return SamePath(match.MatchedPath, target) || SamePath(match.Process.ExecutablePath, target);
    }

    private static bool SamePath(string? left, string right)
    {
        if (string.IsNullOrWhiteSpace(left)) return false;
        var full = Normalize(left);
        return full is not null && string.Equals(full, right, StringComparison.OrdinalIgnoreCase);
    }

    private static string? Normalize(string path)
    {
        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }
}

/// <summary>
/// Test double for the autostart entries of the machine. It never reads or writes the
/// registry, the Startup folders, the task scheduler or the service control manager.
/// </summary>
internal sealed class FakePersistenceEnumerator : IPersistenceEnumerator
{
    /// <summary>The entries the fake reports.</summary>
    public List<PersistenceEntry> Entries { get; } = [];

    /// <summary>Every entry the engine asked to remove, in order.</summary>
    public List<PersistenceEntry> RemovedEntries { get; } = [];

    /// <summary>Entry names whose removal is made to fail.</summary>
    public HashSet<string> FailRemovalNames { get; } = [];

    /// <summary>How often the engine asked for the entry list.</summary>
    public int EnumerateCallCount { get; private set; }

    /// <summary>How often the engine asked for an entry to be removed.</summary>
    public int RemoveCallCount { get; private set; }

    public Task<IReadOnlyList<PersistenceEntry>> EnumerateAsync(string filePath, CancellationToken cancellationToken)
    {
        EnumerateCallCount++;
        return Task.FromResult<IReadOnlyList<PersistenceEntry>>(Entries.ToArray());
    }

    public Task<PersistenceRemovalResult> RemoveAsync(PersistenceEntry entry, CancellationToken cancellationToken)
    {
        RemoveCallCount++;

        if (FailRemovalNames.Contains(entry.Name))
        {
            return Task.FromResult(new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.Failed,
                Message = "The autostart entry could not be removed."
            });
        }

        RemovedEntries.Add(entry);
        return Task.FromResult(new PersistenceRemovalResult
        {
            Removed = true,
            Outcome = PersistenceRemovalOutcome.Removed,
            Message = "The autostart entry was removed."
        });
    }
}

/// <summary>
/// Test double for permanent file removal. It never touches the file system; it only
/// remembers what it was asked to delete.
/// </summary>
internal sealed class FakeFileRemover : IFileRemover
{
    /// <summary>Every path the engine asked to delete, in order.</summary>
    public List<string> RemovedPaths { get; } = [];

    /// <summary>Paths whose removal is made to fail.</summary>
    public HashSet<string> FailPaths { get; } = [];

    /// <summary>How often the engine asked for a file to be deleted.</summary>
    public int RemoveCallCount { get; private set; }

    public Task<FileRemovalResult> RemoveAsync(string filePath, CancellationToken cancellationToken)
    {
        RemoveCallCount++;

        if (FailPaths.Contains(filePath))
        {
            return Task.FromResult(new FileRemovalResult
            {
                Removed = false,
                Outcome = FileRemovalOutcome.Failed,
                Message = "The file could not be removed."
            });
        }

        RemovedPaths.Add(filePath);
        return Task.FromResult(new FileRemovalResult
        {
            Removed = true,
            Outcome = FileRemovalOutcome.Removed,
            Message = "The file was permanently removed."
        });
    }
}

/// <summary>
/// Test double for file hashing. It never reads a file; the test states the digest.
/// </summary>
internal sealed class FakeFileHasher : IFileHasher
{
    private readonly Dictionary<string, FileHashResult> _results = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>How often the engine asked for a file to be hashed.</summary>
    public int HashCallCount { get; private set; }

    public FakeFileHasher Set(string path, string sha256, long sizeBytes = 128)
    {
        _results[path] = new FileHashResult
        {
            Outcome = FileHashOutcome.Hashed,
            Sha256 = sha256,
            SizeBytes = sizeBytes
        };
        return this;
    }

    public FakeFileHasher SetMissing(string path)
    {
        _results[path] = new FileHashResult { Outcome = FileHashOutcome.NotFound };
        return this;
    }

    public FakeFileHasher SetFailure(string path, string error)
    {
        _results[path] = new FileHashResult { Outcome = FileHashOutcome.Failed, Error = error };
        return this;
    }

    public Task<FileHashResult> GetSha256Async(string filePath, CancellationToken cancellationToken)
    {
        HashCallCount++;

        if (_results.TryGetValue(filePath, out var result))
        {
            return Task.FromResult(result);
        }

        return Task.FromResult(new FileHashResult { Outcome = FileHashOutcome.NotFound });
    }
}

/// <summary>
/// Test double for the audit journal. It keeps the entries in memory so a test can assert
/// on the audit trail without writing anything to disk.
/// </summary>
internal sealed class FakeAuditJournal : IAuditJournal
{
    private readonly object _gate = new();
    private readonly List<AuditEntry> _entries = [];

    /// <summary>Every entry the engine wrote, in order.</summary>
    public IReadOnlyList<AuditEntry> Entries
    {
        get { lock (_gate) return _entries.ToArray(); }
    }

    /// <summary>When true, every write fails, so the engine has to fail closed.</summary>
    public bool FailOnAppend { get; set; }

    public Task AppendAsync(AuditEntry entry, CancellationToken cancellationToken)
    {
        if (FailOnAppend) throw new IOException("The audit journal is not writable.");

        lock (_gate) _entries.Add(entry);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditEntry>> ReadAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Entries);
}

/// <summary>
/// Bundles the engine with its test doubles so each test reads as one short story.
/// </summary>
internal sealed class RemediationHarness
{
    public RemediationHarness(bool remediationEnabled = true)
    {
        Engine = new RemediationEngine(
            Processes,
            Persistence,
            Remover,
            Hasher,
            Journal,
            Clock,
            Log,
            remediationEnabled);
    }

    public FakeProcessTerminator Processes { get; } = new();
    public FakePersistenceEnumerator Persistence { get; } = new();
    public FakeFileRemover Remover { get; } = new();
    public FakeFileHasher Hasher { get; } = new();
    public FakeAuditJournal Journal { get; } = new();
    public FakeClock Clock { get; } = new();
    public FakeLog Log { get; } = new();
    public RemediationEngine Engine { get; }

    public RemediationTarget Target(string path, string? sha256 = null, bool allowChangedFile = false) => new()
    {
        FilePath = path,
        Sha256 = sha256,
        SizeBytes = 128,
        FindingTitle = "Test finding",
        FindingDetail = "Test detail",
        QuarantineItemId = "vaultitem000000000000000000000000",
        AllowChangedFile = allowChangedFile
    };

    public static PersistenceEntry RunEntry(string valueName, string targetPath, bool canRestore = true) => new()
    {
        Kind = PersistenceEntryKind.RegistryRunValue,
        Name = valueName,
        TargetPath = targetPath,
        Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        RestoreData = new PersistenceRestoreData
        {
            RegistryKeyPath = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            RegistryValueName = valueName,
            RegistryValueData = targetPath,
            RegistryValueKind = "REG_SZ",
            CanRestore = canRestore
        }
    };
}
