using System.Security.Cryptography;
using Lumen.Core.Abstractions;
using Lumen.Core.Logging;
using Lumen.Core.Models;
using Lumen.Core.Quarantine;
using Lumen.Core.Storage;
using Lumen.Core.Util;

namespace Lumen.Core.Tests;

/// <summary>
/// Regression tests for the data-loss and correctness problems that were found in the
/// quarantine vault, the storage layer and the path rules.
/// </summary>
public sealed class CoreHardeningTests
{
    [Fact]
    public async Task Failing_key_protection_leaves_no_encrypted_vault_residue()
    {
        using var temp = new TempDirectory();
        var source = temp.File("secret.txt", "secret content");
        using var service = CreateService(temp, out var vault, new FailingSecretProtector());

        var result = await service.QuarantineAsync(
            TestData.Quarantine(source),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.Failed, result.Status);
        Assert.False(result.OriginalRemoved);
        Assert.True(File.Exists(source));
        Assert.Empty(service.GetItems());
        Assert.Empty(Directory.GetFiles(vault, "*.qbin*"));
    }

    [Fact]
    public async Task Vault_file_is_removed_again_when_the_index_cannot_be_saved()
    {
        using var temp = new TempDirectory();
        var source = temp.File("rollback.txt", "rollback content");
        var vault = Path.Combine(temp.Root, "vault");
        Directory.CreateDirectory(vault);

        // A folder in place of the manifest file makes every save fail.
        Directory.CreateDirectory(Path.Combine(vault, "manifest.json"));
        using var service = new QuarantineService(
            vault,
            Path.Combine(vault, "manifest.json"),
            new FakeSecretProtector(),
            new FakeClock(),
            new FakeLog());

        var result = await service.QuarantineAsync(
            TestData.Quarantine(source),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.Failed, result.Status);
        Assert.True(File.Exists(source));
        Assert.Empty(service.GetItems());
        Assert.Empty(Directory.GetFiles(vault, "*.qbin*"));
    }

    [Fact]
    public async Task File_that_changes_while_it_is_copied_is_refused_and_not_deleted()
    {
        using var temp = new TempDirectory();
        var source = temp.FileBytes("changing.bin", new byte[6 * 1024 * 1024]);
        using var service = CreateService(temp, out var vault);

        var changed = false;
        var progress = new InlineProgress<long>(total =>
        {
            // The file grows while Lumen is copying it, so the encrypted copy no longer
            // matches the content that was hashed.
            if (total >= 4 * 1024 * 1024 && !changed)
            {
                changed = true;
                File.AppendAllText(source, "changed-after-copy");
            }
        });

        var result = await service.QuarantineAsync(
            TestData.Quarantine(source),
            progress,
            CancellationToken.None);

        Assert.True(changed, "The test never changed the file while it was being copied.");
        Assert.Equal(QuarantineStatus.ChangedSinceScan, result.Status);
        Assert.False(result.OriginalRemoved);
        Assert.True(File.Exists(source));
        Assert.Empty(service.GetItems());
        Assert.Empty(Directory.GetFiles(vault, "*.qbin*"));
    }

    [Fact]
    public async Task Malformed_expected_hash_is_rejected_instead_of_ignored()
    {
        using var temp = new TempDirectory();
        var source = temp.File("hash.txt", "hash content");
        using var service = CreateService(temp, out var vault);

        var result = await service.QuarantineAsync(
            TestData.Quarantine(source, "deadbeef"),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.Failed, result.Status);
        Assert.False(result.OriginalRemoved);
        Assert.True(File.Exists(source));
        Assert.Empty(service.GetItems());
        Assert.Empty(Directory.GetFiles(vault, "*.qbin*"));
    }

    [Fact]
    public async Task Restored_file_keeps_its_original_timestamps_and_attributes()
    {
        using var temp = new TempDirectory();
        var source = temp.File("metadata.txt", "metadata content");
        var stamp = new DateTime(2021, 5, 6, 7, 8, 10, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(source, stamp);
        File.SetCreationTimeUtc(source, stamp);
        File.SetAttributes(source, FileAttributes.ReadOnly);

        using var service = CreateService(temp, out _);

        var quarantine = await service.QuarantineAsync(
            TestData.Quarantine(source),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.Quarantined, quarantine.Status);
        var item = Assert.Single(service.GetItems());
        Assert.NotNull(item.Metadata);

        var restored = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        Assert.Equal(source, restored.RestoredPath);

        var restoredWrite = File.GetLastWriteTimeUtc(source);
        Assert.True(
            Math.Abs((restoredWrite - stamp).TotalSeconds) < 2,
            $"The restored file kept the wrong write time: {restoredWrite:O}.");
        Assert.True(
            File.GetAttributes(source).HasFlag(FileAttributes.ReadOnly),
            "The restored file lost its read-only flag.");
    }

    [Fact]
    public async Task Restore_into_a_system_critical_location_is_refused()
    {
        using var temp = new TempDirectory();
        var source = temp.File("restore.txt", "restore content");
        using var service = CreateService(temp, out _);

        await service.QuarantineAsync(TestData.Quarantine(source), null, CancellationToken.None);
        var item = Assert.Single(service.GetItems());

        var destination = Path.Combine(Environment.SystemDirectory, "lumen-restore-test.txt");
        var restored = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id, DestinationPath = destination },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.DestinationProtected, restored.Status);
        Assert.False(File.Exists(destination));
        Assert.Single(service.GetItems());
    }

    [Fact]
    public async Task Quarantine_after_dispose_returns_a_clean_failure()
    {
        using var temp = new TempDirectory();
        var source = temp.File("after-dispose.txt", "content");
        var service = CreateService(temp, out _);
        service.Dispose();

        QuarantineResult? result = null;
        var exception = await Record.ExceptionAsync(async () =>
        {
            result = await service.QuarantineAsync(
                TestData.Quarantine(source),
                null,
                CancellationToken.None);
        });

        Assert.Null(exception);
        Assert.NotNull(result);
        Assert.Equal(QuarantineStatus.Failed, result!.Status);
        Assert.False(result.OriginalRemoved);
        Assert.True(File.Exists(source));
        Assert.Empty(service.GetItems());
    }

    [Fact]
    public void Normalize_roots_ignores_an_unusable_path_instead_of_throwing()
    {
        var roots = new[] { "C:\\valid\\folder", "bad\0path", "   " };

        var exception = Record.Exception(() => PathRules.NormalizeRoots(roots));

        Assert.Null(exception);
        var normalized = PathRules.NormalizeRoots(roots);
        Assert.Single(normalized);
        Assert.Equal(Path.GetFullPath("C:\\valid\\folder"), normalized[0]);
    }

    [Fact]
    public async Task Manifest_file_does_not_store_derived_properties()
    {
        using var temp = new TempDirectory();
        var source = temp.File("manifest.txt", "manifest content");
        using var service = CreateService(temp, out var vault);

        await service.QuarantineAsync(TestData.Quarantine(source), null, CancellationToken.None);

        var manifest = await File.ReadAllTextAsync(Path.Combine(vault, "manifest.json"));
        Assert.DoesNotContain("\"fileName\"", manifest, StringComparison.Ordinal);
    }

    [Fact]
    public void History_entries_stay_newest_first_when_they_are_added_out_of_order()
    {
        using var temp = new TempDirectory();
        var paths = new AppPaths(temp.Root);
        var store = new HistoryStore(paths, new FakeLog(), maxEntries: 10);
        var start = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

        Assert.True(store.Add(Entry(start.AddMinutes(5), "newer")).Ok);
        Assert.True(store.Add(Entry(start, "older")).Ok);
        Assert.True(store.Add(Entry(start.AddMinutes(9), "newest")).Ok);

        var entries = store.GetEntries();
        Assert.Equal("newest", entries[0].Id);
        Assert.Equal("newer", entries[1].Id);
        Assert.Equal("older", entries[2].Id);

        // The order has to survive a reload from disk as well.
        var reloaded = new HistoryStore(paths, new FakeLog(), maxEntries: 10).GetEntries();
        Assert.Equal("newest", reloaded[0].Id);
        Assert.Equal("older", reloaded[^1].Id);

        var history = File.ReadAllText(paths.HistoryFile);
        Assert.DoesNotContain("statusText", history, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("duration", history, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Corrupt_backups_do_not_overwrite_each_other()
    {
        using var temp = new TempDirectory();
        var paths = new AppPaths(temp.Root);
        var store = new SettingsStore(paths, new FakeLog());

        File.WriteAllText(paths.SettingsFile, "{ broken once");
        store.Load();
        File.WriteAllText(paths.SettingsFile, "{ broken twice");
        store.Load();

        var backups = Directory.GetFiles(temp.Root, "settings.json.corrupt-*");
        Assert.Equal(2, backups.Length);
        Assert.Equal(2, backups.Distinct(StringComparer.OrdinalIgnoreCase).Count());

        File.WriteAllText(paths.HistoryFile, "{ broken history");
        new HistoryStore(paths, new FakeLog());
        File.WriteAllText(paths.HistoryFile, "{ broken history again");
        new HistoryStore(paths, new FakeLog());

        var historyBackups = Directory.GetFiles(temp.Root, "history.json.corrupt-*");
        Assert.Equal(2, historyBackups.Length);
        Assert.Equal(2, historyBackups.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Logger_keeps_three_rotation_generations()
    {
        using var temp = new TempDirectory();
        var logDirectory = Path.Combine(temp.Root, "logs");
        var log = new FileLog(logDirectory, new FakeClock(), enabled: true, maxBytes: 1024);

        for (var index = 0; index < 200; index++)
        {
            log.Info("Scan", new string('x', 500));
        }

        Assert.True(File.Exists(Path.Combine(logDirectory, "lumen.log")));
        Assert.True(File.Exists(Path.Combine(logDirectory, "lumen.log.1")));
        Assert.True(File.Exists(Path.Combine(logDirectory, "lumen.log.2")));
        Assert.True(File.Exists(Path.Combine(logDirectory, "lumen.log.3")));
    }

    [Fact]
    public void Stale_vault_part_files_are_cleaned_up_but_fresh_ones_are_kept()
    {
        using var temp = new TempDirectory();
        var vault = Path.Combine(temp.Root, "vault");
        Directory.CreateDirectory(vault);

        var stale = Path.Combine(vault, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.qbin.part");
        File.WriteAllBytes(stale, [1, 2, 3]);
        File.SetLastWriteTimeUtc(stale, DateTime.UtcNow.AddMinutes(-30));

        var fresh = Path.Combine(vault, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.qbin.part");
        File.WriteAllBytes(fresh, [4, 5, 6]);

        using var service = new QuarantineService(
            vault,
            Path.Combine(vault, "manifest.json"),
            new FakeSecretProtector(),
            new FakeClock(),
            new FakeLog());

        Assert.False(File.Exists(stale));
        Assert.True(File.Exists(fresh));
    }

    [Fact]
    public void Read_only_vault_warning_names_the_broken_record()
    {
        using var temp = new TempDirectory();
        var vault = Path.Combine(temp.Root, "vault");
        Directory.CreateDirectory(vault);
        var manifest = Path.Combine(vault, "manifest.json");
        File.WriteAllText(manifest, """
        {
          "schemaVersion": 1,
          "items": [
            {
              "id": "0123456789abcdef0123456789abcdef",
              "originalPath": "C:\\broken.txt",
              "sha256": "not-a-hash",
              "sizeBytes": 1,
              "detectedUtc": "2026-01-01T00:00:00+00:00",
              "quarantinedUtc": "2026-01-01T00:00:00+00:00",
              "findingTitle": "Test",
              "category": 2,
              "findingDetail": "Test",
              "vaultFileName": "0123456789abcdef0123456789abcdef.qbin",
              "protectedKey": "key",
              "protectedMacKey": "key",
              "mac": "mac",
              "iv": "AAAAAAAAAAAAAAAAAAAAAA=="
            }
          ]
        }
        """);

        using var service = new QuarantineService(
            vault,
            manifest,
            new FakeSecretProtector(),
            new FakeClock(),
            new FakeLog());

        Assert.NotNull(service.LoadWarning);
        Assert.Contains("0123456789abcdef0123456789abcdef", service.LoadWarning, StringComparison.Ordinal);
    }

    private static QuarantineService CreateService(
        TempDirectory temp,
        out string vaultDirectory,
        ISecretProtector? protector = null)
    {
        vaultDirectory = Path.Combine(temp.Root, "vault");
        Directory.CreateDirectory(vaultDirectory);
        return new QuarantineService(
            vaultDirectory,
            Path.Combine(vaultDirectory, "manifest.json"),
            protector ?? new FakeSecretProtector(),
            new FakeClock(),
            new FakeLog());
    }

    private static ScanHistoryEntry Entry(DateTimeOffset started, string id) => new()
    {
        Id = id,
        StartedUtc = started,
        FinishedUtc = started.AddSeconds(10),
        Scope = ScanScopeKind.Quick,
        ScopeDescription = "test",
        FilesScanned = 3,
        DetectionCount = 1
    };

    /// <summary>
    /// Test double for a key store that is not available, for example when the Windows
    /// profile of the current user cannot be unlocked.
    /// </summary>
    private sealed class FailingSecretProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext, byte[] entropy) =>
            throw new CryptographicException("The key store is not available.");

        public byte[] Unprotect(byte[] protectedData, byte[] entropy) =>
            throw new CryptographicException("The key store is not available.");
    }
}
