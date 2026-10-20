using System.Security.Cryptography;
using System.Text;
using Lumen.Core.Models;
using Lumen.Core.Quarantine;
using Lumen.Core.Util;

namespace Lumen.Core.Tests;

public sealed class QuarantineTests
{
    [Fact]
    public async Task Quarantine_then_restore_round_trips_content()
    {
        using var temp = new TempDirectory();
        const string marker = "quarantine marker: preserve me";
        var source = temp.File("source.txt", marker);
        var hash = HashUtil.Sha256File(source, CancellationToken.None);
        using var service = CreateService(temp, out var vault);

        var result = await service.QuarantineAsync(
            TestData.Quarantine(source, hash),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.Quarantined, result.Status);
        Assert.True(result.OriginalRemoved);
        Assert.False(File.Exists(source));

        var item = Assert.Single(service.GetItems());
        Assert.Equal(hash, item.Sha256);
        Assert.Equal(marker.Length, item.SizeBytes);
        Assert.Equal(FindingCategory.Heuristic, item.Category);

        var vaultFile = Path.Combine(vault, item.VaultFileName);
        Assert.True(File.Exists(vaultFile));
        Assert.False(Encoding.UTF8.GetString(File.ReadAllBytes(vaultFile)).Contains(marker, StringComparison.Ordinal));
        Assert.False(File.ReadAllText(Path.Combine(vault, "manifest.json")).Contains(marker, StringComparison.Ordinal));

        var restored = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        Assert.Equal(source, restored.RestoredPath);
        Assert.Equal(marker, File.ReadAllText(source));
        Assert.Empty(service.GetItems());
        Assert.False(File.Exists(vaultFile));
    }

    [Fact]
    public async Task Restore_refuses_to_overwrite_until_confirmed()
    {
        using var temp = new TempDirectory();
        var source = temp.File("report.txt", "original content");
        using var service = CreateService(temp, out _);

        var quarantine = await service.QuarantineAsync(
            TestData.Quarantine(source),
            null,
            CancellationToken.None);
        Assert.Equal(QuarantineStatus.Quarantined, quarantine.Status);

        File.WriteAllText(source, "replacement content");
        var item = Assert.Single(service.GetItems());

        var blocked = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.TargetExists, blocked.Status);
        Assert.Equal("replacement content", File.ReadAllText(source));
        Assert.Single(service.GetItems());

        var overwritten = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id, Overwrite = true },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.Restored, overwritten.Status);
        Assert.Equal("original content", File.ReadAllText(source));
        Assert.Empty(service.GetItems());
    }

    [Fact]
    public async Task Restore_reports_missing_destination_folder()
    {
        using var temp = new TempDirectory();
        var source = temp.File("nested/data.txt", "data");
        using var service = CreateService(temp, out _);

        await service.QuarantineAsync(TestData.Quarantine(source), null, CancellationToken.None);
        var item = Assert.Single(service.GetItems());
        Directory.Delete(Path.GetDirectoryName(source)!, recursive: true);

        var restored = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.DestinationMissing, restored.Status);
        Assert.Single(service.GetItems());
    }

    [Fact]
    public async Task Restore_to_chosen_folder_works()
    {
        using var temp = new TempDirectory();
        var source = temp.File("source.txt", "restore me");
        var destinationFolder = temp.CreateDirectory("restore-here");
        using var service = CreateService(temp, out _);

        await service.QuarantineAsync(TestData.Quarantine(source), null, CancellationToken.None);
        var item = Assert.Single(service.GetItems());
        var destination = Path.Combine(destinationFolder, "restored.txt");

        var restored = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id, DestinationPath = destination },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        Assert.Equal(destination, restored.RestoredPath);
        Assert.Equal("restore me", File.ReadAllText(destination));
        Assert.False(File.Exists(source));
    }

    [Fact]
    public async Task Changed_file_is_refused_unless_explicitly_allowed()
    {
        using var temp = new TempDirectory();
        var source = temp.File("changing.txt", "original");
        var originalHash = HashUtil.Sha256File(source, CancellationToken.None);
        File.WriteAllText(source, "changed after scan");
        using var service = CreateService(temp, out var vault);

        var refused = await service.QuarantineAsync(
            TestData.Quarantine(source, originalHash),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.ChangedSinceScan, refused.Status);
        Assert.True(File.Exists(source));
        Assert.Empty(service.GetItems());
        Assert.Empty(Directory.GetFiles(vault, "*.qbin*"));

        var allowed = await service.QuarantineAsync(
            TestData.Quarantine(source, originalHash, allowChanged: true),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.Quarantined, allowed.Status);
        var item = Assert.Single(service.GetItems());
        Assert.Equal(HashUtil.Sha256Bytes(Encoding.UTF8.GetBytes("changed after scan")), item.Sha256);
    }

    [Fact]
    public async Task Tampered_vault_is_detected_and_nothing_is_restored()
    {
        using var temp = new TempDirectory();
        var source = temp.File("tamper.txt", "tamper test");
        using var service = CreateService(temp, out var vault);

        await service.QuarantineAsync(TestData.Quarantine(source), null, CancellationToken.None);
        var item = Assert.Single(service.GetItems());
        var vaultFile = Path.Combine(vault, item.VaultFileName);
        var bytes = File.ReadAllBytes(vaultFile);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(vaultFile, bytes);

        var restored = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.Corrupt, restored.Status);
        Assert.False(File.Exists(source));
        Assert.Single(service.GetItems());
    }

    [Fact]
    public async Task Missing_vault_file_is_reported_as_corrupt()
    {
        using var temp = new TempDirectory();
        var source = temp.File("gone.txt", "gone");
        using var service = CreateService(temp, out var vault);

        await service.QuarantineAsync(TestData.Quarantine(source), null, CancellationToken.None);
        var item = Assert.Single(service.GetItems());
        File.Delete(Path.Combine(vault, item.VaultFileName));

        var restored = await service.RestoreAsync(
            new RestoreRequest { Id = item.Id },
            CancellationToken.None);

        Assert.Equal(RestoreStatus.Corrupt, restored.Status);
        Assert.False(File.Exists(source));
    }

    [Fact]
    public async Task Delete_removes_index_and_encrypted_file()
    {
        using var temp = new TempDirectory();
        var source = temp.File("delete-me.txt", "delete");
        using var service = CreateService(temp, out var vault);

        await service.QuarantineAsync(TestData.Quarantine(source), null, CancellationToken.None);
        var item = Assert.Single(service.GetItems());
        var vaultFile = Path.Combine(vault, item.VaultFileName);

        var deleted = await service.DeleteAsync(item.Id, CancellationToken.None);

        Assert.True(deleted.Deleted);
        Assert.Empty(service.GetItems());
        Assert.False(File.Exists(vaultFile));
    }

    [Fact]
    public async Task Corrupt_manifest_is_preserved_and_vault_files_are_not_deleted()
    {
        using var temp = new TempDirectory();
        var vault = Path.Combine(temp.Root, "vault");
        Directory.CreateDirectory(vault);
        var manifest = Path.Combine(vault, "manifest.json");
        File.WriteAllText(manifest, "{ this is not json");
        var orphan = Path.Combine(vault, "0123456789abcdef0123456789abcdef.qbin");
        File.WriteAllBytes(orphan, [1, 2, 3]);

        using var service = new QuarantineService(
            vault,
            manifest,
            new FakeSecretProtector(),
            new FakeClock(),
            new FakeLog());

        Assert.NotNull(service.LoadWarning);
        Assert.Contains("preserved", service.LoadWarning, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(service.GetItems());
        Assert.Single(Directory.GetFiles(vault, "manifest.json.corrupt-*"));
        Assert.True(File.Exists(orphan));
    }

    [Fact]
    public async Task Cancellation_leaves_original_untouched_and_cleans_partial_vault()
    {
        using var temp = new TempDirectory();
        var source = temp.FileBytes("large.bin", new byte[12 * 1024 * 1024]);
        using var service = CreateService(temp, out var vault);
        using var cts = new CancellationTokenSource();
        var progress = new InlineProgress<long>(total =>
        {
            if (total > 0) cts.Cancel();
        });

        var result = await service.QuarantineAsync(
            TestData.Quarantine(source),
            progress,
            cts.Token);

        Assert.Equal(QuarantineStatus.Cancelled, result.Status);
        Assert.True(File.Exists(source));
        Assert.Empty(service.GetItems());
        Assert.Empty(Directory.GetFiles(vault, "*.qbin*"));
    }

    [Fact]
    public async Task Original_that_cannot_be_deleted_is_retained_and_noted()
    {
        using var temp = new TempDirectory();
        var source = temp.File("held-open.txt", "held open");
        using var service = CreateService(temp, out _);
        using var hold = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);

        var result = await service.QuarantineAsync(
            TestData.Quarantine(source),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.QuarantinedOriginalRetained, result.Status);
        Assert.False(result.OriginalRemoved);
        Assert.True(File.Exists(source));
        var item = Assert.Single(service.GetItems());
        Assert.False(string.IsNullOrWhiteSpace(item.Note));
    }

    [Fact]
    public async Task Quarantine_refuses_files_inside_its_own_vault()
    {
        using var temp = new TempDirectory();
        using var service = CreateService(temp, out var vault);
        var inside = Path.Combine(vault, "already-here.txt");
        File.WriteAllText(inside, "x");

        var result = await service.QuarantineAsync(
            TestData.Quarantine(inside),
            null,
            CancellationToken.None);

        Assert.Equal(QuarantineStatus.Failed, result.Status);
        Assert.True(File.Exists(inside));
    }

    private static QuarantineService CreateService(TempDirectory temp, out string vaultDirectory)
    {
        vaultDirectory = Path.Combine(temp.Root, "vault");
        Directory.CreateDirectory(vaultDirectory);
        return new QuarantineService(
            vaultDirectory,
            Path.Combine(vaultDirectory, "manifest.json"),
            new FakeSecretProtector(),
            new FakeClock(),
            new FakeLog());
    }

}
