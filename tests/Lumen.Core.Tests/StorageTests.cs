using System.Text;
using Lumen.Core.Logging;
using Lumen.Core.Models;
using Lumen.Core.Storage;

namespace Lumen.Core.Tests;

public sealed class StorageTests
{
    [Fact]
    public void Settings_defaults_when_file_is_missing()
    {
        using var temp = new TempDirectory();
        var paths = new AppPaths(temp.Root);
        var store = new SettingsStore(paths, new FakeLog());

        var settings = store.Load();

        Assert.Equal(AppTheme.System, settings.Theme);
        Assert.True(settings.LoggingEnabled);
        Assert.Equal(AppSettings.DefaultInspectMegabytes, settings.MaxInspectMegabytes);
        Assert.Null(store.LoadWarning);
    }

    [Fact]
    public void Settings_round_trip_and_clamp_out_of_range_values()
    {
        using var temp = new TempDirectory();
        var paths = new AppPaths(temp.Root);
        var store = new SettingsStore(paths, new FakeLog());
        var settings = AppSettings.Default with
        {
            Theme = AppTheme.Dark,
            LoggingEnabled = false,
            MaxInspectMegabytes = 999,
            MinimizeToTray = true,
            ShowTrayNotifications = false
        };

        var saved = store.Save(settings);
        Assert.True(saved.Ok);

        var reloaded = new SettingsStore(paths, new FakeLog()).Load();
        Assert.Equal(AppTheme.Dark, reloaded.Theme);
        Assert.False(reloaded.LoggingEnabled);
        Assert.Equal(AppSettings.MaxAllowedInspectMegabytes, reloaded.MaxInspectMegabytes);
        Assert.True(reloaded.MinimizeToTray);
        Assert.False(reloaded.ShowTrayNotifications);
    }

    [Fact]
    public void Settings_corrupt_file_is_preserved_and_defaults_are_used()
    {
        using var temp = new TempDirectory();
        var paths = new AppPaths(temp.Root);
        File.WriteAllText(paths.SettingsFile, "{ not valid json");

        var store = new SettingsStore(paths, new FakeLog());
        var settings = store.Load();

        Assert.Equal(AppSettings.Default, settings);
        Assert.NotNull(store.LoadWarning);
        Assert.Single(Directory.GetFiles(temp.Root, "settings.json.corrupt-*"));
    }

    [Fact]
    public void Settings_save_failure_is_reported_without_throwing()
    {
        using var temp = new TempDirectory();
        var paths = new AppPaths(temp.Root);
        Directory.CreateDirectory(paths.SettingsFile);
        var store = new SettingsStore(paths, new FakeLog());

        var result = store.Save(AppSettings.Default with { Theme = AppTheme.Light });

        Assert.False(result.Ok);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public void History_caps_entries_newest_first_and_can_be_cleared()
    {
        using var temp = new TempDirectory();
        var paths = new AppPaths(temp.Root);
        var clock = new FakeClock();
        var store = new HistoryStore(paths, new FakeLog(), maxEntries: 10);

        for (var index = 0; index < 12; index++)
        {
            var entry = Entry(clock.UtcNow.AddMinutes(index), $"scan-{index}");
            Assert.True(store.Add(entry).Ok);
        }

        var entries = store.GetEntries();
        Assert.Equal(10, entries.Count);
        Assert.Equal("scan-11", entries[0].Id);
        Assert.Equal("scan-2", entries[^1].Id);

        Assert.True(store.Clear().Ok);
        Assert.Empty(store.GetEntries());
        Assert.Empty(new HistoryStore(paths, new FakeLog()).GetEntries());
    }

    [Fact]
    public void History_corrupt_file_is_preserved()
    {
        using var temp = new TempDirectory();
        var paths = new AppPaths(temp.Root);
        File.WriteAllText(paths.HistoryFile, "broken");

        var store = new HistoryStore(paths, new FakeLog());

        Assert.NotNull(store.LoadWarning);
        Assert.Empty(store.GetEntries());
        Assert.Single(Directory.GetFiles(temp.Root, "history.json.corrupt-*"));
    }

    [Fact]
    public void Atomic_file_replaces_content_and_leaves_no_temp_files()
    {
        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Root, "atomic.txt");

        AtomicFile.WriteAllText(path, "first");
        AtomicFile.WriteAllText(path, "second");

        Assert.Equal("second", File.ReadAllText(path));
        Assert.Empty(Directory.GetFiles(temp.Root, "*.tmp"));
    }

    [Fact]
    public void Logger_writes_sanitized_paths()
    {
        using var temp = new TempDirectory();
        var logDirectory = Path.Combine(temp.Root, "logs");
        var log = new FileLog(
            logDirectory,
            new FakeClock(),
            enabled: true,
            userProfilePath: @"C:\Users\ExampleUser",
            dataDirectory: @"C:\Users\ExampleUser\AppData\Local\Lumen");

        log.Info("Scan", @"Opened C:\Users\ExampleUser\Documents\notes.txt");
        log.Error("Scan", @"Failed C:\Users\ExampleUser\AppData\Local\Lumen\settings.json", new IOException("disk"));

        var text = File.ReadAllText(Path.Combine(logDirectory, "lumen.log"));
        Assert.Contains("%USERPROFILE%", text);
        Assert.DoesNotContain(@"C:\Users\ExampleUser", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("IOException", text);
    }

    [Fact]
    public void Logger_disabled_writes_nothing()
    {
        using var temp = new TempDirectory();
        var log = new FileLog(Path.Combine(temp.Root, "logs"), new FakeClock(), enabled: false);
        log.Info("Scan", "hello");
        Assert.False(File.Exists(Path.Combine(temp.Root, "logs", "lumen.log")));
    }

    [Fact]
    public void Logger_rotates_large_files()
    {
        using var temp = new TempDirectory();
        var logDirectory = Path.Combine(temp.Root, "logs");
        Directory.CreateDirectory(logDirectory);
        var logPath = Path.Combine(logDirectory, "lumen.log");
        File.WriteAllText(logPath, new string('x', 2_100_000));

        var log = new FileLog(logDirectory, new FakeClock(), enabled: true);
        log.Info("Scan", "after rotation");

        Assert.True(File.Exists(logPath + ".1"));
        Assert.True(File.Exists(logPath));
        Assert.Contains("after rotation", File.ReadAllText(logPath));
    }

    [Fact]
    public void Logger_never_throws_on_bad_directories()
    {
        using var temp = new TempDirectory();
        var blockingFile = temp.File("not-a-directory", "x");
        var log = new FileLog(blockingFile, new FakeClock(), enabled: true);

        var exception = Record.Exception(() => log.Info("Scan", "hello"));

        Assert.Null(exception);
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
}
