using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.Services;

/// <summary>
/// The real operating-system implementation of <see cref="IPersistenceEnumerator"/>.
///
/// It looks at the places a program can arrange to start again after a reboot: the
/// Run and RunOnce values in the USER'S OWN registry hive, the Startup folder, Windows
/// scheduled tasks and installed services.
///
/// Two rules are absolute. Nothing is ever written outside the user's own hive.
/// And every entry carries the data needed to put it back, captured BEFORE it is
/// removed, so a wrong removal can be undone by hand.
/// </summary>
public sealed class WindowsPersistenceEnumerator : IPersistenceEnumerator
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceKeyPath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const int MaxTasksToProbe = 60;

    private readonly ILog _log;

    public WindowsPersistenceEnumerator(ILog log)
    {
        _log = log;
    }

    public Task<IReadOnlyList<PersistenceEntry>> EnumerateAsync(string filePath, CancellationToken cancellationToken)
    {
        var entries = new List<PersistenceEntry>();
        if (string.IsNullOrWhiteSpace(filePath)) return Task.FromResult<IReadOnlyList<PersistenceEntry>>(entries);

        string target;
        try
        {
            target = PathRules.NormalizeFile(filePath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Task.FromResult<IReadOnlyList<PersistenceEntry>>(entries);
        }

        try
        {
            entries.AddRange(ReadRegistryValues(RunKeyPath, PersistenceEntryKind.RegistryRunValue, target));
            entries.AddRange(ReadRegistryValues(RunOnceKeyPath, PersistenceEntryKind.RegistryRunOnceValue, target));
        }
        catch (Exception ex)
        {
            _log.Warn("Remediation", "The registry autostart locations could not be read.", ex);
        }

        try
        {
            entries.AddRange(ReadStartupFolder(target));
        }
        catch (Exception ex)
        {
            _log.Warn("Remediation", "The Startup folder could not be read.", ex);
        }

        try
        {
            entries.AddRange(ReadScheduledTasks(target, cancellationToken));
        }
        catch (Exception ex)
        {
            _log.Warn("Remediation", "The scheduled tasks could not be read.", ex);
        }

        try
        {
            entries.AddRange(ReadServices(target));
        }
        catch (Exception ex)
        {
            _log.Warn("Remediation", "The installed services could not be read.", ex);
        }

        return Task.FromResult<IReadOnlyList<PersistenceEntry>>(entries);
    }

    public Task<PersistenceRemovalResult> RemoveAsync(PersistenceEntry entry, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!entry.RestoreData.CanRestore)
        {
            return Task.FromResult(new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.NotReversible,
                Message = "That entry was not captured well enough to be removed safely, so it was left alone."
            });
        }

        try
        {
            switch (entry.Kind)
            {
                case PersistenceEntryKind.RegistryRunValue:
                case PersistenceEntryKind.RegistryRunOnceValue:
                    return Task.FromResult(RemoveRegistryValue(entry));

                case PersistenceEntryKind.StartupFolderItem:
                    return Task.FromResult(RemoveStartupItem(entry));

                case PersistenceEntryKind.ScheduledTask:
                    return Task.FromResult(RemoveScheduledTask(entry));

                case PersistenceEntryKind.Service:
                    return Task.FromResult(RemoveService(entry));

                default:
                    return Task.FromResult(new PersistenceRemovalResult
                    {
                        Removed = false,
                        Outcome = PersistenceRemovalOutcome.Failed,
                        Message = "That kind of autostart entry is not supported."
                    });
            }
        }
        catch (UnauthorizedAccessException)
        {
            return Task.FromResult(new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.AccessDenied,
                Message = "Windows denied access. Lumen does not elevate its privileges."
            });
        }
        catch (Exception ex)
        {
            _log.Warn("Remediation", "An autostart entry could not be removed.", ex);
            return Task.FromResult(new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.Failed,
                Message = "The entry could not be removed: " + ex.GetType().Name
            });
        }
    }

    private IReadOnlyList<PersistenceEntry> ReadRegistryValues(string keyPath, PersistenceEntryKind kind, string target)
    {
        var entries = new List<PersistenceEntry>();

        using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
        if (key is null) return entries;

        foreach (var name in key.GetValueNames())
        {
            var raw = key.GetValue(name);
            if (raw is not string data || string.IsNullOrWhiteSpace(data)) continue;
            if (!References(data, target)) continue;

            entries.Add(new PersistenceEntry
            {
                Kind = kind,
                Name = name,
                TargetPath = target,
                Location = @"HKEY_CURRENT_USER\" + keyPath,
                RestoreData = new PersistenceRestoreData
                {
                    RegistryKeyPath = @"HKEY_CURRENT_USER\" + keyPath,
                    RegistryValueName = name,
                    RegistryValueData = data,
                    RegistryValueKind = key.GetValueKind(name).ToString(),
                    CanRestore = true
                }
            });
        }

        return entries;
    }

    private IReadOnlyList<PersistenceEntry> ReadStartupFolder(string target)
    {
        var entries = new List<PersistenceEntry>();

        foreach (var folder in StartupFolders())
        {
            if (!Directory.Exists(folder)) continue;

            foreach (var path in Directory.EnumerateFiles(folder))
            {
                string? pointsAt = null;

                if (string.Equals(Path.GetExtension(path), ".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    pointsAt = ReadShortcutTarget(path);
                }
                else if (string.Equals(Path.GetFullPath(path), target, StringComparison.OrdinalIgnoreCase))
                {
                    pointsAt = path;
                }

                if (pointsAt is null || !References(pointsAt, target)) continue;

                entries.Add(new PersistenceEntry
                {
                    Kind = PersistenceEntryKind.StartupFolderItem,
                    Name = Path.GetFileName(path),
                    TargetPath = target,
                    Location = folder,
                    RestoreData = new PersistenceRestoreData
                    {
                        StartupItemPath = path,
                        CanRestore = true
                    }
                });
            }
        }

        return entries;
    }

    private IReadOnlyList<PersistenceEntry> ReadScheduledTasks(string target, CancellationToken cancellationToken)
    {
        var entries = new List<PersistenceEntry>();

        // One bulk query tells us whether any task mentions the file at all. Only when
        // it does do we pay for the per-task probing.
        var bulk = RunProcess("schtasks.exe", "/query /xml ONE", cancellationToken);
        if (bulk is null || !bulk.Contains(target, StringComparison.OrdinalIgnoreCase)) return entries;

        var names = ReadScheduledTaskNames(cancellationToken);
        var probed = 0;

        foreach (var name in names)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (probed++ >= MaxTasksToProbe) break;

            var xml = RunProcess("schtasks.exe", $"/query /tn \"{name}\" /xml ONE", cancellationToken);
            if (xml is null || !xml.Contains(target, StringComparison.OrdinalIgnoreCase)) continue;

            entries.Add(new PersistenceEntry
            {
                Kind = PersistenceEntryKind.ScheduledTask,
                Name = name,
                TargetPath = target,
                Location = name,
                RestoreData = new PersistenceRestoreData
                {
                    ScheduledTaskPath = name,
                    ScheduledTaskXml = xml,
                    CanRestore = true
                }
            });
        }

        return entries;
    }

    private IReadOnlyList<PersistenceEntry> ReadServices(string target)
    {
        var entries = new List<PersistenceEntry>();

        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services is null) return entries;

        foreach (var name in services.GetSubKeyNames())
        {
            using var service = services.OpenSubKey(name);
            var imagePath = service?.GetValue("ImagePath") as string;
            if (string.IsNullOrWhiteSpace(imagePath)) continue;
            if (!References(imagePath, target)) continue;

            entries.Add(new PersistenceEntry
            {
                Kind = PersistenceEntryKind.Service,
                Name = name,
                TargetPath = target,
                Location = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + name,
                RestoreData = new PersistenceRestoreData
                {
                    ServiceName = name,
                    ServiceDisplayName = service?.GetValue("DisplayName") as string ?? name,
                    ServiceImagePath = imagePath,
                    CanRestore = true
                }
            });
        }

        return entries;
    }

    private PersistenceRemovalResult RemoveRegistryValue(PersistenceEntry entry)
    {
        var data = entry.RestoreData;
        if (string.IsNullOrWhiteSpace(data.RegistryKeyPath) || string.IsNullOrWhiteSpace(data.RegistryValueName))
        {
            return new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.NotReversible,
                Message = "That registry value was not captured well enough to be removed safely."
            };
        }

        // The path is always inside the user's own hive. Nothing else is ever opened.
        var relative = data.RegistryKeyPath.StartsWith(@"HKEY_CURRENT_USER\", StringComparison.OrdinalIgnoreCase)
            ? data.RegistryKeyPath[@"HKEY_CURRENT_USER\".Length..]
            : data.RegistryKeyPath;

        using var key = Registry.CurrentUser.OpenSubKey(relative, writable: true);
        if (key is null)
        {
            return new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.NotFound,
                Message = "The registry key no longer exists."
            };
        }

        if (key.GetValue(data.RegistryValueName) is null)
        {
            return new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.NotFound,
                Message = "The registry value no longer exists."
            };
        }

        key.DeleteValue(data.RegistryValueName, throwOnMissingValue: false);

        return new PersistenceRemovalResult
        {
            Removed = true,
            Outcome = PersistenceRemovalOutcome.Removed,
            Message = "The autostart entry was removed."
        };
    }

    private PersistenceRemovalResult RemoveStartupItem(PersistenceEntry entry)
    {
        var path = entry.RestoreData.StartupItemPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.NotFound,
                Message = "The Startup item no longer exists."
            };
        }

        File.Delete(path);

        return new PersistenceRemovalResult
        {
            Removed = true,
            Outcome = PersistenceRemovalOutcome.Removed,
            Message = "The Startup item was removed."
        };
    }

    private PersistenceRemovalResult RemoveScheduledTask(PersistenceEntry entry)
    {
        var name = entry.RestoreData.ScheduledTaskPath;
        if (string.IsNullOrWhiteSpace(name))
        {
            return new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.NotReversible,
                Message = "That scheduled task was not captured well enough to be removed safely."
            };
        }

        var exit = RunProcessExit("schtasks.exe", $"/delete /tn \"{name}\" /f");
        if (exit == 0)
        {
            return new PersistenceRemovalResult
            {
                Removed = true,
                Outcome = PersistenceRemovalOutcome.Removed,
                Message = "The scheduled task was removed."
            };
        }

        return new PersistenceRemovalResult
        {
            Removed = false,
            Outcome = PersistenceRemovalOutcome.Failed,
            Message = "The scheduled task could not be removed. It may belong to another user or need elevation."
        };
    }

    private PersistenceRemovalResult RemoveService(PersistenceEntry entry)
    {
        var name = entry.RestoreData.ServiceName;
        if (string.IsNullOrWhiteSpace(name))
        {
            return new PersistenceRemovalResult
            {
                Removed = false,
                Outcome = PersistenceRemovalOutcome.NotReversible,
                Message = "That service was not captured well enough to be removed safely."
            };
        }

        // Removing a service requires administrative rights. Lumen never elevates, so
        // this normally fails — and says so plainly rather than pretending it worked.
        var exit = RunProcessExit("sc.exe", $"delete \"{name}\"");
        if (exit == 0)
        {
            return new PersistenceRemovalResult
            {
                Removed = true,
                Outcome = PersistenceRemovalOutcome.Removed,
                Message = "The service was removed."
            };
        }

        return new PersistenceRemovalResult
        {
            Removed = false,
            Outcome = PersistenceRemovalOutcome.AccessDenied,
            Message = "The service could not be removed. Removing a service needs administrator rights, and Lumen does not elevate."
        };
    }

    private static IEnumerable<string> StartupFolders()
    {
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrWhiteSpace(startup)) yield return startup;

        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (!string.IsNullOrWhiteSpace(common)) yield return common;
    }

    private static string? ReadShortcutTarget(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (!Lumen.Core.Detection.Shortcuts.ShortcutParser.TryParse(bytes, out var info, out _)) return null;
            return info?.EffectiveTarget;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool References(string haystack, string target)
    {
        if (string.IsNullOrWhiteSpace(haystack)) return false;
        if (haystack.Contains(target, StringComparison.OrdinalIgnoreCase)) return true;

        // Registry values often quote the path or add arguments around it.
        var trimmed = haystack.Trim('"');
        var space = trimmed.IndexOf(' ');
        if (space > 0) trimmed = trimmed[..space].Trim('"');

        try
        {
            return string.Equals(
                PathRules.NormalizeFile(trimmed),
                target,
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static IReadOnlyList<string> ReadScheduledTaskNames(CancellationToken cancellationToken)
    {
        var names = new List<string>();
        var output = RunProcess("schtasks.exe", "/query /fo CSV /nh", cancellationToken);
        if (output is null) return names;

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;

            var name = trimmed;
            if (trimmed.StartsWith('"'))
            {
                var end = trimmed.IndexOf('"', 1);
                if (end < 0) continue;
                name = trimmed[1..end];
            }
            else
            {
                var comma = trimmed.IndexOf(',');
                if (comma > 0) name = trimmed[..comma];
            }

            if (name.Length > 0) names.Add(name);
        }

        return names;
    }

    private static string? RunProcess(string fileName, string arguments, CancellationToken cancellationToken)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.Unicode
            };

            using var process = Process.Start(info);
            if (process is null) return null;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(8000);

            return output;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
    }

    private static int RunProcessExit(string fileName, string arguments)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(info);
            if (process is null) return -1;

            process.WaitForExit(10000);
            return process.ExitCode;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return -1;
        }
    }
}
