using System.Diagnostics;
using System.IO;
using Lumen.App.Services;
using Lumen.Core.Abstractions;
using Lumen.Core.Detection;
using Lumen.Core.Models;
using Lumen.Core.Protection;
using Lumen.Core.Quarantine;
using Lumen.Core.Remediation;
using Lumen.Core.Scanning;

namespace Lumen.App.Tests;

/// <summary>
/// The end-to-end story the product is actually for:
/// a file appears, Lumen notices it, the file is running, and Lumen finds the program
/// that is running it and stops it.
///
/// These tests use the REAL operating system: a real executable, a real process, the
/// real watcher and the real process terminator. The only thing faked is the clock.
/// </summary>
public sealed class RealTimeEndToEndTests
{
    /// <summary>
    /// A copy of a harmless Windows executable, with a byte pattern that Lumen's own
    /// packer rule recognises. The file is still a perfectly runnable program: Windows
    /// ignores the bytes after the end of the program, so the copy starts normally.
    /// </summary>
    private static string CreateDetectableExecutable(string folder)
    {
        var source = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "ping.exe");

        var target = Path.Combine(folder, "lumen-sample-executable.exe");
        File.Copy(source, target, overwrite: true);

        // The packer marker. It is what the detection rule looks for, and appending it
        // does not stop the program from running.
        File.AppendAllText(target, "UPX!");

        return target;
    }

    [Fact]
    public async Task A_dropped_file_is_detected_by_the_real_time_watcher()
    {
        using var temp = new TempDirectory();
        var watchFolder = temp.CreateDirectory("watched");

        var registry = DetectorRegistry.CreateDefault();
        using var monitor = new RealtimeMonitor(
            registry,
            [watchFolder],
            [],
            1024 * 1024,
            SystemClock.Instance,
            NullLog.Instance,
            settleDelay: TimeSpan.Zero,
            detectionCooldown: TimeSpan.FromMinutes(2));

        var detected = new TaskCompletionSource<RealtimeDetectionEvent>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        monitor.Detection += (_, e) => detected.TrySetResult(e);

        monitor.Start();
        try
        {
            // The file appears AFTER the watcher is running, so the watcher has to
            // notice it by itself.
            var path = Path.Combine(watchFolder, "dropped.ps1");
            await File.WriteAllTextAsync(path, "Invoke-Expression (New-Object Net.WebClient).DownloadString('x')");

            var detection = await detected.Task.WaitAsync(TimeSpan.FromSeconds(20));

            Assert.NotEmpty(detection.Findings);
            Assert.Equal(path, detection.FilePath);
        }
        finally
        {
            monitor.Stop();
        }
    }

    [Fact]
    public async Task A_running_sample_is_found_and_stopped_by_the_real_terminator()
    {
        using var temp = new TempDirectory();

        // 1. Lumen is watching the folder BEFORE the file appears, so it has to notice
        //    the file by itself.
        var registry = DetectorRegistry.CreateDefault();
        using var monitor = new RealtimeMonitor(
            registry,
            [temp.Root],
            [],
            1024 * 1024,
            SystemClock.Instance,
            NullLog.Instance,
            settleDelay: TimeSpan.Zero,
            detectionCooldown: TimeSpan.FromMinutes(2));

        var detected = new TaskCompletionSource<RealtimeDetectionEvent>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        monitor.Detection += (_, e) => detected.TrySetResult(e);
        monitor.Start();

        Process? running = null;
        try
        {
            // The sample appears while the watcher is running.
            var executable = CreateDetectableExecutable(temp.Root);

            var detection = await detected.Task.WaitAsync(TimeSpan.FromSeconds(20));
            Assert.NotEmpty(detection.Findings);

            // 2. The user runs the file.
            running = Process.Start(new ProcessStartInfo
            {
                FileName = executable,
                Arguments = "-t 127.0.0.1",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            });
            Assert.NotNull(running);

            // Give the process a moment to actually start.
            await Task.Delay(400);

            // 3. Lumen finds the program that is running the flagged file.
            var terminator = new WindowsProcessTerminator();
            var matches = await terminator.FindByFilePathAsync(executable, CancellationToken.None);

            Assert.NotEmpty(matches);
            Assert.Contains(matches, match => match.Process.Pid == running!.Id);

            // 4. And stops it, through the same engine the application uses.
            var service = new RealtimeKillService(
                terminator,
                new NullAuditJournal(),
                SystemClock.Instance,
                NullLog.Instance,
                autoKillEnabled: true,
                remediationEnabled: true);

            var result = await service.KillAsync(
                new RealtimeKillRequest
                {
                    FilePath = executable,
                    Findings = detection.Findings,
                    DetectedUtc = DateTimeOffset.UtcNow
                },
                approvedProcessIds: null,
                cancellationToken: CancellationToken.None);

            Assert.True(result.StoppedAnything, "The running program should have been stopped.");
            Assert.Equal(1, result.StoppedCount);

            // 5. The program really is gone.
            await Task.Delay(300);
            Assert.True(running.HasExited, "The process should have exited.");
        }
        finally
        {
            monitor.Stop();
            if (running is not null)
            {
                try { if (!running.HasExited) running.Kill(entireProcessTree: true); } catch { }
                running.Dispose();
            }
        }
    }

    [Fact]
    public async Task A_protected_process_is_never_stopped()
    {
        // The engine must refuse a system process even when it is asked directly.
        var terminator = new WindowsProcessTerminator();
        var service = new RealtimeKillService(
            terminator,
            new NullAuditJournal(),
            SystemClock.Instance,
            NullLog.Instance,
            autoKillEnabled: true,
            remediationEnabled: true);

        var result = await service.KillAsync(
            new RealtimeKillRequest
            {
                // A system file. Nothing runs from here that Lumen would touch.
                FilePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "cmd.exe"),
                Findings =
                [
                    new Finding
                    {
                        RuleId = "test.protected",
                        Title = "test",
                        Category = FindingCategory.Behavior,
                        Confidence = Confidence.High,
                        Summary = "test",
                        Detail = "test",
                        Advice = "test"
                    }
                ],
                DetectedUtc = DateTimeOffset.UtcNow
            },
            approvedProcessIds: null,
            cancellationToken: CancellationToken.None);

        // Either nothing matched, or everything that matched was refused. Never stopped.
        Assert.Equal(0, result.StoppedCount);
    }
}
