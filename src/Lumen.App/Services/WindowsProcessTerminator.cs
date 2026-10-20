using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.Services;

/// <summary>
/// The real operating-system implementation of <see cref="IProcessTerminator"/>.
///
/// It reads facts about running processes and stops a process ONLY when the
/// remediation engine hands it a step the user has confirmed. It never escalates
/// privileges: a process owned by another user or by the system simply cannot be
/// inspected or stopped, and that is reported honestly rather than worked around.
/// </summary>
public sealed class WindowsProcessTerminator : IProcessTerminator
{
    public Task<IReadOnlyList<ProcessMatch>> FindByFilePathAsync(string filePath, CancellationToken cancellationToken)
    {
        var matches = new List<ProcessMatch>();
        if (string.IsNullOrWhiteSpace(filePath)) return Task.FromResult<IReadOnlyList<ProcessMatch>>(matches);

        string target;
        try
        {
            target = PathRules.NormalizeFile(filePath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Task.FromResult<IReadOnlyList<ProcessMatch>>(matches);
        }

        foreach (var process in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();

            ProcessInfo? info;
            try
            {
                info = Describe(process);
            }
            catch
            {
                // A process can exit, or be protected, between enumeration and inspection.
                continue;
            }
            finally
            {
                process.Dispose();
            }

            if (info is null) continue;

            if (info.ExecutablePath is not null &&
                PathsMatch(info.ExecutablePath, target))
            {
                matches.Add(new ProcessMatch
                {
                    Process = info,
                    MatchKind = ProcessMatchKind.ExecutablePath,
                    MatchedPath = info.ExecutablePath
                });
                continue;
            }

            // Loaded modules are only readable for processes the user owns, so this is
            // best effort and slow. It is the difference between "the file is running"
            // and "the file is loaded into something that is running".
            foreach (var module in SafeModules(process))
            {
                if (!PathsMatch(module, target)) continue;
                matches.Add(new ProcessMatch
                {
                    Process = info,
                    MatchKind = ProcessMatchKind.LoadedModule,
                    MatchedPath = module
                });
                break;
            }
        }

        return Task.FromResult<IReadOnlyList<ProcessMatch>>(matches);
    }

    public Task<ProcessInfo?> GetAsync(int pid, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var process = Process.GetProcessById(pid);
            return Task.FromResult(Describe(process));
        }
        catch (ArgumentException)
        {
            // The process is no longer running.
            return Task.FromResult<ProcessInfo?>(null);
        }
        catch (InvalidOperationException)
        {
            return Task.FromResult<ProcessInfo?>(null);
        }
    }

    public Task<ProcessTerminationResult> TerminateAsync(int pid, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var process = Process.GetProcessById(pid);
            var info = Describe(process);

            // A last, independent check at the moment of execution. The engine also
            // refuses protected processes, but the check is repeated here so that a
            // hand-built step can never reach a protected process.
            if (info is not null && Core.Remediation.ProtectedProcesses.IsProtected(info))
            {
                return Task.FromResult(new ProcessTerminationResult
                {
                    Terminated = false,
                    Outcome = ProcessTerminationOutcome.AccessDenied,
                    Message = "That process is protected and is never stopped by Lumen."
                });
            }

            process.Kill(entireProcessTree: false);
            process.WaitForExit(5000);

            return Task.FromResult(new ProcessTerminationResult
            {
                Terminated = true,
                Outcome = ProcessTerminationOutcome.Terminated,
                Message = "The process was stopped."
            });
        }
        catch (ArgumentException)
        {
            return Task.FromResult(new ProcessTerminationResult
            {
                Terminated = false,
                Outcome = ProcessTerminationOutcome.NotFound,
                Message = "The process had already stopped."
            });
        }
        catch (UnauthorizedAccessException)
        {
            return Task.FromResult(new ProcessTerminationResult
            {
                Terminated = false,
                Outcome = ProcessTerminationOutcome.AccessDenied,
                Message = "Windows denied access. Lumen does not elevate its privileges."
            });
        }
        catch (Win32Exception ex)
        {
            return Task.FromResult(new ProcessTerminationResult
            {
                Terminated = false,
                Outcome = ProcessTerminationOutcome.Failed,
                Message = "The process could not be stopped: " + ex.Message
            });
        }
    }

    private static ProcessInfo? Describe(Process process)
    {
        string? path = null;
        try
        {
            path = process.MainModule?.FileName;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            // Access denied for a process owned by another user. The name is still known.
        }

        var name = process.ProcessName;
        if (string.IsNullOrWhiteSpace(name)) return null;

        var isSystem = path is not null && Core.Remediation.ProtectedProcesses.IsProtectedLocation(path);

        return new ProcessInfo
        {
            Pid = process.Id,
            Name = name + ".exe",
            ExecutablePath = path,
            IsSystemProcess = isSystem,
            IsSigned = path is not null && Authenticode.IsSigned(path)
        };
    }

    private static IEnumerable<string> SafeModules(Process process)
    {
        ProcessModuleCollection modules;
        try
        {
            modules = process.Modules;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            yield break;
        }

        foreach (ProcessModule module in modules)
        {
            string? fileName;
            try
            {
                fileName = module.FileName;
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(fileName)) yield return fileName;
        }
    }

    private static bool PathsMatch(string left, string right)
    {
        try
        {
            return string.Equals(
                PathRules.NormalizeFile(left),
                PathRules.NormalizeFile(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }
}

/// <summary>
/// Checks whether a file carries a valid Authenticode signature using the Windows
/// trust provider. This is a read-only check; nothing is installed or modified.
/// </summary>
internal static class Authenticode
{
    private const uint WinTrustActionGenericVerifyV2 = 0x00020000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr File;
        public IntPtr KnownSubject;
        public IntPtr KnownIssuer;
        public IntPtr Publisher;
        public IntPtr SerialNumber;
        public IntPtr SpcLinkChain;
        public IntPtr Signature;
        public IntPtr FriendlyName;
        public IntPtr DisplayName;
        public IntPtr SpcSpOpusInfo;
        public IntPtr MoreInfo;
        public IntPtr Url;
        public IntPtr Hashes;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UIChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UIContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr window, [MarshalAs(UnmanagedType.LPStr)] Guid actionId, IntPtr data);

    private static readonly Guid WinTrustActionGenericVerifyV2Id = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static bool IsSigned(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;

            var fileInfo = new WinTrustFileInfo
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = Marshal.StringToCoTaskMemUni(path)
            };

            var data = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UIChoice = 2, // WTD_UI_NONE
                RevocationChecks = 0,
                UnionChoice = 1, // WTD_CHOICE_FILE
                FileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>()),
                StateAction = 1, // WTD_STATEACTION_VERIFY
                UIContext = 0
            };

            try
            {
                Marshal.StructureToPtr(fileInfo, data.FileInfo, false);
                var status = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2Id, data.FileInfo);
                return status == 0;
            }
            finally
            {
                Marshal.DestroyStructure<WinTrustFileInfo>(data.FileInfo);
                Marshal.FreeHGlobal(data.FileInfo);
                Marshal.FreeCoTaskMem(fileInfo.FilePath);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or MarshalDirectiveException or ArgumentException or InvalidOperationException)
        {
            // An unreadable or unverifiable file is simply reported as unsigned.
            return false;
        }
    }
}
