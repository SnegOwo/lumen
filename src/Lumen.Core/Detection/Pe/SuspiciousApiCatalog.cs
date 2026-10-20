namespace Lumen.Core.Detection.Pe;

/// <summary>
/// A group of imported functions that tend to appear together in programs that inject code
/// into other processes, hook the keyboard, take screenshots or hide from a debugger.
/// </summary>
/// <param name="Id">Stable identifier for the group.</param>
/// <param name="Title">Short readable title.</param>
/// <param name="Explanation">Plain-language description of why the group matters.</param>
/// <param name="Functions">The imported function names that belong to the group.</param>
public sealed record SuspiciousApiGroup(
    string Id,
    string Title,
    string Explanation,
    IReadOnlyList<string> Functions);

/// <summary>
/// The catalog of import combinations Lumen treats as worth a second look.
/// </summary>
/// <remarks>
/// Every function in this catalog is a documented Windows API that legitimate software
/// also uses. The catalog is a prompt to read the file more carefully, never a verdict.
/// </remarks>
public static class SuspiciousApiCatalog
{
    /// <summary>The grouped catalog of notable Windows API imports.</summary>
    public static IReadOnlyList<SuspiciousApiGroup> Groups { get; } =
    [
        new(
            "api.process-injection",
            "Process injection",
            "These APIs are used to allocate memory in another process, write code into it and run it there. They are also used by debuggers, profilers and legitimate update tools.",
            [
                "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
                "WriteProcessMemory", "NtWriteVirtualMemory", "CreateRemoteThread",
                "CreateRemoteThreadEx", "NtUnmapViewOfSection", "RtlCreateUserThread",
                "QueueUserAPC", "NtCreateThreadEx", "OpenProcess", "SetThreadContext"
            ]),
        new(
            "api.hooking",
            "Global hook installation",
            "Installing a system-wide hook is how keyboard loggers and some accessibility software work. It is also used by legitimate input and monitoring tools.",
            [
                "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
                "UnhookWindowsHookEx", "CallNextHookEx"
            ]),
        new(
            "api.anti-debug",
            "Debugger detection",
            "These APIs are used to notice that a program is being analysed. Legitimate programs rarely need them.",
            [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                "NtSetInformationThread", "QueryPerformanceCounter"
            ]),
        new(
            "api.keylogging",
            "Keyboard state capture",
            "Reading the keyboard state or the typed characters is how key loggers work. Password managers and remote support tools do read the keyboard, so context matters.",
            [
                "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "GetRawInputData",
                "RegisterRawInputDevices", "ToUnicodeEx", "GetKeyNameText"
            ]),
        new(
            "api.screenshot",
            "Screen capture",
            "Capturing the screen or a window is how screenshot stealers work. Screenshot tools, remote desktop clients and support software do the same thing.",
            [
                "BitBlt", "GetDC", "GetWindowDC", "PrintWindow", "CreateCompatibleBitmap",
                "GetDesktopWindow"
            ]),
        new(
            "api.process-hollowing",
            "Process hollowing helpers",
            "These APIs are used to start a suspended copy of another program and then replace its code. Security software uses them for its own scanning.",
            [
                "CreateProcessInternalW", "NtResumeThread",
                "ResumeThread", "GetThreadContext", "Wow64SetThreadContext", "ZwUnmapViewOfSection"
            ])
    ];

    /// <summary>
    /// Returns the group a function belongs to, or null when the function is not notable.
    /// </summary>
    public static SuspiciousApiGroup? Find(string? function)
    {
        if (string.IsNullOrWhiteSpace(function)) return null;

        var normalized = Normalize(function);
        foreach (var group in Groups)
        {
            foreach (var candidate in group.Functions)
            {
                if (string.Equals(Normalize(candidate), normalized, StringComparison.OrdinalIgnoreCase)) return group;
            }
        }

        return null;
    }

    /// <summary>
    /// Returns every group that the supplied imports touch, together with the functions that
    /// matched. The result is sorted so the same file always produces the same output.
    /// </summary>
    public static IReadOnlyList<(SuspiciousApiGroup Group, IReadOnlyList<string> Functions)> Match(
        IEnumerable<PeImportEntry> imports)
    {
        var hits = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var groups = new Dictionary<string, SuspiciousApiGroup>(StringComparer.OrdinalIgnoreCase);

        foreach (var import in imports)
        {
            var group = Find(import.Function);
            if (group is null) continue;

            groups[group.Id] = group;
            if (!hits.TryGetValue(group.Id, out var list))
            {
                list = [];
                hits[group.Id] = list;
            }

            if (!list.Contains(import.Function, StringComparer.OrdinalIgnoreCase)) list.Add(import.Function);
        }

        var result = new List<(SuspiciousApiGroup, IReadOnlyList<string>)>();
        foreach (var group in groups.Values.OrderBy(group => group.Id, StringComparer.Ordinal))
        {
            var functions = hits[group.Id].OrderBy(name => name, StringComparer.Ordinal).ToArray();
            result.Add((group, functions));
        }

        return result;
    }

    /// <summary>
    /// Strips the decoration Windows uses for ANSI and wide variants of the same API, for
    /// example "SetWindowsHookExW" becomes "SetWindowsHookEx".
    /// </summary>
    private static string Normalize(string function)
    {
        var trimmed = function.Trim();
        if (trimmed.Length > 1 && (trimmed[^1] == 'A' || trimmed[^1] == 'W')) trimmed = trimmed[..^1];
        return trimmed;
    }
}
