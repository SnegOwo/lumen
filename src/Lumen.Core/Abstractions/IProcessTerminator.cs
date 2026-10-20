using Lumen.Core.Models;

namespace Lumen.Core.Abstractions;

/// <summary>
/// Narrow view on the running processes that use a detected file. Implementations talk to
/// the operating system; the remediation engine only reads facts through this interface and
/// never terminates anything on its own initiative. Termination always happens because the
/// user confirmed a specific plan step.
/// </summary>
public interface IProcessTerminator
{
    /// <summary>
    /// Lists the running processes whose executable path or loaded module path matches the
    /// given file. Returns an empty list when nothing matches. Implementations must not
    /// terminate anything while enumerating.
    /// </summary>
    Task<IReadOnlyList<ProcessMatch>> FindByFilePathAsync(string filePath, CancellationToken cancellationToken);

    /// <summary>
    /// Reads what is known about a single process, or returns null when the process is no
    /// longer running. The engine uses this to re-check that a process is still safe to
    /// stop at the moment the user confirms the step.
    /// </summary>
    Task<ProcessInfo?> GetAsync(int pid, CancellationToken cancellationToken);

    /// <summary>
    /// Terminates a single process. Implementations must not escalate privileges, must not
    /// terminate anything else, and must report honestly whether the process actually
    /// stopped.
    /// </summary>
    Task<ProcessTerminationResult> TerminateAsync(int pid, CancellationToken cancellationToken);
}
