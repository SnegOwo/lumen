namespace Lumen.Core.Abstractions;

/// <summary>
/// Minimal local diagnostic log. Implementations must never throw and must never be given
/// file contents. Callers pass paths and messages only.
/// </summary>
public interface ILog
{
    void Info(string category, string message);
    void Warn(string category, string message, Exception? exception = null);
    void Error(string category, string message, Exception? exception = null);
}

public sealed class NullLog : ILog
{
    public static NullLog Instance { get; } = new();

    public void Info(string category, string message) { }
    public void Warn(string category, string message, Exception? exception = null) { }
    public void Error(string category, string message, Exception? exception = null) { }
}
