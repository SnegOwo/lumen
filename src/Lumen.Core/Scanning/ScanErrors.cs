using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.Core.Scanning;

public static class ScanErrors
{
    public static ScanError FromException(string path, Exception exception, IClock? clock = null)
    {
        var kind = exception switch
        {
            UnauthorizedAccessException => ScanErrorKind.AccessDenied,
            FileNotFoundException or DirectoryNotFoundException => ScanErrorKind.NotFound,
            PathTooLongException => ScanErrorKind.PathTooLong,
            System.Security.SecurityException => ScanErrorKind.Security,
            ArgumentException or NotSupportedException => ScanErrorKind.InvalidPath,
            IOException io when IsSharingViolation(io) => ScanErrorKind.InUse,
            IOException => ScanErrorKind.Io,
            _ => ScanErrorKind.Other
        };

        var message = kind switch
        {
            ScanErrorKind.AccessDenied => "Access denied. Lumen does not bypass Windows permissions.",
            ScanErrorKind.NotFound => "The file or folder no longer exists.",
            ScanErrorKind.InUse => "The file is in use by another program.",
            ScanErrorKind.PathTooLong => "The path is too long for this system.",
            ScanErrorKind.Security => "Windows security policy blocked access.",
            ScanErrorKind.InvalidPath => "The path is not valid.",
            ScanErrorKind.Io => "The file could not be read.",
            _ => "The item could not be inspected."
        };

        return new ScanError
        {
            Path = DisplayText.SanitizePath(path),
            Kind = kind,
            Message = message,
            OccurredUtc = clock?.UtcNow ?? DateTimeOffset.UtcNow,
            Technical = exception.GetType().Name
        };
    }

    public static ScanError Custom(string path, ScanErrorKind kind, string message, IClock? clock = null) =>
        new()
        {
            Path = DisplayText.SanitizePath(path),
            Kind = kind,
            Message = message,
            OccurredUtc = clock?.UtcNow ?? DateTimeOffset.UtcNow
        };

    private static bool IsSharingViolation(IOException exception)
    {
        var code = exception.HResult & 0xFFFF;
        return code is 32 or 33;
    }
}
