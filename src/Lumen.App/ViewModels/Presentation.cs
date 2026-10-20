using Lumen.Core.Models;
using Lumen.Core.Util;

namespace Lumen.App.ViewModels;

public static class Presentation
{
    public static string Category(FindingCategory category) =>
        category == FindingCategory.TestSignature ? "Test signature" : "Heuristic";

    public static string ConfidenceText(Confidence confidence) => confidence switch
    {
        Confidence.Definitive => "Definitive",
        Confidence.High => "High confidence",
        Confidence.Medium => "Medium confidence",
        _ => "Low confidence"
    };

    public static string Scope(ScanScopeKind scope) => scope switch
    {
        ScanScopeKind.Quick => "Quick scan",
        ScanScopeKind.FullUserProfile => "Full profile scan",
        ScanScopeKind.Folder => "Folder scan",
        _ => "File scan"
    };

    public static string ErrorKind(ScanErrorKind kind) => kind switch
    {
        ScanErrorKind.AccessDenied => "Access denied",
        ScanErrorKind.NotFound => "Not found",
        ScanErrorKind.InUse => "In use",
        ScanErrorKind.PathTooLong => "Path too long",
        ScanErrorKind.InvalidPath => "Invalid path",
        ScanErrorKind.ReparsePoint => "Link skipped",
        ScanErrorKind.Offline => "Cloud placeholder",
        ScanErrorKind.Io => "Read error",
        ScanErrorKind.Security => "Blocked by policy",
        _ => "Skipped"
    };

    public static string Count(long value, string singular, string? plural = null) =>
        value == 1 ? "1 " + singular : value.ToString("N0") + " " + (plural ?? singular + "s");

    public static string Sanitize(string? value, int max = 300) => DisplayText.Sanitize(value, max);

    public static string SanitizePath(string? value, int maxLength = 520) =>
        DisplayText.SanitizePath(value, maxLength);
}
