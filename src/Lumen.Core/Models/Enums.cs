namespace Lumen.Core.Models;

public enum ScanScopeKind
{
    Quick,
    FullUserProfile,
    Folder,
    File
}

public enum ScanPhase
{
    Enumerating,
    Inspecting,
    Finished
}

public enum FindingCategory
{
    TestSignature,
    Heuristic
}

public enum Confidence
{
    Definitive,
    High,
    Medium,
    Low
}

public enum ScanErrorKind
{
    AccessDenied,
    NotFound,
    InUse,
    PathTooLong,
    InvalidPath,
    ReparsePoint,
    Offline,
    Io,
    Security,
    Other
}

public enum AppTheme
{
    System,
    Light,
    Dark
}
