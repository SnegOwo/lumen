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

/// <summary>
/// The kind of signal that produced a finding. The categories describe HOW Lumen
/// knows something is worth a second look, never whether the file is definitely
/// malicious. Only <see cref="TestSignature"/> and <see cref="Signature"/> point
/// at an exact byte pattern; everything else is a heuristic of some kind.
/// </summary>
public enum FindingCategory
{
    /// <summary>
    /// A harmless, industry-standard test artifact such as EICAR. It verifies the
    /// scanner plumbing and says nothing about real malware.
    /// </summary>
    TestSignature,

    /// <summary>An exact byte or pattern match against a known signature.</summary>
    Signature,

    /// <summary>A combination of suspicious tokens or characteristics in a file.</summary>
    Heuristic,

    /// <summary>Behavioural indicators: packing, obfuscation, suspicious API imports.</summary>
    Behavior,

    /// <summary>A local hash reputation match. Lumen never performs a network lookup.</summary>
    Reputation
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
    Dark,

    /// <summary>
    /// The high-contrast palette. It is normally selected automatically when the
    /// operating system requests high contrast, but the user may also pick it.
    /// </summary>
    HighContrast
}

/// <summary>
/// The language the user interface is shown in. Lumen ships English and French.
/// </summary>
public enum AppLanguage
{
    English,
    Francais
}
