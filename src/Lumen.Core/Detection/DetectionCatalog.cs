using Lumen.Core.Models;

namespace Lumen.Core.Detection;

/// <summary>
/// A user-facing description of every rule that Lumen can report. The Settings page renders
/// this list so detection behavior is not a black box.
/// </summary>
/// <remarks>
/// Only the test signature and the signature rules point at an exact pattern. Everything
/// else is a heuristic of some kind, and the wording here says so plainly. A rule that
/// fires is a reason to look at a file, never a proof that the file is malware, and a file
/// that produces no finding is not thereby known to be safe.
/// </remarks>
public static class DetectionCatalog
{
    /// <summary>Every rule Lumen can report, with the explanation shown to the user.</summary>
    public static IReadOnlyList<DetectionRuleSummary> Rules { get; } =
    [
        // Test artifacts.
        new(
            "test.eicar",
            "EICAR test signature",
            "Finds the harmless, industry-standard EICAR test file. It verifies scanner plumbing only; it is not a malware signature.",
            FindingCategory.TestSignature,
            Confidence.Definitive),
        new(
            "test.eicar-hash",
            "EICAR test file hash",
            "The SHA-256 of the file is the EICAR test file. It is a harmless industry-standard test artifact, not malware.",
            FindingCategory.TestSignature,
            Confidence.Definitive),

        // Local reputation.
        new(
            "reputation.known-bad-hash",
            "Hash on the local list",
            "The SHA-256 of the file is on the list stored on this machine. Lumen compares only against that local list and never looks a file up online.",
            FindingCategory.Reputation,
            Confidence.High),

        // Data driven signature rules.
        new(
            "sig.pe-header-in-document-file",
            "Executable header inside a document file",
            "A Windows executable header was found in a file whose name suggests a document or a picture. Documents do not normally carry one.",
            FindingCategory.Signature,
            Confidence.High),
        new(
            "sig.upx-packer-marker",
            "UPX packer marker",
            "The file contains the marker left by the UPX packer. Packed files are compressed on purpose and are hard to review.",
            FindingCategory.Signature,
            Confidence.High),
        new(
            "sig.windows-script-host-reference",
            "Windows Script Host shell object",
            "The file mentions the Windows Script Host shell object, which is used to start other programs from a script.",
            FindingCategory.Signature,
            Confidence.Medium),
        new(
            "sig.amsi-bypass-marker",
            "Antimalware scan interface marker",
            "The file mentions the internal name of the antimalware scanning function. Ordinary software does not usually refer to it. This rule reports the name in every kind of file, so a script that mentions it is only reported once.",
            FindingCategory.Signature,
            Confidence.High),
        new(
            "sig.powershell-stealth-switch",
            "PowerShell concealment switches",
            "PowerShell is started together with a switch that hides the window or relaxes the execution policy.",
            FindingCategory.Signature,
            Confidence.Medium),
        new(
            "sig.base64-decode-call",
            "Base64 decoding call",
            "The file decodes base64 data at runtime, which is a common way to hide the real content of a script.",
            FindingCategory.Signature,
            Confidence.Medium),

        // Script heuristics that Lumen already had.
        new(
            "script.download-execute",
            "Script download + execution",
            "A script contains a remote-download primitive and an execution or decoding primitive.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "script.encoded-command",
            "PowerShell encoded command",
            "Text references PowerShell together with an encoded-command switch.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "script.hidden-bypass",
            "Hidden window + policy bypass",
            "Text combines a hidden window with an execution-policy bypass. Administrators use this too.",
            FindingCategory.Heuristic,
            Confidence.Low),
        new(
            "script.reflection-load",
            "In-memory assembly loading",
            "Text combines in-memory assembly loading with encoded or downloaded data.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "script.tamper-defender",
            "Defender tampering command",
            "A script references Microsoft Defender settings changes. Some administrative scripts do this legitimately.",
            FindingCategory.Heuristic,
            Confidence.Medium),

        // Extended script coverage.
        new(
            "script.lolbin-download",
            "Built-in downloader tool",
            "A script uses a tool that ships with Windows or the command line together with a download target. These tools are meant for ordinary administration, so the context decides what this means.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "script.lolbin-script-execution",
            "Built-in script host execution",
            "A script starts a host that ships with Windows and points it at a script or a downloaded file. Installers do this as well.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "script.powershell-obfuscation",
            "Obfuscated script content",
            "A script builds or decodes its content so that it cannot be read directly. Packaging tools and installers sometimes do this to harmless code.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "script.amsi-bypass",
            "Antimalware scan interface tampering",
            "A script mentions an internal name of the antimalware scanning interface. Ordinary scripts do not need to touch it. The name AmsiScanBuffer is reported by the signature rules instead, so one observation is only reported once.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "script.stealth-powershell",
            "PowerShell started with concealment switches",
            "A script starts PowerShell with a switch that hides the window or relaxes the execution policy. Scheduled tasks are often built this way.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "script.persistence",
            "Script sets up persistence",
            "A script creates a service, a scheduled task or a run key so that it starts again after a restart. Many installers do this too.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "script.av-tampering",
            "Script interferes with security software",
            "A script tries to stop or remove a security product. A person doing this by hand is unusual.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "script.credential-theft",
            "Script reaches for credentials",
            "A script mentions a known credential dumping tool or the credential store of Windows. Red team and research tooling uses the same names.",
            FindingCategory.Behavior,
            Confidence.High),
        new(
            "script.reverse-shell",
            "Script opens a remote shell",
            "A script creates a network connection that carries a command stream back to another machine, which is the shape of a reverse shell.",
            FindingCategory.Behavior,
            Confidence.High),

        // Windows executable analysis.
        new(
            "pe.packer-section-name",
            "Section named after a packer",
            "The executable contains a section named after a well-known packer. Packed executables are compressed on purpose and are hard to review.",
            FindingCategory.Behavior,
            Confidence.High),
        new(
            "pe.high-entropy-section",
            "Section with very high entropy",
            "A section of the executable has the even byte distribution that compressed or encrypted data has. Compressed installers look the same way.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "pe.suspicious-api-import",
            "Notable Windows API imports",
            "The executable imports Windows APIs commonly associated with process injection, hooking, keylogging or screen capture. Legitimate software imports the same APIs.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "pe.unsigned-executable",
            "Unsigned executable in a folder the user can write to",
            "The executable carries no digital signature and sits in a folder the user can freely write to, where any program running as that user can replace it. Being unsigned is normal on its own, so this is a low-confidence signal.",
            FindingCategory.Heuristic,
            Confidence.Low),
        new(
            "pe.invalid-digital-signature",
            "Digital signature information is not valid",
            "The executable points at a certificate table whose contents are not a well-formed signature. The file may be damaged, self-signed, or trying to look signed.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "pe.timestamp-anomaly",
            "Implausible compilation timestamp",
            "The executable claims to have been compiled far in the past or in the future. Build tools can produce a wrong value, and so can someone trying to mislead.",
            FindingCategory.Heuristic,
            Confidence.Low),

        // Office documents.
        new(
            "office.vba-macro-project",
            "Document carries a Visual Basic project",
            "The office document holds embedded Visual Basic code. The code was not run and was not decompiled, and many templates carry macros.",
            FindingCategory.Heuristic,
            Confidence.High),
        new(
            "office.macro-auto-execution",
            "Macro that runs when the document opens",
            "The document holds a macro named to run as soon as the document is opened and macros are enabled.",
            FindingCategory.Heuristic,
            Confidence.High),
        new(
            "office.macro-enabled-extension",
            "Document in a macro enabled format",
            "The file name marks this document as a format that can carry macros. Nothing runs until macros are enabled. A document whose Visual Basic project was already reported is not reported twice.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "office.external-template",
            "Document refers to an outside template",
            "The document links to a template or file that is not stored inside it, so opening it can pull in outside content.",
            FindingCategory.Heuristic,
            Confidence.Low),

        // PDF documents.
        new(
            "pdf.embedded-javascript",
            "PDF with embedded JavaScript",
            "The PDF carries a JavaScript action that runs inside the reader. Forms with scripts exist legitimately.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "pdf.launch-action",
            "PDF that can start another program",
            "The PDF contains an action that asks the reader to launch another program. A document that only holds information rarely needs one.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "pdf.auto-open-action",
            "PDF with an action on open",
            "The PDF asks the reader to perform an action as soon as it is opened. Many ordinary PDFs jump to the first page this way.",
            FindingCategory.Heuristic,
            Confidence.Low),
        new(
            "pdf.script-uri-action",
            "PDF with a link to a script scheme",
            "The document carries a link whose target uses a script scheme instead of an ordinary web address.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "pdf.embedded-executable",
            "PDF with an embedded executable",
            "The PDF carries a file inside it that can run code, so a program only has to be saved and started.",
            FindingCategory.Heuristic,
            Confidence.High),

        // Archives and containers.
        new(
            "archive.executable-inside",
            "Archive containing a program",
            "The archive holds at least one file that Windows can start. Installers and software updates routinely ship programs, so this is a weak reason to look. A file that carries the executable marker is reported whatever it is called.",
            FindingCategory.Heuristic,
            Confidence.High),
        new(
            "archive.nested-archive",
            "Archive inside an archive",
            "The container holds further archives. Nesting makes a payload harder to see, and backup tools also nest archives.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "archive.password-protected",
            "Password protected archive",
            "The archive marks its content as encrypted, so it cannot be reviewed without the password.",
            FindingCategory.Heuristic,
            Confidence.Low),
        new(
            "archive.suspicious-compression-ratio",
            "Archive that expands enormously",
            "The archive claims to expand into far more data than it stores, which is used to exhaust memory or disk when it is unpacked.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "archive.magic-in-document-extension",
            "Archive disguised as a document",
            "The file is an archive even though its name says it is a document. Renaming a file does not change what it is.",
            FindingCategory.Heuristic,
            Confidence.High),

        // Shortcuts.
        new(
            "shortcut.script-target",
            "Shortcut launches a script interpreter",
            "The shortcut starts a program whose job is to run scripts rather than doing work of its own. Shortcuts to the command prompt are also common.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "shortcut.temp-path-target",
            "Shortcut points into a temporary folder",
            "The shortcut launches a file from a folder meant to hold temporary downloads, which is an easy place for a payload to sit, or from a machine other than this one. A shortcut to a program the user installed under their own profile is not reported.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "shortcut.dangling-target",
            "Shortcut points at a missing file",
            "The shortcut launches a target that is not on this machine, either because it was uninstalled or because it was meant to be dropped in later.",
            FindingCategory.Heuristic,
            Confidence.Low),

        // Filename heuristics that Lumen already had.
        new(
            "name.double-extension",
            "Deceptive double extension",
            "A document-like extension is followed by an executable extension, for example report.pdf.exe.",
            FindingCategory.Heuristic,
            Confidence.Medium),
        new(
            "name.bidi-override",
            "Bidirectional filename override",
            "The file name contains bidirectional control characters that can disguise its real extension.",
            FindingCategory.Heuristic,
            Confidence.Medium),

        // Entropy and packing.
        new(
            "entropy.high-entropy-file",
            "File contents are almost perfectly even",
            "The bytes of the file are spread almost evenly, which usually means compressed or encrypted data. Media files and encrypted documents look the same way.",
            FindingCategory.Behavior,
            Confidence.Medium),
        new(
            "entropy.encrypted-tail",
            "Text file with a packed block at the end",
            "The file starts as ordinary text and ends with data that looks compressed or encrypted, which is a common way to hide a payload.",
            FindingCategory.Behavior,
            Confidence.Medium),

        // Aggregate.
        new(
            "risk.aggregate",
            "Combined risk score",
            "Adds up the weight of every rule that fired and lists each contribution, so the score is never shown without its reasons.",
            FindingCategory.Heuristic,
            Confidence.Medium)
    ];
}
