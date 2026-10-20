================================================================================
 LUMEN - a local file inspector, written by an AI
================================================================================

WHAT THIS IS
    Lumen scans files on this computer, explains why it flagged something, and can
    move a match into an encrypted quarantine vault you can restore or delete.

WHAT IT IS NOT
    It is not a replacement for Microsoft Defender. It has 51 documented rules and
    no signatures database. It never touches the network. It does not block files
    before they run - it inspects them after they are written. A clean result does
    not mean safe.

HOW TO RUN
    Start Lumen.cmd
        Normal mode. Settings, history, the vault and the logs live in
        %LOCALAPPDATA%\Lumen. Real-time protection watches Desktop, Documents
        and Downloads while the app is open.

    Start Lumen (isolated).cmd
        Everything Lumen writes goes into the "data" folder next to this script.
        Real-time protection is switched off. Delete that folder to remove every
        trace.

    Lumen.exe --demo
        Starts and immediately raises a detection alert on a harmless sample.

    Lumen.exe --shots <folder>
        Walks every page, saves a PNG of each one, then exits.

EVERYTHING YOU NEED IS HERE
    Lumen.exe is self-contained. It carries its own copy of the .NET runtime, so
    it does not need .NET installed, and it makes no network calls. The
    Signatures folder holds the data-driven detection rules; the app also carries
    a copy inside itself, so it still works if that folder is missing.

TRY THIS FIRST
    1. Open Settings > Tester and create the demonstration file. It is plain
       text that merely READS like a malicious script - it does nothing, it is
       not executable, and Lumen never runs anything it finds.
    2. Press F9. Lumen raises a detection alert with a cat in it.
    3. Settings > Scan. Run a quick scan. The demonstration file is flagged,
       and the app tells you WHICH rule fired and why.
    4. Select the finding and quarantine it. Then look in the Quarantine tab and
       restore it. The file comes back, timestamps and all.

THINGS THAT WILL MAKE YOU SMILE
    F9                  Raises a detection alert on a harmless sample.
    Up Up Down Down Left Right Left Right B A
                        CAT MODE. The accent turns orange and a very smug cat
                        appears. Press Esc to leave.
    Click the cat (in CAT MODE)
                        A completely fictional bug report. Error code 0xC0FFEE.
    Ctrl + Alt + C      A cat walks across the bottom of the window.

    The cat is drawn with WPF vector geometry. There is no image file anywhere.

THE SWITCHES
    Settings > Protection
        Real-time protection on/off, and the folders to watch and exclude.
    Settings > Remediation
        Off by default. When on, Lumen can plan a remediation for a detected
        file - stop the process that is using it, remove the file, clean up
        autostart entries that point at it. It ALWAYS shows you the plan and
        waits for you to choose what to do. Nothing happens without a
        confirmation, and every action is written to an audit journal.
    Settings > Language
        English or French. It switches immediately.

WHERE THE DATA IS
    %LOCALAPPDATA%\Lumen
        settings.json      your settings
        history.json       the last 200 scans
        quarantine\        the encrypted vault and its index
        logs\              the diagnostic log
        remediation.jsonl  the audit journal (when remediation is used)

    Nothing is written to the Program Files folder, to ProgramData, or to the
    registry. Lumen does not install a driver, a service or a scheduled task,
    and it does not change Microsoft Defender's settings.

IF SOMETHING GOES WRONG
    The log is in the logs folder. Lumen never logs file contents - only paths,
    sizes, hashes and rule names.
