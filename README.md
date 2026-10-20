# Lumen

**Transparent local file inspection for Windows.**

Lumen is a user-mode antivirus companion: it inspects files on your machine, explains *why* it
flagged something, and lets you move a match into an encrypted quarantine vault that you can
restore or delete later. It is deliberately small, documented and honest — it never claims a clean
result proves a file is safe.

| | |
|---|---|
| **Stack** | C# 14 / .NET 10, WPF (Windows Forms is used only for the notification-area icon) |
| **Projects** | `Lumen.Core` (net10.0, platform-neutral) · `Lumen.App` (net10.0-windows) · `Lumen.Core.Tests` (xunit) |
| **Elevated?** | No. `asInvoker`, per-user, no driver, no service |
| **Network?** | Never. No uploads, no hash lookups, no telemetry |
| **Data location** | `%LOCALAPPDATA%\Lumen` — nothing is written to the install folder, ProgramData or the registry |

---

## What Lumen does

### On-demand scanning

Four scopes, all read-only:

| Scope | What it covers |
|---|---|
| **Quick** | Desktop, Documents, Downloads |
| **Full** | The whole user profile, minus caches (`AppData`, `.git`, `.nuget`, `node_modules`, …) |
| **Folder** | A folder you pick |
| **File** | A single file |

Scanning never writes, moves or deletes anything. Remediation is always a separate, explicitly
confirmed decision.

### Real-time protection (on-access)

A `FileSystemWatcher` watches the quick-scan folders (plus any folders you add) and re-inspects
new and changed files with the same detector registry the on-demand scan uses.

Be clear about what this is: **Lumen is DETECT-ON-WRITE, not block-on-write.** It is a user-mode
watcher, not a kernel filter driver. A file can be written and executed before the inspection
finishes, and Lumen does not cover system folders. Real-time protection only runs while the app
is running.

Findings are reported, never acted on silently. With auto-quarantine off (the default) Lumen only
tells you. With it on, a match goes into the same confirmed vault service a manual quarantine
uses — never a silent delete.

### Detection

Every rule is documented in `DetectionCatalog.Rules` and rendered on the Settings page, so
detection is never a black box. Rules are grouped by what they actually are:

| Category | Meaning |
|---|---|
| `TestSignature` | A harmless industry-standard test artifact (EICAR). Verifies scanner plumbing only. |
| `Signature` | An exact byte or pattern match. |
| `Heuristic` | A combination of suspicious tokens or characteristics. |
| `Behavior` | Packing, obfuscation, suspicious API imports. |
| `Reputation` | A local hash list match. Lumen never performs a network lookup. |

**A clean result is not proof that a file is safe.** Lumen's rules are small and transparent on
purpose. Microsoft Defender remains the authoritative scanner; Lumen tells you where to look.

### Quarantine vault

Quarantine is a copy-then-verify-then-delete operation:

1. The file is encrypted into an AES-256-CBC vault file (`LQ01` container: magic ‖ IV ‖ ciphertext).
2. The plaintext SHA-256 and an HMAC-SHA256 over the whole vault file are computed.
3. The manifest entry is written and saved.
4. Only then is the original removed.

Keys are protected with DPAPI (`CurrentUser`) and bound to a single vault item through per-item
entropy, so a key blob cannot be moved between items. The original file is only ever deleted
after the encrypted copy provably matches the bytes that were hashed — a file that changes
mid-quarantine is refused, not deleted.

Restore decrypts, verifies the SHA-256, and writes the file back. A corrupt vault file is
detected and nothing is restored.

### Remediation engine (opt-in)

Off by default (`RemediationEnabled`). When enabled, Lumen can plan and then execute a set of
confirmed remediation steps against a detected file:

- **Terminate the process** holding or running the file (protected and system processes are
  never terminated)
- **Permanently remove the file** (after the hash is verified)
- **Clean persistence** — Run/RunOnce registry values, Startup-folder items, scheduled tasks,
  services that point at the file
- **Audit journal** — an append-only record of everything planned and executed

Every action is **plan → review → confirm → execute**. Nothing runs without the confirmation
step, and the engine fails closed: on any error it stops, keeps the vault copy, and reports
exactly which steps ran.

---

## Architecture

```
src/Lumen.Core/          net10.0 — no WPF, no Windows-only APIs except behind interfaces
  Abstractions/          IScanDetector, ILog, IClock, ISecretProtector
  Detection/             Detectors, the signature engine, the rule catalogue
  Scanning/              ScanEngine, ScanPlanner, ProbeReader, FileProbe
  Protection/            RealtimeMonitor
  Quarantine/            QuarantineService, VaultCrypto
  Remediation/           The remediation engine
  Storage/               Atomic JSON storage, settings, history
  Models/                Records and enums
  Util/                  PathRules, HashUtil, DisplayText, formatters

src/Lumen.App/           net10.0-windows — the WPF shell
  Services/AppServices   Composition root
  ViewModels/            MVVM, one per page
  Views/                 One UserControl per page
  Themes/                Tokens, palettes, control styles, icons
  Controls/              Banner, EmptyState, LiveRegion
  Dialogs/               ConfirmDialog
  Infrastructure/        ObservableObject, RelayCommand, converters

tests/Lumen.Core.Tests/  xunit — 67 tests and counting
```

### Principles

- **Read-only by default.** Nothing is written, moved or deleted without an explicit, confirmed
  user action.
- **Detectors are pure.** An `IScanDetector` receives a `FileProbe` and performs zero I/O, so the
  whole detection layer is testable with synthetic in-memory data.
- **Paths go through `PathRules`.** Every path decision — containment, exclusions, system-critical
  locations — is made in one place.
- **Untrusted text goes through `DisplayText`.** File names, paths and error messages are
  sanitised so they cannot spoof the UI with control or bidirectional characters.
- **Contents are never logged.** Hashes, sizes, paths and rule ids are fine. File contents are not.
- **Fail closed.** A corrupt vault, a malformed rule file or a failed write preserves data and
  reports the problem rather than working around it.

---

## Building and testing

The .NET 10 SDK is required (`global.json` pins `10.0.100` with `rollForward: latestFeature`).

```powershell
dotnet build Lumen.slnx
dotnet test tests/Lumen.Core.Tests/Lumen.Core.Tests.csproj
```

To build in isolation (useful when several agents work in the same tree):

```powershell
dotnet restore Lumen.slnx --artifacts-path C:\temp\lumen-art
dotnet build  Lumen.slnx --artifacts-path C:\temp\lumen-art --no-restore
dotnet test   tests/Lumen.Core.Tests/Lumen.Core.Tests.csproj --artifacts-path C:\temp\lumen-art --no-restore
```

Coverage:

```powershell
dotnet test tests/Lumen.Core.Tests/Lumen.Core.Tests.csproj --collect:"XPlat Code Coverage"
```

---

## On-disk formats

```
%LOCALAPPDATA%\Lumen\
├── settings.json                     user settings (see AppSettings)
├── history.json                      the last 200 scans, newest first
├── quarantine\
│   ├── manifest.json                 the vault index
│   └── <32-hex-id>.qbin              one encrypted file per quarantined item
└── logs\
    ├── lumen.log
    ├── lumen.log.1 … .3              rotated at 2 MiB
    └── remediation.jsonl              the remediation audit journal
```

A file that cannot be parsed is never silently discarded: it is preserved beside the original as
`<name>.corrupt-<timestamp>` and the user is told.

---

## Safety notes

Lumen is an inspection tool, not a security boundary.

- It runs as a normal user with no elevation. It does not bypass Windows permissions, and
  access-denied results are reported rather than worked around.
- It installs no driver, service, scheduled task or shell extension.
- It does not change Microsoft Defender settings; it only reads Defender's status.
- It performs no network access at all.
- Its detection rules are small and documented by design. Use it alongside Microsoft Defender,
  not instead of it.

## Testing in a virtual machine

Lumen's own test suite never touches real user files, real processes, the real registry or the
real application-data folder. To exercise the scanner, the quarantine vault and the remediation
engine against real behaviour, run Lumen inside a disposable virtual machine.
