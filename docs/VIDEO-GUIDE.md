# Recording "I tried an AI-made antivirus"

A shot list for the video. Everything here runs against a **disposable virtual machine**.
Nothing in this guide touches a real machine's files, and the app can be run in a mode
where it never watches a real folder.

---

## Before you record

### 1. Use a throwaway VM

Snapshot the VM before you start. Everything in this guide is safe, but a snapshot means
you can try something silly and roll back.

### 2. Run Lumen sandboxed

Lumen keeps everything — settings, history, the quarantine vault, the logs, the
remediation journal — in one folder. Point that folder somewhere disposable and set
`LUMEN_DISABLE_REALTIME=1` so the on-access watcher never looks at the VM's real
Desktop, Documents or Downloads.

```powershell
cd "<the project folder>"
$env:LUMEN_DATA_DIR   = "$PWD\.sandbox\data"
$env:LUMEN_DISABLE_REALTIME = "1"
```

Or just use the helper, which does it for you:

```powershell
.\scripts\run-sandbox.ps1 -Build
```

When you are done, `.\scripts\clean-sandbox.ps1` deletes the lot.

### 3. Get the material you need

Two harmless test files, both created by Lumen itself, in Settings:

| File | What it is | What Lumen says about it |
|---|---|---|
| `lumen-eicar-test-file.com` | The industry-standard EICAR test string | "EICAR antivirus test file — Definitive" |
| `lumen-demo-suspicious.ps1` | Plain text that reads like a download-and-execute script | "Script combines download and execution behavior" — Medium confidence |

**Use the demo sample on camera.** EICAR is the obvious choice, but Microsoft Defender
deletes it the moment it appears, and it reads as "it found a real virus" when it did
not. The demo sample is more honest: Lumen found a *pattern*, and the UI says so.

---

## Shot list

### Shot 1 — the cold open (0:00)

The dashboard, one second in. Point at the hero card and say something like:

> "This is an antivirus. Not one that exists — one that was written by an AI, in about
> an hour. Let's see how far it actually gets."

Do **not** oversell. The honest hook is that you're testing it, not that it works.

### Shot 2 — the empty scan (0:15)

Settings → *Tester* → create the demo sample in `Documents`. Then Scan → Quick scan.

The scan should find it. This is your first real moment: a live detection, with a
reason attached.

**Say the reason out loud.** "It didn't call it malware. It said *this script combines a
download and an execution command*." That distinction is the whole product.

### Shot 3 — the alert (0:45)

Settings → *Tester* → **Trigger the demonstration**. Or start Lumen with `--demo`.

The alert window takes over: pulsing red border, big headline, and the cat.

> "It has a cat."

Let the cat sit on screen for a beat. Do not explain the joke; the joke is the joke.

**Optional but good:** turn the sound on in Settings first. `SystemSounds.Exclamation`
plus a two-tone beep is enough to make the moment land on camera. It is off by default,
which is the right default for software someone might actually install.

### Shot 4 — the quarantine round trip (1:15)

Quarantine the file from the alert window. Then:

- **Quarantine** tab — show the item, the SHA-256, the vault path
- Show the file is **gone** from `Documents`
- **Restore** it — and show it comes back, timestamps and all

> "It copies the file into an encrypted vault first, verifies it, and only then deletes
> the original. If anything goes wrong, the original stays where it is."

That last sentence is the point of the whole design. Say it.

### Shot 5 — the rule catalogue (1:45)

Settings → the rules list. 51 rules.

> "Fifty-one rules, and it will tell you exactly which one fired and why."

Scroll to a PE rule. Show the category and the confidence.

### Shot 6 — the honest limitations (2:15)

This is the shot that makes the video worth watching. Say the true things:

- "It's not an antivirus. It has fifty-one heuristics. Microsoft Defender has a
  hundred million signatures and a cloud. This thing would lose that fight."
- "It doesn't block anything. It's a user-mode watcher. It sees the file after it's
  written — it can't stop it running."
- "It never touches the network. Not for hash lookups, not for anything."
- "A clean result doesn't mean safe. The app says that on the Settings page, in the
  app's own words."

### Shot 7 — the remediation engine (2:45)

Turn on *Remediation* in Settings, select the detection, choose *Nettoyer*.

The point is the shape of the interaction, not the action:

> "It doesn't delete anything. It shows you a plan — 'terminate process 1234',
> 'remove the Run key' — and it waits for you to tick the boxes you want."

Let the audience read the plan. Then confirm one step. Then stop.

### Shot 8 — the interface in French (3:15)

Settings → Language → Français. Everything switches immediately.

> "It speaks French. Because of course it does."

### Shot 9 — the easter eggs (3:40)

These are the ones that make the video. All of them are real, all of them are harmless,
and none of them change how a file is inspected.

| Trigger | What happens |
|---|---|
| **F9** | Raises the detection alert on a harmless sample. The cat, the red border, the whole thing. This is the money shot — press it live rather than setting up a file first. |
| **↑ ↑ ↓ ↓ ← → ← → B A** (the Konami code) | **CAT MODE.** The accent turns orange and a very smug cat appears with the message *"Lumen is now 100% more accurate. This claim is decorative."* Press **Esc** to go back. |
| **Click the cat in CAT MODE** | A completely fictional bug report: `CatException: the scan was interrupted by a cat`, error code **0xC0FFEE**, with a stack trace naming `CatDetector.Inspect` and `CatArt.OnRender`. |
| **Ctrl + Alt + C** | A cat walks across the bottom of the window. It has never been near a file. |

The cat is drawn entirely with WPF vector geometry — no image files, no fonts, no
downloads. It blinks and sways its tail. That is worth mentioning, because it is the
part an AI cannot fake convincingly and a human could not draw in an afternoon.

Do the Konami code **on camera**. The pause before the cat appears is the joke.

### A note on the false positives

Somewhere in the middle of the video it is worth showing a rule that does **not**
fire, because "an antivirus that cries wolf" is the real criticism of this genre.

Lumen has a rule for unsigned executables. On a normal Windows machine a *lot* of
software is unsigned, so the rule only fires when a file is unsigned **and** sits
somewhere the user can freely write to and run from - a temp folder, AppData, the
Downloads folder. An unsigned program in Program Files is ordinary and is not
reported.

There is a test in the suite that fails if any finding's wording contains the words
"malware" or "virus". Lumen describes what it *observed*, and leaves the conclusion
to the person reading it.

### Shot 10 — the process killer (3:55)

The one that sounds scary and is actually the careful part.

Settings → Remediation: turn on **"Stop processes that are using a matched file"**.
Then run a file and watch it. Lumen finds the process whose executable or loaded
module *is* that file, and stops it.

> "It doesn't kill anything it can't place. It doesn't touch system processes. It
> doesn't delete the file — the file is still sitting there, and you can still decide
> what to do with it. And every single action, including every refusal, goes into an
> audit log."

Then show the audit journal. It is a plain text file, one line per action.

**The moment to slow down for:** the protection is re-checked at the instant of the
action, not just when the process was found. A process that was ordinary a second ago
and is protected now is refused.

### Shot 11 — the code (4:15)

The interesting engineering, if the audience is technical:

- `src/Lumen.Core/Quarantine/QuarantineService.cs` — copy, verify, index, *then* delete
- `src/Lumen.Core/Remediation/RemediationEngine.cs` — the engine decides, the adapters act
- `src/Lumen.Core/Protection/RealtimeMonitor.cs` — the watcher that heals itself
- `src/Lumen.App/Alerts/CatArt.cs` — the cat, in vector geometry

Mention the tests: **189 and counting**, and that they never touch a real file, a real
process or the real registry.

---

## Things worth getting right

**Be honest about what it is.** The strongest version of this video is "I tested an AI
antivirus and here's exactly how good it is" — not "look how many features it has".
Every claim you make should survive someone trying it.

**Show the failure modes.** The hardened parts are more interesting than the features:

- Change the file after it was scanned and try to quarantine it → refused
- Try to restore into `C:\Windows` → refused
- Try to remove a system process → refused

**Show the alerts being wrong.** The "Skipped" counter, the degraded real-time state,
the "this is a heuristic, not proof" wording. A tool that admits its limits is a tool
people trust.

**Don't run it on your real machine for the video.** Use the VM. It's the same footage
and it costs you nothing.

---

## Clean-up

```powershell
.\scripts\clean-sandbox.ps1
```

Deletes the sandboxed data folder, the isolated build output and any screenshots.
Nothing outside the project folder is ever written, so there is nothing else to clean.

To reset the app to a fresh state instead of deleting everything, delete
`.sandbox\data` — that is where the settings, the history, the vault and the logs live.
