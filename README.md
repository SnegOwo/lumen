<div align="center">

<img src="docs/media/icon.png" width="88" alt="Lumen">

# Lumen

**A local file inspector for Windows — written by an AI.**

[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![WPF](https://img.shields.io/badge/UI-WPF-0f7a9d)](https://learn.microsoft.com/dotnet/desktop/wpf/)
[![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-0078D4)](https://www.microsoft.com/windows)
[![MIT](https://img.shields.io/badge/license-MIT-3da639)](LICENSE)
<br>
[![66 rules](https://img.shields.io/badge/66-documented%20rules-2ea44f)](#whats-inside)
[![475 tests](https://img.shields.io/badge/475-tests-2ea44f)](#tests)
[![experiment](https://img.shields.io/badge/status-experiment-orange)](#honest-limits)
[![not an antivirus](https://img.shields.io/badge/not%20an-antivirus-critical)](#honest-limits)

</div>

<div align="center">

<a href="https://youtu.be/ZeSmtoD2rUI">
  <img src="https://i.ytimg.com/vi/ZeSmtoD2rUI/maxresdefault.jpg" width="760" alt="J'ai FORCÉ une IA à CRÉER le MEILLEUR ANTIVIRUS">
</a>

I gave an AI a product brief for an antivirus and let it write every line.
Then I ran it in a virtual machine, broke it, and made it fix itself — one commit at a time.

**▶ [Watch the video](https://youtu.be/ZeSmtoD2rUI)**

</div>

> [!WARNING]
> **Not an antivirus. Not signed. Not for your real machine.**
> 66 heuristics, no signature database, no network, no driver. Run it in a throwaway VM and keep
> Microsoft Defender enabled. SmartScreen will warn you about the executable — it is right to.

<div align="center">
<img src="docs/media/lumen.gif" alt="Lumen in motion" width="900">
</div>

**English** · [Français](#francais)

---

## What it is

A small desktop app that looks at files, tells you **why** it flagged something, and can move a match
into an encrypted vault you can restore later.

| ✅ It does | ❌ It does not |
|---|---|
| Scans files and explains every finding | Replace Microsoft Defender |
| Quarantines behind an AES-256 vault | Block a file before it runs |
| Cleans up a detection, with your confirmation | Delete anything silently |
| Runs entirely offline | Touch the network, ever |

There is no malware in this repository. The EICAR test string is assembled at runtime from character
codes, so cloning the repo will not trip your antivirus.

## Download

The build from the video is attached to the **[v2.0.0 release](https://github.com/SnegOwo/lumen/releases/tag/v2.0.0)**.

- **File** — [`Lumen-2.0.0-win-x64.zip`](https://github.com/SnegOwo/lumen/releases/download/v2.0.0/Lumen-2.0.0-win-x64.zip) · 61 MB · self-contained, no .NET install needed
- **SHA-256** — `FD2FEE07EC4D1E772E34761888DF04D5B1D11F11D0A72D2B738AA686CBBC6E0C`
- **Start** — unzip, then run `Start Lumen (isolated).cmd`. Everything stays in a `data` folder next to the script.

It is unsigned, so Windows will warn you. If you would rather not run a stranger's executable, build
it from source — [it takes one command](#build-from-source).

## The experiment

Lumen was written by **[MiniMax M3.1 Flash](https://huggingface.co/MiniMaxAI/MiniMax-M3.1-Flash)**
(`MiniMaxAI/MiniMax-M3.1-Flash`), a native multimodal mixture-of-experts model: ~428B parameters
total, 23B active per token, a context window of up to 1,000,000 tokens, MiniMax Sparse Attention
throughout, with a DSpark speculative-decoding head.

<details>
<summary><b>Full model card</b></summary>

| | |
|---|---|
| **Architecture** | Native multimodal mixture-of-experts (MoE) |
| **Parameters** | ~428B total · 23B activated per token |
| **Inputs / output** | Text, image and video in; text out |
| **Context window** | Up to 1,000,000 tokens |
| **Attention** | MiniMax Sparse Attention (MSA) throughout |
| **Speculative decoding** | DSpark draft head |

</details>

### The one rule

> **I never touched the code.**
> No editor, no patch, no typo fix, no renamed variable. Every line in this repository was written by
> the model.
>
> My job was everything around it: define the product, run it, describe exactly what broke, choose
> between the options it proposed, and say *no, do that again*.
>
> **It fixed the bugs. I found them.**

And one thing I never delegated: **the machine**. Lumen never ran on my real computer. Every build,
every scan, every crash was reproduced in a disposable VM with a snapshot taken first. That is why
this README tells you to do the same.

### What broke along the way

| What broke | How it was found | What changed |
|---|---|---|
| The alert window crashed the app on every detection | Ran it in the VM | Rebuilt the alert's animation path |
| An animation kept running behind a collapsed panel — 11% of a core, forever | Measured idle CPU | A test now fails the build if it comes back |
| Two aggressive rules fired on ordinary files | Ran them over 25,126 real files | Both rules tightened before shipping |
| Four UI defects that only exist once the app is rendered | First launch on a bare VM | Four fixes, one commit |

The parts I like most are the ones I never asked for: allocation budgets instead of flaky timing
tests, a `DisplayText` sanitiser so a file name cannot spoof the UI with bidirectional characters, and
a hard-coded list of processes Lumen refuses to stop *even if a settings file says otherwise*.

## Screenshots

Real captures from the running app. No mockups.

| Dashboard | Scan |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Scan](docs/screenshots/scan.png) |

| Quarantine | Settings |
|---|---|
| ![Quarantine](docs/screenshots/quarantine.png) | ![Settings](docs/screenshots/settings.png) |

| History |
|---|
| ![History](docs/screenshots/history.png) |

## What's inside

| Area | What it does |
|---|---|
| **Scan** | Quick, full profile, one folder, one file. Read-only. |
| **Real-time** | Re-inspects new and changed files while the app runs. Detect-on-write, not a blocker. |
| **Detect** | 66 documented rules: PE parsing, scripts, Office, PDF, archives, shortcuts, entropy, risk scoring. |
| **Quarantine** | AES-256-CBC vault, HMAC-SHA256 integrity, DPAPI keys. Copy → verify → *then* delete. |
| **Remediate** | Opt-in. Stops the process, removes the file, cleans autostart entries. Always plan → confirm → execute. |
| **Interface** | English and French, light / dark / high-contrast, and a cat drawn in vector geometry. |

<details>
<summary><b>What the 66 rules actually cover</b></summary>

A data-driven signature engine (ASCII, hex and token-group rules loaded from JSON), a hand-written
portable-executable parser (headers, sections, entropy, import tables, packing markers, timestamp
anomalies), script analysis (LOLBins, PowerShell obfuscation, AMSI bypass, persistence, AV tampering,
credential theft, reverse shells), Office macros and OLE, PDF analysis, archive analysis (nested
archives, password-protected files, zip bombs), Windows shortcuts, entropy and packing heuristics, a
transparent risk score, and a combination scorer that turns several weak signals into one finding
with every contribution listed.

Every rule is documented in `DetectionCatalog.Rules` and shown on the Settings page. **A clean result
is not proof that a file is safe.** The built-in hash list contains exactly one entry: EICAR.

</details>

## Honest limits

| | |
|---|---|
| **Detection** | 66 heuristics against Defender's cloud and huge signature database. Lumen would lose that fight, and it says so. |
| **Blocking** | It cannot stop a file before it runs. It inspects after the write. |
| **Coverage** | User mode, no driver, no service. It cannot see everything and does not pretend to. |
| **Network** | None. No hash lookups, no telemetry, no updates. Old rules stay old. |
| **Trust** | Written by a language model, unsigned, unaudited. Read the source before you run it. |

## Build from source

Requires the **.NET 10 SDK** (`global.json` pins `10.0.100`).

```powershell
dotnet build Lumen.slnx
dotnet run   --project src\Lumen.App\Lumen.App.csproj
```

To run it without touching your real folders:

```powershell
.\scripts\run-sandbox.ps1 -Build       # isolated data folder, real-time protection off
.\scripts\clean-sandbox.ps1            # delete every trace
```

<details>
<summary><b>Project layout, data folders and command-line arguments</b></summary>

```
src/Lumen.Core/       net10.0 — detection, scanning, quarantine, remediation, storage
src/Lumen.App/        net10.0-windows — the WPF shell (MVVM, themes, alerts)
tests/                xunit — Lumen.Core.Tests and Lumen.App.Tests
docs/                 shot list, UI review, screenshots, media
packaging/            notes and launchers for the self-contained build
scripts/              sandbox run/clean, package, end-to-end verify
```

```
%LOCALAPPDATA%\Lumen\
├── settings.json      user settings
├── history.json       the last 200 scans
├── quarantine\        the encrypted vault and its manifest
└── logs\              diagnostic log + remediation audit journal
```

| Variable / argument | Effect |
|---|---|
| `LUMEN_DATA_DIR` | Puts the data folder somewhere else |
| `LUMEN_DISABLE_REALTIME=1` | Stops the watcher from watching any folder |
| `--demo` | Raises the detection alert on a harmless sample |
| `--shots <folder>` | Saves a PNG of every page, then exits |

Nothing is written to the install folder, to `ProgramData` or to the registry.

</details>

## Tests

```powershell
dotnet test tests/Lumen.Core.Tests/Lumen.Core.Tests.csproj
dotnet test tests/Lumen.App.Tests/Lumen.App.Tests.csproj
```

**428 test methods, 475 cases.** They never touch real user files, real processes, the real registry or
the real data folder. Performance is asserted as an *allocation budget*, not a wall-clock time,
because timing tests are flaky and an allocation budget is not.

## License

[MIT](LICENSE) — **no warranty**. Read [Honest limits](#honest-limits) once more, then run it in a VM.

---

<a id="francais"></a>

## Français

<div align="center">

**Un inspecteur de fichiers local pour Windows — écrit par une IA.**

[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-0078D4)](https://www.microsoft.com/windows)
[![MIT](https://img.shields.io/badge/licence-MIT-3da639)](LICENSE)
[![pas un antivirus](https://img.shields.io/badge/pas%20un-antivirus-critical)](#limites-honnetes)

</div>

> [!WARNING]
> **Pas un antivirus. Pas signé. Pas pour votre vraie machine.**
> 66 heuristiques, aucune base de signatures, aucun réseau, aucun pilote. Lancez-le dans une VM
> jetable et gardez Microsoft Defender activé. SmartScreen va vous alerter sur l'exécutable — et il
> aura raison.

### Ce que c'est

Une petite application de bureau qui inspecte des fichiers, explique **pourquoi** elle a signalé
quelque chose, et peut déplacer un fichier correspondant dans un coffre chiffré que vous pourrez
restaurer plus tard.

| ✅ Ce qu'il fait | ❌ Ce qu'il ne fait pas |
|---|---|
| Analyse des fichiers et explique chaque résultat | Remplacer Microsoft Defender |
| Met en quarantaine dans un coffre AES-256 | Bloquer un fichier avant son exécution |
| Nettoie une détection, avec votre confirmation | Supprimer quoi que ce soit en silence |
| Fonctionne entièrement hors ligne | Toucher au réseau, jamais |

Il n'y a aucun malware dans ce dépôt. La chaîne EICAR est assemblée à l'exécution à partir de codes
de caractères : cloner le repo ne déclenchera pas votre antivirus.

### Télécharger

La version de la vidéo est attachée à la **[release v2.0.0](https://github.com/SnegOwo/lumen/releases/tag/v2.0.0)**.

- **Fichier** — [`Lumen-2.0.0-win-x64.zip`](https://github.com/SnegOwo/lumen/releases/download/v2.0.0/Lumen-2.0.0-win-x64.zip) · 61 Mo · autonome, aucune installation de .NET
- **SHA-256** — `FD2FEE07EC4D1E772E34761888DF04D5B1D11F11D0A72D2B738AA686CBBC6E0C`
- **Lancer** — dézippez, puis exécutez `Start Lumen (isolated).cmd`. Tout reste dans un dossier `data` à côté du script.

Il n'est pas signé, Windows va donc vous prévenir. Si vous préférez ne pas exécuter le binaire d'un
inconnu, compilez depuis les sources — [c'est une seule commande](#compiler-depuis-les-sources).

### L'expérience

Lumen a été écrit par **[MiniMax M3.1 Flash](https://huggingface.co/MiniMaxAI/MiniMax-M3.1-Flash)**
(`MiniMaxAI/MiniMax-M3.1-Flash`), un modèle mixture-of-experts multimodal natif : ~428 Md de
paramètres au total, 23 Md activés par token, une fenêtre de contexte allant jusqu'à 1 000 000 de
tokens, MiniMax Sparse Attention dans tout le modèle, avec une tête de décodage spéculatif DSpark.

<details>
<summary><b>Fiche complète du modèle</b></summary>

| | |
|---|---|
| **Architecture** | Mixture-of-experts (MoE) multimodale native |
| **Paramètres** | ~428 Md au total · 23 Md activés par token |
| **Entrées / sortie** | Texte, image et vidéo en entrée ; texte en sortie |
| **Fenêtre de contexte** | Jusqu'à 1 000 000 de tokens |
| **Attention** | MiniMax Sparse Attention (MSA) dans tout le modèle |
| **Décodage spéculatif** | Tête de brouillon DSpark |

</details>

#### La règle

> **Je n'ai jamais touché au code.**
> Pas d'éditeur, pas de patch, pas de faute de frappe corrigée, pas de variable renommée. Chaque
> ligne de ce dépôt a été écrite par le modèle.
>
> Mon travail, c'était tout ce qu'il y a autour : définir le produit, lancer l'application, décrire
> précisément ce qui casse, choisir entre les options proposées, et dire *non, refais*.
>
> **C'est lui qui corrigeait les bugs. C'est moi qui les trouvais.**

Et une chose n'a jamais été déléguée : **la machine**. Lumen n'a jamais tourné sur mon ordinateur
réel. Chaque compilation, chaque analyse, chaque plantage a été reproduit dans une VM jetable avec un
snapshot pris avant. C'est pour ça que ce README vous demande de faire pareil.

#### Ce qui cassait en route

| Ce qui cassait | Comment ça a été trouvé | Ce qui a changé |
|---|---|---|
| La fenêtre d'alerte faisait planter l'app à chaque détection | Lancé dans la VM | Chemin d'animation reconstruit |
| Une animation tournait derrière un panneau replié — 11 % d'un cœur, en permanence | Mesure du CPU au repos | Un test fait échouer le build si ça revient |
| Deux règles agressives se déclenchaient sur des fichiers ordinaires | Passage sur 25 126 vrais fichiers | Les deux règles resserrées |
| Quatre défauts d'interface visibles seulement à l'affichage | Premier lancement sur une VM nue | Quatre correctifs, un commit |

Ce que j'aime le plus, c'est ce que je n'avais pas demandé : des budgets d'allocation au lieu de
tests de temps instables, un assainisseur `DisplayText` pour qu'un nom de fichier ne puisse pas
usurper l'interface avec des caractères bidirectionnels, et une liste codée en dur de processus que
Lumen refuse d'arrêter *même si un fichier de configuration dit le contraire*.

### Captures d'écran

De vraies captures de l'application. Aucune maquette.

| Tableau de bord | Analyse |
|---|---|
| ![Tableau de bord](docs/screenshots/dashboard.png) | ![Analyse](docs/screenshots/scan.png) |

| Quarantaine | Réglages |
|---|---|
| ![Quarantaine](docs/screenshots/quarantine.png) | ![Réglages](docs/screenshots/settings.png) |

| Historique |
|---|
| ![Historique](docs/screenshots/history.png) |

### Ce qu'il y a dedans

| Zone | Ce qu'elle fait |
|---|---|
| **Analyse** | Rapide, profil complet, un dossier, un fichier. Lecture seule. |
| **Temps réel** | Réinspecte les fichiers nouveaux et modifiés. Détection à l'écriture, pas un bloqueur. |
| **Détection** | 66 règles documentées : parseur PE, scripts, Office, PDF, archives, raccourcis, entropie, score de risque. |
| **Quarantaine** | Coffre AES-256-CBC, intégrité HMAC-SHA256, clés DPAPI. Copier → vérifier → *puis* supprimer. |
| **Remédiation** | Optionnelle. Arrête le processus, supprime le fichier, nettoie les entrées de démarrage. Toujours plan → confirmation → exécution. |
| **Interface** | Anglais et français, clair / sombre / contraste élevé, et un chat dessiné en géométrie vectorielle. |

<details>
<summary><b>Ce que couvrent vraiment les 66 règles</b></summary>

Un moteur de signatures piloté par les données (règles ASCII, hex et groupes de jetons chargées depuis
du JSON), un parseur d'exécutables Windows écrit à la main (en-têtes, sections, entropie, tables
d'imports, marqueurs de packing, anomalies d'horodatage), l'analyse de scripts (LOLBins, obfuscation
PowerShell, contournement AMSI, persistance, sabotage d'antivirus, vol d'identifiants, reverse
shells), les macros Office et OLE, l'analyse PDF, l'analyse d'archives (archives imbriquées, fichiers
protégés par mot de passe, zip bombs), les raccourcis Windows, les heuristiques d'entropie et de
packing, un score de risque transparent, et un scoreur de combinaison qui transforme plusieurs
signaux faibles en un seul résultat, avec chaque contribution listée.

Chaque règle est documentée dans `DetectionCatalog.Rules` et affichée dans les réglages. **Un résultat
propre ne prouve pas qu'un fichier est sûr.** La liste de hachages intégrée contient exactement une
entrée : EICAR.

</details>

<a id="limites-honnetes"></a>

### Limites honnêtes

| | |
|---|---|
| **Détection** | 66 heuristiques face au cloud et à l'énorme base de signatures de Defender. Lumen perdrait ce combat, et il le dit. |
| **Blocage** | Il ne peut pas arrêter un fichier avant son exécution. Il inspecte après l'écriture. |
| **Couverture** | Mode utilisateur, aucun pilote, aucun service. Il ne voit pas tout et ne prétend pas le contraire. |
| **Réseau** | Aucun. Pas de recherche de hachage, pas de télémétrie, pas de mise à jour. Les vieilles règles restent vieilles. |
| **Confiance** | Écrit par un modèle de langage, non signé, non audité. Lisez le code avant de l'exécuter. |

<a id="compiler-depuis-les-sources"></a>

### Compiler depuis les sources

Il faut le **SDK .NET 10** (`global.json` épingle `10.0.100`).

```powershell
dotnet build Lumen.slnx
dotnet run   --project src\Lumen.App\Lumen.App.csproj
```

Pour le lancer sans toucher à vos vrais dossiers :

```powershell
.\scripts\run-sandbox.ps1 -Build       # dossier de données isolé, temps réel désactivé
.\scripts\clean-sandbox.ps1            # efface toute trace
```

<details>
<summary><b>Structure du projet, dossiers de données et arguments</b></summary>

```
src/Lumen.Core/       net10.0 — détection, analyse, quarantaine, remédiation, stockage
src/Lumen.App/        net10.0-windows — la coque WPF (MVVM, thèmes, alertes)
tests/                xunit — Lumen.Core.Tests et Lumen.App.Tests
docs/                 conducteur vidéo, revue d'interface, captures, médias
packaging/            notes et lanceurs pour le build autonome
scripts/              sandbox, packaging, vérification de bout en bout
```

```
%LOCALAPPDATA%\Lumen\
├── settings.json      réglages utilisateur
├── history.json       les 200 dernières analyses
├── quarantine\        le coffre chiffré et son manifeste
└── logs\              journal de diagnostic + journal d'audit
```

| Variable / argument | Effet |
|---|---|
| `LUMEN_DATA_DIR` | Place le dossier de données ailleurs |
| `LUMEN_DISABLE_REALTIME=1` | Empêche le surveillant de regarder le moindre dossier |
| `--demo` | Déclenche l'alerte de détection sur un échantillon inoffensif |
| `--shots <dossier>` | Enregistre un PNG de chaque page, puis quitte |

Rien n'est écrit dans le dossier d'installation, dans `ProgramData` ni dans le registre.

</details>

### Tests

```powershell
dotnet test tests/Lumen.Core.Tests/Lumen.Core.Tests.csproj
dotnet test tests/Lumen.App.Tests/Lumen.App.Tests.csproj
```

**428 méthodes de test, 475 cas.** Elles ne touchent jamais aux vrais fichiers de l'utilisateur, aux
vrais processus, au vrai registre ni au vrai dossier de données. La performance est vérifiée par un
*budget d'allocation*, pas par un temps d'horloge : les tests de temps sont instables, un budget
d'allocation ne l'est pas.

### Licence

[MIT](LICENSE) — **sans garantie**. Relisez [Limites honnêtes](#limites-honnetes), puis lancez-le dans
une VM.

---

<div align="center">
<sub>
Built with <a href="https://huggingface.co/MiniMaxAI/MiniMax-M3.1-Flash">MiniMax M3.1 Flash</a> ·
Video: <a href="https://youtu.be/ZeSmtoD2rUI">J'ai FORCÉ une IA à CRÉER le MEILLEUR ANTIVIRUS</a> ·
MIT, no warranty
</sub>
</div>
