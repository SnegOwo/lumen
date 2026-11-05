<div align="center">

<img src="docs/media/icon.png" width="80" alt="Lumen">

# Lumen

**A local file inspector for Windows — written by an AI.**

[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![WPF](https://img.shields.io/badge/UI-WPF-0f7a9d)](https://learn.microsoft.com/dotnet/desktop/wpf/)
[![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-0078D4)](https://www.microsoft.com/windows)
[![MIT](https://img.shields.io/badge/license-MIT-3da639)](LICENSE)
<br>
[![66 rules](https://img.shields.io/badge/66-documented%20rules-2ea44f)](#what-it-is)
[![475 tests](https://img.shields.io/badge/475-tests-2ea44f)](#tests)
[![not an antivirus](https://img.shields.io/badge/not%20an-antivirus-critical)](#limits)

</div>

<div align="center">

<a href="https://youtu.be/ZeSmtoD2rUI">
  <img src="https://i.ytimg.com/vi/ZeSmtoD2rUI/maxresdefault.jpg" width="720" alt="J'ai FORCÉ une IA à CRÉER le MEILLEUR ANTIVIRUS">
</a>

I gave an AI a brief for an antivirus and let it write every line.
Then I ran it in a VM, broke it, and made it fix itself.

**▶ [Watch the video](https://youtu.be/ZeSmtoD2rUI)** · **[Download](#download)** · **[The experiment](#the-experiment)**

</div>

> [!WARNING]
> **Not an antivirus, not signed, not for your real machine.**
> 66 heuristics, no signature database, no network, no driver. Run it in a throwaway VM and keep
> Microsoft Defender enabled. SmartScreen will warn you — it is right to.

<div align="center">
<img src="docs/media/lumen.gif" alt="Lumen in motion" width="860">
</div>

**English** · [Français](#francais)

---

## What it is

Lumen scans your files, tells you **why** it flagged something, and can lock a match inside an
encrypted vault you can restore later.

It is small on purpose: no driver, no service, no cloud, no telemetry. Nothing is deleted without your
confirmation.

| It does | It does not |
|---|---|
| Scans and explains every finding | Replace Microsoft Defender |
| Quarantines in an AES-256 vault | Block a file before it runs |
| Works fully offline | Delete anything silently |

## Download

The build from the video is the **[v2.0.0 release](https://github.com/SnegOwo/lumen/releases/tag/v2.0.0)**.

- **File** — [`Lumen-2.0.0-win-x64.zip`](https://github.com/SnegOwo/lumen/releases/download/v2.0.0/Lumen-2.0.0-win-x64.zip) (61 MB)
- **Run** — unzip, then `Start Lumen (isolated).cmd`. No .NET needed, data stays in `.\data`.
- **Verify** — SHA-256 `FD2FEE07EC4D1E772E34761888DF04D5B1D11F11D0A72D2B738AA686CBBC6E0C`

It is unsigned, so Windows will warn you. That is expected. If you would rather not run a stranger's
executable, [build it from source](#build-from-source) instead.

## The experiment

Lumen was written by **[MiniMax M3.1 Flash](https://huggingface.co/MiniMaxAI/MiniMax-M3.1-Flash)** —
~428B parameters (23B active per token), a 1M-token context, native multimodal mixture-of-experts,
MiniMax Sparse Attention throughout, plus a DSpark speculative-decoding head.

> **I never touched the code.**
> No editor, no patch, no typo fix, no renamed variable. Every line here was written by the model.
>
> My job was everything around it: define the product, run it, describe exactly what broke, choose
> between the options it proposed, and say *no, do that again*.
>
> **It fixed the bugs. I found them.**

And I never let it near my real machine: every build, scan and crash was reproduced in a disposable
VM with a snapshot taken first.

**What broke, and what changed**

- The alert window crashed the app on every detection → the animation path was rebuilt.
- An animation burned 11% of a core behind a collapsed panel → a test now fails the build if it returns.
- Two aggressive rules fired on ordinary files → tightened after a run over 25,126 real files.
- Four interface defects that only exist once the app is rendered → fixed after the first bare-VM run.

## Screenshots

Real captures, no mockups.

| Dashboard | Scan |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Scan](docs/screenshots/scan.png) |

| Quarantine | Settings |
|---|---|
| ![Quarantine](docs/screenshots/quarantine.png) | ![Settings](docs/screenshots/settings.png) |

<a id="limits"></a>

## Limits

- **Detection** — 66 heuristics against Defender's cloud and huge signature database. Lumen would lose.
- **Blocking** — it inspects after the write, never before.
- **Coverage** — user mode, no driver, no service. It cannot see everything.
- **Network** — none at all. No hash lookups, no telemetry, no updates.
- **Trust** — written by a language model, unsigned, unaudited. Read the source before you run it.

<a id="build-from-source"></a>

## Build from source

Requires the **.NET 10 SDK**.

```powershell
dotnet build Lumen.slnx
dotnet run   --project src\Lumen.App\Lumen.App.csproj
```

Sandboxed run, with an isolated data folder and no real-time protection:

```powershell
.\scripts\run-sandbox.ps1 -Build
.\scripts\clean-sandbox.ps1
```

## Tests

**428 test methods (475 cases).** They never touch real files, processes, the registry or the real data
folder.

## License

[MIT](LICENSE) — **no warranty**.

---

<a id="francais"></a>

## Français

<div align="center">

**Un inspecteur de fichiers local pour Windows — écrit par une IA.**

[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-0078D4)](https://www.microsoft.com/windows)
[![MIT](https://img.shields.io/badge/licence-MIT-3da639)](LICENSE)
[![pas un antivirus](https://img.shields.io/badge/pas%20un-antivirus-critical)](#limites)

</div>

> [!WARNING]
> **Pas un antivirus, pas signé, pas pour votre vraie machine.**
> 66 heuristiques, aucune base de signatures, aucun réseau, aucun pilote. Lancez-le dans une VM
> jetable et gardez Microsoft Defender activé. SmartScreen va vous alerter — et il aura raison.

### Ce que c'est

Lumen inspecte vos fichiers, explique **pourquoi** il a signalé quelque chose, et peut enfermer un
fichier correspondant dans un coffre chiffré que vous pourrez restaurer plus tard.

Il est petit exprès : pas de pilote, pas de service, pas de cloud, pas de télémétrie. Rien n'est
supprimé sans votre confirmation.

| Il fait | Il ne fait pas |
|---|---|
| Analyse et explique chaque résultat | Remplacer Microsoft Defender |
| Met en quarantaine dans un coffre AES-256 | Bloquer un fichier avant son exécution |
| Fonctionne entièrement hors ligne | Supprimer quoi que ce soit en silence |

### Télécharger

La version de la vidéo est la **[release v2.0.0](https://github.com/SnegOwo/lumen/releases/tag/v2.0.0)**.

- **Fichier** — [`Lumen-2.0.0-win-x64.zip`](https://github.com/SnegOwo/lumen/releases/download/v2.0.0/Lumen-2.0.0-win-x64.zip) (61 Mo)
- **Lancer** — dézippez, puis `Start Lumen (isolated).cmd`. Aucun .NET requis, les données restent dans `.\data`.
- **Vérifier** — SHA-256 `FD2FEE07EC4D1E772E34761888DF04D5B1D11F11D0A72D2B738AA686CBBC6E0C`

Il n'est pas signé, Windows va donc vous prévenir. C'est normal. Si vous préférez ne pas exécuter le
binaire d'un inconnu, [compilez depuis les sources](#compiler-depuis-les-sources).

### L'expérience

Lumen a été écrit par **[MiniMax M3.1 Flash](https://huggingface.co/MiniMaxAI/MiniMax-M3.1-Flash)** —
~428 Md de paramètres (23 Md activés par token), une fenêtre de 1 M de tokens, un modèle
mixture-of-experts multimodal natif, MiniMax Sparse Attention dans tout le modèle, et une tête de
décodage spéculatif DSpark.

> **Je n'ai jamais touché au code.**
> Pas d'éditeur, pas de patch, pas de faute de frappe corrigée, pas de variable renommée. Chaque ligne
> de ce dépôt a été écrite par le modèle.
>
> Mon travail, c'était tout ce qu'il y a autour : définir le produit, lancer l'application, décrire
> précisément ce qui casse, choisir entre les options proposées, et dire *non, refais*.
>
> **C'est lui qui corrigeait les bugs. C'est moi qui les trouvais.**

Et je ne l'ai jamais laissé approcher ma vraie machine : chaque compilation, analyse et plantage a été
reproduit dans une VM jetable avec un snapshot pris avant.

**Ce qui cassait, et ce qui a changé**

- La fenêtre d'alerte faisait planter l'app à chaque détection → chemin d'animation reconstruit.
- Une animation brûlait 11 % d'un cœur derrière un panneau replié → un test fait échouer le build si ça revient.
- Deux règles agressives se déclenchaient sur des fichiers ordinaires → resserrées après un passage sur 25 126 vrais fichiers.
- Quatre défauts d'interface visibles seulement à l'affichage → corrigés au premier lancement sur une VM nue.

### Captures d'écran

De vraies captures, aucune maquette.

| Tableau de bord | Analyse |
|---|---|
| ![Tableau de bord](docs/screenshots/dashboard.png) | ![Analyse](docs/screenshots/scan.png) |

| Quarantaine | Réglages |
|---|---|
| ![Quarantaine](docs/screenshots/quarantine.png) | ![Réglages](docs/screenshots/settings.png) |

<a id="limites"></a>

### Limites

- **Détection** — 66 heuristiques face au cloud et à l'énorme base de signatures de Defender. Lumen perdrait.
- **Blocage** — il inspecte après l'écriture, jamais avant.
- **Couverture** — mode utilisateur, aucun pilote, aucun service. Il ne voit pas tout.
- **Réseau** — aucun. Pas de recherche de hachage, pas de télémétrie, pas de mise à jour.
- **Confiance** — écrit par un modèle de langage, non signé, non audité. Lisez le code avant de l'exécuter.

<a id="compiler-depuis-les-sources"></a>

### Compiler depuis les sources

Il faut le **SDK .NET 10**.

```powershell
dotnet build Lumen.slnx
dotnet run   --project src\Lumen.App\Lumen.App.csproj
```

Lancement isolé, sans protection temps réel et sans toucher à vos vrais dossiers :

```powershell
.\scripts\run-sandbox.ps1 -Build
.\scripts\clean-sandbox.ps1
```

### Tests

**428 méthodes de test (475 cas).** Elles ne touchent jamais aux vrais fichiers, processus, registre ou
dossier de données.

### Licence

[MIT](LICENSE) — **sans garantie**.

---

<div align="center">
<sub>
Built with <a href="https://huggingface.co/MiniMaxAI/MiniMax-M3.1-Flash">MiniMax M3.1 Flash</a> ·
<a href="https://youtu.be/ZeSmtoD2rUI">J'ai FORCÉ une IA à CRÉER le MEILLEUR ANTIVIRUS</a> ·
MIT, no warranty
</sub>
</div>
