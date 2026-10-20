using System.Globalization;
using System.Windows;
using Lumen.Core.Models;

namespace Lumen.App.Localization;

/// <summary>
/// A countable noun in both shipped languages, so that "1 file" and "2 fichiers" are
/// both correct without the caller having to know the current language.
/// </summary>
/// <param name="English">The English singular form.</param>
/// <param name="EnglishPlural">The English plural form.</param>
/// <param name="French">The French singular form.</param>
/// <param name="FrenchPlural">The French plural form.</param>
public sealed record TextNoun(
    string English,
    string EnglishPlural,
    string French,
    string FrenchPlural)
{
    /// <summary>The form to use for the given count.</summary>
    public string Select(bool plural) =>
        plural ? EnglishPlural : English;

    /// <summary>The French form to use for the given count.</summary>
    public string SelectFrench(bool plural) =>
        plural ? FrenchPlural : French;
}

/// <summary>
/// Every user-facing string that Lumen builds at run time, in English and in French.
///
/// <para>
/// The static wording that lives inside XAML is not here: it lives in
/// <c>Themes/Strings.en.xaml</c> and <c>Themes/Strings.fr.xaml</c> and is referenced
/// with <c>{DynamicResource Strings.X}</c>, so the views follow the language switch
/// without any code behind them.
/// </para>
///
/// <para>
/// The French copy is written as French, not as a word-for-word translation of the
/// English: the wording stays calm and technical, and it uses the vocabulary a French
/// administrator expects (logiciel, détection, quarantaine, exclusion, surveillance en
/// temps réel, fichier, dossier, règle, confiance).
/// </para>
/// </summary>
public static class Text
{
    private const string EnglishDictionaryUri =
        "pack://application:,,,/Lumen;component/Themes/Strings.en.xaml";

    private const string FrenchDictionaryUri =
        "pack://application:,,,/Lumen;component/Themes/Strings.fr.xaml";

    private static AppLanguage _current = AppLanguage.English;

    /// <summary>The language the interface is currently shown in.</summary>
    public static AppLanguage Current => _current;

    /// <summary>True when the French wording is in use.</summary>
    public static bool IsFrench => _current == AppLanguage.Francais;

    /// <summary>
    /// Raised after the language changed. Every view model that builds its own wording
    /// listens to it and re-raises its text properties, so the whole window follows the
    /// switch immediately.
    /// </summary>
    public static event EventHandler? LanguageChanged;

    /// <summary>
    /// Switches the interface language. The static XAML wording is swapped by replacing
    /// the merged resource dictionary, and <see cref="LanguageChanged"/> is raised so the
    /// view models can rebuild the wording they own.
    /// </summary>
    public static void Set(AppLanguage language)
    {
        var normalized = Enum.IsDefined(language) ? language : AppLanguage.English;
        var changed = normalized != _current;

        _current = normalized;
        ApplyCulture(normalized);
        ApplyResourceDictionary(normalized);

        if (changed) LanguageChanged?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>Formats a count with the noun that fits the current language.</summary>
    public static string Count(long value, TextNoun noun)
    {
        if (IsFrench)
        {
            return value == 1
                ? "1 " + noun.French
                : value.ToString("N0", CultureInfo.CurrentCulture) + " " + noun.FrenchPlural;
        }

        return value == 1
            ? "1 " + noun.English
            : value.ToString("N0", CultureInfo.CurrentCulture) + " " + noun.EnglishPlural;
    }

    // ----------------------------------------------------------------------
    // Countable nouns
    // ----------------------------------------------------------------------

    /// <summary>"file" / "fichier".</summary>
    public static TextNoun File { get; } = new("file", "files", "fichier", "fichiers");

    /// <summary>"finding" / "détection".</summary>
    public static TextNoun Finding { get; } = new("finding", "findings", "détection", "détections");

    /// <summary>"match" / "correspondance".</summary>
    public static TextNoun Match { get; } = new("match", "matches", "correspondance", "correspondances");

    /// <summary>"warning" / "avertissement".</summary>
    public static TextNoun Warning { get; } = new("warning", "warnings", "avertissement", "avertissements");

    /// <summary>"rule" / "règle".</summary>
    public static TextNoun Rule { get; } = new("rule", "rules", "règle", "règles");

    /// <summary>"potential issue" / "problème potentiel".</summary>
    public static TextNoun PotentialIssue { get; } =
        new("potential issue", "potential issues", "problème potentiel", "problèmes potentiels");

    /// <summary>"encrypted copy" / "copie chiffrée".</summary>
    public static TextNoun EncryptedCopy { get; } =
        new("encrypted copy", "encrypted copies", "copie chiffrée", "copies chiffrées");

    /// <summary>"folder" / "dossier".</summary>
    public static TextNoun Folder { get; } = new("folder", "folders", "dossier", "dossiers");

    /// <summary>"item" / "élément".</summary>
    public static TextNoun Item { get; } = new("item", "items", "élément", "éléments");

    /// <summary>"scan" / "analyse".</summary>
    public static TextNoun Scan { get; } = new("scan", "scans", "analyse", "analyses");

    /// <summary>
    /// Finds the noun that matches an English singular, so that a caller which only
    /// knows the English wording still gets a correctly translated count.
    /// </summary>
    public static bool TryGetNoun(string englishSingular, out TextNoun noun)
    {
        foreach (var candidate in AllNouns)
        {
            if (string.Equals(candidate.English, englishSingular, StringComparison.OrdinalIgnoreCase))
            {
                noun = candidate;
                return true;
            }
        }

        noun = File!;
        return false;
    }

    private static readonly TextNoun[] AllNouns =
    [
        File!,
        Finding!,
        Match!,
        Warning!,
        Rule!,
        PotentialIssue!,
        EncryptedCopy!,
        Folder!,
        Item!,
        Scan!
    ];

    // ----------------------------------------------------------------------
    // Shared vocabulary
    // ----------------------------------------------------------------------

    /// <summary>The product name. It is not translated.</summary>
    public static string AppName => "Lumen";

    /// <summary>The one-line description of the product.</summary>
    public static string Tagline => Pick("Local file inspection", "Inspection locale des fichiers");

    /// <summary>Names the kind of signal behind a finding.</summary>
    public static string Category(FindingCategory category) => category switch
    {
        FindingCategory.TestSignature => Pick("Test signature", "Signature de test"),
        FindingCategory.Signature => Pick("Signature match", "Correspondance de signature"),
        FindingCategory.Behavior => Pick("Behaviour", "Comportement"),
        FindingCategory.Reputation => Pick("Known bad hash", "Empreinte connue comme mauvaise"),
        _ => Pick("Heuristic", "Heuristique")
    };

    /// <summary>A short explanation of what a category means.</summary>
    public static string CategoryHint(FindingCategory category) => category switch
    {
        FindingCategory.TestSignature => Pick(
            "A harmless, industry-standard test artifact. It verifies the scanner plumbing only.",
            "Un artefact de test standard et sans danger. Il ne vérifie que la mécanique de l'analyse."),
        FindingCategory.Signature => Pick(
            "An exact byte or pattern match against a known signature.",
            "Une correspondance exacte d'octets ou de motif avec une signature connue."),
        FindingCategory.Behavior => Pick(
            "Indicators of packing, obfuscation or suspicious API use. Not proof of malware.",
            "Indices d'empaquetage, d'obfuscation ou d'API suspectes. Ce n'est pas une preuve de logiciel malveillant."),
        FindingCategory.Reputation => Pick(
            "The file hash is on the local known-bad list. Lumen never checks hashes online.",
            "L'empreinte du fichier figure sur la liste locale des empreintes connues. Lumen ne consulte jamais de liste en ligne."),
        _ => Pick(
            "A combination of suspicious characteristics. Not proof of malware.",
            "Une combinaison de caractéristiques suspectes. Ce n'est pas une preuve de logiciel malveillant.")
    };

    /// <summary>How confident the rule engine is.</summary>
    public static string Confidence(Confidence confidence) => confidence switch
    {
        Confidence.Definitive => Pick("Definitive", "Définitif"),
        Confidence.High => Pick("High confidence", "Confiance élevée"),
        Confidence.Medium => Pick("Medium confidence", "Confiance moyenne"),
        _ => Pick("Low confidence", "Confiance faible")
    };

    /// <summary>The name of a scan scope.</summary>
    public static string Scope(ScanScopeKind scope) => scope switch
    {
        ScanScopeKind.Quick => Pick("Quick scan", "Analyse rapide"),
        ScanScopeKind.FullUserProfile => Pick("Full profile scan", "Analyse du profil complet"),
        ScanScopeKind.Folder => Pick("Folder scan", "Analyse de dossier"),
        _ => Pick("File scan", "Analyse de fichier")
    };

    /// <summary>Why an item could not be inspected.</summary>
    public static string ErrorKind(ScanErrorKind kind) => kind switch
    {
        ScanErrorKind.AccessDenied => Pick("Access denied", "Accès refusé"),
        ScanErrorKind.NotFound => Pick("Not found", "Introuvable"),
        ScanErrorKind.InUse => Pick("In use", "Utilisé par un processus"),
        ScanErrorKind.PathTooLong => Pick("Path too long", "Chemin trop long"),
        ScanErrorKind.InvalidPath => Pick("Invalid path", "Chemin invalide"),
        ScanErrorKind.ReparsePoint => Pick("Link skipped", "Lien ignoré"),
        ScanErrorKind.Offline => Pick("Cloud placeholder", "Fichier distant"),
        ScanErrorKind.Io => Pick("Read error", "Erreur de lecture"),
        ScanErrorKind.Security => Pick("Blocked by policy", "Bloqué par la stratégie"),
        _ => Pick("Skipped", "Ignoré")
    };

    // ----------------------------------------------------------------------
    // Navigation and window chrome
    // ----------------------------------------------------------------------

    /// <summary>The dashboard navigation label.</summary>
    public static string NavDashboard => Pick("Dashboard", "Tableau de bord");

    /// <summary>The scan navigation label.</summary>
    public static string NavScan => Pick("Scan", "Analyse");

    /// <summary>The quarantine navigation label.</summary>
    public static string NavQuarantine => Pick("Quarantine", "Quarantaine");

    /// <summary>The history navigation label.</summary>
    public static string NavHistory => Pick("History", "Historique");

    /// <summary>The settings navigation label.</summary>
    public static string NavSettings => Pick("Settings", "Réglages");

    /// <summary>The sidebar workspace heading.</summary>
    public static string NavWorkspace => Pick("WORKSPACE", "ESPACE DE TRAVAIL");

    /// <summary>The sidebar product strapline.</summary>
    public static string NavStrapline => Pick("LOCAL FILE INSPECTION", "INSPECTION LOCALE DES FICHIERS");

    /// <summary>The sidebar capability card title.</summary>
    public static string NavOnDemandOnly => Pick("On-demand only", "À la demande uniquement");

    /// <summary>The sidebar capability card body.</summary>
    public static string NavOnDemandBody => Pick(
        "No driver, no background protection, no cloud uploads.",
        "Aucun pilote, aucune protection en arrière-plan, aucun envoi dans le cloud.");

    /// <summary>The sidebar footer note.</summary>
    public static string NavKeepDefender => Pick(
        "Keep Microsoft Defender enabled.",
        "Laissez Microsoft Defender activé.");

    /// <summary>The status bar label when nothing is running.</summary>
    public static string StatusReady => Pick("Ready", "Prêt");

    /// <summary>The status bar label while a scan runs.</summary>
    public static string StatusScanning => Pick("Scanning", "Analyse en cours");

    /// <summary>The status bar label while files are being quarantined.</summary>
    public static string StatusQuarantining => Pick("Quarantining", "Mise en quarantaine");

    /// <summary>The status bar detail while files are being quarantined.</summary>
    public static string StatusQuarantiningDetail => Pick(
        "Encrypting files locally",
        "Chiffrement local des fichiers");

    /// <summary>The status bar detail while a scan runs.</summary>
    public static string StatusScanningDetail(string filesScanned) =>
        Pick($"{filesScanned} files inspected", $"{filesScanned} fichiers inspectés");

    /// <summary>The status bar detail when real-time protection is running.</summary>
    public static string StatusRealtimeActive => Pick(
        "Real-time protection active",
        "Surveillance en temps réel active");

    /// <summary>The status bar detail when only on-demand scanning is available.</summary>
    public static string StatusOnDemand => Pick(
        "On-demand scanning",
        "Analyse à la demande");

    /// <summary>The badge text of a navigation entry that has quarantined items.</summary>
    public static string NavBadge(string title, int count) => Pick(
        $"{title}, {count} quarantined items",
        $"{title}, {count} éléments en quarantaine");

    /// <summary>The tooltip of the theme toggle, when the theme is "System".</summary>
    public static string ThemeTooltipSystem => Pick(
        "Follow the Windows theme. Click to use the light theme.",
        "Suivre le thème de Windows. Cliquez pour utiliser le thème clair.");

    /// <summary>The tooltip of the theme toggle, when the theme is "Light".</summary>
    public static string ThemeTooltipLight => Pick(
        "Switch to the dark theme.",
        "Passer au thème sombre.");

    /// <summary>The tooltip of the theme toggle, when the theme is "Dark".</summary>
    public static string ThemeTooltipDark => Pick(
        "Switch back to the Windows theme.",
        "Revenir au thème de Windows.");

    /// <summary>The tooltip of the theme toggle, when Windows asks for high contrast.</summary>
    public static string ThemeTooltipHighContrast => Pick(
        "Windows is using a high-contrast theme. The palette cannot be changed while it is active.",
        "Windows utilise un thème à contraste élevé. La palette ne peut pas être modifiée tant qu'il est actif.");

    /// <summary>The tooltip of the theme toggle when the high-contrast palette was picked by hand.</summary>
    public static string ThemeTooltipHighContrastChosen => Pick(
        "The high-contrast palette is selected. Click to follow the Windows theme.",
        "La palette à contraste élevé est sélectionnée. Cliquez pour suivre le thème de Windows.");

    // ----------------------------------------------------------------------
    // Dashboard
    // ----------------------------------------------------------------------

    /// <summary>The greeting shown in the morning.</summary>
    public static string GreetingMorning => Pick("Good morning", "Bonjour");

    /// <summary>The greeting shown in the afternoon.</summary>
    public static string GreetingAfternoon => Pick("Good afternoon", "Bon après-midi");

    /// <summary>The greeting shown in the evening.</summary>
    public static string GreetingEvening => Pick("Good evening", "Bonsoir");

    /// <summary>The badge above the hero headline.</summary>
    public static string HeroBadge => Pick(
        "ON-DEMAND  ·  ON-ACCESS  ·  LOCAL ONLY",
        "À LA DEMANDE  ·  À L'ACCÈS  ·  100 % LOCAL");

    /// <summary>The hero headline.</summary>
    public static string HeroHeadline => Pick(
        "Your device, inspected on your terms.",
        "Votre poste, inspecté selon vos règles.");

    /// <summary>The hero body copy.</summary>
    public static string HeroBody => Pick(
        "On-demand scans, transparent rules, and a recoverable encrypted vault. No cloud, no telemetry, no background driver.",
        "Des analyses à la demande, des règles transparentes et un coffre chiffré récupérable. Aucun cloud, aucune télémétrie, aucun pilote en arrière-plan.");

    /// <summary>The hero footnote.</summary>
    public static string HeroFootnote => Pick(
        "Files stay read-only until you confirm a quarantine.",
        "Les fichiers restent en lecture seule tant que vous n'avez pas confirmé une mise en quarantaine.");

    /// <summary>The dashboard button that opens the full scan options.</summary>
    public static string DashboardFullScan => Pick("Full scan", "Analyse complète");

    /// <summary>The dashboard button that starts a quick scan.</summary>
    public static string DashboardQuickScan => Pick("Quick scan", "Analyse rapide");

    /// <summary>The dashboard button that opens the folder picker.</summary>
    public static string DashboardChooseFolder => Pick("Choose a folder", "Choisir un dossier");

    /// <summary>The dashboard button that opens the quarantine page.</summary>
    public static string DashboardOpenQuarantine => Pick("Open quarantine", "Ouvrir la quarantaine");

    /// <summary>The dashboard button that opens the history page.</summary>
    public static string DashboardViewHistory => Pick("View history", "Voir l'historique");

    /// <summary>The dashboard button that opens Windows Security.</summary>
    public static string DashboardOpenWindowsSecurity => Pick(
        "Open Windows Security",
        "Ouvrir la sécurité Windows");

    /// <summary>The dashboard button that refreshes the Defender status.</summary>
    public static string DashboardRefreshDefender => Pick(
        "Refresh Defender status",
        "Actualiser l'état de Defender");

    /// <summary>The title of the real-time protection card.</summary>
    public static string RealtimeTitleOn => Pick(
        "Real-time protection is on",
        "La surveillance en temps réel est active");

    /// <summary>The title of the real-time protection card when it is off.</summary>
    public static string RealtimeTitleOff => Pick(
        "Real-time protection is off",
        "La surveillance en temps réel est désactivée");

    /// <summary>The detail of the real-time protection card when it is on.</summary>
    public static string RealtimeDetailOn => Pick(
        "New and changed files in the watched folders are re-checked while Lumen runs.",
        "Les fichiers nouveaux et modifiés des dossiers surveillés sont réanalysés tant que Lumen est ouvert.");

    /// <summary>The detail of the real-time protection card when it is off.</summary>
    public static string RealtimeDetailOff => Pick(
        "Turn it on in Settings to re-check new and changed files while Lumen runs.",
        "Activez-la dans les réglages pour réanalyser les fichiers nouveaux et modifiés.");

    /// <summary>How many folders are actually being watched.</summary>
    public static string RealtimeWatching(int watched, int configured) => Pick(
        $"Watching {watched} of {configured} folders",
        $"{watched} dossier(s) surveillé(s) sur {configured}");

    /// <summary>The warning shown when the monitor does not cover everything.</summary>
    public static string RealtimeDegraded => Pick(
        "Protection is degraded: part of the configured folders is not being watched.",
        "Protection dégradée : une partie des dossiers configurés n'est pas surveillée.");

    /// <summary>How many paths are waiting in the inspection queue.</summary>
    public static string RealtimeQueue(int depth) => Pick(
        $"{depth} path(s) queued",
        $"{depth} chemin(s) en file d'attente");

    /// <summary>How many paths were dropped because the queue was full.</summary>
    public static string RealtimeDropped(long dropped) => Pick(
        $"{dropped} path(s) dropped",
        $"{dropped} chemin(s) abandonné(s)");

    /// <summary>How many times a watcher failed and had to be rebuilt.</summary>
    public static string RealtimeWatcherFailures(long failures) => Pick(
        $"{failures} watcher failure(s)",
        $"{failures} échec(s) de surveillance");

    /// <summary>The last error reported by the monitor.</summary>
    public static string RealtimeLastError(string error) => Pick(
        $"Last error: {error}",
        $"Dernière erreur : {error}");

    /// <summary>The "checked" counter of the real-time card.</summary>
    public static string RealtimeChecked(long files) =>
        Pick($"{files:N0} checked", $"{files:N0} vérifiés");

    /// <summary>The "matches" counter of the real-time card.</summary>
    public static string RealtimeMatches(long matches) =>
        Pick($"{matches:N0} matches", $"{matches:N0} correspondance(s)");

    /// <summary>The real-time card when nothing was detected yet.</summary>
    public static string RealtimeNothingYet => Pick(
        "Nothing detected yet",
        "Rien de détecté pour l'instant");

    /// <summary>The real-time card when a match was found.</summary>
    public static string RealtimeLastMatch(string path, string when) => Pick(
        $"Last match: {path} · {when}",
        $"Dernière correspondance : {path} · {when}");

    /// <summary>The label of the last-scan card.</summary>
    public static string DashboardLastScan => Pick("Last scan", "Dernière analyse");

    /// <summary>The label of the quarantine card.</summary>
    public static string DashboardQuarantine => Pick("Quarantine", "Quarantaine");

    /// <summary>The label of the Defender card.</summary>
    public static string DashboardDefender => Pick("Microsoft Defender", "Microsoft Defender");

    /// <summary>The title of the recent-activity card.</summary>
    public static string DashboardRecentActivity => Pick("Recent activity", "Activité récente");

    /// <summary>The button that shows the whole history.</summary>
    public static string DashboardViewAll => Pick("View all", "Tout afficher");

    /// <summary>The empty state of the recent-activity card.</summary>
    public static string DashboardNoActivity => Pick(
        "No scans yet. Your scan results will appear here, stored only on this device.",
        "Aucune analyse pour l'instant. Vos résultats apparaîtront ici, stockés uniquement sur cet appareil.");

    /// <summary>The button that starts a quick scan from the empty activity card.</summary>
    public static string DashboardRunQuickScan => Pick("Run a quick scan", "Lancer une analyse rapide");

    /// <summary>The title of the "what Lumen checks" card.</summary>
    public static string DashboardChecksTitle => Pick("What Lumen checks", "Ce que Lumen vérifie");

    /// <summary>The subtitle of the "what Lumen checks" card.</summary>
    public static string DashboardChecksSubtitle => Pick(
        "Small, documented rules — not a malware signature database.",
        "Des règles peu nombreuses et documentées, pas une base de signatures de logiciels malveillants.");

    /// <summary>The EICAR bullet title.</summary>
    public static string DashboardCheckEicarTitle => Pick("EICAR test signature", "Signature de test EICAR");

    /// <summary>The EICAR bullet body.</summary>
    public static string DashboardCheckEicarBody => Pick(
        "Verifies scanner plumbing with the standard harmless test file.",
        "Vérifie la mécanique de l'analyse avec le fichier de test standard, sans danger.");

    /// <summary>The script heuristics bullet title.</summary>
    public static string DashboardCheckScriptTitle => Pick("Script heuristics", "Heuristiques de script");

    /// <summary>The script heuristics bullet body.</summary>
    public static string DashboardCheckScriptBody => Pick(
        "Looks for a few risky token combinations in readable scripts.",
        "Recherche quelques combinaisons de mots-clés risquées dans les scripts lisibles.");

    /// <summary>The deceptive-name bullet title.</summary>
    public static string DashboardCheckNameTitle => Pick("Deceptive file names", "Noms de fichiers trompeurs");

    /// <summary>The deceptive-name bullet body.</summary>
    public static string DashboardCheckNameBody => Pick(
        "Flags double extensions and bidirectional override characters.",
        "Signale les doubles extensions et les caractères de contrôle bidirectionnel.");

    /// <summary>The button that opens the rule catalogue.</summary>
    public static string DashboardReviewRules => Pick("Review detection rules", "Examiner les règles de détection");

    /// <summary>The disclaimer under the dashboard.</summary>
    public static string DashboardFooter => Pick(
        "Microsoft Defender should remain your primary antivirus. Lumen's real-time protection is a user-mode folder watcher that runs only while the app is open.",
        "Microsoft Defender doit rester votre antivirus principal. La surveillance en temps réel de Lumen est un observateur de dossiers en mode utilisateur, actif uniquement tant que l'application est ouverte.");

    // ----------------------------------------------------------------------
    // Scan page
    // ----------------------------------------------------------------------

    /// <summary>The scan page title.</summary>
    public static string ScanTitle => Pick("Scan", "Analyse");

    /// <summary>The scan page subtitle.</summary>
    public static string ScanSubtitle => Pick(
        "Inspect files on this device. Nothing is uploaded, and nothing changes until you confirm a quarantine.",
        "Inspectez les fichiers de cet appareil. Rien n'est envoyé, et rien ne change avant que vous confirmiez une mise en quarantaine.");

    /// <summary>The button that clears the current results.</summary>
    public static string ScanClearResults => Pick("Clear results", "Effacer les résultats");

    /// <summary>The title of the scope selector.</summary>
    public static string ScanScopeTitle => Pick("Choose a scope", "Choisissez une portée");

    /// <summary>The explanation of the scope selector.</summary>
    public static string ScanScopeSubtitle => Pick(
        "Quick covers the folders most people care about. Full profile is broader but still skips system and app-data locations.",
        "L'analyse rapide couvre les dossiers qui intéressent la plupart des gens. Le profil complet est plus large, mais ignore toujours les dossiers système et les données d'application.");

    /// <summary>The read-only badge.</summary>
    public static string ScanReadOnly => Pick("READ-ONLY", "LECTURE SEULE");

    /// <summary>The quick scope card title.</summary>
    public static string ScanScopeQuickTitle => Pick("Quick", "Rapide");

    /// <summary>The quick scope card body.</summary>
    public static string ScanScopeQuickBody => Pick(
        "Desktop, Documents, Downloads",
        "Bureau, Documents, Téléchargements");

    /// <summary>The quick scope card accessible name.</summary>
    public static string ScanScopeQuickName => Pick(
        "Quick scan: Desktop, Documents and Downloads",
        "Analyse rapide : Bureau, Documents et Téléchargements");

    /// <summary>The full-profile scope card title.</summary>
    public static string ScanScopeFullTitle => Pick("Full profile", "Profil complet");

    /// <summary>The full-profile scope card body.</summary>
    public static string ScanScopeFullBody => Pick(
        "Your user profile, minus app data",
        "Votre profil utilisateur, hors données d'application");

    /// <summary>The full-profile scope card accessible name.</summary>
    public static string ScanScopeFullName => Pick(
        "Full profile scan of your user profile",
        "Analyse du profil utilisateur complet");

    /// <summary>The folder scope card title.</summary>
    public static string ScanScopeFolderTitle => Pick("Folder", "Dossier");

    /// <summary>The folder scope card body.</summary>
    public static string ScanScopeFolderBody => Pick(
        "One folder you choose",
        "Un dossier de votre choix");

    /// <summary>The folder scope card accessible name.</summary>
    public static string ScanScopeFolderName => Pick(
        "Folder scan of a folder you choose",
        "Analyse d'un dossier de votre choix");

    /// <summary>The file scope card title.</summary>
    public static string ScanScopeFileTitle => Pick("Single file", "Fichier unique");

    /// <summary>The file scope card body.</summary>
    public static string ScanScopeFileBody => Pick(
        "One file you choose",
        "Un fichier de votre choix");

    /// <summary>The file scope card accessible name.</summary>
    public static string ScanScopeFileName => Pick(
        "Single file scan",
        "Analyse d'un fichier unique");

    /// <summary>The label of the chosen location.</summary>
    public static string ScanLocationLabel => Pick("Location", "Emplacement");

    /// <summary>The button that opens the folder or file picker.</summary>
    public static string ScanChoose => Pick("Choose…", "Choisir…");

    /// <summary>The note under the scope selector.</summary>
    public static string ScanQuarantineNote => Pick(
        "Quarantine is a separate, confirmed action.",
        "La mise en quarantaine est une action distincte, qui doit être confirmée.");

    /// <summary>The description of the quick scope.</summary>
    public static string ScanScopeQuickDescription => Pick(
        "Checks Desktop, Documents and Downloads with Lumen's small set of transparent rules.",
        "Vérifie le Bureau, les Documents et les Téléchargements avec le petit ensemble de règles transparentes de Lumen.");

    /// <summary>The description of the full-profile scope.</summary>
    public static string ScanScopeFullDescription => Pick(
        "Walks your user profile while skipping AppData, caches, reparse points and Lumen's own data.",
        "Parcourt votre profil utilisateur en ignorant AppData, les caches, les points de jonction et les données de Lumen.");

    /// <summary>The description of the folder scope.</summary>
    public static string ScanScopeFolderDescription => Pick(
        "Checks one folder you choose. Links and cloud placeholders are skipped, never followed.",
        "Vérifie un dossier de votre choix. Les liens et les fichiers distants sont ignorés, jamais suivis.");

    /// <summary>The description of the file scope.</summary>
    public static string ScanScopeFileDescription => Pick(
        "Checks one file you choose. Nothing is uploaded, changed or removed.",
        "Vérifie un fichier de votre choix. Rien n'est envoyé, modifié ni supprimé.");

    /// <summary>The placeholder for the quick scope path.</summary>
    public static string ScanPathQuick => Pick(
        "Desktop, Documents and Downloads",
        "Bureau, Documents et Téléchargements");

    /// <summary>The placeholder for the full-profile scope path.</summary>
    public static string ScanPathFull => Pick(
        "Your user profile — app data, caches and Lumen's vault are excluded",
        "Votre profil utilisateur — les données d'application, les caches et le coffre de Lumen sont exclus");

    /// <summary>The placeholder when no folder was picked yet.</summary>
    public static string ScanPathNoFolder => Pick("No folder selected yet", "Aucun dossier sélectionné");

    /// <summary>The placeholder when no file was picked yet.</summary>
    public static string ScanPathNoFile => Pick("No file selected yet", "Aucun fichier sélectionné");

    /// <summary>The note under the live progress strip.</summary>
    public static string ScanCancelNote => Pick(
        "You can cancel at any time. Files already inspected are left untouched.",
        "Vous pouvez annuler à tout moment. Les fichiers déjà inspectés restent inchangés.");

    /// <summary>The label of the inspected counter.</summary>
    public static string ScanInspected => Pick("Inspected", "Inspectés");

    /// <summary>The label of the files-inspected counter.</summary>
    public static string ScanFilesInspected => Pick("Files inspected", "Fichiers inspectés");

    /// <summary>The label of the findings counter.</summary>
    public static string ScanFindings => Pick("Findings", "Détections");

    /// <summary>The label of the skipped counter.</summary>
    public static string ScanSkipped => Pick("Skipped", "Ignorés");

    /// <summary>The label of the warnings counter.</summary>
    public static string ScanWarnings => Pick("Warnings", "Avertissements");

    /// <summary>The label of the elapsed counter.</summary>
    public static string ScanElapsed => Pick("Elapsed", "Durée");

    /// <summary>The checkbox that selects every finding.</summary>
    public static string ScanSelectAll => Pick("Select all", "Tout sélectionner");

    /// <summary>The note above the findings list.</summary>
    public static string ScanReviewNote => Pick(
        "Review each match before quarantining. Lumen never changes a file without your confirmation.",
        "Examinez chaque correspondance avant de la mettre en quarantaine. Lumen ne modifie jamais un fichier sans votre confirmation.");

    /// <summary>The size field label.</summary>
    public static string ScanSize => Pick("Size", "Taille");

    /// <summary>The detection-date field label.</summary>
    public static string ScanDetected => Pick("Detected", "Détecté");

    /// <summary>The button that copies the path.</summary>
    public static string ScanCopyPath => Pick("Copy path", "Copier le chemin");

    /// <summary>The button that shows the file in Explorer.</summary>
    public static string ScanShowInExplorer => Pick("Show in Explorer", "Afficher dans l'Explorateur");

    /// <summary>The empty state of the detail pane.</summary>
    public static string ScanSelectFinding => Pick(
        "Select a finding to review its details.",
        "Sélectionnez une détection pour afficher ses détails.");

    /// <summary>The empty state of the results card.</summary>
    public static string ScanNoMatchesTitle => Pick("No matches found", "Aucune correspondance");

    /// <summary>The body of the empty results card.</summary>
    public static string ScanNoMatchesMessage => Pick(
        "Lumen's limited rules did not match any inspected file. That does not prove the files are safe. Keep Microsoft Defender enabled and review skipped items below.",
        "Les règles limitées de Lumen n'ont correspondant à aucun fichier inspecté. Cela ne prouve pas que les fichiers sont sûrs. Gardez Microsoft Defender activé et examinez les éléments ignorés ci-dessous.");

    /// <summary>The button that restarts the scan from the empty results card.</summary>
    public static string ScanAgain => Pick("Scan again", "Analyser à nouveau");

    /// <summary>The disclaimer under the scan page.</summary>
    public static string ScanFooter => Pick(
        "Lumen reads a limited prefix of each file for content checks. It never uploads file contents and never bypasses Windows permissions.",
        "Lumen ne lit qu'un début limité de chaque fichier pour les vérifications de contenu. Il n'envoie jamais le contenu des fichiers et ne contourne jamais les permissions de Windows.");

    /// <summary>The remediation action offered on a finding.</summary>
    public static string ScanClean => Pick("Clean", "Nettoyer");

    /// <summary>The phase shown when the scan page is idle.</summary>
    public static string ScanPhaseReady => Pick("Ready when you are", "Prêt quand vous l'êtes");

    /// <summary>The phase shown while the request is being built.</summary>
    public static string ScanPhasePreparing => Pick("Preparing scan…", "Préparation de l'analyse…");

    /// <summary>The phase shown while the file list is being built.</summary>
    public static string ScanPhasePreparingList => Pick(
        "Preparing the file list…",
        "Préparation de la liste des fichiers…");

    /// <summary>The phase shown while the files are being enumerated.</summary>
    public static string ScanPhaseEnumerating => Pick("Finding files…", "Recherche des fichiers…");

    /// <summary>The phase shown while the files are being inspected.</summary>
    public static string ScanPhaseInspecting => Pick("Inspecting files…", "Inspection des fichiers…");

    /// <summary>The phase shown while the scan is wrapping up.</summary>
    public static string ScanPhaseFinishing => Pick("Finishing…", "Finalisation…");

    /// <summary>The phase shown while the scan is being cancelled.</summary>
    public static string ScanPhaseCancelling => Pick("Cancelling…", "Annulation…");

    /// <summary>The phase shown after a cancelled scan.</summary>
    public static string ScanPhaseCancelled => Pick("Cancelled", "Annulée");

    /// <summary>The phase shown after a successful scan.</summary>
    public static string ScanPhaseComplete => Pick("Scan complete", "Analyse terminée");

    /// <summary>The phase shown when the scan failed.</summary>
    public static string ScanPhaseFailed => Pick("Scan failed", "Échec de l'analyse");

    /// <summary>The placeholder for the current file while a scan runs.</summary>
    public static string ScanWaitingForFile => Pick(
        "Waiting for the first file…",
        "En attente du premier fichier…");

    /// <summary>The caption of the start button when no scan is running.</summary>
    public static string ScanStart => Pick("Start scan", "Démarrer l'analyse");

    /// <summary>The caption of the start button while a scan runs.</summary>
    public static string ScanRunning => Pick("Scanning…", "Analyse en cours…");

    /// <summary>The caption of the cancel button.</summary>
    public static string ScanCancel => Pick("Cancel scan", "Annuler l'analyse");

    /// <summary>The caption of the cancel button while cancelling.</summary>
    public static string ScanCancelling => Pick("Cancelling…", "Annulation…");

    /// <summary>The toggle that expands the skipped items.</summary>
    public static string ScanShowSkipped(int count) => Pick(
        $"Show {count:N0} skipped item(s)",
        $"Afficher {count:N0} élément(s) ignoré(s)");

    /// <summary>The toggle that collapses the skipped items.</summary>
    public static string ScanHideSkipped => Pick("Hide skipped items", "Masquer les éléments ignorés");

    /// <summary>The caption of the quarantine button when nothing is selected.</summary>
    public static string ScanQuarantineNone => Pick("Quarantine selected", "Mettre en quarantaine");

    /// <summary>The caption of the quarantine button for one file.</summary>
    public static string ScanQuarantineOne => Pick("Quarantine 1 file", "Mettre 1 fichier en quarantaine");

    /// <summary>The caption of the quarantine button for several files.</summary>
    public static string ScanQuarantineMany(int count) => Pick(
        $"Quarantine {count} files",
        $"Mettre {count} fichiers en quarantaine");

    /// <summary>The summary title of a cancelled scan.</summary>
    public static string ScanSummaryCancelled => Pick("Scan cancelled", "Analyse annulée");

    /// <summary>The summary body of a cancelled scan.</summary>
    public static string ScanSummaryCancelledBody => Pick(
        "The scan stopped before finishing. Partial results, if any, are shown. No files were changed.",
        "L'analyse s'est arrêtée avant la fin. Les résultats partiels éventuels sont affichés. Aucun fichier n'a été modifié.");

    /// <summary>The summary title when the scan could not be completed.</summary>
    public static string ScanSummaryFailed => Pick(
        "The scan could not be completed",
        "L'analyse n'a pas pu être terminée");

    /// <summary>The summary body when the scan could not be completed.</summary>
    public static string ScanSummaryFailedBody => Pick(
        "An unexpected error stopped the scan. No files were changed. Details were written to the local log.",
        "Une erreur inattendue a interrompu l'analyse. Aucun fichier n'a été modifié. Les détails figurent dans le journal local.");

    /// <summary>The summary title when findings were reported.</summary>
    public static string ScanSummaryFound(int count) => Pick(
        $"{count} potential issue(s) found",
        $"{count} problème(s) potentiel(s) détecté(s)");

    /// <summary>The summary body when findings were reported.</summary>
    public static string ScanSummaryFoundBody => Pick(
        "Review each finding before deciding what to quarantine. Some items could not be inspected, so this result is incomplete.",
        "Examinez chaque détection avant de décider quoi mettre en quarantaine. Certains éléments n'ont pas pu être inspectés : ce résultat est donc incomplet.");

    /// <summary>The summary body when findings were reported and everything was inspected.</summary>
    public static string ScanSummaryFoundCleanBody => Pick(
        "Lumen has not changed or removed anything. Review the findings and quarantine only what you understand.",
        "Lumen n'a rien modifié ni supprimé. Examinez les détections et ne mettez en quarantaine que ce que vous comprenez.");

    /// <summary>The summary title when the scan completed with warnings.</summary>
    public static string ScanSummaryWarnings => Pick(
        "Scan completed with warnings",
        "Analyse terminée avec des avertissements");

    /// <summary>The summary body when the scan completed with warnings.</summary>
    public static string ScanSummaryWarningsBody => Pick(
        "No matches for Lumen's limited rules were found, but some files could not be inspected. This does not prove the uninspected files are safe.",
        "Aucune correspondance avec les règles limitées de Lumen, mais certains fichiers n'ont pas pu être inspectés. Cela ne prouve pas que les fichiers non inspectés sont sûrs.");

    /// <summary>The summary title of a clean scan.</summary>
    public static string ScanSummaryClean => Pick("No matches found", "Aucune correspondance");

    /// <summary>The summary body of a clean scan.</summary>
    public static string ScanSummaryCleanBody => Pick(
        "No matches for Lumen's limited rules (EICAR, script heuristics and deceptive file names). This does not prove the files are safe. Keep Microsoft Defender enabled.",
        "Aucune correspondance avec les règles limitées de Lumen (EICAR, heuristiques de script, noms trompeurs). Cela ne prouve pas que les fichiers sont sûrs. Gardez Microsoft Defender activé.");

    /// <summary>The title of the "choose a location" warning.</summary>
    public static string ScanChooseLocation => Pick("Choose a scan location", "Choisissez un emplacement d'analyse");

    /// <summary>The title of the "no standard folders" warning.</summary>
    public static string ScanNoStandardFolders => Pick(
        "No standard folders found",
        "Aucun dossier standard trouvé");

    /// <summary>The body of the "no standard folders" warning.</summary>
    public static string ScanNoStandardFoldersBody => Pick(
        "None of the usual quick-scan folders exist for this account. Choose a folder instead.",
        "Aucun des dossiers habituels de l'analyse rapide n'existe pour ce compte. Choisissez plutôt un dossier.");

    /// <summary>The title of the protected-location confirmation.</summary>
    public static string ScanProtectedLocationTitle => Pick(
        "Scan a protected system location?",
        "Analyser un emplacement système protégé ?");

    /// <summary>The body of the protected-location confirmation.</summary>
    public static string ScanProtectedLocationBody => Pick(
        "Lumen would normally never scan Windows, Program Files or a drive root. This scan is read-only, but many files will return access-denied results. Lumen does not bypass Windows permissions. Only continue if you have a specific reason.",
        "Lumen n'analyse normalement jamais Windows, Program Files ni la racine d'un disque. Cette analyse est en lecture seule, mais de nombreux fichiers renverront un accès refusé. Lumen ne contourne pas les permissions de Windows. Ne continuez que pour une raison précise.");

    /// <summary>The confirmation button of the protected-location dialog.</summary>
    public static string ScanProtectedLocationConfirm => Pick("Scan anyway", "Analyser malgré tout");

    /// <summary>The title of the network-location confirmation.</summary>
    public static string ScanNetworkLocationTitle => Pick(
        "Scan a network location?",
        "Analyser un emplacement réseau ?");

    /// <summary>The body of the network-location confirmation.</summary>
    public static string ScanNetworkLocationBody => Pick(
        "Scanning a network share can be slow and may be logged by the remote computer. Lumen reads files directly from this device and does not upload anything.",
        "L'analyse d'un partage réseau peut être lente et être journalisée sur l'ordinateur distant. Lumen lit les fichiers directement depuis cet appareil et n'envoie rien.");

    /// <summary>The confirmation button of the network-location dialog.</summary>
    public static string ScanNetworkLocationConfirm => Pick(
        "Scan network location",
        "Analyser l'emplacement réseau");

    /// <summary>The prefix of the location detail line in the confirmations.</summary>
    public static string ScanLocationPrefix => Pick("Location: ", "Emplacement : ");

    /// <summary>The title of the quarantine confirmation.</summary>
    public static string ScanQuarantineTitle => Pick(
        "Quarantine selected files?",
        "Mettre les fichiers sélectionnés en quarantaine ?");

    /// <summary>The body of the quarantine confirmation.</summary>
    public static string ScanQuarantineBody => Pick(
        "Lumen will copy the selected files into the encrypted quarantine vault, verify the encrypted copy, and then remove the original. You can restore each file later. Files are never uploaded.",
        "Lumen va copier les fichiers sélectionnés dans le coffre chiffré, vérifier la copie chiffrée, puis supprimer l'original. Vous pourrez restaurer chaque fichier. Les fichiers ne sont jamais envoyés.");

    /// <summary>The confirmation button of the quarantine dialog for one file.</summary>
    public static string ScanQuarantineConfirmOne => Pick("Quarantine file", "Mettre en quarantaine");

    /// <summary>The confirmation button of the quarantine dialog for several files.</summary>
    public static string ScanQuarantineConfirmMany(int count) => Pick(
        $"Quarantine {count} files",
        $"Mettre {count} fichiers en quarantaine");

    /// <summary>The banner title while files are being quarantined.</summary>
    public static string ScanQuarantineRunningTitle => Pick(
        "Quarantining files",
        "Mise en quarantaine");

    /// <summary>The banner body while files are being quarantined.</summary>
    public static string ScanQuarantineRunningBody(int count) => Pick(
        $"Encrypting {count} file(s). Keep Lumen open until this finishes.",
        $"Chiffrement de {count} fichier(s). Gardez Lumen ouvert jusqu'à la fin.");

    /// <summary>The banner title when the quarantine finished.</summary>
    public static string ScanQuarantineDoneTitle => Pick("Quarantine finished", "Mise en quarantaine terminée");

    /// <summary>The banner body when the quarantine finished.</summary>
    public static string ScanQuarantineDoneBody(int count) => Pick(
        $"{count} file(s) moved into the encrypted vault.",
        $"{count} fichier(s) déplacé(s) dans le coffre chiffré.");

    /// <summary>The banner body when an original could not be removed.</summary>
    public static string ScanQuarantineRetainedBody(int count) => Pick(
        $"The encrypted copy was preserved for {count} item(s), but the original could not be removed. Close any program using it and delete it manually.",
        $"La copie chiffrée a été conservée pour {count} élément(s), mais l'original n'a pas pu être supprimé. Fermez le programme qui l'utilise et supprimez-le à la main.");

    /// <summary>The banner title when the quarantine finished with problems.</summary>
    public static string ScanQuarantineWarnTitle => Pick(
        "Quarantine finished with warnings",
        "Mise en quarantaine terminée avec des avertissements");

    /// <summary>The banner body when the quarantine finished with problems.</summary>
    public static string ScanQuarantineWarnBody(int quarantined, int skipped, int failed) => Pick(
        $"{quarantined} quarantined, {skipped} skipped, {failed} failed. Originals were kept for every item that was not quarantined.",
        $"{quarantined} en quarantaine, {skipped} ignoré(s), {failed} en échec. Les originaux ont été conservés pour chaque élément non mis en quarantaine.");

    /// <summary>The title of the quarantine results dialog.</summary>
    public static string ScanQuarantineResultsTitle => Pick("Quarantine results", "Résultats de la quarantaine");

    /// <summary>The detail line about retained copies.</summary>
    public static string ScanRetainedDetail => Pick(
        "Encrypted copy created, original still present:",
        "Copie chiffrée créée, original toujours présent :");

    /// <summary>The detail line about failures.</summary>
    public static string ScanFailedDetail => Pick("Could not be quarantined:", "Ont échoué :");

    /// <summary>The "and N more" line.</summary>
    public static string ScanAndMore(int count) => Pick($"…and {count} more", $"…et {count} de plus");

    /// <summary>The title of the "file changed since the scan" confirmation.</summary>
    public static string ScanChangedTitle => Pick(
        "This file changed since the scan",
        "Ce fichier a changé depuis l'analyse");

    /// <summary>The body of the "file changed since the scan" confirmation.</summary>
    public static string ScanChangedBody => Pick(
        "The file no longer matches the content Lumen inspected. Quarantining now would preserve the unreviewed current content. Do you want to quarantine the current content anyway?",
        "Le fichier ne correspond plus au contenu que Lumen a inspecté. Une mise en quarantaine conserverait le contenu actuel, non examiné. Voulez-vous malgré tout mettre en quarantaine le contenu actuel ?");

    /// <summary>The confirmation button of the "file changed" dialog.</summary>
    public static string ScanChangedConfirm => Pick(
        "Quarantine current content",
        "Mettre le contenu actuel en quarantaine");

    /// <summary>The banner title when a path was copied.</summary>
    public static string ScanPathCopiedTitle => Pick("Path copied", "Chemin copié");

    /// <summary>The banner body when a path was copied.</summary>
    public static string ScanPathCopiedBody => Pick(
        "The full file path was copied to the clipboard.",
        "Le chemin complet du fichier a été copié dans le presse-papiers.");

    /// <summary>The banner title when a path could not be copied.</summary>
    public static string ScanPathCopyFailedTitle => Pick(
        "Could not copy the path",
        "Impossible de copier le chemin");

    /// <summary>The banner body when a path could not be copied.</summary>
    public static string ScanPathCopyFailedBody => Pick(
        "The clipboard is unavailable right now.",
        "Le presse-papiers est indisponible pour le moment.");

    /// <summary>The title of the "file not found" message.</summary>
    public static string ScanFileNotFoundTitle => Pick("File not found", "Fichier introuvable");

    /// <summary>The body of the "file not found" message.</summary>
    public static string ScanFileNotFoundBody => Pick(
        "That file is no longer at its original location. If you quarantined it, use the Quarantine page to restore it.",
        "Ce fichier n'est plus à son emplacement d'origine. Si vous l'avez mis en quarantaine, utilisez la page Quarantaine pour le restaurer.");

    /// <summary>The banner title when the history could not be saved.</summary>
    public static string ScanHistorySaveFailedTitle => Pick(
        "Scan history could not be saved",
        "L'historique des analyses n'a pas pu être enregistré");

    /// <summary>The banner body when the history could not be saved.</summary>
    public static string ScanHistorySaveFailedBody => Pick(
        "The result is shown here, but it may not appear in History.",
        "Le résultat est affiché ici, mais il peut ne pas apparaître dans l'historique.");

    /// <summary>The tray notification title of a cancelled scan.</summary>
    public static string ScanTrayCancelled => Pick("Scan cancelled", "Analyse annulée");

    /// <summary>The tray notification title of a scan with findings.</summary>
    public static string ScanTrayReview => Pick(
        "Scan complete — review needed",
        "Analyse terminée — vérification nécessaire");

    /// <summary>The tray notification title of a clean scan.</summary>
    public static string ScanTrayComplete => Pick("Scan complete", "Analyse terminée");

    /// <summary>The tray notification body of a cancelled scan.</summary>
    public static string ScanTrayCancelledBody => Pick(
        "The scan stopped early. Open Lumen to review partial results.",
        "L'analyse s'est arrêtée plus tôt. Ouvrez Lumen pour examiner les résultats partiels.");

    /// <summary>The tray notification body of a scan with findings.</summary>
    public static string ScanTrayFoundBody(int count) => Pick(
        $"{count} potential issue(s) found. Nothing was changed.",
        $"{count} problème(s) potentiel(s) détecté(s). Rien n'a été modifié.");

    /// <summary>The tray notification body of a clean scan.</summary>
    public static string ScanTrayCleanBody => Pick(
        "No matches for Lumen's limited rules. Open Lumen for details.",
        "Aucune correspondance avec les règles limitées de Lumen. Ouvrez Lumen pour plus de détails.");

    // ----------------------------------------------------------------------
    // Quarantine page
    // ----------------------------------------------------------------------

    /// <summary>The quarantine page title.</summary>
    public static string QuarantineTitle => Pick("Quarantine", "Quarantaine");

    /// <summary>The quarantine page subtitle.</summary>
    public static string QuarantineSubtitle => Pick(
        "Encrypted, integrity-checked copies that only you can restore or delete.",
        "Copies chiffrées et vérifiées, que vous seul pouvez restaurer ou supprimer.");

    /// <summary>The button that opens the vault folder.</summary>
    public static string QuarantineOpenVault => Pick("Open vault folder", "Ouvrir le dossier du coffre");

    /// <summary>The tooltip of the refresh button.</summary>
    public static string QuarantineRefreshVault => Pick("Refresh the vault", "Actualiser le coffre");

    /// <summary>The title of the "vault data could not be read" banner.</summary>
    public static string QuarantineReadWarningTitle => Pick(
        "Some quarantine data could not be read",
        "Certaines données de quarantaine n'ont pas pu être lues");

    /// <summary>The title of the empty vault card.</summary>
    public static string QuarantineEmptyTitle => Pick("The vault is empty", "Le coffre est vide");

    /// <summary>The body of the empty vault card.</summary>
    public static string QuarantineEmptyBody => Pick(
        "Files you choose to quarantine are encrypted with AES-256, integrity-checked, and kept here until you restore or delete them.",
        "Les fichiers que vous mettez en quarantaine sont chiffrés en AES-256, vérifiés, et conservés ici jusqu'à ce que vous les restauriez ou les supprimiez.");

    /// <summary>The button that goes to the scan page from the empty vault.</summary>
    public static string QuarantineRunScan => Pick("Run a scan", "Lancer une analyse");

    /// <summary>The title of the vault list.</summary>
    public static string QuarantineEncryptedItems => Pick("Encrypted items", "Éléments chiffrés");

    /// <summary>The note shown when the original file still exists.</summary>
    public static string QuarantineOriginalExists => Pick(
        "The original file still exists at its original location. It was not removed when the copy was quarantined.",
        "Le fichier original existe toujours à son emplacement d'origine. Il n'a pas été supprimé lors de la mise en quarantaine de la copie.");

    /// <summary>The label of the note block.</summary>
    public static string QuarantineNote => Pick("Note", "Note");

    /// <summary>The label of the quarantine date.</summary>
    public static string QuarantineDate => Pick("Quarantined", "Mis en quarantaine");

    /// <summary>The label of the size field.</summary>
    public static string QuarantineSize => Pick("Size", "Taille");

    /// <summary>The button that restores the file.</summary>
    public static string QuarantineRestore => Pick("Restore", "Restaurer");

    /// <summary>The button that restores the file somewhere else.</summary>
    public static string QuarantineRestoreTo => Pick("Restore to…", "Restaurer vers…");

    /// <summary>The button that deletes the encrypted copy.</summary>
    public static string QuarantineDelete => Pick("Delete permanently", "Supprimer définitivement");

    /// <summary>The button that reveals the original file.</summary>
    public static string QuarantineShowOriginal => Pick("Show original", "Afficher l'original");

    /// <summary>The button that copies the original path.</summary>
    public static string QuarantineCopyPath => Pick("Copy original path", "Copier le chemin d'origine");

    /// <summary>The explanation of what restoring does.</summary>
    public static string QuarantineRestoreExplainer => Pick(
        "Restore decrypts the copy, verifies its SHA-256 hash, and only then writes the file. The encrypted copy is kept if verification fails.",
        "La restauration déchiffre la copie, vérifie son empreinte SHA-256, puis seulement écrit le fichier. La copie chiffrée est conservée si la vérification échoue.");

    /// <summary>The empty state of the detail pane.</summary>
    public static string QuarantineSelectItem => Pick(
        "Select an item to review it",
        "Sélectionnez un élément pour l'examiner");

    /// <summary>The technical note about the vault encryption.</summary>
    public static string QuarantineVaultTech => Pick(
        "AES-256-CBC encryption · HMAC-SHA256 integrity · per-user DPAPI-protected keys",
        "Chiffrement AES-256-CBC · intégrité HMAC-SHA256 · clés protégées par DPAPI par utilisateur");

    /// <summary>The button that opens the vault folder in the footer.</summary>
    public static string QuarantineOpenFolder => Pick("Open folder", "Ouvrir le dossier");

    /// <summary>The remediation action offered on a quarantine item.</summary>
    public static string QuarantineCleanFile => Pick("Clean the file", "Nettoyer le fichier");

    /// <summary>The vault summary when it is empty.</summary>
    public static string QuarantineSummaryEmpty => Pick(
        "Nothing is quarantined.",
        "Rien n'est en quarantaine.");

    /// <summary>The vault summary when it holds items.</summary>
    public static string QuarantineSummary(int count) => Pick(
        $"{count} encrypted file(s) isolated in this account's encrypted vault.",
        $"{count} fichier(s) chiffré(s) isolé(s) dans le coffre chiffré de ce compte.");

    /// <summary>The quarantine count chip.</summary>
    public static string QuarantineCountChip(int count) => Pick(
        $"{count} encrypted file(s)",
        $"{count} fichier(s) chiffré(s)");

    /// <summary>The title of the restore confirmation.</summary>
    public static string RestoreTitle => Pick("Restore this file?", "Restaurer ce fichier ?");

    /// <summary>The body of the restore confirmation.</summary>
    public static string RestoreBody => Pick(
        "Lumen will decrypt the encrypted copy, verify its SHA-256 hash, and write it back. If the original folder no longer exists, you will be asked where to put the file.",
        "Lumen va déchiffrer la copie, vérifier son empreinte SHA-256 et la réécrire. Si le dossier d'origine n'existe plus, on vous demandera où la placer.");

    /// <summary>The detail prefix of the restore confirmation.</summary>
    public static string RestoreOriginalPrefix => Pick(
        "Original location: ",
        "Emplacement d'origine : ");

    /// <summary>The banner title when a file was restored.</summary>
    public static string RestoreDoneTitle => Pick("File restored", "Fichier restauré");

    /// <summary>The banner body when a file was restored.</summary>
    public static string RestoreDoneBody(string path) => Pick(
        $"The file was decrypted and verified at {path}",
        $"Le fichier a été déchiffré et vérifié dans {path}");

    /// <summary>The banner title when the restore failed.</summary>
    public static string RestoreFailedTitle => Pick("Restore failed", "Échec de la restauration");

    /// <summary>The banner body when the restore failed.</summary>
    public static string RestoreFailedBody => Pick(
        "The file could not be restored. The encrypted copy was kept.",
        "Le fichier n'a pas pu être restauré. La copie chiffrée a été conservée.");

    /// <summary>The banner title when the restore was cancelled.</summary>
    public static string RestoreCancelledTitle => Pick("Restore cancelled", "Restauration annulée");

    /// <summary>The banner body when the restore was cancelled.</summary>
    public static string RestoreCancelledBody => Pick("Nothing was written.", "Rien n'a été écrit.");

    /// <summary>The banner body when the restore was cancelled because the file was kept.</summary>
    public static string RestoreCancelledKeptBody => Pick(
        "The existing file was left in place. The quarantine item was not changed.",
        "Le fichier existant a été laissé en place. L'élément de quarantaine n'a pas été modifié.");

    /// <summary>The banner body when the encrypted copy was kept.</summary>
    public static string RestoreKeptBody => Pick(
        "The encrypted copy was kept. You can restore it later to a folder you choose.",
        "La copie chiffrée a été conservée. Vous pourrez la restaurer plus tard dans un dossier de votre choix.");

    /// <summary>The title of the "a file already exists" confirmation.</summary>
    public static string RestoreTargetExistsTitle => Pick(
        "A file already exists at the original location",
        "Un fichier existe déjà à l'emplacement d'origine");

    /// <summary>The body of the "a file already exists" confirmation.</summary>
    public static string RestoreTargetExistsBody => Pick(
        "Restoring will replace the current file with the verified quarantined copy. The current file cannot be recovered by Lumen.",
        "La restauration remplacera le fichier actuel par la copie vérifiée du coffre. Lumen ne pourra pas récupérer le fichier actuel.");

    /// <summary>The confirmation button of the "a file already exists" dialog.</summary>
    public static string RestoreReplaceConfirm => Pick(
        "Replace existing file",
        "Remplacer le fichier existant");

    /// <summary>The title of the "the original folder is gone" confirmation.</summary>
    public static string RestoreFolderGoneTitle => Pick(
        "The original folder no longer exists",
        "Le dossier d'origine n'existe plus");

    /// <summary>The body of the "the original folder is gone" confirmation.</summary>
    public static string RestoreFolderGoneBody => Pick(
        "The folder this file came from is gone. Choose another folder to restore the file into.",
        "Le dossier d'origine a disparu. Choisissez un autre dossier pour y restaurer le fichier.");

    /// <summary>The confirmation button of the "the original folder is gone" dialog.</summary>
    public static string RestoreChooseFolder => Pick("Choose folder", "Choisir un dossier");

    /// <summary>The title of the "replace the existing file" confirmation.</summary>
    public static string RestoreReplaceTitle => Pick("Replace the existing file?", "Remplacer le fichier existant ?");

    /// <summary>The body of the "replace the existing file" confirmation.</summary>
    public static string RestoreReplaceBody => Pick(
        "A file with this name already exists in the folder you chose. Replace it with the quarantined copy?",
        "Un fichier portant ce nom existe déjà dans le dossier choisi. Le remplacer par la copie du coffre ?");

    /// <summary>The confirmation button of the "replace the existing file" dialog.</summary>
    public static string RestoreReplaceFileConfirm => Pick("Replace file", "Remplacer le fichier");

    /// <summary>The title of the integrity-check failure.</summary>
    public static string RestoreCorruptTitle => Pick(
        "The encrypted copy failed verification",
        "La copie chiffrée n'a pas passé la vérification");

    /// <summary>The body of the integrity-check failure.</summary>
    public static string RestoreCorruptBody => Pick(
        "Lumen did not restore the file because the encrypted copy is incomplete or was modified. The quarantine item remains in the vault so the evidence is preserved. Do not delete it if you may need support.",
        "Lumen n'a pas restauré le fichier parce que la copie chiffrée est incomplète ou a été modifiée. L'élément reste dans le coffre afin de préserver la preuve. Ne le supprimez pas si vous avez besoin d'assistance.");

    /// <summary>The detail line of the integrity-check failure.</summary>
    public static string RestoreStatusPrefix => Pick("Status: ", "État : ");

    /// <summary>The banner title when the integrity check failed.</summary>
    public static string RestoreIntegrityTitle => Pick(
        "Restore failed integrity check",
        "Échec de la vérification d'intégrité");

    /// <summary>The banner body when the integrity check failed.</summary>
    public static string RestoreIntegrityBody => Pick(
        "Nothing was written. The quarantine item remains in the vault.",
        "Rien n'a été écrit. L'élément de quarantaine reste dans le coffre.");

    /// <summary>The banner title when the item was not found.</summary>
    public static string QuarantineItemNotFoundTitle => Pick("Item not found", "Élément introuvable");

    /// <summary>The title of the permanent-deletion confirmation.</summary>
    public static string QuarantineDeleteTitle => Pick(
        "Permanently delete this encrypted copy?",
        "Supprimer définitivement cette copie chiffrée ?");

    /// <summary>The body of the permanent-deletion confirmation.</summary>
    public static string QuarantineDeleteBody => Pick(
        "This deletes the encrypted vault file and its index entry. It cannot be undone. If the original file was removed when it was quarantined, the file will be gone permanently.",
        "Cela supprime le fichier du coffre chiffré et son entrée d'index. L'action est irréversible. Si l'original avait été supprimé lors de la mise en quarantaine, le fichier disparaîtra définitivement.");

    /// <summary>The confirmation button of the permanent-deletion dialog.</summary>
    public static string QuarantineDeleteConfirm => Pick("Delete permanently", "Supprimer définitivement");

    /// <summary>The detail line about the original still being present.</summary>
    public static string QuarantineOriginalPresentDetail => Pick(
        "The original file still exists at its original location because it could not be removed.",
        "Le fichier original existe toujours à son emplacement d'origine, car il n'a pas pu être supprimé.");

    /// <summary>The banner title when the item was deleted.</summary>
    public static string QuarantineDeletedTitle => Pick(
        "Quarantine item deleted",
        "Élément de quarantaine supprimé");

    /// <summary>The banner title when the deletion failed.</summary>
    public static string QuarantineDeleteFailedTitle => Pick("Delete failed", "Échec de la suppression");

    /// <summary>The banner body when the deletion failed.</summary>
    public static string QuarantineDeleteFailedBody => Pick(
        "The item could not be deleted.",
        "L'élément n'a pas pu être supprimé.");

    /// <summary>The title of the "original file not found" message.</summary>
    public static string QuarantineOriginalMissingTitle => Pick(
        "Original file not found",
        "Fichier original introuvable");

    /// <summary>The body of the "original file not found" message.</summary>
    public static string QuarantineOriginalMissingBody => Pick(
        "The original file is no longer at that location. Use Restore to write the quarantined copy to a folder you choose.",
        "Le fichier original n'est plus à cet emplacement. Utilisez Restaurer pour écrire la copie du coffre dans un dossier de votre choix.");

    /// <summary>The banner title when the vault folder could not be opened.</summary>
    public static string QuarantineFolderFailedTitle => Pick(
        "Folder could not be opened",
        "Impossible d'ouvrir le dossier");

    /// <summary>The banner body when the vault folder could not be opened.</summary>
    public static string QuarantineFolderFailedBody => Pick(
        "The quarantine folder could not be opened.",
        "Le dossier de quarantaine n'a pas pu être ouvert.");

    /// <summary>The banner title when a path was copied.</summary>
    public static string QuarantinePathCopiedTitle => Pick("Path copied", "Chemin copié");

    /// <summary>The banner body when a path was copied.</summary>
    public static string QuarantinePathCopiedBody => Pick(
        "The original path was copied to the clipboard.",
        "Le chemin d'origine a été copié dans le presse-papiers.");

    /// <summary>The banner title when a path could not be copied.</summary>
    public static string QuarantinePathCopyFailedTitle => Pick(
        "Could not copy the path",
        "Impossible de copier le chemin");

    /// <summary>The banner body when a path could not be copied.</summary>
    public static string QuarantinePathCopyFailedBody => Pick(
        "The clipboard is unavailable right now.",
        "Le presse-papiers est indisponible pour le moment.");

    /// <summary>The title of the folder picker.</summary>
    public static string RestoreFolderPickerTitle => Pick(
        "Choose a folder for the restored file",
        "Choisissez un dossier pour le fichier restauré");

    // ----------------------------------------------------------------------
    // History page
    // ----------------------------------------------------------------------

    /// <summary>The history page title.</summary>
    public static string HistoryTitle => Pick("History", "Historique");

    /// <summary>The button that clears the history.</summary>
    public static string HistoryClear => Pick("Clear history", "Effacer l'historique");

    /// <summary>The tooltip of the refresh button.</summary>
    public static string HistoryRefresh => Pick("Refresh scan history", "Actualiser l'historique des analyses");

    /// <summary>The title of the "history data could not be read" banner.</summary>
    public static string HistoryReadWarningTitle => Pick(
        "Some history data could not be read",
        "Certaines données d'historique n'ont pas pu être lues");

    /// <summary>The title of the empty history card.</summary>
    public static string HistoryEmptyTitle => Pick("No scan history yet", "Aucun historique d'analyse");

    /// <summary>The body of the empty history card.</summary>
    public static string HistoryEmptyBody => Pick(
        "Completed scans are recorded locally with their scope, counts and skipped items. File contents and paths are never written to the log.",
        "Les analyses terminées sont enregistrées localement avec leur portée, leurs compteurs et les éléments ignorés. Le contenu des fichiers et les chemins ne sont jamais écrits dans le journal.");

    /// <summary>The button that starts a quick scan from the empty history card.</summary>
    public static string HistoryRunQuickScan => Pick("Run a quick scan", "Lancer une analyse rapide");

    /// <summary>The title of the history list.</summary>
    public static string HistoryScans => Pick("Scans", "Analyses");

    /// <summary>The count of stored scans.</summary>
    public static string HistoryStored(int count) => Pick(
        $"{count:N0} stored",
        $"{count:N0} enregistrée(s)");

    /// <summary>The summary of the history page.</summary>
    public static string HistorySummary(int count) => Pick(
        $"{count} scan(s) stored locally on this device",
        $"{count} analyse(s) enregistrée(s) localement sur cet appareil");

    /// <summary>The summary of the history page when it is empty.</summary>
    public static string HistorySummaryEmpty => Pick("No scan history yet.", "Aucun historique d'analyse.");

    /// <summary>The label of the duration field.</summary>
    public static string HistoryDuration => Pick("Duration", "Durée");

    /// <summary>The label of the locations block.</summary>
    public static string HistoryLocations => Pick("Locations", "Emplacements");

    /// <summary>The placeholder when no location was recorded.</summary>
    public static string HistoryNoLocations => Pick("No locations recorded.", "Aucun emplacement enregistré.");

    /// <summary>The note when a scan recorded no skipped item.</summary>
    public static string HistoryNoSkipped => Pick(
        "No skipped items were recorded for this scan.",
        "Aucun élément ignoré n'a été enregistré pour cette analyse.");

    /// <summary>The caption of the skipped-item block when there are some.</summary>
    public static string HistorySkippedCount(int count) => Pick(
        $"{count:N0} skipped or unreadable item(s)",
        $"{count:N0} élément(s) ignoré(s) ou illisible(s)");

    /// <summary>The caption of the skipped-item block when there are none.</summary>
    public static string HistorySkippedNone => Pick(
        "No skipped items were recorded.",
        "Aucun élément ignoré n'a été enregistré.");

    /// <summary>The button that starts another quick scan.</summary>
    public static string HistoryRunAnother => Pick(
        "Run another quick scan",
        "Lancer une autre analyse rapide");

    /// <summary>The disclaimer under the history page.</summary>
    public static string HistoryFooter => Pick(
        "Scan history is stored in this Windows account's app data. Clearing it does not affect quarantined files.",
        "L'historique des analyses est enregistré dans les données d'application de ce compte Windows. L'effacer n'affecte pas les fichiers en quarantaine.");

    /// <summary>The title of the clear-history confirmation.</summary>
    public static string HistoryClearTitle => Pick("Clear scan history?", "Effacer l'historique des analyses ?");

    /// <summary>The body of the clear-history confirmation.</summary>
    public static string HistoryClearBody => Pick(
        "This deletes the local scan-history file. Quarantined files and their encrypted copies are not affected.",
        "Cela supprime le fichier local d'historique. Les fichiers en quarantaine et leurs copies chiffrées ne sont pas affectés.");

    /// <summary>The confirmation button of the clear-history dialog.</summary>
    public static string HistoryClearConfirm => Pick("Clear history", "Effacer l'historique");

    /// <summary>The banner title when the history could not be cleared.</summary>
    public static string HistoryClearFailedTitle => Pick(
        "History could not be cleared",
        "L'historique n'a pas pu être effacé");

    /// <summary>The banner body when the history could not be cleared.</summary>
    public static string HistoryClearFailedBody => Pick(
        "The local history file could not be updated.",
        "Le fichier local d'historique n'a pas pu être mis à jour.");

    /// <summary>The banner title when the history was cleared.</summary>
    public static string HistoryClearedTitle => Pick(
        "Scan history cleared",
        "Historique des analyses effacé");

    /// <summary>The banner body when the history was cleared.</summary>
    public static string HistoryClearedBody => Pick(
        "Local scan history was removed. Quarantined files were not changed.",
        "L'historique local a été supprimé. Les fichiers en quarantaine n'ont pas été modifiés.");

    // ----------------------------------------------------------------------
    // Settings page
    // ----------------------------------------------------------------------

    /// <summary>The settings page title.</summary>
    public static string SettingsTitle => Pick("Settings", "Réglages");

    /// <summary>The settings page subtitle.</summary>
    public static string SettingsSubtitle => Pick(
        "Tune the scanner and decide how Lumen behaves. Everything is stored locally in this Windows account.",
        "Ajustez l'analyse et le comportement de Lumen. Tout est enregistré localement dans ce compte Windows.");

    /// <summary>The badge that says the settings are saved automatically.</summary>
    public static string SettingsSavedAutomatically => Pick("SAVED AUTOMATICALLY", "ENREGISTREMENT AUTOMATIQUE");

    /// <summary>The title of the "a setting could not be saved" banner.</summary>
    public static string SettingsSaveErrorTitle => Pick(
        "A setting could not be saved",
        "Un réglage n'a pas pu être enregistré");

    /// <summary>The title of the appearance card.</summary>
    public static string SettingsAppearanceTitle => Pick("Appearance", "Apparence");

    /// <summary>The body of the appearance card.</summary>
    public static string SettingsAppearanceBody => Pick(
        "Choose a theme. High contrast mode from Windows always takes priority.",
        "Choisissez un thème. Le mode à contraste élevé de Windows reste prioritaire.");

    /// <summary>The system theme label.</summary>
    public static string SettingsThemeSystem => Pick("System", "Système");

    /// <summary>The light theme label.</summary>
    public static string SettingsThemeLight => Pick("Light", "Clair");

    /// <summary>The dark theme label.</summary>
    public static string SettingsThemeDark => Pick("Dark", "Sombre");

    /// <summary>The high-contrast theme label.</summary>
    public static string SettingsThemeHighContrast => Pick("High contrast", "Contraste élevé");

    /// <summary>The title of the scanning card.</summary>
    public static string SettingsScanningTitle => Pick("Scanning", "Analyse");

    /// <summary>The body of the scanning card.</summary>
    public static string SettingsScanningBody => Pick(
        "Controls how much of each file Lumen reads for its content rules.",
        "Contrôle la quantité de chaque fichier que Lumen lit pour ses règles de contenu.");

    /// <summary>The label of the content-prefix slider.</summary>
    public static string SettingsMaxPrefix => Pick(
        "Maximum content prefix per file",
        "Préfixe de contenu maximal par fichier");

    /// <summary>The tooltip of the content-prefix slider.</summary>
    public static string SettingsSliderTooltip => Pick("1 to 16 MB", "De 1 à 16 Mo");

    /// <summary>The explanation of the content-prefix slider.</summary>
    public static string SettingsInspectLimit(int megabytes) => Pick(
        $"Lumen reads at most {megabytes} MB from the start of each file for content checks. File-name rules still examine the full name. Contents are never uploaded or written to the log.",
        $"Lumen lit au plus {megabytes} Mo au début de chaque fichier pour les vérifications de contenu. Les règles de nom analysent toujours le nom complet. Le contenu n'est jamais envoyé ni écrit dans le journal.");

    /// <summary>The label of the logging switch.</summary>
    public static string SettingsLoggingLabel => Pick(
        "Write a local diagnostic log",
        "Écrire un journal de diagnostic local");

    /// <summary>The explanation of the logging switch.</summary>
    public static string SettingsLoggingBody => Pick(
        "Technical events only. File contents, hashes and user names are never logged.",
        "Événements techniques uniquement. Le contenu des fichiers, les empreintes et les noms d'utilisateur ne sont jamais journalisés.");

    /// <summary>The title of the window and tray card.</summary>
    public static string SettingsTrayTitle => Pick("Window and tray", "Fenêtre et zone de notification");

    /// <summary>The body of the window and tray card.</summary>
    public static string SettingsTrayBody => Pick(
        "The tray icon is optional. Every action remains available in the main window.",
        "L'icône de notification est facultative. Toutes les actions restent disponibles dans la fenêtre principale.");

    /// <summary>The label of the minimize-to-tray switch.</summary>
    public static string SettingsMinimizeToTrayLabel => Pick(
        "Keep Lumen in the notification area",
        "Garder Lumen dans la zone de notification");

    /// <summary>The explanation of the minimize-to-tray switch.</summary>
    public static string SettingsMinimizeToTrayBody => Pick(
        "Closing or minimizing the window hides it instead of exiting. Use the tray menu to exit.",
        "Fermer ou réduire la fenêtre la masque au lieu de quitter. Utilisez le menu de notification pour quitter.");

    /// <summary>The label of the tray-notification switch.</summary>
    public static string SettingsTrayNotificationsLabel => Pick(
        "Show scan notifications",
        "Afficher les notifications d'analyse");

    /// <summary>The explanation of the tray-notification switch.</summary>
    public static string SettingsTrayNotificationsBody => Pick(
        "A small notification when a scan finishes while Lumen is hidden.",
        "Une petite notification lorsqu'une analyse se termine pendant que Lumen est masqué.");

    /// <summary>The title of the real-time protection card.</summary>
    public static string SettingsRealtimeTitle => Pick(
        "Real-time protection",
        "Surveillance en temps réel");

    /// <summary>The body of the real-time protection card.</summary>
    public static string SettingsRealtimeBody => Pick(
        "While Lumen is open it re-checks new, changed and renamed files in your watched folders with the same documented rules used by on-demand scans. Files are only read; nothing is changed unless auto-quarantine is on.",
        "Tant que Lumen est ouvert, il réanalyse les fichiers nouveaux, modifiés et renommés de vos dossiers surveillés avec les mêmes règles documentées que les analyses à la demande. Les fichiers sont seulement lus ; rien n'est modifié sauf si la quarantaine automatique est activée.");

    /// <summary>The label of the real-time switch.</summary>
    public static string SettingsRealtimeLabel => Pick(
        "Watch the configured folders",
        "Surveiller les dossiers configurés");

    /// <summary>The explanation of the real-time switch when it is on.</summary>
    public static string SettingsRealtimeOnBody => Pick(
        "Watching the configured folders while Lumen runs.",
        "Les dossiers configurés sont surveillés tant que Lumen est ouvert.");

    /// <summary>The explanation of the real-time switch when it is off.</summary>
    public static string SettingsRealtimeOffBody => Pick(
        "Paused. New and changed files are only checked during scans.",
        "En pause. Les fichiers nouveaux et modifiés ne sont vérifiés que pendant les analyses.");

    /// <summary>The label of the auto-quarantine switch.</summary>
    public static string SettingsAutoQuarantineLabel => Pick(
        "Quarantine matches automatically",
        "Mettre les correspondances en quarantaine automatiquement");

    /// <summary>The explanation of the auto-quarantine switch.</summary>
    public static string SettingsAutoQuarantineBody => Pick(
        "Matched files are moved into the encrypted vault without an extra prompt. With this off, Lumen only notifies you and never touches the file.",
        "Les fichiers correspondants sont déplacés dans le coffre chiffré sans question supplémentaire. Si cette option est désactivée, Lumen se contente de vous prévenir et ne touche jamais au fichier.");

    /// <summary>The footnote of the real-time protection card.</summary>
    public static string SettingsRealtimeFootnote => Pick(
        "This is a user-mode folder watcher, not a driver. It cannot see activity in system folders or outside your user profile, and it only runs while Lumen is open. Keep Microsoft Defender on.",
        "Il s'agit d'un observateur de dossiers en mode utilisateur, pas un pilote. Il ne voit rien dans les dossiers système ni hors de votre profil, et ne fonctionne que tant que Lumen est ouvert. Gardez Microsoft Defender activé.");

    /// <summary>The title of the language card.</summary>
    public static string SettingsLanguageTitle => Pick("Language", "Langue");

    /// <summary>The body of the language card.</summary>
    public static string SettingsLanguageBody => Pick(
        "Choose the language of the interface. The change applies immediately, without a restart.",
        "Choisissez la langue de l'interface. Le changement s'applique immédiatement, sans redémarrage.");

    /// <summary>The English language label.</summary>
    public static string SettingsLanguageEnglish => Pick("English", "English");

    /// <summary>The French language label.</summary>
    public static string SettingsLanguageFrench => Pick("Français", "Français");

    /// <summary>The title of the watched-folders card.</summary>
    public static string SettingsWatchedTitle => Pick(
        "Watched folders",
        "Dossiers surveillés");

    /// <summary>The body of the watched-folders card.</summary>
    public static string SettingsWatchedBody => Pick(
        "Extra folders the real-time monitor watches, in addition to the standard quick-scan folders. Paths that do not exist are ignored.",
        "Dossiers supplémentaires surveillés par le moniteur en temps réel, en plus des dossiers habituels de l'analyse rapide. Les chemins inexistants sont ignorés.");

    /// <summary>The title of the excluded-folders card.</summary>
    public static string SettingsExcludedTitle => Pick(
        "Excluded folders",
        "Dossiers exclus");

    /// <summary>The body of the excluded-folders card.</summary>
    public static string SettingsExcludedBody => Pick(
        "Folders whose entire subtree the real-time monitor skips. Use this for build caches and tool directories that are noisy but harmless.",
        "Dossiers dont toute la sous-arborescence est ignorée par le moniteur. Utilisez-les pour les caches de compilation et les répertoires d'outils bruyants mais inoffensifs.");

    /// <summary>The button that adds a watched or excluded folder.</summary>
    public static string SettingsAddFolder => Pick("Add folder…", "Ajouter un dossier…");

    /// <summary>The button that removes a watched or excluded folder.</summary>
    public static string SettingsRemoveFolder => Pick("Remove", "Retirer");

    /// <summary>The empty state of the watched-folders list.</summary>
    public static string SettingsNoWatched => Pick(
        "Only the standard quick-scan folders are watched.",
        "Seuls les dossiers habituels de l'analyse rapide sont surveillés.");

    /// <summary>The empty state of the excluded-folders list.</summary>
    public static string SettingsNoExcluded => Pick(
        "No folder is excluded.",
        "Aucun dossier n'est exclu.");

    /// <summary>The title of the folder picker for a watched folder.</summary>
    public static string SettingsPickWatchedTitle => Pick(
        "Choose a folder to watch",
        "Choisissez un dossier à surveiller");

    /// <summary>The title of the folder picker for an excluded folder.</summary>
    public static string SettingsPickExcludedTitle => Pick(
        "Choose a folder to exclude",
        "Choisissez un dossier à exclure");

    /// <summary>The title of the remediation card.</summary>
    public static string SettingsRemediationTitle => Pick("Remediation", "Remédiation");

    /// <summary>The body of the remediation card.</summary>
    public static string SettingsRemediationBody => Pick(
        "Let Lumen clean up a detection: stop the processes that use the file, remove the file permanently, and delete the autostart entries that point at it. Everything is presented as a plan that you confirm before anything happens.",
        "Autorisez Lumen à nettoyer une détection : arrêter les processus qui utilisent le fichier, supprimer le fichier définitivement et effacer les entrées de démarrage automatique qui pointent vers lui. Tout est présenté sous forme de plan que vous confirmez avant toute action.");

    /// <summary>The warning inside the remediation card.</summary>
    public static string SettingsRemediationWarning => Pick(
        "Warning: when this is on, Lumen can stop processes and delete files permanently. A file removed this way is not recoverable, except from the encrypted quarantine vault.",
        "Attention : lorsque cette option est active, Lumen peut arrêter des processus et supprimer des fichiers définitivement. Un fichier supprimé ainsi n'est pas récupérable, sauf depuis le coffre chiffré.");

    /// <summary>The label of the remediation switch.</summary>
    public static string SettingsRemediationLabel => Pick(
        "Allow remediation actions",
        "Autoriser les actions de remédiation");

    /// <summary>The explanation of the remediation switch.</summary>
    public static string SettingsRemediationSwitchBody => Pick(
        "Off by default. With this on, the Clean action appears on the Scan and Quarantine pages.",
        "Désactivée par défaut. Lorsque cette option est active, l'action Nettoyer apparaît sur les pages Analyse et Quarantaine.");

    /// <summary>The title of the detection-alert card.</summary>
    public static string SettingsAlertTitle => Pick("Detection alert", "Alerte de détection");

    /// <summary>The body of the detection-alert card.</summary>
    public static string SettingsAlertBody => Pick(
        "Lumen can raise a full-screen alert when something is flagged, so a detection is never missed in a crowded window.",
        "Lumen peut afficher une alerte plein écran lorsqu'un élément est signalé, afin qu'une détection ne passe jamais inaperçue.");

    /// <summary>The label of the "show the alert" switch.</summary>
    public static string SettingsAlertShowLabel => Pick(
        "Show the detection alert",
        "Afficher l'alerte de détection");

    /// <summary>The explanation of the "show the alert" switch.</summary>
    public static string SettingsAlertShowBody => Pick(
        "A window appears as soon as a file matches a rule.",
        "Une fenêtre apparaît dès qu'un fichier correspond à une règle.");

    /// <summary>The label of the "play the sound" switch.</summary>
    public static string SettingsAlertSoundLabel => Pick(
        "Play the alert sound",
        "Jouer le son d'alerte");

    /// <summary>The explanation of the "play the sound" switch.</summary>
    public static string SettingsAlertSoundBody => Pick(
        "Off by default: an unexpected noise on someone's machine is rude.",
        "Désactivé par défaut : un bruit inattendu sur la machine de quelqu'un est déplacé.");

    /// <summary>The label of the "show the cat" switch.</summary>
    public static string SettingsAlertCatLabel => Pick("Show the cat", "Afficher le chat");

    /// <summary>The explanation of the "show the cat" switch.</summary>
    public static string SettingsAlertCatBody => Pick(
        "It has no effect on any detection. It is there because a security tool that takes itself too seriously is a security tool nobody wants to open.",
        "Cela n'a aucun effet sur les détections. C'est là parce qu'un logiciel de sécurité qui se prend trop au sérieux est un logiciel que personne n'ouvre.");

    /// <summary>The title of the Defender card.</summary>
    public static string SettingsDefenderTitle => Pick("Microsoft Defender", "Microsoft Defender");

    /// <summary>The body of the Defender card.</summary>
    public static string SettingsDefenderBody => Pick(
        "Read-only status. Lumen never changes Defender settings.",
        "État en lecture seule. Lumen ne modifie jamais les réglages de Defender.");

    /// <summary>The title of the detection-rules card.</summary>
    public static string SettingsRulesTitle => Pick("Detection rules", "Règles de détection");

    /// <summary>The body of the detection-rules card.</summary>
    public static string SettingsRulesBody => Pick(
        "These rules are documented and cover signatures, heuristics, archives, documents and scripts. They are not a malware signature database.",
        "Ces règles sont documentées et couvrent les signatures, les heuristiques, les archives, les documents et les scripts. Ce n'est pas une base de signatures de logiciels malveillants.");

    /// <summary>The chip that marks the test-signature rules.</summary>
    public static string SettingsTestSignature => Pick("Test signature", "Signature de test");

    /// <summary>The count of documented rules.</summary>
    public static string SettingsRulesCount(int count) => Pick(
        $"{count:N0} documented rules",
        $"{count:N0} règles documentées");

    /// <summary>The title of the data and privacy card.</summary>
    public static string SettingsDataTitle => Pick("Data and privacy", "Données et confidentialité");

    /// <summary>The body of the data and privacy card.</summary>
    public static string SettingsDataBody => Pick(
        "Lumen keeps its state under this account's local app data. It does not write to its install folder.",
        "Lumen conserve ses données dans les données d'application locales de ce compte. Il n'écrit jamais dans son dossier d'installation.");

    /// <summary>The label of the settings, history and logs row.</summary>
    public static string SettingsDataRow => Pick(
        "Settings, history and logs",
        "Réglages, historique et journaux");

    /// <summary>The label of the encrypted quarantine row.</summary>
    public static string SettingsQuarantineRow => Pick(
        "Encrypted quarantine",
        "Quarantaine chiffrée");

    /// <summary>The label of the diagnostic log row.</summary>
    public static string SettingsLogRow => Pick("Diagnostic log", "Journal de diagnostic");

    /// <summary>The button that opens a folder.</summary>
    public static string SettingsOpen => Pick("Open", "Ouvrir");

    /// <summary>The title of the test-tools card.</summary>
    public static string SettingsTestToolsTitle => Pick("Test tools", "Outils de test");

    /// <summary>The body of the test-tools card.</summary>
    public static string SettingsTestToolsBody => Pick(
        "Create harmless files to verify that scanning, findings and quarantine work end to end.",
        "Créez des fichiers sans danger pour vérifier que l'analyse, les détections et la quarantaine fonctionnent de bout en bout.");

    /// <summary>The title of the harmless-files banner.</summary>
    public static string SettingsHarmlessTitle => Pick("These files are harmless", "Ces fichiers sont sans danger");

    /// <summary>The body of the harmless-files banner.</summary>
    public static string SettingsHarmlessBody => Pick(
        "EICAR is a standard antivirus test string, not malware, but Microsoft Defender may quarantine it immediately. Use only a folder you control, preferably inside a test VM.",
        "EICAR est une chaîne de test standard pour les antivirus, pas un logiciel malveillant, mais Microsoft Defender peut le mettre en quarantaine immédiatement. Utilisez uniquement un dossier que vous contrôlez, de préférence dans une machine virtuelle de test.");

    /// <summary>The label of the benign-samples row.</summary>
    public static string SettingsSamplesLabel => Pick("Benign test files", "Fichiers de test inoffensifs");

    /// <summary>The explanation of the benign-samples row.</summary>
    public static string SettingsSamplesBody => Pick(
        "Plain text plus a deceptive double-extension name. None are executable.",
        "Du texte simple ainsi qu'un nom à double extension trompeuse. Aucun n'est exécutable.");

    /// <summary>The button that creates the benign samples.</summary>
    public static string SettingsCreateSamples => Pick("Create samples…", "Créer des exemples…");

    /// <summary>The label of the EICAR row.</summary>
    public static string SettingsEicarLabel => Pick("EICAR test file", "Fichier de test EICAR");

    /// <summary>The explanation of the EICAR row.</summary>
    public static string SettingsEicarBody => Pick(
        "The industry-standard scanner plumbing test. Defender may remove it at once.",
        "Le test standard de la mécanique de l'analyse. Defender peut le supprimer aussitôt.");

    /// <summary>The button that creates the EICAR file.</summary>
    public static string SettingsCreateEicar => Pick("Create EICAR…", "Créer EICAR…");

    /// <summary>The title of the about card.</summary>
    public static string SettingsAboutTitle => Pick("About Lumen", "À propos de Lumen");

    /// <summary>The disclaimer under the about text.</summary>
    public static string SettingsAboutFooter => Pick(
        "Keep Microsoft Defender enabled. Lumen's real-time protection is a user-mode folder watcher that runs only while the app is open; it is not a driver, cloud analysis or a full malware signature database.",
        "Laissez Microsoft Defender activé. La surveillance en temps réel de Lumen est un observateur de dossiers en mode utilisateur, actif uniquement tant que l'application est ouverte ; ce n'est ni un pilote, ni une analyse dans le cloud, ni une base complète de signatures.");

    /// <summary>The button that restores the default settings.</summary>
    public static string SettingsRestoreDefaults => Pick("Restore defaults", "Rétablir les valeurs par défaut");

    /// <summary>The footer of the settings page.</summary>
    public static string SettingsFooter => Pick(
        "Settings are saved to this Windows account only. No account, cloud sync or telemetry is used.",
        "Les réglages sont enregistrés uniquement dans ce compte Windows. Aucun compte, aucune synchronisation cloud, aucune télémétrie.");

    /// <summary>The version label.</summary>
    public static string SettingsVersion(string version) => Pick($"Version {version}", $"Version {version}");

    /// <summary>The body of the about card.</summary>
    public static string SettingsAboutBody => Pick(
        "Lumen is a transparent, local file inspector. It runs on-demand scans and, when real-time protection is on, re-checks new and changed files in your watched folders while the app is open. It does not install a driver, monitor system folders, upload files, or change Microsoft Defender settings. Its rules are documented, so a clean result is not proof that a file is safe.",
        "Lumen est un inspecteur de fichiers local et transparent. Il lance des analyses à la demande et, lorsque la surveillance en temps réel est active, réanalyse les fichiers nouveaux et modifiés de vos dossiers surveillés pendant que l'application est ouverte. Il n'installe aucun pilote, ne surveille pas les dossiers système, n'envoie aucun fichier et ne modifie pas les réglages de Microsoft Defender. Ses règles sont documentées : un résultat propre ne prouve pas qu'un fichier est sûr.");

    /// <summary>The title of the restore-defaults confirmation.</summary>
    public static string SettingsResetTitle => Pick(
        "Restore default settings?",
        "Rétablir les réglages par défaut ?");

    /// <summary>The body of the restore-defaults confirmation.</summary>
    public static string SettingsResetBody => Pick(
        "Theme, logging, tray behavior and content-inspection size will return to their defaults. Scan history and quarantined files are not affected.",
        "Le thème, la journalisation, le comportement de la zone de notification et la taille d'inspection reviennent à leurs valeurs par défaut. L'historique des analyses et les fichiers en quarantaine ne sont pas affectés.");

    /// <summary>The confirmation button of the restore-defaults dialog.</summary>
    public static string SettingsResetConfirm => Pick("Restore defaults", "Rétablir");

    /// <summary>The body of the "folder could not be opened" error.</summary>
    public static string SettingsFolderFailed => Pick(
        "That folder could not be opened.",
        "Ce dossier n'a pas pu être ouvert.");

    /// <summary>The body of the "settings could not be saved" error.</summary>
    public static string SettingsSaveFailed => Pick(
        "The setting could not be saved.",
        "Le réglage n'a pas pu être enregistré.");

    /// <summary>The title of the "Windows Security could not be opened" message.</summary>
    public static string WindowsSecurityFailedTitle => Pick(
        "Windows Security could not be opened",
        "Impossible d'ouvrir la sécurité Windows");

    /// <summary>The body of the "Windows Security could not be opened" message.</summary>
    public static string WindowsSecurityFailedBody => Pick(
        "This system may not include the Windows Security app. Microsoft Defender settings can also be managed by your organization.",
        "Ce système ne comporte peut-être pas l'application Sécurité Windows. Les réglages de Microsoft Defender peuvent aussi être gérés par votre organisation.");

    /// <summary>The body of the "Windows Security could not be opened" message in Settings.</summary>
    public static string WindowsSecurityFailedBodyShort => Pick(
        "This system may not include the Windows Security app.",
        "Ce système ne comporte peut-être pas l'application Sécurité Windows.");

    /// <summary>The title of the sample-creation message.</summary>
    public static string SamplesCreatedTitle => Pick(
        "Harmless test files created",
        "Fichiers de test sans danger créés");

    /// <summary>The body of the sample-creation confirmation.</summary>
    public static string SamplesCreatedBody => Pick(
        "The folder now contains plain-text files plus one deceptive double-extension name for testing Lumen's file-name rule. None of them is executable or malicious. Do you want to open a folder scan for this location?",
        "Le dossier contient maintenant des fichiers texte simples ainsi qu'un nom à double extension trompeuse pour tester la règle de nom de Lumen. Aucun n'est exécutable ni malveillant. Voulez-vous ouvrir une analyse de dossier sur cet emplacement ?");

    /// <summary>The confirmation button of the sample-creation dialog.</summary>
    public static string SamplesCreatedConfirm => Pick("Scan test folder", "Analyser le dossier de test");

    /// <summary>The title of the "test files could not be created" message.</summary>
    public static string SamplesFailedTitle => Pick(
        "Test files could not be created",
        "Les fichiers de test n'ont pas pu être créés");

    /// <summary>The title of the folder picker for the test files.</summary>
    public static string SamplesFolderTitle => Pick(
        "Choose a folder for harmless test files",
        "Choisissez un dossier pour les fichiers de test sans danger");

    /// <summary>The title of the EICAR creation confirmation.</summary>
    public static string EicarCreateTitle => Pick("Create the EICAR test file?", "Créer le fichier de test EICAR ?");

    /// <summary>The body of the EICAR creation confirmation.</summary>
    public static string EicarCreateBody => Pick(
        "EICAR is a harmless, industry-standard antivirus test string, not malware. Microsoft Defender may quarantine the file immediately and record an event. Only create it in a folder you control, preferably inside a test VM.",
        "EICAR est une chaîne de test standard pour les antivirus, sans danger et non malveillante. Microsoft Defender peut la mettre en quarantaine immédiatement et enregistrer un événement. Ne la créez que dans un dossier que vous contrôlez, de préférence dans une machine virtuelle de test.");

    /// <summary>The confirmation button of the EICAR creation dialog.</summary>
    public static string EicarCreateConfirm => Pick("Create EICAR file", "Créer le fichier EICAR");

    /// <summary>The title of the folder picker for the EICAR file.</summary>
    public static string EicarFolderTitle => Pick(
        "Choose a folder for the EICAR test file",
        "Choisissez un dossier pour le fichier de test EICAR");

    /// <summary>The title of the "EICAR file could not be created" message.</summary>
    public static string EicarFailedTitle => Pick(
        "EICAR test file could not be created",
        "Le fichier de test EICAR n'a pas pu être créé");

    /// <summary>The title of the EICAR creation success dialog.</summary>
    public static string EicarCreatedTitle => Pick("EICAR test file created", "Fichier de test EICAR créé");

    /// <summary>The body of the EICAR creation success dialog.</summary>
    public static string EicarCreatedBody => Pick(
        "If Microsoft Defender did not remove the file, a Lumen scan should report the EICAR test signature. This verifies scanner plumbing only and says nothing about real malware. Open a folder scan now?",
        "Si Microsoft Defender n'a pas supprimé le fichier, une analyse Lumen devrait signaler la signature de test EICAR. Cela ne vérifie que la mécanique de l'analyse et ne dit rien du vrai logiciel malveillant. Ouvrir une analyse de dossier ?");

    // ----------------------------------------------------------------------
    // Defender status
    // ----------------------------------------------------------------------

    /// <summary>The Defender title while the status is being read.</summary>
    public static string DefenderChecking => Pick("Checking Windows Security…", "Consultation de la sécurité Windows…");

    /// <summary>The Defender title when the status is unavailable.</summary>
    public static string DefenderUnavailable => Pick("Status unavailable", "État indisponible");

    /// <summary>The Defender title when real-time protection is on.</summary>
    public static string DefenderOn => Pick("Real-time protection is on", "La protection en temps réel est active");

    /// <summary>The Defender title when real-time protection is off.</summary>
    public static string DefenderOff => Pick("Real-time protection is off", "La protection en temps réel est désactivée");

    /// <summary>The Defender body when the status is unavailable.</summary>
    public static string DefenderDetailFallback => Pick(
        "Lumen reads Microsoft Defender status but never changes it.",
        "Lumen lit l'état de Microsoft Defender mais ne le modifie jamais.");

    /// <summary>The Defender badge while the status is being read.</summary>
    public static string DefenderBadgeChecking => Pick("Checking", "Lecture");

    /// <summary>The Defender badge when the status is unavailable.</summary>
    public static string DefenderBadgeUnknown => Pick("Unknown", "Inconnu");

    /// <summary>The Defender badge when real-time protection is on.</summary>
    public static string DefenderBadgeOn => Pick("On", "Active");

    /// <summary>The Defender badge when real-time protection is off.</summary>
    public static string DefenderBadgeOff => Pick("Off", "Désactivée");

    /// <summary>The Defender detail about the last check.</summary>
    public static string DefenderChecked(string when) => Pick(
        $"Read-only status checked {when}",
        $"État en lecture seule consulté {when}");

    /// <summary>The Defender error when the check was cancelled.</summary>
    public static string DefenderCancelled => Pick(
        "The status check was cancelled.",
        "La consultation de l'état a été annulée.");

    /// <summary>The Defender error when the status is unavailable.</summary>
    public static string DefenderUnavailableBody => Pick(
        "Windows Security status is unavailable on this system.",
        "L'état de la sécurité Windows est indisponible sur ce système.");

    // ----------------------------------------------------------------------
    // Remediation
    // ----------------------------------------------------------------------

    /// <summary>The title of the remediation plan window.</summary>
    public static string RemediationPlanTitle => Pick(
        "Remediation plan",
        "Plan de remédiation");

    /// <summary>The intro of the remediation plan window.</summary>
    public static string RemediationPlanIntro => Pick(
        "Nothing has happened yet. This is what Lumen would do. Tick the steps you want and confirm.",
        "Rien ne s'est encore produit. Voici ce que Lumen ferait. Cochez les étapes souhaitées puis confirmez.");

    /// <summary>The title of the remediation plan window for one file.</summary>
    public static string RemediationPlanTitleFor(string fileName) => Pick(
        $"Remediation plan — {fileName}",
        $"Plan de remédiation — {fileName}");

    /// <summary>The label of the finding the plan is about.</summary>
    public static string RemediationFinding => Pick("Finding", "Détection");

    /// <summary>The label of the file the plan is about.</summary>
    public static string RemediationFile => Pick("File", "Fichier");

    /// <summary>The label of the steps list.</summary>
    public static string RemediationSteps => Pick("Steps", "Étapes");

    /// <summary>The label of a step that stops a process.</summary>
    public static string RemediationKindTerminate => Pick(
        "Stop a running process",
        "Arrêter un processus en cours");

    /// <summary>The label of a step that removes the file.</summary>
    public static string RemediationKindRemoveFile => Pick(
        "Permanently delete the file",
        "Supprimer le fichier définitivement");

    /// <summary>The label of a step that removes an autostart entry.</summary>
    public static string RemediationKindRemovePersistence => Pick(
        "Remove an autostart entry",
        "Supprimer une entrée de démarrage automatique");

    /// <summary>The confirmation button of the remediation plan window.</summary>
    public static string RemediationExecute => Pick("Execute the selected steps", "Exécuter les étapes sélectionnées");

    /// <summary>The cancel button of the remediation plan window.</summary>
    public static string RemediationCancel => Pick("Cancel", "Annuler");

    /// <summary>The label of the process id in a step.</summary>
    public static string RemediationProcess => Pick("Process", "Processus");

    /// <summary>The label of the autostart location in a step.</summary>
    public static string RemediationLocation => Pick("Location", "Emplacement");

    /// <summary>The label of a signed process in a step.</summary>
    public static string RemediationSigned => Pick("Signed executable", "Exécutable signé");

    /// <summary>The label of an unsigned process in a step.</summary>
    public static string RemediationUnsigned => Pick("No valid digital signature", "Aucune signature numérique valide");

    /// <summary>The empty state of the plan window.</summary>
    public static string RemediationNoSteps => Pick(
        "There is nothing to clean up for this file.",
        "Il n'y a rien à nettoyer pour ce fichier.");

    /// <summary>The short reminder shown next to the buttons of the plan window.</summary>
    public static string RemediationNothingChangedYet => Pick(
        "Nothing has been changed yet.",
        "Rien n'a encore été modifié.");

    /// <summary>The title of the remediation outcome window.</summary>
    public static string RemediationResultTitle => Pick("Remediation result", "Résultat de la remédiation");

    /// <summary>The outcome label of a step that succeeded.</summary>
    public static string RemediationSucceeded => Pick("Done", "Terminé");

    /// <summary>The outcome label of a step that failed.</summary>
    public static string RemediationFailed => Pick("Failed", "Échec");

    /// <summary>The outcome label of a step that was skipped.</summary>
    public static string RemediationSkipped => Pick("Skipped", "Ignorée");

    /// <summary>The outcome label of a step that was refused.</summary>
    public static string RemediationRefused => Pick("Refused", "Refusée");

    /// <summary>The outcome label of a step that is still pending.</summary>
    public static string RemediationPending => Pick("Not run", "Non exécutée");

    /// <summary>The overall outcome when everything succeeded.</summary>
    public static string RemediationStatusExecuted => Pick(
        "Every selected step completed.",
        "Toutes les étapes sélectionnées se sont terminées.");

    /// <summary>The overall outcome when some steps failed.</summary>
    public static string RemediationStatusPartial => Pick(
        "Some steps completed and at least one failed. The remaining steps were skipped, and the encrypted vault copy was kept.",
        "Certaines étapes ont abouti et au moins une a échoué. Les étapes restantes ont été ignorées et la copie chiffrée a été conservée.");

    /// <summary>The overall outcome when everything failed.</summary>
    public static string RemediationStatusFailed => Pick(
        "No step completed. The encrypted vault copy was kept.",
        "Aucune étape n'a abouti. La copie chiffrée a été conservée.");

    /// <summary>The overall outcome when the run was refused.</summary>
    public static string RemediationStatusRefused => Pick(
        "Nothing was changed.",
        "Rien n'a été modifié.");

    /// <summary>The overall outcome when the run was cancelled.</summary>
    public static string RemediationStatusCancelled => Pick(
        "The run was cancelled. Nothing was changed.",
        "L'exécution a été annulée. Rien n'a été modifié.");

    /// <summary>The banner title when the remediation was refused.</summary>
    public static string RemediationDisabledTitle => Pick(
        "Remediation is turned off",
        "La remédiation est désactivée");

    /// <summary>The banner body when the remediation was refused.</summary>
    public static string RemediationDisabledBody => Pick(
        "Turn it on in Settings to let Lumen stop processes and delete files.",
        "Activez-la dans les réglages pour autoriser Lumen à arrêter des processus et à supprimer des fichiers.");

    /// <summary>The banner title when the plan could not be produced.</summary>
    public static string RemediationPlanFailedTitle => Pick(
        "The remediation plan could not be built",
        "Le plan de remédiation n'a pas pu être établi");

    /// <summary>The banner body when the plan could not be produced.</summary>
    public static string RemediationPlanFailedBody => Pick(
        "Lumen could not collect the facts it needs. Nothing was changed.",
        "Lumen n'a pas pu réunir les informations nécessaires. Rien n'a été modifié.");

    /// <summary>The banner title when the remediation finished.</summary>
    public static string RemediationDoneTitle => Pick(
        "Remediation finished",
        "Remédiation terminée");

    /// <summary>The banner body when the remediation finished.</summary>
    public static string RemediationDoneBody => Pick(
        "Every selected step completed. The encrypted vault copy was kept.",
        "Toutes les étapes sélectionnées ont abouti. La copie chiffrée a été conservée.");

    /// <summary>The banner title when the remediation finished with problems.</summary>
    public static string RemediationWarnTitle => Pick(
        "Remediation finished with problems",
        "Remédiation terminée avec des problèmes");

    /// <summary>The banner body when the remediation finished with problems.</summary>
    public static string RemediationWarnBody => Pick(
        "Some steps failed and the rest were skipped. The encrypted vault copy was kept.",
        "Certaines étapes ont échoué et les autres ont été ignorées. La copie chiffrée a été conservée.");

    // ----------------------------------------------------------------------
    // Shared helpers
    // ----------------------------------------------------------------------

    /// <summary>The singular or plural form of "finding".</summary>
    public static string FindingCaption(int count) => IsFrench
        ? (count == 1 ? "détection" : "détections")
        : (count == 1 ? "finding" : "findings");

    /// <summary>Shown when a file has no digest.</summary>
    public static string HashUnavailable => Pick("SHA-256 unavailable", "Empreinte SHA-256 indisponible");

    /// <summary>The accessible name of the tick box that selects a detection.</summary>
    public static string SelectFileName(string fileName) => Pick(
        $"Select {fileName}",
        $"Sélectionner {fileName}");

    /// <summary>The "and N more findings" line under a detection.</summary>
    public static string AdditionalFindings(int count) => Pick(
        $"+{count} more finding(s)",
        $"+{count} autre(s) détection(s)");

    /// <summary>The title used for a file quarantined from the detection alert.</summary>
    public static string QuarantineAlertTitle => Pick(
        "Quarantined from the detection alert",
        "Mis en quarantaine depuis l'alerte de détection");

    /// <summary>The detail used for a file quarantined from the detection alert.</summary>
    public static string QuarantineAlertDetail => Pick(
        "The user asked for this file to be quarantined from the detection alert.",
        "L'utilisateur a demandé la mise en quarantaine de ce fichier depuis l'alerte de détection.");

    /// <summary>The history status of a cancelled scan.</summary>
    public static string HistoryStatusCancelled => Pick("Cancelled", "Annulée");

    /// <summary>The history status of a scan that reported errors.</summary>
    public static string HistoryStatusErrors => Pick("Completed with errors", "Terminée avec des erreurs");

    /// <summary>The history status of a clean scan.</summary>
    public static string HistoryStatusCompleted => Pick("Completed", "Terminée");

    private static string Pick(string english, string french) => IsFrench ? french : english;

    private static void ApplyCulture(AppLanguage language)
    {
        var culture = language == AppLanguage.Francais
            ? new CultureInfo("fr-FR")
            : new CultureInfo("en-US");

        CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentUICulture = culture;
        Thread.CurrentThread.CurrentUICulture = culture;
    }

    private static void ApplyResourceDictionary(AppLanguage language)
    {
        var application = Application.Current;
        if (application is null) return;

        var uri = language == AppLanguage.Francais ? FrenchDictionaryUri : EnglishDictionaryUri;
        var merged = application.Resources.MergedDictionaries;

        var index = -1;
        for (var position = 0; position < merged.Count; position++)
        {
            var source = merged[position].Source?.ToString() ?? string.Empty;
            if (source.EndsWith("Strings.en.xaml", StringComparison.OrdinalIgnoreCase) ||
                source.EndsWith("Strings.fr.xaml", StringComparison.OrdinalIgnoreCase))
            {
                index = position;
                break;
            }
        }

        var replacement = new ResourceDictionary { Source = new Uri(uri, UriKind.Absolute) };
        if (index >= 0) merged[index] = replacement;
        else merged.Add(replacement);
    }
}
