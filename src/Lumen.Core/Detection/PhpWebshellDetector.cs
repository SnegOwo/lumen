using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// Looks at PHP pages that hand a value taken from the request to a function that can run
/// code.
/// </summary>
/// <remarks>
/// <para>
/// The shape is rare in healthy software. A page that reads the request and prints it
/// back out is completely ordinary; a page that hands the raw request value to
/// <c>eval</c>, <c>system</c> or <c>shell_exec</c> lets whoever sends the request decide
/// what the machine runs.
/// </para>
/// <para>
/// The rule lives in the standard tier because it has very few false positives, but it
/// still applies only to files that are named like a PHP page, so it stays quiet on a
/// machine that has none.
/// </para>
/// <para>
/// The detector reads only the text the scanner already decoded. It performs no file
/// system access and never runs anything it finds.
/// </para>
/// </remarks>
public sealed class PhpWebshellDetector : IScanDetector
{
    /// <summary>The identifier of the rule this detector reports.</summary>
    public const string RuleId = "php.request-evaluation";

    private static readonly string[] PageExtensions =
    [
        ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phps", ".inc"
    ];

    private static readonly string[] ExecutionFunctions =
    [
        "eval", "assert", "system", "shell_exec", "passthru", "proc_open", "popen", "exec", "create_function"
    ];

    private static readonly string[] RequestSources =
    [
        "$_get", "$_post", "$_request", "$_cookie", "$_files"
    ];

    /// <summary>
    /// The way the request values are written in the page, so the finding shows the name
    /// the reader would recognize.
    /// </summary>
    private static readonly string[] RequestSourceNames =
    [
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"
    ];

    /// <summary>
    /// Calls that make a value safe to hand to another function. A page that wraps the
    /// request value in one of these is not handing the raw value over, so it is not
    /// reported.
    /// </summary>
    private static readonly string[] Sanitizers =
    [
        "escapeshellarg", "escapeshellcmd", "htmlspecialchars", "htmlentities",
        "intval", "floatval", "boolval", "filter_input", "filter_var", "preg_quote"
    ];

    private const string Advice =
        "Find out where the page came from and who can reach it. A page that runs a value taken from the request lets whoever sends that request run code on the machine.";

    /// <inheritdoc />
    public string Id => "php.pages";

    /// <inheritdoc />
    public string Name => "PHP page analysis";

    /// <inheritdoc />
    public string Description =>
        "Looks for pages that take a value from the request and hand it to a function that evaluates code or runs a command.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var extension = Path.GetExtension(probe.FileName);
        if (!PageExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)) return Array.Empty<Finding>();

        var text = probe.GetTextSample();
        if (string.IsNullOrWhiteSpace(text)) return Array.Empty<Finding>();

        var lower = text.ToLowerInvariant();
        var observations = new List<string>();

        foreach (var function in ExecutionFunctions)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!TextPatterns.TryFindCall(lower, function, out var openParenthesis)) continue;

            var arguments = TextPatterns.ExtractArguments(text, openParenthesis);
            if (arguments.Length == 0) continue;

            var lowerArguments = arguments.ToLowerInvariant();
            if (Sanitizers.Any(sanitizer => TextPatterns.Contains(lowerArguments, sanitizer))) continue;

            var index = Array.FindIndex(RequestSources, candidate => TextPatterns.Contains(lowerArguments, candidate));
            if (index < 0) continue;

            observations.Add($"{function}() receives {RequestSourceNames[index]}");
        }

        if (observations.Count == 0)
        {
            if (!TryFindPregReplace(lower, text, out var pregDescription)) return Array.Empty<Finding>();
            observations.Add(pregDescription!);
        }

        return
        [
            new Finding
            {
                RuleId = RuleId,
                Title = "Request data passed to a code or command function",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.Medium,
                Summary = "The page hands a value taken from the request to a function that can run code.",
                Detail =
                    "The page was found to contain: " + string.Join("; ", observations) + ". " +
                    "The value comes straight from the request, so whoever sends the request can choose what is run. " +
                    "A page that only reads the request and prints it back out does not look like this.",
                Advice = Advice
            }
        ];
    }

    /// <summary>
    /// Looks for the regular expression form of the same shape: a replacement expression
    /// that carries the /e modifier, which tells the engine to run the result as code.
    /// </summary>
    private static bool TryFindPregReplace(string lower, string text, out string? description)
    {
        description = null;

        if (!TextPatterns.TryFindCall(lower, "preg_replace", out var openParenthesis)) return false;

        var arguments = TextPatterns.ExtractArguments(text, openParenthesis);
        if (arguments.Length == 0) return false;

        var lowerArguments = arguments.ToLowerInvariant();
        var index = Array.FindIndex(RequestSources, candidate => TextPatterns.Contains(lowerArguments, candidate));
        if (index < 0) return false;

        // The /e modifier is what turns the replacement into code. It has to be in the
        // pattern, which is the first argument of the call.
        var comma = arguments.IndexOf(',');
        if (comma <= 0) return false;

        var pattern = arguments[..comma];
        var lowerPattern = pattern.ToLowerInvariant();
        if (!lowerPattern.Contains("/e", StringComparison.Ordinal)) return false;

        description = $"preg_replace() evaluates its result as code and receives {RequestSourceNames[index]} in the pattern";
        return true;
    }
}
