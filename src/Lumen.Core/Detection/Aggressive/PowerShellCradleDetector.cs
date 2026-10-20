using System.Text;
using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;
using Lumen.Core.Util;

namespace Lumen.Core.Detection.Aggressive;

/// <summary>
/// Reports a script that fetches something and then runs it, using an alias, a pipe or
/// an encoded blob.
/// </summary>
/// <remarks>
/// <para>
/// The standard rules already cover the plain shapes, such as a download function
/// together with an execution function. This rule covers the shapes that are easier to
/// read past: the short aliases, the pipe that joins a download to an execution, the two
/// statements that sit next to each other, and the blob of base64 that decodes to a
/// PowerShell keyword.
/// </para>
/// <para>
/// The blob is decoded to see what it holds. Nothing is executed, and the decoded text is
/// never shown: only the keyword that was found is named.
/// </para>
/// <para>
/// This rule belongs to the AGGRESSIVE tier: it only runs when the user has asked for
/// maximum sensitivity.
/// </para>
/// </remarks>
public sealed class PowerShellCradleDetector : IScanDetector, IAggressiveDetector
{
    /// <summary>The identifier of the rule this detector reports.</summary>
    public const string RuleId = "script.powershell-download-cradle";

    private static readonly string[] ScriptExtensions =
    [
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
        ".wsh", ".hta", ".txt"
    ];

    /// <summary>
    /// The ways a script fetches something.
    /// </summary>
    private static readonly string[] DownloadTokens =
    [
        "invoke-webrequest", "iwr ", "irm ", "invoke-restmethod", "system.net.webclient",
        "webclient", "downloadstring", "downloadfile", "start-bitstransfer", "certutil",
        "bitsadmin", "curl ", "wget ", "new-object net.webclient"
    ];

    /// <summary>
    /// The ways a script runs what it fetched.
    /// </summary>
    private static readonly string[] ExecutionTokens =
    [
        "invoke-expression", "iex ", "iex(", "frombase64string", "-encodedcommand",
        "-enc ", "powershell -c", "cmd /c", "cmd.exe /c", "wscript.shell",
        "system.reflection.assembly]::load"
    ];

    /// <summary>
    /// The short forms that make the shape harder to read.
    /// </summary>
    private static readonly string[] AliasTokens =
    [
        "iwr ", "irm ", "iex ", "iex(", "iex$"
    ];

    /// <summary>
    /// The keywords a decoded blob is looked for. Nothing is executed and the decoded text
    /// is never shown to the reader.
    /// </summary>
    private static readonly string[] DecodedKeywords =
    [
        "invoke-expression", "invoke-webrequest", "frombase64string", "downloadstring",
        "downloadfile", "new-object", "system.", "start-process", "add-type", "iex"
    ];

    /// <summary>
    /// The shortest blob that is worth decoding.
    /// </summary>
    public const int MinimumBlobLength = 40;

    /// <summary>
    /// How far apart the download and the execution may be and still count as one cradle.
    /// </summary>
    public const int MaximumDistance = 400;

    private const string Advice =
        "Read the script before you run it and find out where it came from. " +
        "Installers and deployment scripts fetch a file and then run it as well, so the context decides what this means.";

    /// <inheritdoc />
    public string Id => "script.download-cradle";

    /// <inheritdoc />
    public string Name => "Download and execution cradles";

    /// <inheritdoc />
    public string Description =>
        "Reports a script that fetches something and then runs it, using an alias, a pipe, an encoded blob or two statements next to each other.";

    /// <inheritdoc />
    public FindingCategory Category => FindingCategory.Behavior;

    /// <inheritdoc />
    public Confidence Confidence => Confidence.Medium;

    /// <inheritdoc />
    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var extension = Path.GetExtension(probe.FileName);
        if (!ScriptExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)) return Array.Empty<Finding>();

        var text = probe.GetTextSample();
        if (string.IsNullOrWhiteSpace(text)) return Array.Empty<Finding>();

        var lower = text.ToLowerInvariant();

        var downloads = DownloadTokens.Where(token => TextPatterns.Contains(lower, token)).ToArray();
        var executions = ExecutionTokens.Where(token => TextPatterns.Contains(lower, token)).ToArray();

        if (downloads.Length == 0 || executions.Length == 0) return Array.Empty<Finding>();

        var shapes = new List<string>();

        var aliases = AliasTokens.Where(token => TextPatterns.Contains(lower, token)).ToArray();
        if (aliases.Length > 0)
        {
            shapes.Add("the short form " + string.Join(", ", aliases.Select(token => $"\"{DisplayText.Sanitize(token.Trim())}\"")) + " is used");
        }

        var distance = DistanceBetween(lower, downloads, executions);
        if (distance >= 0 && distance <= MaximumDistance)
        {
            shapes.Add($"the download and the execution are {distance} characters apart");
        }

        if (HasPipeBetween(lower, downloads, executions))
        {
            shapes.Add("the output of the download is piped into the execution");
        }

        var blob = FindDecodedBlobKeyword(text);
        if (blob is not null)
        {
            shapes.Add($"a base64 blob that decodes to text containing \"{DisplayText.Sanitize(blob)}\"");
        }

        if (shapes.Count == 0) return Array.Empty<Finding>();

        return
        [
            new Finding
            {
                RuleId = RuleId,
                Title = "Download and execution in one script",
                Category = FindingCategory.Behavior,
                Confidence = Confidence.Medium,
                Summary = "The script fetches something and then runs what it fetched.",
                Detail =
                    "The script was found to hold " +
                    string.Join(", ", downloads.Select(token => $"\"{DisplayText.Sanitize(token.Trim())}\"")) + " and " +
                    string.Join(", ", executions.Select(token => $"\"{DisplayText.Sanitize(token.Trim())}\"")) + ". " +
                    "The two are joined in the shape of a cradle: " + string.Join("; ", shapes) + ". " +
                    "The script was not run and nothing was downloaded.",
                Advice = Advice
            }
        ];
    }

    /// <summary>
    /// Returns the distance in characters between the first download token and the first
    /// execution token, or -1 when they cannot be compared.
    /// </summary>
    private static int DistanceBetween(string lower, string[] downloads, string[] executions)
    {
        var downloadIndex = -1;
        foreach (var token in downloads)
        {
            var index = TextPatterns.IndexOf(lower, token);
            if (index < 0) continue;
            downloadIndex = index;
            break;
        }

        var executionIndex = -1;
        foreach (var token in executions)
        {
            var index = TextPatterns.IndexOf(lower, token);
            if (index < 0) continue;
            executionIndex = index;
            break;
        }

        if (downloadIndex < 0 || executionIndex < 0) return -1;
        return Math.Abs(executionIndex - downloadIndex);
    }

    /// <summary>
    /// Returns true when a pipe sits between the download and the execution, which is the
    /// shape where the output of one becomes the input of the other.
    /// </summary>
    private static bool HasPipeBetween(string lower, string[] downloads, string[] executions)
    {
        var downloadIndex = -1;
        foreach (var token in downloads)
        {
            var index = TextPatterns.IndexOf(lower, token);
            if (index < 0) continue;
            downloadIndex = index;
            break;
        }

        var executionIndex = -1;
        foreach (var token in executions)
        {
            var index = TextPatterns.IndexOf(lower, token);
            if (index < 0) continue;
            executionIndex = index;
            break;
        }

        if (downloadIndex < 0 || executionIndex < 0) return false;

        var start = Math.Min(downloadIndex, executionIndex);
        var end = Math.Max(downloadIndex, executionIndex);
        return lower.IndexOf('|', start) is var pipe && pipe >= 0 && pipe < end;
    }

    /// <summary>
    /// Looks for a blob of base64 that decodes to text holding a PowerShell keyword. The
    /// blob is decoded, never executed, and only the keyword is reported.
    /// </summary>
    private static string? FindDecodedBlobKeyword(string text)
    {
        var start = -1;

        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            if (!IsBase64Character(character))
            {
                if (start >= 0 && index - start >= MinimumBlobLength)
                {
                    var keyword = DecodeAndMatch(text[start..index]);
                    if (keyword is not null) return keyword;
                }

                start = -1;
                continue;
            }

            if (start < 0) start = index;
        }

        if (start >= 0 && text.Length - start >= MinimumBlobLength)
        {
            var keyword = DecodeAndMatch(text[start..]);
            if (keyword is not null) return keyword;
        }

        return null;
    }

    /// <summary>
    /// Decodes one candidate blob and returns the first keyword it holds.
    /// </summary>
    private static string? DecodeAndMatch(string candidate)
    {
        if (candidate.Length is < MinimumBlobLength or > 8192) return null;

        try
        {
            var bytes = Convert.FromBase64String(candidate);
            if (bytes.Length == 0) return null;

            var decoded = Encoding.UTF8.GetString(bytes).ToLowerInvariant();
            foreach (var keyword in DecodedKeywords)
            {
                if (decoded.Contains(keyword, StringComparison.Ordinal)) return keyword;
            }
        }
        catch (FormatException)
        {
            // The run of characters was not valid base64 after all, which is common in
            // ordinary text. Nothing is reported about it.
        }

        return null;
    }

    private static bool IsBase64Character(char value) =>
        value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/' or '=';
}
