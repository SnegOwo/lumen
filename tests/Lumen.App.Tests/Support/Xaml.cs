using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Lumen.App.Tests.Support;

/// <summary>
/// Small text helpers shared by the theme scans. Everything here works on the
/// raw source files so the scans stay independent of how the XAML is compiled.
/// </summary>
internal static partial class Xaml
{
    private static readonly XNamespace XamlNamespace = "http://schemas.microsoft.com/winfx/2006/xaml";

    private static readonly ConcurrentDictionary<string, Regex> KeyPatterns = new(StringComparer.Ordinal);

    [GeneratedRegex(@"\{(?:Static|Dynamic)Resource\s+([^\s{}]+)\s*\}", RegexOptions.CultureInvariant)]
    private static partial Regex ResourceReference();

    [GeneratedRegex(@"<!--.*?-->", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex XmlComment();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockComment();

    [GeneratedRegex(@"(?m)//.*?$", RegexOptions.CultureInvariant)]
    private static partial Regex LineComment();

    /// <summary>Every <c>x:Key</c> declared in the file, in document order.</summary>
    public static IReadOnlyList<string> DeclaredKeys(string path)
    {
        var document = XDocument.Load(path, LoadOptions.None);
        return document.Descendants()
            .Attributes()
            .Where(attribute => attribute.Name.Namespace == XamlNamespace && attribute.Name.LocalName == "Key")
            .Select(attribute => attribute.Value)
            .ToArray();
    }

    /// <summary>
    /// Every <c>{StaticResource Key}</c> and <c>{DynamicResource Key}</c> reference
    /// in the file. Nested markup extensions such as
    /// <c>{DynamicResource {x:Static SystemColors.WindowColorKey}}</c> are system
    /// resources and are deliberately not reported.
    /// </summary>
    public static IReadOnlyList<string> ResourceReferences(string path) =>
        ResourceReferencesIn(File.ReadAllText(path), isXaml: true);

    public static IReadOnlyList<string> ResourceReferencesIn(string text, bool isXaml) =>
        ResourceReference()
            .Matches(StripComments(text, isXaml))
            .Select(match => match.Groups[1].Value)
            .Where(key => !key.StartsWith("{", StringComparison.Ordinal))
            .ToArray();

    /// <summary>The value of every element that declares an <c>x:Key</c>.</summary>
    public static IReadOnlyDictionary<string, string> KeyedElementValues(string path)
    {
        var document = XDocument.Load(path, LoadOptions.None);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var element in document.Descendants())
        {
            var key = element.Attributes()
                .FirstOrDefault(attribute =>
                    attribute.Name.Namespace == XamlNamespace && attribute.Name.LocalName == "Key")?.Value;

            if (key is null) continue;
            values[key] = element.Value;
        }

        return values;
    }

    /// <summary>
    /// Removes comments so that a key which is only mentioned in a documentation
    /// comment is not mistaken for a key that is actually used.
    /// </summary>
    public static string StripComments(string text, bool isXaml)
    {
        if (isXaml) return XmlComment().Replace(text, string.Empty);

        var withoutBlocks = BlockComment().Replace(text, string.Empty);
        return LineComment().Replace(withoutBlocks, string.Empty);
    }

    /// <summary>
    /// A regular expression that matches the key as a whole token. A key such as
    /// <c>App.Background</c> must not be found inside <c>App.BackgroundStrong</c>
    /// and <c>Background</c> must not be found inside <c>App.Background</c>.
    /// </summary>
    public static Regex KeyPattern(string key) =>
        KeyPatterns.GetOrAdd(key, static value =>
            new Regex(@"(?<![\w.])" + Regex.Escape(value) + @"(?![\w.])", RegexOptions.CultureInvariant));
}
