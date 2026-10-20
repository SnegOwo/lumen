using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Markup;
using System.Xml.Linq;

namespace Lumen.App.Tests.Support;

/// <summary>
/// Builds the same resource graph the application builds at start-up, but in
/// the test host: the compiled theme dictionaries, the data templates and the
/// converters that <c>App.xaml</c> declares.
///
/// <para>
/// The application itself is never started. No window is shown, no service is
/// created and nothing outside the test process is touched.
/// </para>
/// </summary>
internal static class LumenApplication
{
    private const string PackPrefix = "/Lumen;component/";

    private static Application? _application;
    private static bool _resourcesInstalled;

    /// <summary>The WPF application that owns the test resources.</summary>
    public static Application Ensure()
    {
        if (WpfHost.Shared.IsOnHostThread) return EnsureCore();
        return WpfHost.Shared.Invoke(EnsureCore);
    }

    private static Application EnsureCore()
    {
        if (_application is not null) return _application;

        UseLumenResourceAssembly();

        _application = Application.Current ?? new Application();
        return _application;
    }

    /// <summary>
    /// Merges the theme dictionaries, the data templates and the application
    /// converters into the test application's resources, exactly like
    /// <c>App.xaml</c> does.
    /// </summary>
    public static void InstallResources() => WpfHost.Shared.Invoke(() =>
    {
        if (_resourcesInstalled) return;

        var application = EnsureCore();

        // Every dictionary is loaded before any of them is merged: WPF can
        // only resolve one pack resource at a time while a dictionary is being
        // attached to the application resources.
        var theme = LoadDictionaryCore(ThemeRelativePath("Controls.xaml"));
        var templates = LoadDictionaryCore(ThemeRelativePath("DataTemplates.xaml"));
        var converters = LoadApplicationResourcesFromSource();

        application.Resources.MergedDictionaries.Add(theme);
        application.Resources.MergedDictionaries.Add(templates);
        application.Resources.MergedDictionaries.Add(converters);

        _resourcesInstalled = true;
    });

    /// <summary>Loads a compiled resource dictionary by its path in the project.</summary>
    public static ResourceDictionary LoadDictionary(string relativePath) => WpfHost.Shared.Invoke(() =>
        LoadDictionaryCore(relativePath));

    private static ResourceDictionary LoadDictionaryCore(string relativePath)
    {
        EnsureCore();

        return (ResourceDictionary)Application.LoadComponent(PackUri(relativePath));
    }

    /// <summary>Creates an instance of a compiled view, which loads its XAML.</summary>
    public static object CreateView(string relativePath) => WpfHost.Shared.Invoke(() =>
    {
        var type = TypeFor(relativePath)
            ?? throw new InvalidOperationException($"'{relativePath}' does not declare an x:Class.");

        return Activator.CreateInstance(type)!;
    });

    /// <summary>The type declared by the <c>x:Class</c> attribute of the file.</summary>
    public static Type? TypeFor(string relativePath)
    {
        var document = XDocument.Load(Path.Combine(SourceTree.AppProjectDirectory, relativePath.Replace('/', '\\')));
        var className = document.Root?.Attributes()
            .FirstOrDefault(attribute =>
                attribute.Name.LocalName == "Class" &&
                attribute.Name.Namespace == "http://schemas.microsoft.com/winfx/2006/xaml")?.Value;

        return className is null ? null : Type.GetType(className + ", Lumen", throwOnError: false);
    }

    private static Uri PackUri(string relativePath) =>
        new(PackPrefix + relativePath, UriKind.Relative);

    /// <summary>
    /// The path of a theme file, with the casing the file system uses. The
    /// pack resource names keep that casing, so it has to be preserved.
    /// </summary>
    private static string ThemeRelativePath(string fileName)
    {
        var match = SourceTree.ThemeFiles.FirstOrDefault(path =>
            path.EndsWith(fileName, StringComparison.OrdinalIgnoreCase));

        if (match is null) throw new InvalidOperationException($"Themes/{fileName} was not found.");

        return SourceTree.Relative(match);
    }

    private static void UseLumenResourceAssembly()
    {
        var target = typeof(global::Lumen.App.App).Assembly;
        if (Application.ResourceAssembly == target) return;

        // The public setter refuses to run once the property has a value, and
        // the test host always has one (the entry assembly). The backing field
        // is therefore written directly: the test host owns its own process
        // and nothing else reads it.
        var field = typeof(Application)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Static)
            .FirstOrDefault(candidate =>
                candidate.FieldType == typeof(Assembly) &&
                candidate.Name.Contains("resourceAssembly", StringComparison.OrdinalIgnoreCase));

        if (field is null)
        {
            throw new InvalidOperationException(
                "The WPF resource assembly cannot be redirected, so the compiled Lumen XAML cannot be loaded.");
        }

        field.SetValue(null, target);
    }

    /// <summary>
    /// Reads the resources that <c>App.xaml</c> declares. The merged
    /// dictionaries of that file are skipped: they are loaded from their
    /// compiled form instead, because a relative <c>Source</c> cannot be
    /// resolved by the loose XAML parser.
    ///
    /// <para>
    /// The file is rewritten as text instead of being re-serialised from an
    /// XML document: only the original text keeps the namespace prefixes of
    /// the elements, and a prefixed element is the only way the loose parser
    /// can resolve a type from a CLR namespace.
    /// </para>
    /// </summary>
    private static ResourceDictionary LoadApplicationResourcesFromSource()
    {
        var path = Path.Combine(SourceTree.AppProjectDirectory, "App.xaml");
        var text = File.ReadAllText(path);

        var rootTag = SliceTag(text, "<Application");
        var declarations = NamespaceDeclarations(rootTag)
            .Select(declaration => WithAssembly(declaration))
            .ToArray();

        var resourcesTag = "<Application.Resources";
        var resourcesStart = text.IndexOf(resourcesTag, StringComparison.Ordinal);
        if (resourcesStart < 0) return new ResourceDictionary();

        var contentStart = text.IndexOf('>', resourcesStart) + 1;
        var contentEnd = text.IndexOf("</Application.Resources>", contentStart, StringComparison.Ordinal);
        var inner = text[contentStart..contentEnd];

        var dictionaryStart = inner.IndexOf("<ResourceDictionary", StringComparison.Ordinal);
        if (dictionaryStart < 0) return new ResourceDictionary();

        var childrenStart = inner.IndexOf('>', dictionaryStart) + 1;
        var childrenEnd = inner.LastIndexOf("</ResourceDictionary>", StringComparison.Ordinal);
        var children = inner[childrenStart..childrenEnd];

        // The merged dictionaries are loaded from their compiled form instead:
        // a relative Source cannot be resolved by the loose XAML parser.
        children = RemoveMergedDictionaries(children);

        var rewritten =
            "<ResourceDictionary " + string.Join(' ', declarations) + ">" + children + "</ResourceDictionary>";

        return (ResourceDictionary)XamlReader.Parse(rewritten);
    }

    private static string RemoveMergedDictionaries(string children)
    {
        const string open = "<ResourceDictionary.MergedDictionaries";
        const string close = "</ResourceDictionary.MergedDictionaries>";

        var start = children.IndexOf(open, StringComparison.Ordinal);
        if (start < 0) return children;

        var end = children.IndexOf(close, start, StringComparison.Ordinal);
        if (end < 0) return children[..start];

        end += close.Length;

        return children[..start] + children[end..];
    }

    /// <summary>The text of the first tag that starts with the given name.</summary>
    private static string SliceTag(string text, string tagName)
    {
        var start = text.IndexOf(tagName, StringComparison.Ordinal);
        if (start < 0) return string.Empty;

        var end = text.IndexOf('>', start);
        return end < 0 ? string.Empty : text[start..(end + 1)];
    }

    private static IReadOnlyList<string> NamespaceDeclarations(string tag)
    {
        var declarations = new List<string>();

        foreach (Match match in Regex.Matches(tag, "xmlns(?::[A-Za-z0-9_.-]+)?\\s*=\\s*\"[^\"]*\""))
        {
            declarations.Add(match.Value);
        }

        return declarations;
    }

    /// <summary>
    /// The loose XAML parser does not know which assembly a
    /// <c>clr-namespace</c> belongs to, so the assembly is added here.
    /// </summary>
    private static string WithAssembly(string declaration)
    {
        if (!declaration.Contains("clr-namespace:", StringComparison.Ordinal)) return declaration;
        if (declaration.Contains(";assembly=", StringComparison.OrdinalIgnoreCase)) return declaration;

        var quote = declaration.LastIndexOf('"');
        if (quote < 0) return declaration;

        return declaration[..quote] + ";assembly=Lumen" + declaration[quote..];
    }
}
