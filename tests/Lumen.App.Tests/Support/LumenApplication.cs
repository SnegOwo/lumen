using System.Reflection;
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

    private static readonly XNamespace Presentation =
        "http://schemas.microsoft.com/winfx/2006/xaml/presentation";

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

        application.Resources.MergedDictionaries.Add(LoadDictionaryCore("themes/controls.xaml"));
        application.Resources.MergedDictionaries.Add(LoadDictionaryCore("themes/datemplates.xaml"));
        application.Resources.MergedDictionaries.Add(LoadApplicationResourcesFromSource());

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
        Activator.CreateInstance(TypeFor(relativePath))!);

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
        new(PackPrefix + relativePath.ToLowerInvariant(), UriKind.Relative);

    private static void UseLumenResourceAssembly()
    {
        var target = typeof(global::Lumen.App.App).Assembly;
        if (Application.ResourceAssembly == target) return;

        var setter = typeof(Application)
            .GetProperty(nameof(Application.ResourceAssembly), BindingFlags.Public | BindingFlags.Static)
            ?.GetSetMethod(nonPublic: true);

        if (setter is null)
        {
            throw new InvalidOperationException(
                "Application.ResourceAssembly cannot be set, so the compiled Lumen XAML cannot be loaded.");
        }

        setter.Invoke(null, new object[] { target });
    }

    /// <summary>
    /// Reads the converters that <c>App.xaml</c> declares. The merged
    /// dictionaries of that file are skipped: they are loaded from their
    /// compiled form instead, because a relative <c>Source</c> cannot be
    /// resolved by the loose XAML parser.
    /// </summary>
    private static ResourceDictionary LoadApplicationResourcesFromSource()
    {
        var path = Path.Combine(SourceTree.AppProjectDirectory, "App.xaml");
        var document = XDocument.Load(path);
        var root = document.Root!;

        var resources = root.Elements().FirstOrDefault(element => element.Name.LocalName == "Application.Resources");
        var inner = resources?.Elements().FirstOrDefault(element => element.Name.LocalName == "ResourceDictionary");

        var dictionary = new XElement(Presentation + "ResourceDictionary",
            root.Attributes().Where(attribute => attribute.IsNamespaceDeclaration));

        if (inner is not null)
        {
            foreach (var child in inner.Elements())
            {
                if (child.Name.LocalName == "ResourceDictionary.MergedDictionaries") continue;
                dictionary.Add(child);
            }
        }

        return (ResourceDictionary)XamlReader.Parse(dictionary.ToString());
    }
}
