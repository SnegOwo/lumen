using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Lumen.Core.Models;
using Microsoft.Win32;

namespace Lumen.App.Services;

/// <summary>
/// Swaps color dictionaries at runtime and asks DWM to render the native title bar in a
/// matching dark or light mode. High contrast always wins over the brand themes.
/// </summary>
public sealed class ThemeService
{
    private const string PersonalizeKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    private const int DwmUseImmersiveDarkMode = 20;
    private const int DwmUseImmersiveDarkModeBefore20H1 = 19;

    private ResourceDictionary? _currentTheme;
    private AppTheme _preference = AppTheme.System;

    public ThemeService()
    {
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
    }

    public AppTheme Preference => _preference;
    public bool IsDark { get; private set; }
    public bool IsHighContrast => SystemParameters.HighContrast;

    public bool Apply(AppTheme preference)
    {
        _preference = Enum.IsDefined(preference) ? preference : AppTheme.System;

        var dictionary = IsHighContrast
            ? Load("Colors.HighContrast.xaml")
            : Resolve(preference) == AppTheme.Dark
                ? Load("Colors.Dark.xaml")
                : Load("Colors.Light.xaml");

        IsDark = !IsHighContrast && Resolve(preference) == AppTheme.Dark;

        var merged = Application.Current.Resources.MergedDictionaries;
        if (_currentTheme is not null) merged.Remove(_currentTheme);
        merged.Insert(0, dictionary);
        _currentTheme = dictionary;

        foreach (Window window in Application.Current.Windows)
        {
            if (window.IsLoaded) ApplyWindowChrome(window);
        }

        return IsDark;
    }

    public void ApplyWindowChrome(Window window)
    {
        if (IsHighContrast) return;

        try
        {
            var handle = new WindowInteropHelper(window).Handle;
            if (handle == IntPtr.Zero) return;

            var value = IsDark ? 1 : 0;
            if (DwmSetWindowAttribute(handle, DwmUseImmersiveDarkMode, ref value, sizeof(int)) != 0)
            {
                DwmSetWindowAttribute(handle, DwmUseImmersiveDarkModeBefore20H1, ref value, sizeof(int));
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // Older Windows builds simply keep their default title bar.
        }
    }

    private static ResourceDictionary Load(string fileName) =>
        new()
        {
            Source = new Uri(
                "pack://application:,,,/Lumen;component/Themes/" + fileName,
                UriKind.Absolute)
        };

    private static AppTheme Resolve(AppTheme preference)
    {
        if (preference != AppTheme.System) return preference;

        try
        {
            var value = Registry.GetValue(
                Registry.CurrentUser.Name + "\\" + PersonalizeKey,
                "AppsUseLightTheme",
                1);
            return value is int number && number == 0 ? AppTheme.Dark : AppTheme.Light;
        }
        catch
        {
            return AppTheme.Light;
        }
    }

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (_preference != AppTheme.System && e.Category != UserPreferenceCategory.General) return;

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.HasShutdownStarted) return;

        dispatcher.BeginInvoke(() =>
        {
            if (_preference == AppTheme.System || SystemParameters.HighContrast)
            {
                Apply(_preference);
            }
        });
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd,
        int attribute,
        ref int value,
        int size);
}
