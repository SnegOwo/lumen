using System.ComponentModel;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;

namespace Lumen.App.Controls;

/// <summary>
/// Raises UI Automation live-region events when a status TextBlock changes, so screen
/// readers announce scan progress and results without stealing focus.
/// </summary>
public static class LiveRegion
{
    private static readonly DependencyPropertyDescriptor? TextDescriptor =
        DependencyPropertyDescriptor.FromProperty(TextBlock.TextProperty, typeof(TextBlock));

    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled",
        typeof(bool),
        typeof(LiveRegion),
        new PropertyMetadata(false, OnIsEnabledChanged));

    private static readonly DependencyProperty HookedProperty = DependencyProperty.RegisterAttached(
        "Hooked",
        typeof(bool),
        typeof(LiveRegion),
        new PropertyMetadata(false));

    public static bool GetIsEnabled(DependencyObject element) => (bool)element.GetValue(IsEnabledProperty);

    public static void SetIsEnabled(DependencyObject element, bool value) => element.SetValue(IsEnabledProperty, value);

    private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextBlock textBlock || TextDescriptor is null) return;

        if (e.NewValue is true)
        {
            AutomationProperties.SetLiveSetting(textBlock, AutomationLiveSetting.Polite);
            textBlock.Loaded += OnLoaded;
            textBlock.Unloaded += OnUnloaded;
            if (textBlock.IsLoaded) Hook(textBlock);
        }
        else
        {
            textBlock.Loaded -= OnLoaded;
            textBlock.Unloaded -= OnUnloaded;
            Unhook(textBlock);
            AutomationProperties.SetLiveSetting(textBlock, AutomationLiveSetting.Off);
        }
    }

    private static void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is TextBlock textBlock) Hook(textBlock);
    }

    private static void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (sender is TextBlock textBlock) Unhook(textBlock);
    }

    private static void Hook(TextBlock textBlock)
    {
        if (TextDescriptor is null || (bool)textBlock.GetValue(HookedProperty)) return;

        TextDescriptor.AddValueChanged(textBlock, OnTextChanged);
        textBlock.SetValue(HookedProperty, true);
    }

    private static void Unhook(TextBlock textBlock)
    {
        if (TextDescriptor is null || textBlock.GetValue(HookedProperty) is not true) return;

        TextDescriptor.RemoveValueChanged(textBlock, OnTextChanged);
        textBlock.SetValue(HookedProperty, false);
    }

    private static void OnTextChanged(object? sender, EventArgs e)
    {
        if (sender is not TextBlock textBlock || string.IsNullOrWhiteSpace(textBlock.Text)) return;

        try
        {
            var peer = UIElementAutomationPeer.FromElement(textBlock)
                       ?? new FrameworkElementAutomationPeer(textBlock);
            peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
        }
        catch
        {
            // Automation is best effort and must never affect scanning.
        }
    }
}
