using System.Windows;
using System.Windows.Automation;
using System.Windows.Input;
using System.Windows.Media;

namespace Lumen.App.Dialogs;

public partial class ConfirmDialog : Window
{
    private readonly ConfirmDialogOptions _options;

    public ConfirmDialog(ConfirmDialogOptions options)
    {
        _options = options;
        InitializeComponent();
        DataContext = options;
        Title = options.Title;
        AutomationProperties.SetName(this, options.Title + ". " + options.Message);

        ApplySeverity(options.Severity);

        PrimaryButton.IsDefault = !options.IsDanger;
        CancelButton.IsCancel = options.ShowCancel;
        Loaded += OnLoaded;
    }

    public static bool Show(Window? owner, ConfirmDialogOptions options)
    {
        var dialog = new ConfirmDialog(options);
        if (owner is not null && owner.IsVisible)
        {
            dialog.Owner = owner;
            dialog.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }
        else
        {
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }

        return dialog.ShowDialog() == true;
    }

    private void ApplySeverity(MessageSeverity severity)
    {
        var (glyph, softKey, textKey) = severity switch
        {
            MessageSeverity.Success => ("\uE73E", "Success.Soft", "Success.Text"),
            MessageSeverity.Warning => ("\uE7BA", "Warning.Soft", "Warning.Text"),
            MessageSeverity.Danger => ("\uEA39", "Danger.Soft", "Danger.Text"),
            _ => ("\uE946", "Info.Soft", "Info.Text")
        };

        IconGlyph.Text = glyph;
        if (TryFindResource(softKey) is Brush background) IconTile.Background = background;
        if (TryFindResource(textKey) is Brush foreground) IconGlyph.Foreground = foreground;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_options.IsDanger)
        {
            CancelButton.Focus();
        }
        else
        {
            PrimaryButton.Focus();
        }
    }

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
        {
            try { DragMove(); } catch (InvalidOperationException) { /* window state changed */ }
        }
    }

    private void PrimaryButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            DialogResult = false;
            Close();
            e.Handled = true;
            return;
        }

        base.OnKeyDown(e);
    }
}
