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

        // Only the title is used as the accessible name. The message is part of
        // the dialog content and is announced from there; repeating it in the
        // window name made a screen reader say it twice.
        AutomationProperties.SetName(this, options.Title);

        ApplySeverity(options.Severity);

        // Enter always means the safe choice. On a destructive dialog the
        // cancel button is the default one, so pressing Enter cannot trigger
        // the destructive action by accident. Before, a danger dialog had no
        // default button at all and Enter did nothing.
        PrimaryButton.IsDefault = !options.IsDanger;
        DangerButton.IsDefault = false;
        CancelButton.IsDefault = options.IsDanger && options.ShowCancel;
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
        var (iconKey, softKey, textKey) = severity switch
        {
            MessageSeverity.Success => ("Icon.Check", "Success.Soft", "Success.Text"),
            MessageSeverity.Warning => ("Icon.Warning", "Warning.Soft", "Warning.Text"),
            MessageSeverity.Danger => ("Icon.Error", "Danger.Soft", "Danger.Text"),
            _ => ("Icon.Info", "Info.Soft", "Info.Text")
        };

        if (TryFindResource(iconKey) is string glyph) IconGlyph.Text = glyph;
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
