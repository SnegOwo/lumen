using System.Windows;
using Lumen.App.Dialogs;
using Microsoft.Win32;

namespace Lumen.App.Services;

public sealed class DialogService
{
    private readonly ThemeService _theme;

    public DialogService(ThemeService theme)
    {
        _theme = theme;
    }

    public bool Confirm(
        string title,
        string message,
        string primaryText,
        bool danger = false,
        string? details = null,
        string cancelText = "Cancel",
        Window? owner = null)
    {
        var window = ResolveOwner(owner);
        var result = ConfirmDialog.Show(window, new ConfirmDialogOptions
        {
            Title = title,
            Message = message,
            PrimaryText = primaryText,
            CancelText = cancelText,
            IsDanger = danger,
            Details = details,
            // A destructive confirmation must LOOK destructive. Previously this used the
            // Warning severity, so a "delete permanently" prompt showed an amber
            // information icon next to a red button, and the Danger severity could never
            // be reached through Confirm at all.
            Severity = danger ? MessageSeverity.Danger : MessageSeverity.Info
        });

        return result;
    }

    public void ShowMessage(
        string title,
        string message,
        MessageSeverity severity = MessageSeverity.Info,
        string? details = null,
        Window? owner = null)
    {
        var window = ResolveOwner(owner);
        ConfirmDialog.Show(window, new ConfirmDialogOptions
        {
            Title = title,
            Message = message,
            PrimaryText = "Close",
            ShowCancel = false,
            IsDanger = false,
            Details = details,
            Severity = severity
        });
    }

    public string? PickFolder(string title, string? initialDirectory = null, Window? owner = null)
    {
        var dialog = new OpenFolderDialog
        {
            Title = title,
            Multiselect = false
        };

        if (!string.IsNullOrWhiteSpace(initialDirectory) && Directory.Exists(initialDirectory))
            dialog.InitialDirectory = initialDirectory;

        var window = ResolveOwner(owner);
        var accepted = window is not null ? dialog.ShowDialog(window) : dialog.ShowDialog();
        return accepted == true ? dialog.FolderName : null;
    }

    public string? PickFile(string title, string? initialDirectory = null, Window? owner = null)
    {
        var dialog = new OpenFileDialog
        {
            Title = title,
            Multiselect = false,
            CheckFileExists = true,
            Filter = "All files (*.*)|*.*"
        };

        if (!string.IsNullOrWhiteSpace(initialDirectory) && Directory.Exists(initialDirectory))
            dialog.InitialDirectory = initialDirectory;

        var window = ResolveOwner(owner);
        var accepted = window is not null ? dialog.ShowDialog(window) : dialog.ShowDialog();
        return accepted == true ? dialog.FileName : null;
    }

    private static Window? ResolveOwner(Window? owner)
    {
        var candidate = owner ?? Application.Current?.MainWindow;
        return candidate is { IsVisible: true } ? candidate : null;
    }
}
