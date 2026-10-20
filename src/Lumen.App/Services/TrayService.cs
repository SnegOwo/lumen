using System.Drawing;
using System.Windows.Forms;

namespace Lumen.App.Services;

/// <summary>
/// Standard notification-area icon. The tray is optional; every action is also available in
/// the main window, so the app remains fully keyboard accessible without it.
/// </summary>
public sealed class TrayService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly ContextMenuStrip _menu;
    private readonly Icon _iconImage;
    private bool _disposed;
    private bool _notificationsEnabled = true;

    public TrayService(Action open, Action quickScan, Action exit)
    {
        _iconImage = LoadIcon();
        _menu = new ContextMenuStrip
        {
            ShowImageMargin = false
        };

        var openItem = new ToolStripMenuItem("Open Lumen", null, (_, _) => open());
        openItem.Font = new Font(_menu.Font, FontStyle.Bold);
        _menu.Items.Add(openItem);
        _menu.Items.Add(new ToolStripMenuItem("Quick scan", null, (_, _) => quickScan()));
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add(new ToolStripMenuItem("Exit", null, (_, _) => exit()));

        _notifyIcon = new NotifyIcon
        {
            Icon = _iconImage,
            Text = "Lumen \u2014 real-time protection",
            Visible = true,
            ContextMenuStrip = _menu
        };
        _notifyIcon.DoubleClick += (_, _) => open();
    }

    public bool NotificationsEnabled
    {
        get => _notificationsEnabled;
        set => _notificationsEnabled = value;
    }

    public void SetStatus(string? status)
    {
        var text = string.IsNullOrWhiteSpace(status)
            ? "Lumen \u2014 real-time protection"
            : "Lumen \u2014 " + status.Trim();

        if (text.Length > 63) text = text[..62] + "\u2026";
        _notifyIcon.Text = text;
    }

    public void Notify(string title, string message)
    {
        if (!_notificationsEnabled || _disposed) return;

        try
        {
            _notifyIcon.BalloonTipTitle = title;
            _notifyIcon.BalloonTipText = message;
            _notifyIcon.BalloonTipIcon = ToolTipIcon.Info;
            _notifyIcon.ShowBalloonTip(4500);
        }
        catch
        {
            // Notification settings are controlled by Windows; failure is non-fatal.
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _menu.Dispose();
        _iconImage.Dispose();
    }

    private static Icon LoadIcon()
    {
        try
        {
            var resource = System.Windows.Application.GetResourceStream(
                new Uri("pack://application:,,,/Assets/lumen.ico"));
            if (resource?.Stream is not null)
            {
                using var stream = resource.Stream;
                return new Icon(stream);
            }
        }
        catch
        {
            // Fall through to the executable or a system icon.
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(Environment.ProcessPath))
            {
                var extracted = Icon.ExtractAssociatedIcon(Environment.ProcessPath);
                if (extracted is not null) return extracted;
            }
        }
        catch
        {
            // Use the generic shield below.
        }

        return SystemIcons.Shield;
    }
}
