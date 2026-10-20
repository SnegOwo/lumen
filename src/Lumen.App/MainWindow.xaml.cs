using System.ComponentModel;
using System.Windows;
using Lumen.App.Dialogs;
using Lumen.App.Localization;
using Lumen.App.Services;
using Lumen.App.ViewModels;

namespace Lumen.App;

public partial class MainWindow : Window
{
    private readonly AppServices _services;
    private readonly MainViewModel _viewModel;
    private bool _isExiting;
    private bool _trayHintShown;

    public MainWindow(AppServices services, MainViewModel viewModel)
    {
        _services = services;
        _viewModel = viewModel;

        InitializeComponent();
        DataContext = viewModel;

        // The interface language follows the saved settings from the very first
        // frame, so the window never flashes the wrong language.
        Text.Set(services.Language);

        var workArea = SystemParameters.WorkArea;
        Width = Math.Min(1320, Math.Max(MinWidth, workArea.Width - 64));
        Height = Math.Min(860, Math.Max(MinHeight, workArea.Height - 56));

        Loaded += OnLoaded;
    }

    public void ShowFromTray()
    {
        if (!IsVisible) Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;

        ShowInTaskbar = true;
        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    public void ExitApplication()
    {
        if (_isExiting) return;
        if (!ConfirmStopScan()) return;

        _isExiting = true;
        Close();
        Application.Current?.Shutdown();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (_isExiting)
        {
            base.OnClosing(e);
            return;
        }

        if (_services.Settings.MinimizeToTray)
        {
            e.Cancel = true;
            Hide();
            ShowTrayHintOnce();
            return;
        }

        if (!ConfirmStopScan())
        {
            e.Cancel = true;
            return;
        }

        _isExiting = true;
        base.OnClosing(e);
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);

        if (!_isExiting
            && WindowState == WindowState.Minimized
            && _services.Settings.MinimizeToTray)
        {
            Hide();
            ShowTrayHintOnce();
        }
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        _services.Theme.ApplyWindowChrome(this);
    }

    private bool ConfirmStopScan()
    {
        if (!_viewModel.Scan.IsScanning) return true;

        var proceed = _services.Dialogs.Confirm(
            Text.ExitStopScanTitle,
            Text.ExitStopScanBody,
            Text.ExitStopScanConfirm,
            danger: true);
        if (!proceed) return false;

        _viewModel.CancelActiveWork();
        return true;
    }

    private void ShowTrayHintOnce()
    {
        if (_trayHintShown) return;
        _trayHintShown = true;
        _services.Tray?.Notify(
            Text.TrayStillRunningTitle,
            Text.TrayStillRunningBody);
    }
}
