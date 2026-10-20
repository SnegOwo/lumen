using System.Threading;
using System.Windows;
using System.Windows.Threading;
using Lumen.App.Dialogs;
using Lumen.App.Services;
using Lumen.App.ViewModels;

namespace Lumen.App;

public partial class App : Application
{
    private Mutex? _singleInstanceMutex;
    private bool _ownsMutex;
    private AppServices? _services;
    private MainViewModel? _viewModel;
    private bool _handlingUiCrash;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _singleInstanceMutex = new Mutex(
            initiallyOwned: true,
            name: @"Local\Lumen.Desktop.SingleInstance",
            createdNew: out var createdNew);
        _ownsMutex = createdNew;

        if (!createdNew)
        {
            MessageBox.Show(
                "Lumen is already running. Open it from the notification area or use the existing window.",
                "Lumen",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

        try
        {
            _services = new AppServices();
            _services.Theme.Apply(_services.Settings.Theme);

            _viewModel = new MainViewModel(_services);
            var window = new MainWindow(_services, _viewModel);
            MainWindow = window;

            _services.AttachTray(new TrayService(
                open: window.ShowFromTray,
                quickScan: () =>
                {
                    window.ShowFromTray();
                    _viewModel.StartQuickScan();
                },
                exit: window.ExitApplication));

            window.Show();
            _viewModel.Navigate("dashboard");

            // A demonstration run: raise the detection alert on a harmless sample so
            // the whole pipeline can be shown without real malware.
            if (e.Args.Any(argument => string.Equals(argument, "--demo", StringComparison.OrdinalIgnoreCase)))
            {
                Dispatcher.BeginInvoke(
                    new Action(() => _services.TriggerDemoDetection()),
                    DispatcherPriority.ApplicationIdle);
            }

            var shotsIndex = Array.FindIndex(e.Args, a => a == "--shots");
            if (shotsIndex >= 0)
            {
                var dir = shotsIndex + 1 < e.Args.Length ? e.Args[shotsIndex + 1] : "shots";
                Dispatcher.BeginInvoke(new Action(() => CapturePages(window, _viewModel, dir)));
            }

            if (_services.StartupWarnings.Count > 0)
            {
                var warnings = string.Join(Environment.NewLine, _services.StartupWarnings);
                Dispatcher.BeginInvoke(
                    new Action(() => _services.Dialogs.ShowMessage(
                        "Some local data could not be loaded",
                        "Lumen started, but part of its local state could not be read. New data will still be saved. " +
                        "Existing quarantine items are never deleted automatically.",
                        MessageSeverity.Warning,
                        warnings)),
                    DispatcherPriority.ApplicationIdle);
            }
        }
        catch (Exception ex)
        {
            try
            {
                _services?.Log.Error("Startup", "Lumen could not finish starting.", ex);
            }
            catch
            {
                // Logging must not mask the startup failure.
            }

            MessageBox.Show(
                "Lumen could not start. The local data folder may be inaccessible or damaged.\n\n" +
                ex.Message,
                "Lumen could not start",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    /// <summary>
    /// Walks every page and saves the window as a PNG. It exists so the interface can be
    /// reviewed without a human clicking through it, and so a change to the design can be
    /// compared page by page.
    /// </summary>
    private static void CapturePages(Window window, MainViewModel? viewModel, string directory)
    {
        if (viewModel is null) return;

        try
        {
            Directory.CreateDirectory(directory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        var pages = viewModel.NavigationItems.ToArray();
        var index = 0;

        void Step()
        {
            if (index >= pages.Length)
            {
                Application.Current.Shutdown();
                return;
            }

            var page = pages[index++];
            try
            {
                viewModel.Navigate(page.Key);
            }
            catch (Exception ex)
            {
                _services?.Log.Warn("Screenshots", "A page could not be captured: " + page.Key, ex);
            }

            var timer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(600)
            };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                Save(window, directory, page.Key);
                Step();
            };
            timer.Start();
        }

        Step();
    }

    private static void Save(Window window, string directory, string name)
    {
        try
        {
            var width = (int)Math.Max(1, window.ActualWidth);
            var height = (int)Math.Max(1, window.ActualHeight);
            if (width < 10 || height < 10) return;

            var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap(
                width, height, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
            bitmap.Render(window);

            var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
            encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));

            var path = Path.Combine(directory, name + ".png");
            using var stream = File.Create(path);
            encoder.Save(stream);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // A screenshot that fails is not worth crashing over.
        }
    }

    protected override void OnExit(ExitEventArgs e)    {
        try
        {
            _viewModel?.Dispose();
        }
        catch
        {
            // Best-effort disposal during shutdown.
        }

        try
        {
            _services?.Dispose();
        }
        catch
        {
            // Best-effort disposal during shutdown.
        }

        if (_singleInstanceMutex is not null)
        {
            if (_ownsMutex)
            {
                try
                {
                    _singleInstanceMutex.ReleaseMutex();
                }
                catch (ApplicationException)
                {
                    // The mutex was already released.
                }
            }

            _singleInstanceMutex.Dispose();
            _singleInstanceMutex = null;
        }

        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            _services?.Log.Error("App", "An unexpected UI error occurred.", e.Exception);
        }
        catch
        {
            // Ignore logging failures.
        }

        if (_handlingUiCrash)
        {
            e.Handled = true;
            Shutdown(1);
            return;
        }

        _handlingUiCrash = true;
        e.Handled = true;

        MessageBox.Show(
            "Lumen hit an unexpected error. No files were changed by this error. " +
            "Details were written to the local diagnostic log.\n\n" +
            "You can continue, but if the problem repeats, restart Lumen.",
            "Unexpected error",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);

        _handlingUiCrash = false;
    }

    private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        try
        {
            if (e.ExceptionObject is Exception exception)
                _services?.Log.Error("App", "An unhandled background error occurred.", exception);
            else
                _services?.Log.Error("App", "An unknown unhandled background error occurred.");
        }
        catch
        {
            // The process may be terminating.
        }
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        try
        {
            _services?.Log.Warn("App", "An unobserved background task failed.", e.Exception);
        }
        catch
        {
            // Ignore logging failures.
        }

        e.SetObserved();
    }
}
