using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Windows.Input;

namespace Lumen.App.Infrastructure;

public sealed class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;

    public void Execute(object? parameter)
    {
        if (CanExecute(parameter)) _execute();
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>
/// A command that takes a typed parameter.
/// </summary>
/// <remarks>
/// A parameter of the wrong type is treated as "cannot execute" rather than as
/// a silent no-op, and the mismatch is written to <see cref="Trace"/>, which
/// is compiled into Release builds (unlike <c>Debug.WriteLine</c>). Calling
/// <see cref="Execute"/> with a wrong-typed parameter throws an
/// <see cref="InvalidCastException"/> with an explanatory message, so a binding
/// mistake is loud when it is hit directly and only quiet when it merely
/// disables a button.
/// </remarks>
public sealed class RelayCommand<T> : ICommand
{
    private readonly Action<T?> _execute;
    private readonly Func<T?, bool>? _canExecute;

    public RelayCommand(Action<T?> execute, Func<T?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter)
    {
        if (parameter is not null and not T)
        {
            Trace.WriteLine(
                $"{nameof(RelayCommand<T>)}<{typeof(T).Name}> received a parameter of type " +
                $"'{parameter.GetType().FullName}'. The command cannot execute. This is almost " +
                "always a binding mistake.");
            return false;
        }

        return parameter is T value
            ? _canExecute?.Invoke(value) ?? true
            : _canExecute?.Invoke(default) ?? true;
    }

    public void Execute(object? parameter)
    {
        if (parameter is not null and not T)
        {
            throw new InvalidCastException(
                $"{nameof(RelayCommand<T>)}<{typeof(T).Name}> was given a parameter of type " +
                $"'{parameter.GetType().FullName}' but expects '{typeof(T).FullName}'. " +
                "This is a binding mistake.");
        }

        if (!CanExecute(parameter)) return;
        _execute(parameter is T value ? value : default);
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>
/// A command that runs an asynchronous operation.
/// </summary>
/// <remarks>
/// The command is deliberately <c>async void</c>: that is the only shape the
/// WPF command infrastructure accepts. The consequences are handled here:
///
/// <list type="bullet">
/// <item>Re-entrancy is blocked while the operation is running.</item>
/// <item>Cancellation is a normal outcome and is not reported as an error.</item>
/// <item>Any other failure is forwarded to the error handler that was passed
/// to the constructor. Without a handler the exception is rethrown on the UI
/// thread, where the application's dispatcher handler logs it and tells the
/// user about it. It used to be swallowed into <c>Debug.WriteLine</c>, which
/// vanishes in Release builds and turned a failed command into an invisible
/// failure.</item>
/// </list>
/// </remarks>
public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private readonly Func<Exception, Task>? _onError;
    private bool _isRunning;

    public AsyncRelayCommand(
        Func<Task> execute,
        Func<bool>? canExecute = null,
        Func<Exception, Task>? onError = null)
    {
        _execute = execute;
        _canExecute = canExecute;
        _onError = onError;
    }

    /// <summary>
    /// Creates a command that reports failures through a synchronous handler.
    /// </summary>
    public static AsyncRelayCommand WithErrorHandler(
        Func<Task> execute,
        Action<Exception> onError,
        Func<bool>? canExecute = null)
    {
        ArgumentNullException.ThrowIfNull(onError);
        return new AsyncRelayCommand(
            execute,
            canExecute,
            exception =>
            {
                onError(exception);
                return Task.CompletedTask;
            });
    }

    public event EventHandler? CanExecuteChanged;

    public bool IsRunning => _isRunning;

    public bool CanExecute(object? parameter) => !_isRunning && (_canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;

        _isRunning = true;
        RaiseCanExecuteChanged();
        try
        {
            await _execute();
        }
        catch (OperationCanceledException)
        {
            // Cancellation is a normal outcome and is reported by the view model.
        }
        catch (Exception ex)
        {
            await HandleFailureAsync(ex);
        }
        finally
        {
            _isRunning = false;
            RaiseCanExecuteChanged();
        }
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    private async Task HandleFailureAsync(Exception ex)
    {
        if (_onError is not null)
        {
            await _onError(ex);
            return;
        }

        // No error handler was supplied. The failure must not be invisible:
        // Debug.WriteLine disappears in Release builds, so the exception is
        // rethrown on the UI thread where the application logs it and shows
        // the user what went wrong.
        Debug.WriteLine(ex);
        ExceptionDispatchInfo.Capture(ex).Throw();
    }
}
