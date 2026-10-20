using System.Windows.Input;
using Lumen.App.Infrastructure;

namespace Lumen.App.Tests;

public sealed class CommandTests
{
    [Fact]
    public void RelayCommand_execute_invokesTheAction()
    {
        var invocations = 0;
        var command = new RelayCommand(() => invocations++);

        command.Execute(null);

        Assert.Equal(1, invocations);
    }

    [Fact]
    public void RelayCommand_execute_withACommandParameter_ignoresTheParameter()
    {
        var invocations = 0;
        var command = new RelayCommand(() => invocations++);

        command.Execute("payload");

        Assert.Equal(1, invocations);
    }

    [Fact]
    public void RelayCommand_canExecute_withoutAPredicate_isTrue()
    {
        var command = new RelayCommand(() => { });

        Assert.True(command.CanExecute(null));
    }

    [Fact]
    public void RelayCommand_canExecute_reflectsThePredicate()
    {
        var allowed = false;
        var command = new RelayCommand(() => { }, () => allowed);

        Assert.False(command.CanExecute(null));

        allowed = true;

        Assert.True(command.CanExecute(null));
    }

    [Fact]
    public void RelayCommand_execute_whenCanExecuteIsFalse_doesNotInvokeTheAction()
    {
        var invocations = 0;
        var command = new RelayCommand(() => invocations++, () => false);

        command.Execute(null);

        Assert.Equal(0, invocations);
    }

    [Fact]
    public void RelayCommand_raiseCanExecuteChanged_raisesTheCanExecuteChangedEvent()
    {
        var command = new RelayCommand(() => { });
        var raised = 0;
        command.CanExecuteChanged += (_, _) => raised++;

        command.RaiseCanExecuteChanged();

        Assert.Equal(1, raised);
    }

    [Fact]
    public void RelayCommandT_execute_invokesTheActionWithTheParameter()
    {
        string? received = null;
        var command = new RelayCommand<string>(value => received = value);

        command.Execute("payload");

        Assert.Equal("payload", received);
    }

    [Fact]
    public void RelayCommandT_execute_withANullParameter_passesTheDefaultValue()
    {
        string? received = "not null";
        var command = new RelayCommand<string>(value => received = value);

        command.Execute(null);

        Assert.Null(received);
    }

    [Fact]
    public void RelayCommandT_canExecute_reflectsThePredicate()
    {
        var allowed = false;
        var command = new RelayCommand<string>(_ => { }, _ => allowed);

        Assert.False(command.CanExecute("payload"));

        allowed = true;

        Assert.True(command.CanExecute("payload"));
    }

    [Fact]
    public void RelayCommandT_canExecute_withAWrongParameterType_returnsFalse()
    {
        var command = new RelayCommand<string>(_ => { });

        Assert.False(command.CanExecute(42));
    }

    [Fact]
    public void RelayCommandT_execute_withAWrongParameterType_throwsInvalidCastException()
    {
        var command = new RelayCommand<string>(_ => { });

        Assert.Throws<InvalidCastException>(() => command.Execute(42));
    }

    [Fact]
    public void RelayCommandT_execute_whenCanExecuteIsFalse_doesNotInvokeTheAction()
    {
        var invocations = 0;
        var command = new RelayCommand<string>(_ => invocations++, _ => false);

        command.Execute("payload");

        Assert.Equal(0, invocations);
    }

    [Fact]
    public void RelayCommandT_raiseCanExecuteChanged_raisesTheCanExecuteChangedEvent()
    {
        var command = new RelayCommand<string>(_ => { });
        var raised = 0;
        command.CanExecuteChanged += (_, _) => raised++;

        command.RaiseCanExecuteChanged();

        Assert.Equal(1, raised);
    }

    [Fact]
    public async Task AsyncRelayCommand_execute_awaitsTheTask()
    {
        var completed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var finished = false;

        var command = new AsyncRelayCommand(async () =>
        {
            await Task.Delay(20);
            finished = true;
            completed.SetResult(true);
        });

        command.Execute(null);

        await completed.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(finished);
    }

    [Fact]
    public async Task AsyncRelayCommand_execute_raisesCanExecuteChangedWhileRunning()
    {
        var completed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var raisedWhileRunning = 0;
        var command = new AsyncRelayCommand(async () =>
        {
            await Task.Delay(20);
            completed.SetResult(true);
        });

        command.CanExecuteChanged += (_, _) =>
        {
            if (command.IsRunning) raisedWhileRunning++;
        };

        command.Execute(null);

        await completed.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(raisedWhileRunning > 0);
        Assert.False(command.IsRunning);
        Assert.True(command.CanExecute(null));
    }

    [Fact]
    public async Task AsyncRelayCommand_execute_withAFailingTask_reportsTheFailureToTheErrorHandler()
    {
        var reported = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        var failure = new InvalidOperationException("boom");

        var command = new AsyncRelayCommand(
            () => Task.FromException(failure),
            onError: exception =>
            {
                reported.SetResult(exception);
                return Task.CompletedTask;
            });

        command.Execute(null);

        var captured = await reported.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Same(failure, captured);
    }

    [Fact]
    public async Task AsyncRelayCommand_withErrorHandler_reportsTheFailureToTheHandler()
    {
        var reported = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        var failure = new InvalidOperationException("boom");

        var command = AsyncRelayCommand.WithErrorHandler(
            () => Task.FromException(failure),
            exception => reported.SetResult(exception));

        command.Execute(null);

        var captured = await reported.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Same(failure, captured);
    }

    [Fact]
    public async Task AsyncRelayCommand_execute_withACancelledTask_doesNotReportAnError()
    {
        var reported = false;
        var completed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        var command = new AsyncRelayCommand(
            () =>
            {
                completed.SetResult(true);
                return Task.FromCanceled(new CancellationToken(true));
            },
            onError: _ =>
            {
                reported = true;
                return Task.CompletedTask;
            });

        command.Execute(null);

        await completed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await Task.Delay(100);

        Assert.False(reported);
    }

    [Fact]
    public void AsyncRelayCommand_execute_withoutAnErrorHandler_surfacesTheException()
    {
        var captured = new List<Exception>();
        var previous = SynchronizationContext.Current;
        var context = new CapturingSynchronizationContext(captured);

        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            var command = new AsyncRelayCommand(() => Task.FromException(new InvalidOperationException("boom")));
            command.Execute(null);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        Assert.Contains(captured, exception => exception is InvalidOperationException && exception.Message == "boom");
    }

    [Fact]
    public void AsyncRelayCommand_canExecute_isFalseWhileTheCommandRuns()
    {
        var release = new ManualResetEventSlim(false);
        var command = new AsyncRelayCommand(() => Task.Run(() => release.Wait(TimeSpan.FromSeconds(10))));

        command.Execute(null);

        Assert.False(command.CanExecute(null));
        Assert.True(command.IsRunning);

        release.Set();
    }

    private sealed class CapturingSynchronizationContext : SynchronizationContext
    {
        private readonly List<Exception> _exceptions;

        public CapturingSynchronizationContext(List<Exception> exceptions) => _exceptions = exceptions;

        public override void Post(SendOrPostCallback callback, object? state)
        {
            try
            {
                callback(state);
            }
            catch (Exception exception)
            {
                lock (_exceptions) _exceptions.Add(exception);
            }
        }

        public override void Send(SendOrPostCallback callback, object? state) => Post(callback, state);
    }
}
