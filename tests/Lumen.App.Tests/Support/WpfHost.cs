using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;

namespace Lumen.App.Tests.Support;

/// <summary>
/// A single, dedicated STA thread that owns every WPF object the tests touch.
///
/// <para>
/// WPF objects are thread affine and the dispatcher may only be created on a
/// single-threaded apartment, so the tests never touch WPF directly. They hand
/// work to this host instead and get plain data back.
/// </para>
/// </summary>
internal sealed class WpfHost
{
    private static readonly Lazy<WpfHost> Lazy = new(() => new WpfHost());

    public static WpfHost Shared => Lazy.Value;

    /// <summary>True when the caller already runs on the WPF host thread.</summary>
    public bool IsOnHostThread => Environment.CurrentManagedThreadId == _thread.ManagedThreadId;

    private readonly BlockingCollection<Action> _queue = new(new ConcurrentQueue<Action>());
    private readonly Thread _thread;

    private WpfHost()
    {
        _thread = new Thread(Loop)
        {
            IsBackground = true,
            Name = "Lumen.App.Tests WPF host",
        };

        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
    }

    public void Invoke(Action action) => Invoke<object?>(() =>
    {
        action();
        return null;
    });

    public T Invoke<T>(Func<T> function)
    {
        using var done = new ManualResetEventSlim(false);
        Exception? failure = null;
        T result = default!;

        _queue.Add(() =>
        {
            try
            {
                result = function();
            }
            catch (Exception exception)
            {
                failure = exception;
            }
            finally
            {
                done.Set();
            }
        });

        if (!done.Wait(TimeSpan.FromMinutes(1)))
        {
            throw new TimeoutException("The WPF test host did not answer within one minute.");
        }

        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();

        return result;
    }

    private void Loop()
    {
        foreach (var action in _queue.GetConsumingEnumerable()) action();
    }
}
