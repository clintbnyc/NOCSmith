using System.Globalization;
using System.Text.Json.Nodes;

namespace UnifiMcp.Api;

public sealed class SiteManagerRateLimiter
{
    public const int DefaultPermitLimit = 9_000;
    public const int DefaultQueueLimit = 100;

    private static readonly TimeSpan DefaultWindow = TimeSpan.FromMinutes(1);

    private readonly object _sync = new();
    private readonly Queue<DateTimeOffset> _requests = new();
    private readonly int _permitLimit;
    private readonly int _queueLimit;
    private readonly TimeSpan _window;
    private readonly Func<DateTimeOffset> _getUtcNow;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private int _waiting;

    public SiteManagerRateLimiter(
        int permitLimit = DefaultPermitLimit,
        TimeSpan? window = null,
        int queueLimit = DefaultQueueLimit,
        Func<DateTimeOffset>? getUtcNow = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        if (permitLimit < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(permitLimit));
        }

        if (queueLimit < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(queueLimit));
        }

        _permitLimit = permitLimit;
        _window = window ?? DefaultWindow;
        _queueLimit = queueLimit;
        _getUtcNow = getUtcNow ?? (() => DateTimeOffset.UtcNow);
        _delay = delay ?? Task.Delay;
    }

    public Task WaitAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            var now = _getUtcNow();
            Prune(now);
            if (_requests.Count < _permitLimit)
            {
                _requests.Enqueue(now);
                return Task.CompletedTask;
            }
        }

        return WaitQueuedAsync(cancellationToken);
    }

    private async Task WaitQueuedAsync(CancellationToken cancellationToken)
    {
        var waiting = Interlocked.Increment(ref _waiting);
        if (waiting > _queueLimit)
        {
            Interlocked.Decrement(ref _waiting);
            throw new SiteManagerRateLimitQueueException(
                $"The Site Manager request queue is full ({_queueLimit} waiting request(s)).");
        }

        try
        {
            while (true)
            {
                TimeSpan wait;
                lock (_sync)
                {
                    var now = _getUtcNow();
                    Prune(now);
                    if (_requests.Count < _permitLimit)
                    {
                        _requests.Enqueue(now);
                        return;
                    }

                    wait = _requests.Peek() + _window - now;
                }

                if (wait > TimeSpan.Zero)
                {
                    await _delay(wait, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            Interlocked.Decrement(ref _waiting);
        }
    }

    public JsonObject Describe()
    {
        int used;
        lock (_sync)
        {
            Prune(_getUtcNow());
            used = _requests.Count;
        }

        return new JsonObject
        {
            ["algorithm"] = "rolling-window",
            ["permitLimit"] = _permitLimit,
            ["windowSeconds"] = _window.TotalSeconds,
            ["queueLimit"] = _queueLimit,
            ["requestsInCurrentWindow"] = used,
            ["waitingRequests"] = Volatile.Read(ref _waiting),
            ["scope"] = "connector-process",
            ["providerLimit"] = "stable v1: 10000 requests per minute",
            ["headroom"] = "10%"
        };
    }

    private void Prune(DateTimeOffset now)
    {
        var cutoff = now - _window;
        while (_requests.Count > 0 && _requests.Peek() <= cutoff)
        {
            _requests.Dequeue();
        }
    }
}

public sealed class SiteManagerRateLimitQueueException : Exception
{
    public SiteManagerRateLimitQueueException(string message)
        : base(message)
    {
    }
}
