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
    private DateTimeOffset? _providerRetryAt;

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
            if (!IsProviderCooldownActive(now) && _requests.Count < _permitLimit)
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
                    if (!IsProviderCooldownActive(now) && _requests.Count < _permitLimit)
                    {
                        _requests.Enqueue(now);
                        return;
                    }

                    var rollingWindowWait = _requests.Count >= _permitLimit
                        ? _requests.Peek() + _window - now
                        : TimeSpan.Zero;
                    var providerWait = _providerRetryAt is DateTimeOffset providerRetryAt
                        ? providerRetryAt - now
                        : TimeSpan.Zero;
                    wait = rollingWindowWait > providerWait
                        ? rollingWindowWait
                        : providerWait;
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

    public void DeferUntil(DateTimeOffset retryAt)
    {
        lock (_sync)
        {
            var now = _getUtcNow();
            if (retryAt <= now)
            {
                return;
            }

            if (_providerRetryAt is null || retryAt > _providerRetryAt)
            {
                _providerRetryAt = retryAt;
            }
        }
    }

    public JsonObject Describe()
    {
        int used;
        DateTimeOffset? providerRetryAt;
        lock (_sync)
        {
            var now = _getUtcNow();
            Prune(now);
            used = _requests.Count;
            providerRetryAt = IsProviderCooldownActive(now)
                ? _providerRetryAt
                : null;
        }

        return new JsonObject
        {
            ["algorithm"] = "rolling-window",
            ["permitLimit"] = _permitLimit,
            ["windowSeconds"] = _window.TotalSeconds,
            ["queueLimit"] = _queueLimit,
            ["requestsInCurrentWindow"] = used,
            ["waitingRequests"] = Volatile.Read(ref _waiting),
            ["providerRetryAt"] = providerRetryAt?.ToString("O", CultureInfo.InvariantCulture),
            ["providerCooldownActive"] = providerRetryAt is not null,
            ["scope"] = "connector-process",
            ["providerLimit"] = "stable v1: 10000 requests per minute",
            ["headroom"] = "10%"
        };
    }

    private void Prune(DateTimeOffset now)
    {
        if (_providerRetryAt <= now)
        {
            _providerRetryAt = null;
        }

        var cutoff = now - _window;
        while (_requests.Count > 0 && _requests.Peek() <= cutoff)
        {
            _requests.Dequeue();
        }
    }

    private bool IsProviderCooldownActive(DateTimeOffset now) =>
        _providerRetryAt is DateTimeOffset retryAt && retryAt > now;
}

public sealed class SiteManagerRateLimitQueueException : Exception
{
    public SiteManagerRateLimitQueueException(string message)
        : base(message)
    {
    }
}
