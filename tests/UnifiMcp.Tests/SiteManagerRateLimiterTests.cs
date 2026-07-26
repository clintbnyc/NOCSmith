using UnifiMcp.Api;

namespace UnifiMcp.Tests;

public sealed class SiteManagerRateLimiterTests
{
    [Fact]
    public async Task Rolling_window_waits_until_the_oldest_permit_expires()
    {
        var now = new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero);
        var delays = new List<TimeSpan>();
        var limiter = new SiteManagerRateLimiter(
            permitLimit: 2,
            window: TimeSpan.FromMinutes(1),
            queueLimit: 2,
            getUtcNow: () => now,
            delay: (value, _) =>
            {
                delays.Add(value);
                now += value;
                return Task.CompletedTask;
            });

        await limiter.WaitAsync(CancellationToken.None);
        await limiter.WaitAsync(CancellationToken.None);
        await limiter.WaitAsync(CancellationToken.None);

        Assert.Equal(TimeSpan.FromMinutes(1), Assert.Single(delays));
        Assert.Equal(1, limiter.Describe()["requestsInCurrentWindow"]!.GetValue<int>());
    }

    [Fact]
    public async Task Queue_is_bounded_and_wait_is_cancellable()
    {
        var now = new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero);
        var limiter = new SiteManagerRateLimiter(
            permitLimit: 1,
            window: TimeSpan.FromHours(1),
            queueLimit: 1,
            getUtcNow: () => now,
            delay: (_, cancellationToken) =>
                Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken));
        await limiter.WaitAsync(CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        var waiting = limiter.WaitAsync(cancellation.Token);

        await Assert.ThrowsAsync<SiteManagerRateLimitQueueException>(() =>
            limiter.WaitAsync(CancellationToken.None));

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
    }
}
