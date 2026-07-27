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

    [Fact]
    public async Task Provider_retry_after_defers_all_new_permits()
    {
        var now = new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero);
        var delays = new List<TimeSpan>();
        var limiter = new SiteManagerRateLimiter(
            permitLimit: 10,
            window: TimeSpan.FromMinutes(1),
            queueLimit: 2,
            getUtcNow: () => now,
            delay: (value, _) =>
            {
                delays.Add(value);
                now += value;
                return Task.CompletedTask;
            });

        limiter.DeferUntil(now.AddSeconds(30));
        Assert.True(limiter.Describe()["providerCooldownActive"]!.GetValue<bool>());

        await limiter.WaitAsync(CancellationToken.None);

        Assert.Equal(TimeSpan.FromSeconds(30), Assert.Single(delays));
        Assert.False(limiter.Describe()["providerCooldownActive"]!.GetValue<bool>());
        Assert.Equal(1, limiter.Describe()["requestsInCurrentWindow"]!.GetValue<int>());
    }

    [Fact]
    public async Task Provider_cooldown_over_five_minutes_fails_without_waiting()
    {
        var now = new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero);
        var delays = new List<TimeSpan>();
        var limiter = new SiteManagerRateLimiter(
            permitLimit: 10,
            window: TimeSpan.FromMinutes(1),
            queueLimit: 2,
            getUtcNow: () => now,
            delay: (value, _) =>
            {
                delays.Add(value);
                return Task.CompletedTask;
            });
        var retryAt = now.AddMinutes(5).Add(TimeSpan.FromTicks(1));
        limiter.DeferUntil(retryAt);

        var exception = await Assert.ThrowsAsync<SiteManagerApiException>(
            () => limiter.WaitAsync(CancellationToken.None));

        Assert.True(exception.IsRateLimited);
        Assert.Equal(retryAt, exception.RetryAt);
        Assert.Equal("provider_cooldown", exception.Code);
        Assert.Empty(delays);
        Assert.Equal(
            0,
            limiter.Describe()["waitingRequests"]!.GetValue<int>());
    }

    [Fact]
    public async Task Availability_wait_does_not_reserve_a_dispatch_permit()
    {
        var now = new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero);
        var limiter = new SiteManagerRateLimiter(
            permitLimit: 1,
            getUtcNow: () => now);

        await limiter.WaitForAvailabilityAsync(CancellationToken.None);

        Assert.Equal(
            0,
            limiter.Describe()["requestsInCurrentWindow"]!.GetValue<int>());
        Assert.True(limiter.TryAcquirePermit());
        Assert.Equal(
            1,
            limiter.Describe()["requestsInCurrentWindow"]!.GetValue<int>());
        Assert.False(limiter.TryAcquirePermit());
    }

    [Fact]
    public async Task Final_permit_check_observes_a_new_provider_cooldown()
    {
        var now = new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero);
        var limiter = new SiteManagerRateLimiter(
            permitLimit: 1,
            getUtcNow: () => now);
        await limiter.WaitForAvailabilityAsync(CancellationToken.None);

        limiter.DeferUntil(now.AddSeconds(30));

        Assert.False(limiter.TryAcquirePermit());
        Assert.Equal(
            0,
            limiter.Describe()["requestsInCurrentWindow"]!.GetValue<int>());
    }
}
