using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Configuration;
using UnifiMcp.Journal;
using UnifiMcp.Security;

namespace UnifiMcp.Tests;

public sealed class ScheduledClientCollectionServiceTests
{
    [Fact]
    public void Overdue_collection_runs_immediately()
    {
        var now = DateTimeOffset.Parse("2026-07-27T12:00:00Z");

        var delay = ScheduledCollectionPlanner.DelayUntilDue(
            now.AddMinutes(-61),
            now,
            TimeSpan.FromHours(1));

        Assert.Equal(TimeSpan.Zero, delay);
    }

    [Fact]
    public void Recent_collection_waits_only_for_the_remaining_interval()
    {
        var now = DateTimeOffset.Parse("2026-07-27T12:00:00Z");

        var delay = ScheduledCollectionPlanner.DelayUntilDue(
            now.AddMinutes(-15),
            now,
            TimeSpan.FromHours(1));

        Assert.Equal(TimeSpan.FromMinutes(45), delay);
    }

    [Fact]
    public void Far_future_collection_retries_at_the_normal_interval()
    {
        var now = DateTimeOffset.Parse("2026-07-27T12:00:00Z");
        var interval = TimeSpan.FromHours(1);

        var delay = ScheduledCollectionPlanner.DelayUntilDue(
            now.AddDays(50),
            now,
            interval);

        Assert.Equal(interval, delay);
    }

    [Fact]
    public void Invalid_interval_fails_closed()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => ScheduledCollectionPlanner.DelayUntilDue(
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                TimeSpan.Zero));
    }

    [Fact]
    public void Startup_inspection_failure_defers_to_the_normal_retry_interval()
    {
        var configuration = new UnifiConfiguration(
            new Uri("https://example.test/proxy/network/integration/"),
            "test-key",
            DefaultSiteId: null,
            RequestTimeout: TimeSpan.FromSeconds(30),
            EnableClientJournal: true,
            ClientJournalDatabasePath: null,
            EnableScheduledCollection: true);
        var service = new ScheduledClientCollectionService(
            configuration,
            null!,
            new ClientJournalStore(configuration),
            new SecretRedactor(),
            TimeProvider.System,
            NullLogger<ScheduledClientCollectionService>.Instance);

        var delay = service.GetInitialDelayOrRetry();

        Assert.Equal(configuration.ScheduledCollectionInterval, delay);
    }
}
