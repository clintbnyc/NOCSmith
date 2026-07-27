using UnifiMcp.Journal;

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
    public void Invalid_interval_fails_closed()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => ScheduledCollectionPlanner.DelayUntilDue(
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                TimeSpan.Zero));
    }
}
