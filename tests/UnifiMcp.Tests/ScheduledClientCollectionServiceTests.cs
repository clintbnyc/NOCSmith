using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
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
    public async Task Startup_inspection_failure_defers_to_the_normal_retry_interval()
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
            null!,
            new ClientJournalStore(configuration),
            new SecretRedactor(),
            TimeProvider.System,
            NullLogger<ScheduledClientCollectionService>.Instance);

        var delay = await service.GetInitialDelayOrRetryAsync(TestContext.Current.CancellationToken);

        Assert.Equal(configuration.ScheduledCollectionInterval, delay);
    }

    [Fact]
    public async Task Implicit_site_is_resolved_before_the_last_collection_is_queried()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = TemporaryPrivateDirectory.Create();
        var configuration = new UnifiConfiguration(
            new Uri("https://example.test/proxy/network/integration/"),
            "test-key",
            DefaultSiteId: null,
            RequestTimeout: TimeSpan.FromSeconds(30),
            EnableClientJournal: true,
            ClientJournalDatabasePath: Path.Combine(directory.Path, "journal.db"),
            EnableScheduledCollection: true);
        var store = new ClientJournalStore(configuration);
        await store.PersistAsync(
            Collection(
                "other-site-collection",
                "00000000-0000-0000-0000-000000000999",
                DateTimeOffset.UtcNow),
            TestContext.Current.CancellationToken);

        var client = new SingleSiteClient();
        var contracts = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            client,
            NullLogger<ContractProvider>.Instance);
        var service = new ScheduledClientCollectionService(
            configuration,
            new SiteResolver(configuration, contracts, client),
            null!,
            store,
            new SecretRedactor(),
            TimeProvider.System,
            NullLogger<ScheduledClientCollectionService>.Instance);

        var delay = await service.GetInitialDelayOrRetryAsync(TestContext.Current.CancellationToken);

        Assert.Equal(TimeSpan.Zero, delay);
        Assert.Equal(1, client.ReadCalls);
    }

    private static ClientObservationCollection Collection(
        string collectionId,
        string siteId,
        DateTimeOffset completedAt)
    {
        var emptyClients = new SourceCollection<NormalizedClientObservation>(
            ClientObservationSource.OfficialConnected,
            CollectionSourceStatus.Complete,
            Array.Empty<NormalizedClientObservation>(),
            null,
            null);
        var emptyHistory = new SourceCollection<NormalizedClientObservation>(
            ClientObservationSource.UiHistory,
            CollectionSourceStatus.Complete,
            Array.Empty<NormalizedClientObservation>(),
            null,
            null);
        var emptyGroups = new SourceCollection<NormalizedClientGroup>(
            ClientObservationSource.ConfiguredGroups,
            CollectionSourceStatus.Complete,
            Array.Empty<NormalizedClientGroup>(),
            null,
            null);
        return new ClientObservationCollection(
            collectionId,
            siteId,
            24,
            completedAt.AddSeconds(-1),
            completedAt,
            emptyClients,
            emptyHistory,
            emptyGroups);
    }

    private sealed class SingleSiteClient : IUnifiClient
    {
        public int ReadCalls { get; private set; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            Assert.Equal("getSiteOverviewPage", request.Operation.OperationId);
            ReadCalls++;
            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = "00000000-0000-0000-0000-000000000201"
                    }
                }
            });
        }

        public Task<JsonNode?> MutateAsync(ValidatedRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> GetFixedAsync(string relativePath, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadPrivateClientsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadClientHistoryAsync(
            string internalSiteReference,
            int withinHours,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
