using System.Text.Json.Nodes;
using UnifiMcp.Configuration;
using UnifiMcp.Journal;

namespace UnifiMcp.Tests;

public sealed class ClientJournalServiceTests
{
    private const string SiteId = "6cc5f1b8-cec7-4c50-9b92-805b73892756";
    private static readonly DateTimeOffset Start =
        DateTimeOffset.Parse("2026-07-26T10:00:00.0000000+00:00");

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Describe_reports_scheduled_collection_side_effects(
        bool scheduledCollectionEnabled,
        bool scheduledCollectionHost)
    {
        var configuration = Configuration("/private/tmp/client-journal.db") with
        {
            EnableScheduledCollection = scheduledCollectionEnabled,
            IsScheduledCollectionHost = scheduledCollectionHost
        };
        var service = new ClientJournalService(configuration, null!, null!);

        var description = service.Describe();

        Assert.Equal(
            scheduledCollectionEnabled && scheduledCollectionHost,
            description["automaticCollection"]!.GetValue<bool>());
        Assert.Equal(
            scheduledCollectionEnabled && scheduledCollectionHost,
            description["createsAtStartup"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Recovery_respects_the_cross_process_collection_lease()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        File.WriteAllText(path, "not a sqlite database");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var configuration = Configuration(path);
        var store = new ClientJournalStore(configuration);
        var service = new ClientJournalService(configuration, null!, store);
        var fingerprint = store.Inspect().CorruptionFingerprint!;
        using var lease = store.AcquireCollectionLease();

        await Assert.ThrowsAsync<ClientCollectionInProgressException>(
            () => service.RecoverAsync(fingerprint, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Changes_use_only_complete_source_baselines_and_are_deterministic()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var configuration = Configuration(Path.Combine(directory.Path, "journal.db"));
        var store = new ClientJournalStore(configuration);
        await PersistScenario(store);
        var service = new ClientJournalService(configuration, null!, store);

        var response = await service.ChangesAsync(
            SiteId,
            null,
            24,
            0,
            200,
            TestContext.Current.CancellationToken);

        var data = Assert.IsType<JsonObject>(response.Data);
        var changes = data["changes"]!.AsArray().Select(value => value!.AsObject()).ToArray();
        Assert.Contains(changes, change =>
            Text(change, "source") == "officialConnected" &&
            Text(change, "changeType") == "noLongerConnected" &&
            Text(change, "key") == "aa:bb:cc:dd:ee:02");
        Assert.Contains(changes, change =>
            Text(change, "source") == "uiHistory" &&
            Text(change, "changeType") == "leftHistoryWindow" &&
            Text(change, "key") == "aa:bb:cc:dd:ee:10");
        Assert.Contains(changes, change =>
            Text(change, "changeType") == "groupRenamed");
        Assert.Contains(changes, change =>
            Text(change, "changeType") == "membershipAdded");
        Assert.Contains(changes, change =>
            Text(change, "changeType") == "membershipNoLongerConfigured");
        Assert.Contains(changes, change =>
            Text(change, "source") == "uiHistory" &&
            Text(change, "changeType") == "enteredHistoryWindow" &&
            Text(change, "key") == "aa:bb:cc:dd:ee:11" &&
            Text(change, "after") == "offline");

        var connectedComparison = data["comparisons"]!.AsArray()
            .Select(value => value!.AsObject())
            .Single(value => Text(value, "source") == "officialConnected");
        Assert.Equal("complete-1", Text(connectedComparison, "baselineCollectionId"));
        Assert.Equal("complete-3", Text(connectedComparison, "targetCollectionId"));
        Assert.DoesNotContain("partial-2", connectedComparison.ToJsonString(), StringComparison.Ordinal);

        var sortKeys = changes.Select(value =>
            string.Join(
                "|",
                Text(value, "source"),
                Text(value, "changeType"),
                Text(value, "key"),
                Text(value, "field"))).ToArray();
        Assert.Equal(
            sortKeys.OrderBy(value => value, StringComparer.Ordinal),
            sortKeys);
    }

    [Fact]
    public async Task A_partial_target_never_produces_absence_changes()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var configuration = Configuration(Path.Combine(directory.Path, "journal.db"));
        var store = new ClientJournalStore(configuration);
        await store.PersistAsync(Collection(
            "complete",
            Start,
            CompleteClients(
                Client("aa:bb:cc:dd:ee:01", "One"),
                Client("aa:bb:cc:dd:ee:02", "Two")),
            CompleteHistory(),
            CompleteGroups()),
            TestContext.Current.CancellationToken);
        await store.PersistAsync(Collection(
            "partial",
            Start.AddHours(1),
            PartialClients(Client("aa:bb:cc:dd:ee:01", "One")),
            CompleteHistory(),
            CompleteGroups()),
            TestContext.Current.CancellationToken);
        var service = new ClientJournalService(configuration, null!, store);

        var response = await service.ChangesAsync(
            SiteId,
            null,
            24,
            0,
            200,
            TestContext.Current.CancellationToken);
        var data = Assert.IsType<JsonObject>(response.Data);
        var connectedComparison = data["comparisons"]!.AsArray()
            .Select(value => value!.AsObject())
            .Single(value => Text(value, "source") == "officialConnected");

        Assert.False(connectedComparison["comparisonAvailable"]!.GetValue<bool>());
        Assert.False(connectedComparison["absenceCompared"]!.GetValue<bool>());
        Assert.DoesNotContain(
            data["changes"]!.AsArray(),
            value => Text(value!.AsObject(), "changeType") == "noLongerConnected");
    }

    [Fact]
    public async Task Per_client_history_returns_source_grains_and_bounded_pagination()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var configuration = Configuration(Path.Combine(directory.Path, "journal.db"));
        var store = new ClientJournalStore(configuration);
        await PersistScenario(store);
        var service = new ClientJournalService(configuration, null!, store);

        var response = await service.HistoryAsync(
            "AA:BB:CC:DD:EE:02",
            SiteId,
            Start.AddMinutes(-1).ToString("O"),
            Start.AddHours(3).ToString("O"),
            0,
            1,
            TestContext.Current.CancellationToken);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal("aa:bb:cc:dd:ee:02", Text(data, "macAddress"));
        Assert.Single(data["observations"]!.AsArray());
        Assert.True(data["pagination"]!["truncated"]!.GetValue<bool>());
        Assert.Equal(3, data["pagination"]!["total"]!.GetValue<int>());
        Assert.Equal(1, data["pagination"]!["nextOffset"]!.GetValue<int>());
        Assert.Contains(
            "never imply",
            Text(data, "semantics"),
            StringComparison.Ordinal);

        var secondPage = await service.HistoryAsync(
            "aa:bb:cc:dd:ee:02",
            SiteId,
            null,
            null,
            1,
            1,
            TestContext.Current.CancellationToken);
        var second = Assert.Single(
            Assert.IsType<JsonObject>(secondPage.Data)["observations"]!.AsArray())!.AsObject();
        Assert.Equal("officialConnected", Text(second, "source"));
        Assert.False(second["gapInferenceAllowed"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Health_is_read_only_and_reports_success_rates_without_clients()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var configuration = Configuration(Path.Combine(directory.Path, "journal.db"));
        var store = new ClientJournalStore(configuration);
        await PersistScenario(store);
        var service = new ClientJournalService(configuration, null!, store);
        var before = new FileInfo(store.DatabasePath).LastWriteTimeUtc;

        var response = await service.HealthAsync(TestContext.Current.CancellationToken);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal("healthy", Text(data, "state"));
        Assert.False(data["containsClientData"]!.GetValue<bool>());
        Assert.False(data["filesystemMutated"]!.GetValue<bool>());
        Assert.NotEmpty(data["sourceSuccessRates"]!.AsArray());
        Assert.DoesNotContain("aa:bb:cc", data.ToJsonString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(before, new FileInfo(store.DatabasePath).LastWriteTimeUtc);
    }

    [Theory]
    [InlineData(25, 0, 100)]
    [InlineData(24, -1, 100)]
    [InlineData(24, 0, 0)]
    [InlineData(24, 0, 201)]
    public async Task Change_query_bounds_fail_before_database_access(
        int historyHours,
        int offset,
        int limit)
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var configuration = Configuration(Path.Combine(directory.Path, "missing.db"));
        var service = new ClientJournalService(
            configuration,
            null!,
            new ClientJournalStore(configuration));

        await Assert.ThrowsAsync<UnifiMcp.Contracts.ContractException>(
            () => service.ChangesAsync(
                SiteId,
                null,
                historyHours,
                offset,
                limit,
                TestContext.Current.CancellationToken));
        Assert.False(File.Exists(configuration.ClientJournalDatabasePath));
    }

    [Theory]
    [InlineData("not-a-mac", null, null)]
    [InlineData("aa:bb:cc:dd:ee:01", "2026-07-26T10:00:00", null)]
    [InlineData("aa:bb:cc:dd:ee:01", "2026-07-27T10:00:00Z", "2026-07-26T10:00:00Z")]
    [InlineData("aa:bb:cc:dd:ee:01", "2010-01-01T00:00:00Z", "2026-07-26T10:00:00Z")]
    public async Task Client_history_bounds_fail_before_database_access(
        string mac,
        string? from,
        string? to)
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var configuration = Configuration(Path.Combine(directory.Path, "missing.db"));
        var service = new ClientJournalService(
            configuration,
            null!,
            new ClientJournalStore(configuration));

        await Assert.ThrowsAsync<UnifiMcp.Contracts.ContractException>(
            () => service.HistoryAsync(
                mac,
                SiteId,
                from,
                to,
                0,
                100,
                TestContext.Current.CancellationToken));
        Assert.False(File.Exists(configuration.ClientJournalDatabasePath));
    }

    private static async Task PersistScenario(ClientJournalStore store)
    {
        await store.PersistAsync(Collection(
            "complete-1",
            Start,
            CompleteClients(
                Client("aa:bb:cc:dd:ee:01", "One"),
                Client("aa:bb:cc:dd:ee:02", "Two")),
            CompleteHistory(HistoryClient("aa:bb:cc:dd:ee:10", "Old history")),
            CompleteGroups(Group(
                "0123456789abcdef01234567",
                "Old name",
                "aa:bb:cc:dd:ee:01",
                "aa:bb:cc:dd:ee:02"))),
            TestContext.Current.CancellationToken);
        await store.PersistAsync(Collection(
            "partial-2",
            Start.AddHours(1),
            PartialClients(Client("aa:bb:cc:dd:ee:01", "One")),
            CompleteHistory(HistoryClient("aa:bb:cc:dd:ee:10", "Old history")),
            FailedGroups()),
            TestContext.Current.CancellationToken);
        await store.PersistAsync(Collection(
            "complete-3",
            Start.AddHours(2),
            CompleteClients(Client("aa:bb:cc:dd:ee:01", "One renamed")),
            CompleteHistory(HistoryClient("aa:bb:cc:dd:ee:11", "New history")),
            CompleteGroups(Group(
                "0123456789abcdef01234567",
                "New name",
                "aa:bb:cc:dd:ee:02",
                "aa:bb:cc:dd:ee:03"))),
            TestContext.Current.CancellationToken);
    }

    private static UnifiConfiguration Configuration(string path) =>
        new(
            new Uri("https://example.test/proxy/network/integration/"),
            "test-key",
            SiteId,
            TimeSpan.FromSeconds(30),
            EnableLegacyReadEnrichment: true,
            EnableClientJournal: true,
            ClientJournalDatabasePath: path,
            ClientJournalRetentionDays: 90,
            ClientJournalMaximumMib: 16);

    private static ClientObservationCollection Collection(
        string id,
        DateTimeOffset timestamp,
        SourceCollection<NormalizedClientObservation> connected,
        SourceCollection<NormalizedClientObservation> history,
        SourceCollection<NormalizedClientGroup> groups) =>
        new(
            id,
            SiteId,
            24,
            timestamp.AddSeconds(-1),
            timestamp,
            connected,
            history,
            groups);

    private static SourceCollection<NormalizedClientObservation> CompleteClients(
        params NormalizedClientObservation[] values) =>
        Source(ClientObservationSource.OfficialConnected, CollectionSourceStatus.Complete, values);

    private static SourceCollection<NormalizedClientObservation> PartialClients(
        params NormalizedClientObservation[] values) =>
        new(
            ClientObservationSource.OfficialConnected,
            CollectionSourceStatus.Partial,
            values,
            "controllerReadFailed",
            "safe fixed error");

    private static SourceCollection<NormalizedClientObservation> CompleteHistory(
        params NormalizedClientObservation[] values) =>
        Source(ClientObservationSource.UiHistory, CollectionSourceStatus.Complete, values);

    private static SourceCollection<NormalizedClientObservation> Source(
        ClientObservationSource source,
        CollectionSourceStatus status,
        params NormalizedClientObservation[] values) =>
        new(source, status, values, null, null);

    private static SourceCollection<NormalizedClientGroup> CompleteGroups(
        params NormalizedClientGroup[] values) =>
        new(
            ClientObservationSource.ConfiguredGroups,
            CollectionSourceStatus.Complete,
            values,
            null,
            null);

    private static SourceCollection<NormalizedClientGroup> FailedGroups() =>
        new(
            ClientObservationSource.ConfiguredGroups,
            CollectionSourceStatus.Failed,
            Array.Empty<NormalizedClientGroup>(),
            "endpointUnavailable",
            "safe fixed error");

    private static NormalizedClientObservation Client(string mac, string name) =>
        new(
            mac,
            name,
            null,
            "online",
            null,
            null,
            new[] { new FieldEvidence("name", "name", "authoritative-current", true) });

    private static NormalizedClientObservation HistoryClient(string mac, string name) =>
        new(
            mac,
            name,
            null,
            "historyEvidence",
            null,
            Start.ToUnixTimeMilliseconds(),
            new[] { new FieldEvidence("lastSeenAt", "last_seen", "historical-evidence", true) });

    private static NormalizedClientGroup Group(
        string id,
        string name,
        params string[] members) =>
        new(id, name, members);

    private static string? Text(JsonObject value, string field) =>
        value[field]?.GetValue<string>();
}
