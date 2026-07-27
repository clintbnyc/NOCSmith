using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Journal;
using UnifiMcp.Security;

namespace UnifiMcp.Tests;

public sealed class ClientObservationCollectorTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-26T12:00:00.0000000+00:00");

    [Fact]
    public async Task Collection_keeps_sources_separate_normalizes_redacts_and_projects()
    {
        var client = new ObservationClient
        {
            Connected = new JsonArray(
                Connected("AA:BB:CC:DD:EE:01", "Laptop token=secret", "192.0.2.1"),
                Connected("aa:bb:cc:dd:ee:01", "Duplicate", "192.0.2.9")),
            History = new JsonArray(
                new JsonObject
                {
                    ["mac"] = "AA:BB:CC:DD:EE:02",
                    ["hostname"] = "Phone password=secret",
                    ["last_ip"] = "2001:0db8::2",
                    ["last_seen"] = Now.AddMinutes(-5).ToUnixTimeSeconds(),
                    ["controller_internal_id"] = "must-not-survive",
                    ["apiKey"] = "must-not-survive"
                }),
            Groups = new JsonArray(
                Group(
                    "0123456789abcdef01234567",
                    "Trusted secret=secret",
                    "AA:BB:CC:DD:EE:01",
                    "aa:bb:cc:dd:ee:01",
                    "AA:BB:CC:DD:EE:02"))
        };
        var collector = CreateCollector(client);

        var result = await collector.CollectAsync(
            null,
            24,
            TestContext.Current.CancellationToken);

        Assert.Equal("collection-id", result.CollectionId);
        Assert.Equal(CollectionSourceStatus.Complete, result.OverallStatus);
        var connected = Assert.Single(result.Connected.Records);
        Assert.Equal("aa:bb:cc:dd:ee:01", connected.MacAddress);
        Assert.Equal("Laptop token=<redacted>", connected.Name);
        Assert.Equal("online", connected.State);
        Assert.Equal(1, result.Connected.DuplicateRecordsSuppressed);
        var history = Assert.Single(result.History.Records);
        Assert.Equal("2001:db8::2", history.IpAddress);
        Assert.Equal("historyEvidence", history.State);
        Assert.NotNull(history.LastSeenEpochMilliseconds);
        var group = Assert.Single(result.Groups.Records);
        Assert.Equal(2, group.Members.Count);
        Assert.Equal("Trusted <redacted>=<redacted>", group.Name);

        var serialized = System.Text.Json.JsonSerializer.Serialize(result);
        Assert.DoesNotContain("must-not-survive", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("controller_internal_id", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("apiKey", serialized, StringComparison.Ordinal);
        Assert.All(connected.Provenance, value => Assert.NotEmpty(value.SourceField));
    }

    [Fact]
    public async Task Later_official_page_failure_preserves_validated_partial_positive_evidence()
    {
        var connected = new JsonArray();
        for (var index = 0; index < 201; index++)
        {
            connected.Add(Connected(Mac(index), $"Client {index}", "192.0.2.1"));
        }

        var client = new ObservationClient
        {
            Connected = connected,
            FailConnectedAfterFirstPage = true
        };
        var result = await CreateCollector(client).CollectAsync(
            null,
            24,
            TestContext.Current.CancellationToken);

        Assert.Equal(CollectionSourceStatus.Partial, result.Connected.Status);
        Assert.Equal(200, result.Connected.Records.Count);
        Assert.False(result.Connected.Status == CollectionSourceStatus.Complete);
        Assert.Equal("controllerReadFailed", result.Connected.ErrorCode);
        Assert.Equal(CollectionSourceStatus.Partial, result.OverallStatus);
    }

    [Fact]
    public async Task Malformed_private_source_fails_independently_without_losing_other_sources()
    {
        var client = new ObservationClient
        {
            Connected = new JsonArray(
                Connected("aa:bb:cc:dd:ee:01", "Laptop", "192.0.2.1")),
            History = new JsonArray(new JsonObject { ["mac"] = "not-a-mac" }),
            Groups = new JsonArray()
        };

        var result = await CreateCollector(client).CollectAsync(
            null,
            24,
            TestContext.Current.CancellationToken);

        Assert.Equal(CollectionSourceStatus.Complete, result.Connected.Status);
        Assert.Equal(CollectionSourceStatus.Failed, result.History.Status);
        Assert.Empty(result.History.Records);
        Assert.Equal("unrecognizedResponseContract", result.History.ErrorCode);
        Assert.Equal(CollectionSourceStatus.Complete, result.Groups.Status);
        Assert.Equal(CollectionSourceStatus.Partial, result.OverallStatus);
    }

    [Fact]
    public async Task Validated_private_records_before_a_malformed_record_are_partial_evidence()
    {
        var client = new ObservationClient
        {
            History = new JsonArray(
                new JsonObject
                {
                    ["mac"] = "aa:bb:cc:dd:ee:01",
                    ["last_seen"] = Now.AddMinutes(-5).ToUnixTimeSeconds()
                },
                new JsonObject
                {
                    ["mac"] = "invalid"
                }),
            Groups = new JsonArray(
                Group(
                    "0123456789abcdef01234567",
                    "Valid",
                    "aa:bb:cc:dd:ee:01"),
                new JsonObject
                {
                    ["id"] = "invalid"
                })
        };

        var result = await CreateCollector(client).CollectAsync(
            null,
            24,
            TestContext.Current.CancellationToken);

        Assert.Equal(CollectionSourceStatus.Partial, result.History.Status);
        Assert.Single(result.History.Records);
        Assert.Equal(CollectionSourceStatus.Partial, result.Groups.Status);
        Assert.Single(result.Groups.Records);
    }

    [Fact]
    public async Task Overall_collection_is_failed_when_no_source_yields_usable_evidence()
    {
        var client = new ObservationClient
        {
            Connected = new JsonArray(new JsonObject
            {
                ["macAddress"] = "invalid"
            }),
            History = new JsonArray(new JsonObject
            {
                ["mac"] = "invalid"
            }),
            Groups = new JsonArray(new JsonObject
            {
                ["id"] = "invalid"
            })
        };

        var result = await CreateCollector(client).CollectAsync(
            null,
            24,
            TestContext.Current.CancellationToken);

        Assert.Equal(CollectionSourceStatus.Failed, result.Connected.Status);
        Assert.Equal(CollectionSourceStatus.Failed, result.History.Status);
        Assert.Equal(CollectionSourceStatus.Failed, result.Groups.Status);
        Assert.Equal(CollectionSourceStatus.Failed, result.OverallStatus);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(25)]
    [InlineData(8760)]
    public async Task Invalid_history_bounds_fail_before_controller_reads(int historyHours)
    {
        var client = new ObservationClient();
        var collector = CreateCollector(client);

        await Assert.ThrowsAsync<ContractException>(() =>
            collector.CollectAsync(
                null,
                historyHours,
                TestContext.Current.CancellationToken));

        Assert.Equal(0, client.TotalSourceReads);
    }

    [Fact]
    public async Task Collection_requires_both_journal_and_private_read_gates()
    {
        var client = new ObservationClient();
        await Assert.ThrowsAsync<ConfigurationException>(() =>
            CreateCollector(client, journalEnabled: false).CollectAsync(
                null,
                24,
                TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ConfigurationException>(() =>
            CreateCollector(client, privateReadsEnabled: false).CollectAsync(
                null,
                24,
                TestContext.Current.CancellationToken));
        Assert.Equal(0, client.TotalSourceReads);
    }

    private static ClientObservationCollector CreateCollector(
        ObservationClient client,
        bool journalEnabled = true,
        bool privateReadsEnabled = true)
    {
        var configuration = new UnifiConfiguration(
            new Uri("https://example.test/proxy/network/integration/"),
            "test-key",
            SiteId,
            TimeSpan.FromSeconds(5),
            EnableLegacyReadEnrichment: privateReadsEnabled,
            EnableClientJournal: journalEnabled,
            ClientJournalDatabasePath: "/tmp/unifi-journal-tests.db",
            ClientJournalMaximumMib: 16);
        var contracts = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            client,
            NullLogger<ContractProvider>.Instance);
        return new ClientObservationCollector(
            configuration,
            client,
            contracts,
            new SiteResolver(configuration, contracts, client),
            new SecretRedactor("test-key", "secret"),
            new FixedClock(),
            new FixedIds());
    }

    private static JsonObject Connected(
        string mac,
        string name,
        string? ip) =>
        new()
        {
            ["id"] = Guid.NewGuid().ToString(),
            ["name"] = name,
            ["macAddress"] = mac,
            ["ipAddress"] = ip,
            ["connectedAt"] = Now.AddHours(-1).ToString("O")
        };

    private static JsonObject Group(
        string id,
        string name,
        params string[] members) =>
        new()
        {
            ["id"] = id,
            ["name"] = name,
            ["type"] = "CLIENTS",
            ["members"] = new JsonArray(
                members.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray())
        };

    private static string Mac(int index) =>
        $"02:00:{(index >> 24) & 0xff:x2}:{(index >> 16) & 0xff:x2}:{(index >> 8) & 0xff:x2}:{index & 0xff:x2}";

    private sealed class FixedClock : IClientJournalClock
    {
        public DateTimeOffset UtcNow => Now;
    }

    private sealed class FixedIds : IClientCollectionIdGenerator
    {
        public string Create() => "collection-id";
    }

    private sealed class ObservationClient : IUnifiClient
    {
        public JsonArray Connected { get; init; } = new();

        public JsonNode? History { get; init; } = new JsonArray();

        public JsonNode? Groups { get; init; } = new JsonArray();

        public bool FailConnectedAfterFirstPage { get; init; }

        public int TotalSourceReads { get; private set; }

        public Task<JsonNode?> ReadAsync(
            ValidatedRequest request,
            CancellationToken cancellationToken)
        {
            if (request.Operation.OperationId == "getSiteOverviewPage")
            {
                return Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["offset"] = 0,
                    ["limit"] = 200,
                    ["count"] = 1,
                    ["totalCount"] = 1,
                    ["data"] = new JsonArray(new JsonObject
                    {
                        ["id"] = SiteId,
                        ["internalReference"] = "default"
                    })
                });
            }

            if (request.Operation.OperationId != "getConnectedClientOverviewPage")
            {
                throw new NotSupportedException(request.Operation.OperationId);
            }

            TotalSourceReads++;
            var offset = request.RelativeUri.Contains("offset=200", StringComparison.Ordinal)
                ? 200
                : 0;
            if (offset == 200 && FailConnectedAfterFirstPage)
            {
                return Task.FromException<JsonNode?>(new UnifiApiException(
                    HttpStatusCode.ServiceUnavailable,
                    "unsafe upstream details",
                    "busy"));
            }

            var page = new JsonArray(Connected
                .Skip(offset)
                .Take(200)
                .Select(value => value?.DeepClone())
                .ToArray());
            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["offset"] = offset,
                ["limit"] = 200,
                ["count"] = page.Count,
                ["totalCount"] = Connected.Count,
                ["data"] = page
            });
        }

        public Task<JsonNode?> ReadClientHistoryAsync(
            string internalSiteReference,
            int withinHours,
            CancellationToken cancellationToken)
        {
            TotalSourceReads++;
            return Task.FromResult(History?.DeepClone());
        }

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(
            string internalSiteReference,
            CancellationToken cancellationToken)
        {
            TotalSourceReads++;
            return Task.FromResult(Groups?.DeepClone());
        }

        public Task<JsonNode?> MutateAsync(
            ValidatedRequest request,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> GetFixedAsync(
            string relativePath,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadLegacyDevicesAsync(
            string internalSiteReference,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadPrivateClientsAsync(
            string internalSiteReference,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> QuerySystemLogsAsync(
            string internalSiteReference,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
