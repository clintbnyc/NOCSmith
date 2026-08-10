using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class ClientTrafficReadServiceTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";
    private static readonly DateTimeOffset ObservedAt = new(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Ranks_current_clients_by_projected_counters_and_preserves_zero()
    {
        var client = new TrafficClient
        {
            ConnectedClients = new JsonArray(
                Connected("00000000-0000-0000-0000-000000000011", "Laptop token=secret", "aa:bb:cc:dd:ee:01"),
                Connected("00000000-0000-0000-0000-000000000012", "Server", "aa:bb:cc:dd:ee:02"),
                Connected("00000000-0000-0000-0000-000000000013", "Printer", "aa:bb:cc:dd:ee:03")),
            PrivateClients = new JsonArray(
                Traffic("aa:bb:cc:dd:ee:01", 100, 50, 10, 5, 12.5, 2.5),
                Traffic("aa:bb:cc:dd:ee:02", 0, 400, 0, 20, 0, 8),
                new JsonObject
                {
                    ["mac"] = "aa:bb:cc:dd:ee:99",
                    ["rx_bytes"] = 999999,
                    ["x_authkey"] = "must-not-escape"
                })
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(SiteId, "combinedBytes", 2, null, CancellationToken.None);

        var records = response.Data!["clients"]!.AsArray();
        Assert.Equal(2, records.Count);
        Assert.Equal("aa:bb:cc:dd:ee:02", records[0]!["macAddress"]!.GetValue<string>());
        Assert.Equal(400, records[0]!["combinedBytes"]!.GetValue<long>());
        Assert.Equal(0, records[0]!["receivedBytes"]!.GetValue<long>());
        Assert.Equal("aa:bb:cc:dd:ee:01", records[1]!["macAddress"]!.GetValue<string>());
        Assert.Equal(150, records[1]!["combinedBytes"]!.GetValue<long>());
        Assert.Null(records[1]!["receivedBytesPerSecond"]);
        Assert.False(records[1]!["fieldProvenance"]!["receivedBytesPerSecond"]!["available"]!.GetValue<bool>());
        Assert.Contains("token=<redacted>", records[1]!["name"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.Equal(3, response.Data["_connector"]!["totalConnectedClients"]!.GetValue<int>());
        Assert.Equal(2, response.Data["_connector"]!["clientsWithRequestedSortValue"]!.GetValue<int>());
        Assert.Equal("2026-08-09T12:00:00.0000000+00:00", response.Data["_connector"]!["observedAt"]!.GetValue<string>());
        Assert.DoesNotContain("must-not-escape", response.Data.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Missing_and_ambiguous_values_are_null_and_rank_after_available_values()
    {
        var client = new TrafficClient
        {
            ConnectedClients = new JsonArray(
                Connected("00000000-0000-0000-0000-000000000011", "Complete", "aa:bb:cc:dd:ee:01"),
                Connected("00000000-0000-0000-0000-000000000012", "Partial", "aa:bb:cc:dd:ee:02"),
                Connected("00000000-0000-0000-0000-000000000013", "Missing", "aa:bb:cc:dd:ee:03")),
            PrivateClients = new JsonArray(
                Traffic("aa:bb:cc:dd:ee:01", 10, 20, 1, 2, 3, 4),
                new JsonObject
                {
                    ["mac"] = "aa:bb:cc:dd:ee:02",
                    ["rx_bytes"] = 100,
                    ["tx_bytes"] = -1,
                    ["rx_packets"] = "not-a-number",
                    ["rx_bytes-r"] = "NaN"
                },
                new JsonObject { ["type"] = "TELEPORT" })
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(SiteId, "combined", 10, null, CancellationToken.None);

        var records = response.Data!["clients"]!.AsArray();
        Assert.Equal("aa:bb:cc:dd:ee:01", records[0]!["macAddress"]!.GetValue<string>());
        Assert.Null(records[1]!["combinedBytes"]);
        Assert.Null(records[1]!["transmittedBytes"]);
        Assert.Null(records[1]!["receivedPackets"]);
        Assert.Null(records[1]!["receivedBytesPerSecond"]);
        Assert.Null(records[2]!["receivedBytes"]);
        Assert.False(records[2]!["fieldProvenance"]!["receivedBytes"]!["available"]!.GetValue<bool>());
        Assert.Equal(1, response.Data["_connector"]!["privateRecordsWithoutJoinKeySuppressed"]!.GetValue<int>());
        Assert.Contains("null means unavailable and zero is preserved", response.Data["_connector"]!["counterSemantics"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Supports_mac_filter_rejects_invalid_inputs_and_degrades_duplicate_private_macs()
    {
        var client = new TrafficClient
        {
            ConnectedClients = new JsonArray(
                Connected("00000000-0000-0000-0000-000000000011", "Laptop", "aa:bb:cc:dd:ee:01")),
            PrivateClients = new JsonArray(Traffic("aa:bb:cc:dd:ee:01", 10, 20, 1, 2, 3, 4))
        };
        var service = CreateService(client, enabled: true);

        var filtered = await service.ReadAsync(
            SiteId,
            "receivedBytes",
            1,
            "AA:BB:CC:DD:EE:01",
            CancellationToken.None);

        Assert.Single(filtered.Data!["clients"]!.AsArray());
        await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, "rate", 1, null, CancellationToken.None));
        await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, "downloadBytes", 1, null, CancellationToken.None));
        await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, "combinedBytes", 201, null, CancellationToken.None));

        client.PrivateClients = new JsonArray(
            Traffic("aa:bb:cc:dd:ee:01", 1, 1, 1, 1, 1, 1),
            Traffic("AA:BB:CC:DD:EE:01", 2, 2, 2, 2, 2, 2));
        var duplicateResponse = await service.ReadAsync(SiteId, null, null, null, CancellationToken.None);
        Assert.Equal("unavailable", duplicateResponse.Data!["_connector"]!["sources"]![1]!["status"]!.GetValue<string>());
        Assert.Null(Assert.Single(duplicateResponse.Data["clients"]!.AsArray())!["combinedBytes"]);
    }

    [Fact]
    public async Task Unsupported_private_source_preserves_official_clients_with_unavailable_traffic()
    {
        var client = new TrafficClient
        {
            ConnectedClients = new JsonArray(
                Connected("00000000-0000-0000-0000-000000000011", "Laptop", "aa:bb:cc:dd:ee:01")),
            PrivateFailure = true
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(SiteId, null, null, null, CancellationToken.None);

        var record = Assert.Single(response.Data!["clients"]!.AsArray())!;
        Assert.Equal("aa:bb:cc:dd:ee:01", record["macAddress"]!.GetValue<string>());
        Assert.Null(record["receivedBytes"]);
        Assert.Null(record["transmittedBytes"]);
        Assert.Equal("unavailable", response.Data["_connector"]!["sources"]![1]!["status"]!.GetValue<string>());
        Assert.Contains("unavailable", record["fieldProvenance"]!["receivedBytes"]!["reason"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Feature_is_opt_in_and_official_pagination_must_be_complete()
    {
        var disabledClient = new TrafficClient();
        var disabled = CreateService(disabledClient, enabled: false);
        await Assert.ThrowsAsync<ConfigurationException>(() =>
            disabled.ReadAsync(SiteId, null, null, null, CancellationToken.None));
        Assert.Equal(0, disabledClient.PrivateReadCount);

        var contradictoryClient = new TrafficClient
        {
            ConnectedClients = new JsonArray(
                Connected("00000000-0000-0000-0000-000000000011", "Laptop", "aa:bb:cc:dd:ee:01")),
            ConnectedTotalCount = 2
        };
        var service = CreateService(contradictoryClient, enabled: true);
        await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, null, null, null, CancellationToken.None));
    }

    [Fact]
    public async Task Rejects_duplicate_official_normalized_macs_across_pages()
    {
        var connectedClients = ConnectedRange(200);
        connectedClients.Add(Connected(
            "00000000-0000-0000-0000-000000000201",
            "Duplicate",
            "02:00:00:00:00:0A"));
        var client = new TrafficClient { ConnectedClients = connectedClients };
        var service = CreateService(client, enabled: true);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, null, null, null, CancellationToken.None));

        Assert.Contains("duplicate normalized macAddress", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Accepts_unique_official_clients_across_pages()
    {
        var client = new TrafficClient { ConnectedClients = ConnectedRange(201) };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(SiteId, null, 200, null, CancellationToken.None);

        Assert.Equal(201, response.Data!["_connector"]!["totalConnectedClients"]!.GetValue<int>());
        Assert.Equal(200, response.Data["clients"]!.AsArray().Count);
    }

    private static ClientTrafficReadService CreateService(TrafficClient client, bool enabled)
    {
        var configuration = new UnifiConfiguration(
            new Uri("https://unifi.example.com/proxy/network/integration/"),
            "test-api-key",
            SiteId,
            TimeSpan.FromSeconds(5),
            enabled);
        var contracts = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            client,
            NullLogger<ContractProvider>.Instance);
        var resolver = new SiteResolver(configuration, contracts, client);
        return new ClientTrafficReadService(
            configuration,
            client,
            contracts,
            resolver,
            new SecretRedactor("test-api-key"),
            new FixedTimeProvider(ObservedAt));
    }

    private static JsonObject Connected(string id, string name, string mac) => new()
    {
        ["id"] = id,
        ["name"] = name,
        ["macAddress"] = mac
    };

    private static JsonArray ConnectedRange(int count)
    {
        var clients = new JsonArray();
        for (var index = 0; index < count; index++)
        {
            clients.Add(Connected(
                $"00000000-0000-0000-0000-{index + 1:D12}",
                $"Client {index + 1}",
                $"02:00:00:00:{index / 256:x2}:{index % 256:x2}"));
        }

        return clients;
    }

    private static JsonObject Traffic(
        string mac,
        long rxBytes,
        long txBytes,
        long rxPackets,
        long txPackets,
        double rxRate,
        double txRate) => new()
        {
            ["mac"] = mac,
            ["rx_bytes"] = rxBytes,
            ["tx_bytes"] = txBytes,
            ["rx_packets"] = rxPackets,
            ["tx_packets"] = txPackets,
            ["rx_bytes-r"] = rxRate,
            ["tx_bytes-r"] = txRate
        };

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow) => _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }

    private sealed class TrafficClient : IUnifiClient
    {
        public JsonArray ConnectedClients { get; set; } = new();

        public int? ConnectedTotalCount { get; init; }

        public JsonArray PrivateClients { get; set; } = new();

        public bool PrivateFailure { get; init; }

        public int PrivateReadCount { get; private set; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            if (request.Operation.OperationId == "getSiteOverviewPage")
            {
                return Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["offset"] = 0,
                    ["limit"] = 200,
                    ["count"] = 1,
                    ["totalCount"] = 1,
                    ["data"] = new JsonArray(
                        new JsonObject { ["id"] = SiteId, ["internalReference"] = "default" })
                });
            }

            Assert.Equal("getConnectedClientOverviewPage", request.Operation.OperationId);
            var offset = request.RelativeUri.Contains("offset=200", StringComparison.Ordinal) ? 200 : 0;
            var page = new JsonArray(ConnectedClients
                .Skip(offset)
                .Take(200)
                .Select(record => record?.DeepClone())
                .ToArray());
            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["offset"] = offset,
                ["limit"] = 200,
                ["count"] = page.Count,
                ["totalCount"] = ConnectedTotalCount ?? ConnectedClients.Count,
                ["data"] = page
            });
        }

        public Task<JsonNode?> ReadPrivateClientsAsync(string internalSiteReference, CancellationToken cancellationToken)
        {
            Assert.Equal("default", internalSiteReference);
            PrivateReadCount++;
            return PrivateFailure
                ? Task.FromException<JsonNode?>(new UnifiApiException(System.Net.HttpStatusCode.NotFound, "unsupported"))
                : Task.FromResult<JsonNode?>(PrivateClients.DeepClone());
        }

        public Task<JsonNode?> MutateAsync(ValidatedRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> GetFixedAsync(string relativePath, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadClientHistoryAsync(string internalSiteReference, int withinHours, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
