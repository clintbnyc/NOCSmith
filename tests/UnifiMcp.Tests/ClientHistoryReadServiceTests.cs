using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class ClientHistoryReadServiceTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";

    [Fact]
    public async Task History_keeps_source_grains_separate_joins_groups_redacts_and_preserves_current_authority()
    {
        var recent = DateTimeOffset.UtcNow.AddMinutes(-30).ToUnixTimeSeconds();
        var client = new HistoryClient
        {
            ConnectedClients = new JsonArray
            {
                Connected("aa:bb:cc:dd:ee:01", "Current Laptop", "192.168.1.10"),
                Connected("aa:bb:cc:dd:ee:05", "Current Phone", null)
            },
            History = new JsonArray
            {
                History(
                    "aa:bb:cc:dd:ee:01",
                    "Stale password=supersecret",
                    "192.168.1.99",
                    recent),
                History(
                    "aa:bb:cc:dd:ee:02",
                    "Tablet token=supersecret",
                    "192.168.1.20",
                    recent),
                new JsonObject
                {
                    ["mac"] = "aa:bb:cc:dd:ee:03",
                    ["network_id"] = "must-not-leak",
                    ["apiKey"] = "must-not-leak"
                }
            },
            Groups = new JsonArray
            {
                Group(
                    "111111111111111111111111",
                    "IoT password=supersecret",
                    "aa:bb:cc:dd:ee:01",
                    "aa:bb:cc:dd:ee:02",
                    "aa:bb:cc:dd:ee:04"),
                Group(
                    "222222222222222222222222",
                    "Personal",
                    "aa:bb:cc:dd:ee:02")
            }
        };
        var service = CreateService(client);

        var response = await service.ReadAsync(null, 24, 0, 100, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal(2, data["counts"]!["online"]!.GetValue<int>());
        Assert.Equal(2, data["counts"]!["offlineWithinWindow"]!.GetValue<int>());
        Assert.Equal(1, data["counts"]!["groupMembersWithoutHistory"]!.GetValue<int>());
        Assert.Equal(1, data["counts"]!["historyRecordsAlsoCurrentlyConnected"]!.GetValue<int>());

        var current = data["currentlyConnectedClients"]!.AsArray()
            .OfType<JsonObject>()
            .Single(record => record["macAddress"]!.GetValue<string>() == "aa:bb:cc:dd:ee:01");
        Assert.Equal("Current Laptop", current["name"]!.GetValue<string>());
        Assert.Equal("192.168.1.10", current["ipAddress"]!.GetValue<string>());
        Assert.Equal("online", current["state"]!.GetValue<string>());
        Assert.Null(current["lastSeenAt"]);
        Assert.Equal(
            "official-network-integration-api",
            current["fieldProvenance"]!["name"]!["source"]!.GetValue<string>());

        var tablet = data["offlineClientsWithinWindow"]!.AsArray()
            .OfType<JsonObject>()
            .Single(record => record["macAddress"]!.GetValue<string>() == "aa:bb:cc:dd:ee:02");
        Assert.Equal("Tablet token=<redacted>", tablet["name"]!.GetValue<string>());
        Assert.Equal("offline", tablet["state"]!.GetValue<string>());
        Assert.NotNull(tablet["lastSeenAt"]);
        Assert.Equal(2, tablet["groups"]!.AsArray().Count);
        Assert.Equal(
            "private-v2-client-history-api",
            tablet["fieldProvenance"]!["lastSeenAt"]!["source"]!.GetValue<string>());

        var sparse = data["offlineClientsWithinWindow"]!.AsArray()
            .OfType<JsonObject>()
            .Single(record => record["macAddress"]!.GetValue<string>() == "aa:bb:cc:dd:ee:03");
        Assert.Equal("aa:bb:cc:dd:ee:03", sparse["name"]!.GetValue<string>());
        Assert.Null(sparse["ipAddress"]);
        Assert.Null(sparse["lastSeenAt"]);

        var missing = Assert.Single(data["groupMembersWithoutHistory"]!.AsArray())!.AsObject();
        Assert.Equal("aa:bb:cc:dd:ee:04", missing["macAddress"]!.GetValue<string>());
        Assert.Equal("unknown", missing["state"]!.GetValue<string>());
        Assert.Null(missing["name"]);

        var metadata = data["_connector"]!.AsObject();
        Assert.Equal("ok", metadata["status"]!.GetValue<string>());
        Assert.Equal(2, metadata["onlineCount"]!.GetValue<int>());
        Assert.Equal(2, metadata["offlineCount"]!.GetValue<int>());
        Assert.False(metadata["rawPrivateResponsesReturned"]!.GetValue<bool>());
        Assert.Contains(
            "Current",
            metadata["auditScope"]!.GetValue<string>(),
            StringComparison.Ordinal);
        Assert.Equal(24, data["historyWindow"]!["requestedHours"]!.GetValue<int>());
        Assert.Equal(24, data["historyWindow"]!["effectiveHours"]!.GetValue<int>());

        var serialized = data.ToJsonString();
        Assert.DoesNotContain("supersecret", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("must-not-leak", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("network_id", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("apiKey", serialized, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0, 0, 100)]
    [InlineData(25, 0, 100)]
    [InlineData(8760, 0, 100)]
    [InlineData(24, -1, 100)]
    [InlineData(24, 10001, 100)]
    [InlineData(24, 0, 0)]
    [InlineData(24, 0, 201)]
    public async Task Request_bounds_fail_before_any_controller_read(
        int historyHours,
        int offset,
        int limit)
    {
        var client = new HistoryClient();
        var service = CreateService(client);

        await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(null, historyHours, offset, limit, CancellationToken.None));

        Assert.Equal(0, client.TotalReadCount);
    }

    [Fact]
    public async Task History_requires_explicit_feature_opt_in()
    {
        var client = new HistoryClient();
        var service = CreateService(client, enabled: false);

        await Assert.ThrowsAsync<ConfigurationException>(() =>
            service.ReadAsync(null, 24, 0, 100, CancellationToken.None));

        Assert.Equal(0, client.TotalReadCount);
    }

    [Fact]
    public async Task Connector_pagination_is_applied_independently_and_reports_truncation()
    {
        var recent = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds();
        var client = new HistoryClient
        {
            ConnectedClients = new JsonArray(
                Connected("aa:bb:cc:dd:10:01", "Connected 1", "192.168.1.1"),
                Connected("aa:bb:cc:dd:10:02", "Connected 2", "192.168.1.2"),
                Connected("aa:bb:cc:dd:10:03", "Connected 3", "192.168.1.3")),
            History = new JsonArray(
                History("aa:bb:cc:dd:20:01", "Offline 1", null, recent),
                History("aa:bb:cc:dd:20:02", "Offline 2", null, recent),
                History("aa:bb:cc:dd:20:03", "Offline 3", null, recent)),
            Groups = new JsonArray
            {
                Group(
                    "111111111111111111111111",
                    "Missing",
                    "aa:bb:cc:dd:30:01",
                    "aa:bb:cc:dd:30:02",
                    "aa:bb:cc:dd:30:03")
            }
        };
        var service = CreateService(client);

        var response = await service.ReadAsync(null, 72, 1, 1, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Single(data["currentlyConnectedClients"]!.AsArray());
        Assert.Single(data["offlineClientsWithinWindow"]!.AsArray());
        Assert.Single(data["groupMembersWithoutHistory"]!.AsArray());
        var pagination = data["_connector"]!["pagination"]!.AsObject();
        Assert.True(pagination["truncated"]!.GetValue<bool>());
        Assert.Equal(
            3,
            pagination["currentlyConnected"]!["totalCount"]!.GetValue<int>());
        Assert.Equal(
            2,
            pagination["offlineWithinWindow"]!["nextOffset"]!.GetValue<int>());
        Assert.Equal(72, data["historyWindow"]!["effectiveHours"]!.GetValue<int>());
    }

    [Fact]
    public async Task Official_connected_client_pages_are_bounded_and_fully_classified()
    {
        var connected = new JsonArray();
        for (var index = 0; index < 201; index++)
        {
            connected.Add(Connected(Mac(index), $"Client {index:D3}", $"192.168.1.{index % 250 + 1}"));
        }

        var client = new HistoryClient
        {
            ConnectedClients = connected,
            History = new JsonArray(),
            Groups = new JsonArray()
        };
        var service = CreateService(client);

        var response = await service.ReadAsync(null, 24, 0, 100, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal(201, data["counts"]!["online"]!.GetValue<int>());
        Assert.Equal(2, client.ConnectedOverviewReadCount);
        Assert.Equal(100, data["currentlyConnectedClients"]!.AsArray().Count);
        Assert.True(
            data["_connector"]!["pagination"]!["currentlyConnected"]!["truncated"]!.GetValue<bool>());
    }

    [Theory]
    [MemberData(nameof(MalformedHistoryResponses))]
    public async Task Malformed_private_history_contract_fails_closed(JsonNode malformed)
    {
        var client = new HistoryClient
        {
            History = malformed,
            Groups = new JsonArray(),
            ConnectedClients = new JsonArray()
        };
        var service = CreateService(client);

        var response = await service.ReadAsync(null, 24, 0, 100, CancellationToken.None);

        AssertNotSupported(response, "unrecognizedResponseContract");
        Assert.Equal(0, client.GroupReadCount);
        Assert.Equal(0, client.ConnectedOverviewReadCount);
    }

    [Fact]
    public async Task Malformed_group_contract_fails_closed_without_returning_history()
    {
        var client = new HistoryClient
        {
            History = new JsonArray(
                History(
                    "aa:bb:cc:dd:ee:10",
                    "Offline",
                    "192.168.1.10",
                    DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds())),
            Groups = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "111111111111111111111111",
                    ["name"] = "Bad",
                    ["type"] = "CLIENTS",
                    ["members"] = new JsonArray("not-a-mac")
                }
            }
        };
        var service = CreateService(client);

        var response = await service.ReadAsync(null, 24, 0, 100, CancellationToken.None);

        AssertNotSupported(response, "unrecognizedResponseContract");
    }

    [Fact]
    public async Task Malformed_official_current_contract_fails_closed_without_returning_history()
    {
        var client = new HistoryClient
        {
            History = new JsonArray(
                History(
                    "aa:bb:cc:dd:ee:10",
                    "Offline",
                    "192.168.1.10",
                    DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds())),
            ConnectedResponseOverride = new JsonArray()
        };
        var service = CreateService(client);

        var response = await service.ReadAsync(null, 24, 0, 100, CancellationToken.None);

        AssertNotSupported(response, "unrecognizedResponseContract");
        Assert.Equal(0, client.GroupReadCount);
    }

    [Fact]
    public async Task Unsupported_controller_endpoint_returns_clear_not_supported_result()
    {
        var client = new HistoryClient
        {
            HistoryException = new UnifiApiException(
                HttpStatusCode.NotFound,
                "not found",
                "api.err.NotFound")
        };
        var service = CreateService(client);

        var response = await service.ReadAsync(null, 24, 0, 100, CancellationToken.None);

        AssertNotSupported(response, "endpointUnavailable");
        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal(404, data["_connector"]!["httpStatus"]!.GetValue<int>());
        Assert.Equal("api.err.NotFound", data["_connector"]!["controllerReasonCode"]!.GetValue<string>());
    }

    public static IEnumerable<object[]> MalformedHistoryResponses()
    {
        yield return new object[] { new JsonObject { ["records"] = new JsonArray() } };
        yield return new object[] { new JsonArray("not-an-object") };
        yield return new object[] { new JsonArray(new JsonObject { ["mac"] = "not-a-mac" }) };
        yield return new object[]
        {
            new JsonArray(
                new JsonObject { ["mac"] = "aa:bb:cc:dd:ee:01" },
                new JsonObject { ["mac"] = "aa:bb:cc:dd:ee:01" })
        };
        yield return new object[]
        {
            new JsonArray(
                new JsonObject
                {
                    ["mac"] = "aa:bb:cc:dd:ee:01",
                    ["ip"] = "not-an-ip"
                })
        };
        yield return new object[]
        {
            new JsonArray(
                new JsonObject
                {
                    ["mac"] = "aa:bb:cc:dd:ee:01",
                    ["last_seen"] = DateTimeOffset.UtcNow.AddDays(-2).ToUnixTimeSeconds()
                })
        };
        yield return new object[]
        {
            new JsonArray(
                new JsonObject
                {
                    ["mac"] = "aa:bb:cc:dd:ee:01",
                    ["last_seen"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
                })
        };
        yield return new object[]
        {
            new JsonArray(
                new JsonObject
                {
                    ["mac"] = "aa:bb:cc:dd:ee:01",
                    ["last_seen"] = "not-an-epoch"
                })
        };
    }

    private static void AssertNotSupported(ToolResponse response, string reasonCode)
    {
        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal("notSupported", data["_connector"]!["status"]!.GetValue<string>());
        Assert.Equal(reasonCode, data["_connector"]!["reasonCode"]!.GetValue<string>());
        Assert.Empty(data["currentlyConnectedClients"]!.AsArray());
        Assert.Empty(data["offlineClientsWithinWindow"]!.AsArray());
        Assert.Empty(data["groupMembersWithoutHistory"]!.AsArray());
        Assert.False(data["_connector"]!["rawPrivateResponsesReturned"]!.GetValue<bool>());
    }

    private static ClientHistoryReadService CreateService(HistoryClient client, bool enabled = true)
    {
        var configuration = new UnifiConfiguration(
            new Uri("https://unifi.nutria-newton.ts.net/proxy/network/integration/"),
            "test-api-key",
            SiteId,
            TimeSpan.FromSeconds(5),
            enabled);
        var contracts = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            client,
            NullLogger<ContractProvider>.Instance);
        var resolver = new SiteResolver(configuration, contracts, client);
        return new ClientHistoryReadService(
            configuration,
            client,
            contracts,
            resolver,
            new SecretRedactor("test-api-key"));
    }

    private static JsonObject Connected(string mac, string name, string? ip) => new()
    {
        ["id"] = Guid.NewGuid().ToString(),
        ["name"] = name,
        ["macAddress"] = mac,
        ["ipAddress"] = ip,
        ["connectedAt"] = DateTimeOffset.UtcNow.AddHours(-1).ToString("O")
    };

    private static JsonObject History(string mac, string name, string? ip, long lastSeen) => new()
    {
        ["_id"] = "aaaaaaaaaaaaaaaaaaaaaaaa",
        ["mac"] = mac,
        ["name"] = name,
        ["ip"] = ip,
        ["last_seen"] = lastSeen,
        ["network_id"] = "discarded-network-id",
        ["bytes-r"] = 123456
    };

    private static JsonObject Group(string id, string name, params string[] members) => new()
    {
        ["id"] = id,
        ["name"] = name,
        ["type"] = "CLIENTS",
        ["members"] = new JsonArray(
            members.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()),
        ["unrelated"] = "discarded"
    };

    private static string Mac(int index) =>
        $"02:00:{(index >> 24) & 0xff:x2}:{(index >> 16) & 0xff:x2}:{(index >> 8) & 0xff:x2}:{index & 0xff:x2}";

    private sealed class HistoryClient : IUnifiClient
    {
        public JsonNode? History { get; init; } = new JsonArray();

        public JsonNode? Groups { get; init; } = new JsonArray();

        public JsonArray ConnectedClients { get; init; } = new();

        public JsonNode? ConnectedResponseOverride { get; init; }

        public Exception? HistoryException { get; init; }

        public int HistoryReadCount { get; private set; }

        public int GroupReadCount { get; private set; }

        public int ConnectedOverviewReadCount { get; private set; }

        public int SiteReadCount { get; private set; }

        public int TotalReadCount =>
            HistoryReadCount + GroupReadCount + ConnectedOverviewReadCount + SiteReadCount;

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            return request.Operation.OperationId switch
            {
                "getSiteOverviewPage" => ReadSites(),
                "getConnectedClientOverviewPage" => ReadConnected(request.RelativeUri),
                _ => throw new NotSupportedException(request.Operation.OperationId)
            };
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
            CancellationToken cancellationToken)
        {
            HistoryReadCount++;
            Assert.Equal("default", internalSiteReference);
            Assert.Contains(withinHours, new[] { 24, 72, 168, 336, 720, 4320 });
            return HistoryException is null
                ? Task.FromResult(History?.DeepClone())
                : Task.FromException<JsonNode?>(HistoryException);
        }

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(
            string internalSiteReference,
            CancellationToken cancellationToken)
        {
            GroupReadCount++;
            Assert.Equal("default", internalSiteReference);
            return Task.FromResult(Groups?.DeepClone());
        }

        public Task<JsonNode?> QuerySystemLogsAsync(
            string internalSiteReference,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        private Task<JsonNode?> ReadSites()
        {
            SiteReadCount++;
            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["offset"] = 0,
                ["limit"] = 200,
                ["count"] = 1,
                ["totalCount"] = 1,
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = SiteId,
                        ["internalReference"] = "default"
                    }
                }
            });
        }

        private Task<JsonNode?> ReadConnected(string relativeUri)
        {
            ConnectedOverviewReadCount++;
            if (ConnectedResponseOverride is not null)
            {
                return Task.FromResult<JsonNode?>(ConnectedResponseOverride.DeepClone());
            }

            var offset = relativeUri.Contains("offset=200", StringComparison.Ordinal) ? 200 : 0;
            var page = new JsonArray(
                ConnectedClients
                    .Skip(offset)
                    .Take(200)
                    .Select(record => record?.DeepClone())
                    .ToArray());
            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["offset"] = offset,
                ["limit"] = 200,
                ["count"] = page.Count,
                ["totalCount"] = ConnectedClients.Count,
                ["data"] = page
            });
        }
    }
}
