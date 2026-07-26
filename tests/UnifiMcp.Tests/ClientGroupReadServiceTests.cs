using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class ClientGroupReadServiceTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";

    [Fact]
    public async Task List_projects_groups_redacts_names_and_returns_members_only_when_requested()
    {
        var client = CreateClient();
        var service = CreateService(client, enabled: true);

        var withoutMembers = await service.ReadAsync("list", null, includeMembers: false, CancellationToken.None);
        var withoutData = Assert.IsType<JsonObject>(withoutMembers.Data);
        var iot = withoutData["data"]!.AsArray()
            .OfType<JsonObject>()
            .Single(group => group["id"]!.GetValue<string>() == "111111111111111111111111");
        Assert.Equal("IoT password=<redacted>", iot["name"]!.GetValue<string>());
        Assert.Equal(2, iot["memberCount"]!.GetValue<int>());
        Assert.False(iot.ContainsKey("members"));

        var withMembers = await service.ReadAsync("list", SiteId, includeMembers: true, CancellationToken.None);
        var withData = Assert.IsType<JsonObject>(withMembers.Data);
        var withIot = withData["data"]!.AsArray()
            .OfType<JsonObject>()
            .Single(group => group["id"]!.GetValue<string>() == "111111111111111111111111");
        Assert.Equal(2, withIot["members"]!.AsArray().Count);
        Assert.Equal(2, client.GroupReadCount);
        Assert.Equal("v2/api/site/{site}/network-members-groups", withData["_connector"]!["fixedResource"]!.GetValue<string>());
        Assert.False(withData["_connector"]!["rawResponseReturned"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Audit_joins_group_memberships_to_connected_clients_and_reports_ungrouped_clients()
    {
        var client = CreateClient();
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync("audit", null, includeMembers: true, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal(3, data["connectedClientCount"]!.GetValue<int>());
        Assert.Equal(2, data["groupedConnectedClientCount"]!.GetValue<int>());
        Assert.Equal(1, data["ungroupedConnectedClientCount"]!.GetValue<int>());

        var ungrouped = Assert.Single(data["ungroupedConnectedClients"]!.AsArray())!;
        Assert.Equal("Laptop", ungrouped["name"]!.GetValue<string>());
        Assert.Equal(0, ungrouped["groupCount"]!.GetValue<int>());

        var camera = data["clients"]!.AsArray()
            .OfType<JsonObject>()
            .Single(record => record["name"]!.GetValue<string>() == "Camera");
        Assert.Equal(2, camera["groupCount"]!.GetValue<int>());
        Assert.Equal(
            new[] { "Homekit", "IoT password=<redacted>" },
            camera["groups"]!.AsArray().Select(group => group!["name"]!.GetValue<string>()).ToArray());

        var homekit = data["groups"]!.AsArray()
            .OfType<JsonObject>()
            .Single(group => group["name"]!.GetValue<string>() == "Homekit");
        Assert.Equal(2, homekit["memberCount"]!.GetValue<int>());
        Assert.Equal(1, homekit["connectedMemberCount"]!.GetValue<int>());
        Assert.Equal(1, homekit["notCurrentlyConnectedMemberCount"]!.GetValue<int>());
        Assert.Contains("offline clients", data["_connector"]!["knownLimitation"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_requires_opt_in_valid_action_and_mac_only_members()
    {
        var disabledClient = CreateClient();
        var disabled = CreateService(disabledClient, enabled: false);
        await Assert.ThrowsAsync<ConfigurationException>(() =>
            disabled.ReadAsync("list", null, includeMembers: false, CancellationToken.None));
        Assert.Equal(0, disabledClient.ReadCount);

        var enabledClient = CreateClient();
        var enabled = CreateService(enabledClient, enabled: true);
        await Assert.ThrowsAsync<ContractException>(() =>
            enabled.ReadAsync("delete", null, includeMembers: false, CancellationToken.None));
        Assert.Equal(0, enabledClient.ReadCount);

        var invalidClient = CreateClient();
        invalidClient.Groups = new JsonArray
        {
            new JsonObject
            {
                ["id"] = "333333333333333333333333",
                ["name"] = "Bad",
                ["type"] = "CLIENTS",
                ["members"] = new JsonArray("not-a-mac")
            }
        };
        var invalid = CreateService(invalidClient, enabled: true);
        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            invalid.ReadAsync("list", null, includeMembers: false, CancellationToken.None));
        Assert.Contains("non-MAC", exception.Message, StringComparison.Ordinal);
    }

    private static GroupClient CreateClient() => new()
    {
        Groups = new JsonArray
        {
            new JsonObject
            {
                ["id"] = "111111111111111111111111",
                ["name"] = "IoT password=hunter2",
                ["type"] = "CLIENTS",
                ["members"] = new JsonArray("44:73:d6:23:33:c5", "64:16:66:cf:bc:af")
            },
            new JsonObject
            {
                ["id"] = "222222222222222222222222",
                ["name"] = "Homekit",
                ["type"] = "CLIENTS",
                ["members"] = new JsonArray("44:73:d6:23:33:c5", "00:11:22:33:44:55")
            }
        },
        ConnectedClients = new JsonArray
        {
            new JsonObject
            {
                ["id"] = "camera-id",
                ["name"] = "Camera",
                ["macAddress"] = "44:73:d6:23:33:c5"
            },
            new JsonObject
            {
                ["id"] = "protect-id",
                ["name"] = "Nest Protect",
                ["macAddress"] = "64:16:66:cf:bc:af"
            },
            new JsonObject
            {
                ["id"] = "laptop-id",
                ["name"] = "Laptop",
                ["macAddress"] = "aa:bb:cc:dd:ee:ff"
            }
        }
    };

    private static ClientGroupReadService CreateService(GroupClient client, bool enabled)
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
        var siteResolver = new SiteResolver(configuration, contracts, client);
        return new ClientGroupReadService(
            configuration,
            client,
            contracts,
            siteResolver,
            new SecretRedactor("test-api-key"));
    }

    private sealed class GroupClient : IUnifiClient
    {
        public JsonNode? Groups { get; set; }

        public JsonArray ConnectedClients { get; init; } = new();

        public int GroupReadCount { get; private set; }

        public int ReadCount { get; private set; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            ReadCount++;
            return request.Operation.OperationId switch
            {
                "getSiteOverviewPage" => Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["offset"] = 0,
                    ["limit"] = 200,
                    ["count"] = 1,
                    ["totalCount"] = 1,
                    ["data"] = new JsonArray
                    {
                        new JsonObject { ["id"] = SiteId, ["internalReference"] = "default" }
                    }
                }),
                "getConnectedClientOverviewPage" => Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["offset"] = 0,
                    ["limit"] = 200,
                    ["count"] = ConnectedClients.Count,
                    ["totalCount"] = ConnectedClients.Count,
                    ["data"] = ConnectedClients.DeepClone()
                }),
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
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(string internalSiteReference, CancellationToken cancellationToken)
        {
            GroupReadCount++;
            Assert.Equal("default", internalSiteReference);
            return Task.FromResult(Groups?.DeepClone());
        }

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
