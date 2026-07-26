using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class SystemLogReadServiceTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";

    [Fact]
    public async Task Read_projects_ui_fields_redacts_text_filters_read_records_and_limits_results()
    {
        var client = new SystemLogClient
        {
            SystemLogs = new JsonObject
            {
                ["page_number"] = 0,
                ["total_element_count"] = 81,
                ["total_page_count"] = 2,
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["_id"] = "alert-1",
                        ["key"] = "EVT_IP_CONFLICT",
                        ["event"] = "IP Address Conflict",
                        ["message_raw"] = "Multiple devices use 192.168.7.2; password=hunter2",
                        ["severity"] = "high",
                        ["category"] = "UniFi Devices",
                        ["timestamp"] = 1784761465301,
                        ["status"] = "NEW",
                        ["parameters"] = new JsonObject
                        {
                            ["IP"] = "192.168.7.2",
                            ["LEARN_MORE"] = "https://help.ui.com/hc/en-us/articles/19154105498007",
                            ["CLIENTS"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["display_name"] = "pinode pishim",
                                    ["mac"] = "aa:bb:cc:dd:ee:01",
                                    ["ip"] = "192.168.7.2",
                                    ["x_authkey"] = "must-never-escape"
                                },
                                "pinode-eth0"
                            },
                            ["SECRET_CONFIGURATION"] = "must-not-escape"
                        },
                        ["networkconf_id"] = "must-not-escape"
                    },
                    new JsonObject
                    {
                        ["_id"] = "alert-2",
                        ["event"] = "Device Offline",
                        ["message_raw"] = "USW Pro Max 24 PoE went offline.",
                        ["status"] = "READ"
                    },
                    new JsonObject
                    {
                        ["_id"] = "alert-3",
                        ["event"] = "Device Ready for Adoption",
                        ["message_raw"] = "USW Pro Max 24 PoE is ready for adoption.",
                        ["status"] = "NEW"
                    }
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(null, includeRead: false, requestedLimit: 1, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        var record = Assert.Single(data["data"]!.AsArray())!;
        Assert.Equal("IP Address Conflict", record["event"]!.GetValue<string>());
        Assert.Equal("high", record["severity"]!.GetValue<string>());
        Assert.Equal("UniFi Devices", record["category"]!.GetValue<string>());
        Assert.Equal("NEW", record["status"]!.GetValue<string>());
        Assert.Equal(1784761465301, record["timestamp"]!.GetValue<long>());
        Assert.Equal("192.168.7.2", record["context"]!["ipAddress"]!.GetValue<string>());
        Assert.Equal(
            "https://help.ui.com/hc/en-us/articles/19154105498007",
            record["context"]!["referenceUrl"]!.GetValue<string>());
        Assert.Equal(2, record["clients"]!.AsArray().Count);
        Assert.Contains("password=<redacted>", record["description"]!.GetValue<string>(), StringComparison.Ordinal);

        var metadata = data["_connector"]!;
        Assert.Equal("v2/api/site/{site}/system-log/all", metadata["fixedResource"]!.GetValue<string>());
        Assert.True(metadata["queryStylePost"]!.GetValue<bool>());
        Assert.False(metadata["rawResponseReturned"]!.GetValue<bool>());
        Assert.Equal(3, metadata["sourceRecordCount"]!.GetValue<int>());
        Assert.Equal(2, metadata["matchingRecordCount"]!.GetValue<int>());
        Assert.Equal(81, metadata["sourceTotalElementCount"]!.GetValue<int>());
        Assert.True(metadata["truncated"]!.GetValue<bool>());
        Assert.Equal(1, client.SystemLogQueryCount);

        var serialized = data.ToJsonString();
        Assert.DoesNotContain("hunter2", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("must-never-escape", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("must-not-escape", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("networkconf_id", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_can_include_read_and_staled_records()
    {
        var client = new SystemLogClient
        {
            SystemLogs = new JsonObject
            {
                ["page_number"] = 0,
                ["total_element_count"] = 2,
                ["total_page_count"] = 1,
                ["data"] = new JsonArray
                {
                    new JsonObject { ["id"] = "new", ["status"] = "NEW" },
                    new JsonObject { ["id"] = "read", ["status"] = "READ" }
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(SiteId, includeRead: true, requestedLimit: 10, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal(2, data["count"]!.GetValue<int>());
        Assert.Equal(2, data["data"]!.AsArray().Count);
        Assert.False(data["_connector"]!["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Read_reports_missing_private_resource_as_not_supported()
    {
        var client = new SystemLogClient
        {
            SystemLogException = new UnifiApiException(
                HttpStatusCode.NotFound,
                "not found",
                "api.err.NotFound")
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(null, includeRead: false, requestedLimit: null, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal(0, data["count"]!.GetValue<int>());
        Assert.Empty(data["data"]!.AsArray());
        Assert.Equal("notSupported", data["_connector"]!["status"]!.GetValue<string>());
        Assert.Equal(404, data["_connector"]!["httpStatus"]!.GetValue<int>());
        Assert.Equal("api.err.NotFound", data["_connector"]!["reasonCode"]!.GetValue<string>());
        Assert.Contains("System Logs query", data["_connector"]!["reason"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_requires_opt_in_and_validates_limit_before_network_access()
    {
        var disabledClient = new SystemLogClient();
        var disabled = CreateService(disabledClient, enabled: false);

        await Assert.ThrowsAsync<ConfigurationException>(() =>
            disabled.ReadAsync(null, includeRead: false, requestedLimit: null, CancellationToken.None));
        Assert.Equal(0, disabledClient.ReadCount);

        var enabledClient = new SystemLogClient();
        var enabled = CreateService(enabledClient, enabled: true);
        await Assert.ThrowsAsync<ContractException>(() =>
            enabled.ReadAsync(null, includeRead: false, requestedLimit: 51, CancellationToken.None));
        Assert.Equal(0, enabledClient.ReadCount);
    }

    private static SystemLogReadService CreateService(SystemLogClient client, bool enabled)
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
        return new SystemLogReadService(
            configuration,
            client,
            new SiteResolver(configuration, contracts, client),
            new SecretRedactor("test-api-key"));
    }

    private sealed class SystemLogClient : IUnifiClient
    {
        public JsonNode? SystemLogs { get; init; } = new JsonObject { ["data"] = new JsonArray() };

        public Exception? SystemLogException { get; init; }

        public int ReadCount { get; private set; }

        public int SystemLogQueryCount { get; private set; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            ReadCount++;
            Assert.Equal("getSiteOverviewPage", request.Operation.OperationId);
            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["offset"] = 0,
                ["limit"] = 200,
                ["count"] = 1,
                ["totalCount"] = 1,
                ["data"] = new JsonArray
                {
                    new JsonObject { ["id"] = SiteId, ["internalReference"] = "default" }
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

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken)
        {
            SystemLogQueryCount++;
            Assert.Equal("default", internalSiteReference);
            return SystemLogException is null
                ? Task.FromResult(SystemLogs?.DeepClone())
                : Task.FromException<JsonNode?>(SystemLogException);
        }
    }
}
