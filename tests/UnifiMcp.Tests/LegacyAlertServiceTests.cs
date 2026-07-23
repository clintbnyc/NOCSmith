using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class LegacyAlertServiceTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";

    [Fact]
    public async Task Read_projects_ui_fields_redacts_text_filters_archived_and_limits_results()
    {
        var client = new AlertClient
        {
            Alerts = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["_id"] = "alert-1",
                        ["key"] = "EVT_IP_CONFLICT",
                        ["event"] = "IP Address Conflict",
                        ["msg"] = "Multiple devices use 192.168.7.2; password=hunter2",
                        ["severity"] = "high",
                        ["catname"] = "UniFi Devices",
                        ["utctime"] = "2026-07-22T23:04:25.301Z",
                        ["archived"] = false,
                        ["ip_address"] = "192.168.7.2",
                        ["reference"] = "https://help.ui.com/hc/en-us/articles/19154105498007",
                        ["cef"] = "CEF:0|Ubiquiti|UniFi Network|10.4.57|539|Device IP Address Conflict|8|msg=password=hunter2",
                        ["clients"] = new JsonArray
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
                        ["networkconf_id"] = "must-not-escape"
                    },
                    new JsonObject
                    {
                        ["_id"] = "alert-2",
                        ["event"] = "Device Offline",
                        ["msg"] = "USW Pro Max 24 PoE went offline.",
                        ["archived"] = true
                    },
                    new JsonObject
                    {
                        ["_id"] = "alert-3",
                        ["event"] = "Device Ready for Adoption",
                        ["msg"] = "USW Pro Max 24 PoE is ready for adoption.",
                        ["archived"] = false
                    }
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(null, includeArchived: false, requestedLimit: 1, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        var record = Assert.Single(data["data"]!.AsArray())!;
        Assert.Equal("IP Address Conflict", record["event"]!.GetValue<string>());
        Assert.Equal("high", record["severity"]!.GetValue<string>());
        Assert.Equal("UniFi Devices", record["category"]!.GetValue<string>());
        Assert.Equal("192.168.7.2", record["ipAddress"]!.GetValue<string>());
        Assert.Equal("2026-07-22T23:04:25.301Z", record["utcTime"]!.GetValue<string>());
        Assert.Equal(2, record["clients"]!.AsArray().Count);
        Assert.Contains("password=<redacted>", record["description"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.Contains("msg=password=<redacted>", record["cefLog"]!.GetValue<string>(), StringComparison.Ordinal);

        var metadata = data["_connector"]!;
        Assert.Equal("stat/alarm", metadata["fixedResource"]!.GetValue<string>());
        Assert.False(metadata["rawResponseReturned"]!.GetValue<bool>());
        Assert.Equal(3, metadata["sourceRecordCount"]!.GetValue<int>());
        Assert.Equal(2, metadata["matchingRecordCount"]!.GetValue<int>());
        Assert.True(metadata["truncated"]!.GetValue<bool>());
        Assert.Equal(1, client.LegacyAlertReadCount);

        var serialized = data.ToJsonString();
        Assert.DoesNotContain("hunter2", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("must-never-escape", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("must-not-escape", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("networkconf_id", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_can_include_archived_records()
    {
        var client = new AlertClient
        {
            Alerts = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject { ["id"] = "active", ["archived"] = false },
                    new JsonObject { ["id"] = "archived", ["archived"] = "1" }
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(SiteId, includeArchived: true, requestedLimit: 10, CancellationToken.None);

        var data = Assert.IsType<JsonObject>(response.Data);
        Assert.Equal(2, data["count"]!.GetValue<int>());
        Assert.Equal(2, data["data"]!.AsArray().Count);
        Assert.False(data["_connector"]!["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Read_requires_opt_in_and_validates_limit_before_network_access()
    {
        var disabledClient = new AlertClient();
        var disabled = CreateService(disabledClient, enabled: false);

        await Assert.ThrowsAsync<ConfigurationException>(() =>
            disabled.ReadAsync(null, includeArchived: false, requestedLimit: null, CancellationToken.None));
        Assert.Equal(0, disabledClient.ReadCount);

        var enabledClient = new AlertClient();
        var enabled = CreateService(enabledClient, enabled: true);
        await Assert.ThrowsAsync<ContractException>(() =>
            enabled.ReadAsync(null, includeArchived: false, requestedLimit: 201, CancellationToken.None));
        Assert.Equal(0, enabledClient.ReadCount);
    }

    private static LegacyAlertService CreateService(AlertClient client, bool enabled)
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
        return new LegacyAlertService(
            configuration,
            contracts,
            client,
            new SiteResolver(configuration, contracts, client),
            new SecretRedactor("test-api-key"));
    }

    private sealed class AlertClient : IUnifiClient
    {
        public JsonNode? Alerts { get; init; } = new JsonObject { ["data"] = new JsonArray() };

        public int ReadCount { get; private set; }

        public int LegacyAlertReadCount { get; private set; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            ReadCount++;
            Assert.Equal("getSiteOverviewPage", request.Operation.OperationId);
            return Task.FromResult<JsonNode?>(new JsonObject
            {
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

        public Task<JsonNode?> ReadLegacyClientsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadLegacyAlertsAsync(string internalSiteReference, CancellationToken cancellationToken)
        {
            LegacyAlertReadCount++;
            Assert.Equal("default", internalSiteReference);
            return Task.FromResult(Alerts?.DeepClone());
        }
    }
}
