using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class LegacyReadEnrichmentServiceTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";
    private const string DeviceId = "00000000-0000-0000-0000-000000000002";

    [Fact]
    public async Task Device_enrichment_projects_only_documentation_fields_and_redacts_free_text()
    {
        var client = new LegacyClient
        {
            LegacyDevices = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["mac"] = "74:fa:29:42:c1:cb",
                        ["note"] = "Core switch; password=hunter2",
                        ["x_authkey"] = "must-never-escape",
                        ["networkconf_id"] = "sensitive-network-config",
                        ["port_table"] = new JsonArray
                        {
                            new JsonObject
                            {
                                ["port_idx"] = 1,
                                ["name"] = "UPLINK - OpenWrt One LAN",
                                ["stp_state"] = "forwarding",
                                ["stp_role"] = "participant",
                                ["is_uplink"] = true,
                                ["comment"] = "Recovery token: abc123",
                                ["native_networkconf_id"] = "must-not-escape"
                            }
                        },
                        ["port_overrides"] = new JsonArray
                        {
                            new JsonObject
                            {
                                ["port_idx"] = 1,
                                ["stp_port_mode"] = true,
                                ["setting_preference"] = "manual",
                                ["psk"] = "must-not-escape"
                            }
                        }
                    }
                }
            }
        };
        var service = CreateService(client, enabled: true);
        var response = new JsonObject
        {
            ["id"] = DeviceId,
            ["macAddress"] = "74:fa:29:42:c1:cb",
            ["name"] = "switch-core"
        };

        var result = await service.EnrichAsync(
            "getAdoptedDeviceDetails",
            new Dictionary<string, string> { ["siteId"] = SiteId, ["deviceId"] = DeviceId },
            response,
            CancellationToken.None);

        var enrichment = result!["_connector"]!["legacyReadEnrichment"]!;
        var record = Assert.Single(enrichment["records"]!.AsArray())!;
        var port = Assert.Single(record["ports"]!.AsArray())!;
        Assert.Equal("ok", enrichment["status"]!.GetValue<string>());
        Assert.True(enrichment["readOnly"]!.GetValue<bool>());
        Assert.False(enrichment["rawResponseReturned"]!.GetValue<bool>());
        Assert.False(enrichment["normalizedUiStpRole"]!["available"]!.GetValue<bool>());
        Assert.Equal("unavailable", enrichment["normalizedUiStpRole"]!["status"]!.GetValue<string>());
        Assert.Equal("port_table.name", enrichment["fieldProvenance"]!["label"]!.GetValue<string>());
        Assert.Equal("UPLINK - OpenWrt One LAN", port["label"]!.GetValue<string>());
        Assert.Equal("forwarding", port["stpState"]!.GetValue<string>());
        Assert.Equal("participant", port["stpRole"]!.GetValue<string>());
        Assert.True(port["isUplink"]!.GetValue<bool>());
        Assert.True(port["stpPortMode"]!.GetValue<bool>());
        Assert.Equal("manual", port["settingPreference"]!.GetValue<string>());

        Assert.Contains("password=<redacted>", record["note"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.Contains("token: <redacted>", port["comment"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase);
        var serialized = enrichment.ToJsonString();
        Assert.DoesNotContain("hunter2", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("abc123", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("must-never-escape", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("sensitive-network-config", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("native_networkconf_id", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("psk", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Does_not_infer_normalized_ui_role_from_ambiguous_live_field_combinations()
    {
        var client = new LegacyClient
        {
            LegacyDevices = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["mac"] = "74:fa:29:42:c1:cb",
                        ["port_table"] = new JsonArray(
                            CreatePort(1, "forwarding", isUplink: true),
                            CreatePort(2, "forwarding"),
                            CreatePort(4, "disabled"),
                            CreatePort(5, "forwarding"),
                            CreatePort(17, "forwarding"),
                            CreatePort(24, "disabled")),
                        ["port_overrides"] = new JsonArray(
                            CreateOverride(1, "manual"),
                            CreateOverride(2, "manual"),
                            CreateOverride(4, "manual"),
                            CreateOverride(5, "auto"),
                            CreateOverride(17, "auto"),
                            CreateOverride(24, "manual"))
                    }
                }
            }
        };
        var service = CreateService(client, enabled: true);
        var response = new JsonObject { ["id"] = DeviceId, ["macAddress"] = "74:fa:29:42:c1:cb" };

        var result = await service.EnrichAsync(
            "getAdoptedDeviceDetails",
            new Dictionary<string, string> { ["siteId"] = SiteId },
            response,
            CancellationToken.None);

        var enrichment = result!["_connector"]!["legacyReadEnrichment"]!;
        var projected = Assert.Single(enrichment["records"]!.AsArray())!["ports"]!.AsArray()
            .OfType<JsonObject>()
            .ToDictionary(port => port["idx"]!.GetValue<int>());
        var verifiedUiRoles = new Dictionary<int, string>
        {
            [1] = "PARTICIPANT",
            [2] = "EDGE",
            [4] = "EDGE",
            [5] = "EDGE",
            [17] = "PARTICIPANT",
            [24] = "EDGE"
        };

        Assert.All(verifiedUiRoles.Keys, index => Assert.False(projected[index].ContainsKey("uiStpRole")));
        Assert.True(projected[1]["isUplink"]!.GetValue<bool>());
        Assert.Equal("disabled", projected[4]["stpState"]!.GetValue<string>());
        Assert.Equal("disabled", projected[24]["stpState"]!.GetValue<string>());
        Assert.Equal("auto", projected[5]["settingPreference"]!.GetValue<string>());
        Assert.Equal("auto", projected[17]["settingPreference"]!.GetValue<string>());
        Assert.All(projected.Values, port => Assert.True(port["stpPortMode"]!.GetValue<bool>()));
        Assert.Equal("unavailable", enrichment["normalizedUiStpRole"]!["status"]!.GetValue<string>());
    }

    [Fact]
    public async Task Client_enrichment_projects_notes_for_only_the_official_page_records()
    {
        var client = new LegacyClient
        {
            PrivateClients = new JsonArray
            {
                new JsonObject { ["mac"] = "aa:bb:cc:dd:ee:01", ["note"] = "Patch panel 9" },
                new JsonObject { ["mac"] = "aa:bb:cc:dd:ee:02", ["note"] = "Not on requested page" }
            }
        };
        var service = CreateService(client, enabled: true);
        var response = new JsonObject
        {
            ["data"] = new JsonArray
            {
                new JsonObject { ["id"] = DeviceId, ["macAddress"] = "aa:bb:cc:dd:ee:01" }
            }
        };

        var result = await service.EnrichAsync(
            "getConnectedClientOverviewPage",
            new Dictionary<string, string> { ["siteId"] = SiteId },
            response,
            CancellationToken.None);

        var enrichment = result!["_connector"]!["legacyReadEnrichment"]!;
        var records = enrichment["records"]!.AsArray();
        var record = Assert.Single(records)!;
        Assert.Equal("private-v2-api", enrichment["source"]!.GetValue<string>());
        Assert.Equal(
            "v2/api/site/{site}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true",
            enrichment["fixedResource"]!.GetValue<string>());
        Assert.Equal("Patch panel 9", record["note"]!.GetValue<string>());
        Assert.DoesNotContain("Not on requested page", records.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Client_enrichment_rejects_non_object_private_records()
    {
        var client = new LegacyClient
        {
            PrivateClients = new JsonArray
            {
                new JsonObject { ["mac"] = "aa:bb:cc:dd:ee:01", ["note"] = "Patch panel 9" },
                JsonValue.Create("not-a-client-record")
            }
        };
        var service = CreateService(client, enabled: true);
        var response = new JsonObject
        {
            ["id"] = DeviceId,
            ["macAddress"] = "aa:bb:cc:dd:ee:01"
        };

        var result = await service.EnrichAsync(
            "getConnectedClientDetails",
            new Dictionary<string, string> { ["siteId"] = SiteId },
            response,
            CancellationToken.None);

        var enrichment = Assert.IsType<JsonObject>(result!["_connector"]!["legacyReadEnrichment"]);
        Assert.Equal("failed", enrichment["status"]!.GetValue<string>());
        Assert.Contains("non-object record at index 1", enrichment["error"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.False(enrichment.ContainsKey("records"));
    }

    [Fact]
    public async Task Enrichment_is_opt_in_and_failure_does_not_fail_the_official_read()
    {
        var disabledClient = new LegacyClient();
        var disabledService = CreateService(disabledClient, enabled: false);
        var official = new JsonObject { ["id"] = DeviceId, ["macAddress"] = "74:fa:29:42:c1:cb" };

        var disabled = await disabledService.EnrichAsync(
            "getAdoptedDeviceDetails",
            new Dictionary<string, string> { ["siteId"] = SiteId },
            official,
            CancellationToken.None);

        Assert.Equal("disabled", disabled!["_connector"]!["legacyReadEnrichment"]!["status"]!.GetValue<string>());
        Assert.Equal(0, disabledClient.LegacyReadCount);

        var failingClient = new LegacyClient { LegacyFailure = true };
        var failingService = CreateService(failingClient, enabled: true);
        var failingOfficial = new JsonObject { ["id"] = DeviceId, ["macAddress"] = "74:fa:29:42:c1:cb" };

        var failed = await failingService.EnrichAsync(
            "getAdoptedDeviceDetails",
            new Dictionary<string, string> { ["siteId"] = SiteId },
            failingOfficial,
            CancellationToken.None);

        Assert.Same(failingOfficial, failed);
        Assert.Equal("failed", failed!["_connector"]!["legacyReadEnrichment"]!["status"]!.GetValue<string>());
        Assert.Equal(DeviceId, failed["id"]!.GetValue<string>());
    }

    private static LegacyReadEnrichmentService CreateService(LegacyClient client, bool enabled)
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
        return new LegacyReadEnrichmentService(
            configuration,
            client,
            siteResolver,
            new SecretRedactor("test-api-key"),
            NullLogger<LegacyReadEnrichmentService>.Instance);
    }

    private static JsonObject CreatePort(int index, string stpState, bool isUplink = false) => new()
    {
        ["port_idx"] = index,
        ["name"] = $"Port {index}",
        ["stp_state"] = stpState,
        ["is_uplink"] = isUplink
    };

    private static JsonObject CreateOverride(int index, string settingPreference) => new()
    {
        ["port_idx"] = index,
        ["stp_port_mode"] = true,
        ["setting_preference"] = settingPreference
    };

    private sealed class LegacyClient : IUnifiClient
    {
        public JsonNode? LegacyDevices { get; init; } = new JsonObject { ["data"] = new JsonArray() };

        public JsonNode? PrivateClients { get; init; } = new JsonArray();

        public bool LegacyFailure { get; init; }

        public int LegacyReadCount { get; private set; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
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

        public Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken)
        {
            LegacyReadCount++;
            Assert.Equal("default", internalSiteReference);
            return LegacyFailure
                ? Task.FromException<JsonNode?>(new UnifiApiException(HttpStatusCode.Unauthorized, "denied"))
                : Task.FromResult(LegacyDevices?.DeepClone());
        }

        public Task<JsonNode?> ReadPrivateClientsAsync(string internalSiteReference, CancellationToken cancellationToken)
        {
            LegacyReadCount++;
            Assert.Equal("default", internalSiteReference);
            return LegacyFailure
                ? Task.FromException<JsonNode?>(new UnifiApiException(HttpStatusCode.Unauthorized, "denied"))
                : Task.FromResult(PrivateClients?.DeepClone());
        }

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
