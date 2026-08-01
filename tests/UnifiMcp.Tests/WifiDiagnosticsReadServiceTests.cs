using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class WifiDiagnosticsReadServiceTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";

    [Fact]
    public async Task Read_projects_client_and_radio_diagnostics_without_raw_field_leakage()
    {
        var client = new DiagnosticsClient
        {
            Clients = new JsonArray
            {
                new JsonObject
                {
                    ["mac"] = "AA-BB-CC-DD-EE-01",
                    ["name"] = "Phone password=hunter2",
                    ["is_wired"] = false,
                    ["ap_mac"] = "11:22:33:44:55:66",
                    ["radio"] = "ng",
                    ["channel"] = 6,
                    ["channel_width"] = 40,
                    ["signal"] = -62,
                    ["noise"] = -95,
                    ["satisfaction"] = 91,
                    ["signal_quality_class"] = "good",
                    ["signal_balance"] = "balanced",
                    ["radio_proto"] = "ax",
                    ["rx_rate"] = 866_700,
                    ["tx_rate_mbps"] = 433.3,
                    ["rx_mcs"] = 9,
                    ["tx_mcs"] = 7,
                    ["rx_nss"] = 2,
                    ["tx_nss"] = 2,
                    ["tx_retries"] = 12,
                    ["rx_errors"] = 2,
                    ["first_seen"] = 1_700_000_000,
                    ["last_seen"] = 1_700_000_100,
                    ["ip"] = "169.254.4.8",
                    ["dhcp_state"] = "failed",
                    ["dhcp_failure_reason"] = "token=abc123",
                    ["x_authkey"] = "must-never-escape"
                }
            },
            Devices = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    AccessPoint("11:22:33:44:55:66", "Upstairs password=hunter2", "ng", 6, 40, 17, 16, 38, -96),
                    AccessPoint("22:33:44:55:66:77", "Downstairs", "na", 149, 80, 20, 19, 62, -92)
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(
            SiteId,
            "aa:bb:cc:dd:ee:01",
            clientLimit: 10,
            radioLimit: 10,
            TestContext.Current.CancellationToken);

        var data = Assert.IsType<JsonObject>(response.Data);
        var projectedClient = Assert.Single(data["clients"]!["data"]!.AsArray())!;
        Assert.Equal("aa:bb:cc:dd:ee:01", projectedClient["macAddress"]!.GetValue<string>());
        Assert.Contains("password=<redacted>", projectedClient["name"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.Equal("11:22:33:44:55:66", projectedClient["association"]!["accessPointMacAddress"]!.GetValue<string>());
        Assert.Contains("password=<redacted>", projectedClient["association"]!["accessPointName"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.Equal("2.4 GHz", projectedClient["association"]!["band"]!.GetValue<string>());
        Assert.Equal(33d, projectedClient["signal"]!["snrDb"]!.GetValue<double>());
        Assert.Equal("balanced", projectedClient["signal"]!["signalBalance"]!.GetValue<string>());
        Assert.Equal(866.7d, projectedClient["phy"]!["rxRateMbps"]!.GetValue<double>(), precision: 3);
        Assert.Null(projectedClient["association"]!["associatedAt"]);
        Assert.True(projectedClient["network"]!["apipa"]!.GetValue<bool>());
        Assert.Contains("token=<redacted>", projectedClient["network"]!["dhcpFailureReason"]!.GetValue<string>(), StringComparison.Ordinal);

        var radios = data["accessPointRadios"]!["data"]!.AsArray();
        Assert.Equal(2, radios.Count);
        var upstairs = radios.Single(radio => radio!["accessPointMacAddress"]!.GetValue<string>() == "11:22:33:44:55:66")!;
        Assert.Equal(17d, upstairs["configuredTransmitPowerDbm"]!.GetValue<double>());
        Assert.Equal(16d, upstairs["effectiveTransmitPowerDbm"]!.GetValue<double>());
        Assert.Equal(38d, upstairs["channelUtilizationPercent"]!.GetValue<double>());
        Assert.Equal(-96d, upstairs["noiseFloorDbm"]!.GetValue<double>());

        var serialized = data.ToJsonString();
        Assert.DoesNotContain("hunter2", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("abc123", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("x_authkey", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("must-never-escape", serialized, StringComparison.Ordinal);
        Assert.False(data["_connector"]!["rawPrivateResponsesReturned"]!.GetValue<bool>());
        Assert.Equal("explicit-allowlist", data["_connector"]!["outputProjection"]!.GetValue<string>());
        Assert.Equal(2, client.PrivateReadCount);
    }

    [Fact]
    public async Task Read_supports_camel_case_drift_and_keeps_unavailable_fields_null()
    {
        var client = new DiagnosticsClient
        {
            Clients = new JsonArray
            {
                new JsonObject
                {
                    ["macAddress"] = "aa:bb:cc:dd:ee:02",
                    ["apMac"] = "11:22:33:44:55:66",
                    ["radioName"] = "6e",
                    ["channelWidth"] = 160,
                    ["rssiDbm"] = -70,
                    ["noiseFloorDbm"] = -98,
                    ["snrDb"] = 28,
                    ["signalQuality"] = 74,
                    ["wifiStandard"] = "be",
                    ["rxRateMbps"] = 1200,
                    ["txNss"] = 2,
                    ["associatedAt"] = 1_700_000_000,
                    ["ipAddress"] = "192.0.2.10",
                    ["isWired"] = false
                }
            },
            Devices = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["macAddress"] = "11:22:33:44:55:66",
                        ["radioTable"] = new JsonArray
                        {
                            new JsonObject
                            {
                                ["radioName"] = "6e",
                                ["channel"] = 37,
                                ["channelWidth"] = 160,
                                ["configuredTransmitPowerDbm"] = 14
                            }
                        }
                    }
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(
            SiteId,
            null,
            null,
            null,
            TestContext.Current.CancellationToken);

        var projectedClient = Assert.Single(response.Data!["clients"]!["data"]!.AsArray())!;
        Assert.Equal("6 GHz", projectedClient["association"]!["band"]!.GetValue<string>());
        Assert.Equal(
            "2023-11-14T22:13:20.0000000+00:00",
            projectedClient["association"]!["associatedAt"]!.GetValue<string>());
        Assert.Equal(28d, projectedClient["signal"]!["snrDb"]!.GetValue<double>());
        Assert.Null(projectedClient["signal"]!["signalBalance"]);
        Assert.Null(projectedClient["network"]!["dhcpState"]);
        Assert.False(projectedClient["network"]!["apipa"]!.GetValue<bool>());

        var radio = Assert.Single(response.Data!["accessPointRadios"]!["data"]!.AsArray())!;
        Assert.Equal(14d, radio["configuredTransmitPowerDbm"]!.GetValue<double>());
        Assert.Null(radio["effectiveTransmitPowerDbm"]);
        Assert.Null(radio["channelUtilizationPercent"]);
    }

    [Fact]
    public async Task Read_enforces_output_bounds_and_opt_in_before_private_reads()
    {
        var client = new DiagnosticsClient
        {
            Clients = new JsonArray(
                new JsonObject { ["mac"] = "aa:bb:cc:dd:ee:01", ["is_wired"] = false },
                new JsonObject { ["mac"] = "aa:bb:cc:dd:ee:02", ["is_wired"] = false }),
            Devices = new JsonObject
            {
                ["data"] = new JsonArray(
                    AccessPoint("11:22:33:44:55:66", "One", "ng", 1, 20, 10, 9, 10, -95),
                    AccessPoint("22:33:44:55:66:77", "Two", "na", 36, 80, 20, 19, 20, -90))
            }
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(SiteId, null, 1, 1, TestContext.Current.CancellationToken);

        Assert.Single(response.Data!["clients"]!["data"]!.AsArray());
        Assert.True(response.Data!["clients"]!["truncated"]!.GetValue<bool>());
        Assert.Single(response.Data!["accessPointRadios"]!["data"]!.AsArray());
        Assert.True(response.Data!["accessPointRadios"]!["truncated"]!.GetValue<bool>());

        await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, null, 201, 1, CancellationToken.None));

        var disabledClient = new DiagnosticsClient();
        var disabled = CreateService(disabledClient, enabled: false);
        await Assert.ThrowsAsync<ConfigurationException>(() =>
            disabled.ReadAsync(SiteId, null, null, null, CancellationToken.None));
        Assert.Equal(0, disabledClient.PrivateReadCount);
    }

    [Fact]
    public async Task Read_filters_nonwireless_records_before_applying_client_limit()
    {
        var client = new DiagnosticsClient
        {
            Clients = new JsonArray(
                new JsonObject
                {
                    ["mac"] = "00:00:00:00:00:01",
                    ["is_wired"] = true,
                    ["name"] = "Wired"
                },
                new JsonObject
                {
                    ["mac"] = "ff:ff:ff:ff:ff:01",
                    ["ap_mac"] = "11:22:33:44:55:66",
                    ["signal"] = -60
                },
                new JsonObject
                {
                    ["mac"] = "00:00:00:00:00:02",
                    ["name"] = "Unknown transport"
                })
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(
            SiteId,
            null,
            clientLimit: 1,
            radioLimit: 1,
            TestContext.Current.CancellationToken);

        var clients = response.Data!["clients"]!;
        var projected = Assert.Single(clients["data"]!.AsArray())!;
        Assert.Equal("ff:ff:ff:ff:ff:01", projected["macAddress"]!.GetValue<string>());
        Assert.Equal(1, clients["matched"]!.GetValue<int>());
        Assert.False(clients["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Read_rejects_oversized_nested_radio_sources()
    {
        var radioTable = new JsonArray();
        for (var index = 0; index < 17; index++)
        {
            radioTable.Add(new JsonObject
            {
                ["radio"] = $"radio-{index}",
                ["channel"] = index + 1
            });
        }

        var client = new DiagnosticsClient
        {
            Devices = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["mac"] = "11:22:33:44:55:66",
                        ["radio_table"] = radioTable
                    }
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, null, null, null, TestContext.Current.CancellationToken));

        Assert.Contains("radio_table", exception.Message, StringComparison.Ordinal);
        Assert.Contains("16", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_rejects_oversized_aggregate_radio_projection()
    {
        var devices = new JsonArray();
        for (var deviceIndex = 0; deviceIndex < 126; deviceIndex++)
        {
            var radioTable = new JsonArray();
            for (var radioIndex = 0; radioIndex < 16; radioIndex++)
            {
                radioTable.Add(new JsonObject
                {
                    ["radio"] = $"radio-{radioIndex}",
                    ["channel"] = radioIndex + 1
                });
            }

            devices.Add(new JsonObject
            {
                ["mac"] = $"02:00:00:00:{deviceIndex / 256:x2}:{deviceIndex % 256:x2}",
                ["radio_table"] = radioTable
            });
        }

        var client = new DiagnosticsClient
        {
            Devices = new JsonObject { ["data"] = devices }
        };
        var service = CreateService(client, enabled: true);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, null, null, null, TestContext.Current.CancellationToken));

        Assert.Contains("2000", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_does_not_expose_duplicate_radio_identifiers_in_errors()
    {
        const string privateIdentifier = "password=hunter2";
        var client = new DiagnosticsClient
        {
            Devices = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["mac"] = "11:22:33:44:55:66",
                        ["radio_table"] = new JsonArray
                        {
                            new JsonObject { ["radio"] = privateIdentifier },
                            new JsonObject { ["radio"] = privateIdentifier }
                        }
                    }
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadAsync(SiteId, null, null, null, TestContext.Current.CancellationToken));

        Assert.Equal(
            "Private UniFi device diagnostics returned a duplicate radio identifier.",
            exception.Message);
        Assert.DoesNotContain(privateIdentifier, exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Read_does_not_merge_anonymous_radio_arrays_by_position()
    {
        var client = new DiagnosticsClient
        {
            Devices = new JsonObject
            {
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["mac"] = "11:22:33:44:55:66",
                        ["radio_table"] = new JsonArray
                        {
                            new JsonObject
                            {
                                ["channel"] = 1,
                                ["tx_power"] = 10
                            }
                        },
                        ["radio_table_stats"] = new JsonArray
                        {
                            new JsonObject
                            {
                                ["channel"] = 36,
                                ["tx_power"] = 20,
                                ["cu_total"] = 30
                            }
                        }
                    }
                }
            }
        };
        var service = CreateService(client, enabled: true);

        var response = await service.ReadAsync(
            SiteId,
            null,
            null,
            null,
            TestContext.Current.CancellationToken);

        var radios = response.Data!["accessPointRadios"]!["data"]!.AsArray();
        Assert.Equal(2, radios.Count);
        var configured = Assert.Single(radios, radio => radio!["configuredTransmitPowerDbm"] is not null)!;
        Assert.Equal(1, configured["channel"]!.GetValue<int>());
        Assert.Equal(10d, configured["configuredTransmitPowerDbm"]!.GetValue<double>());
        Assert.Null(configured["effectiveTransmitPowerDbm"]);
        var operational = Assert.Single(radios, radio => radio!["effectiveTransmitPowerDbm"] is not null)!;
        Assert.Equal(36, operational["channel"]!.GetValue<int>());
        Assert.Null(operational["configuredTransmitPowerDbm"]);
        Assert.Equal(20d, operational["effectiveTransmitPowerDbm"]!.GetValue<double>());
    }

    private static JsonObject AccessPoint(
        string mac,
        string name,
        string radio,
        int channel,
        int width,
        int configuredPower,
        int effectivePower,
        int utilization,
        int noise) => new()
        {
            ["mac"] = mac,
            ["name"] = name,
            ["radio_table"] = new JsonArray
        {
            new JsonObject
            {
                ["radio"] = radio,
                ["channel"] = channel,
                ["ht"] = $"HT{width}",
                ["tx_power"] = configuredPower,
                ["tx_power_mode"] = "manual"
            }
        },
            ["radio_table_stats"] = new JsonArray
        {
            new JsonObject
            {
                ["radio"] = radio,
                ["channel"] = channel,
                ["tx_power"] = effectivePower,
                ["cu_total"] = utilization,
                ["noise"] = noise,
                ["num_sta"] = 3,
                ["tx_retries"] = 4,
                ["tx_errors"] = 1
            }
        }
        };

    private static WifiDiagnosticsReadService CreateService(DiagnosticsClient client, bool enabled)
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
        return new WifiDiagnosticsReadService(
            configuration,
            client,
            siteResolver,
            new SecretRedactor("test-api-key"));
    }

    private sealed class DiagnosticsClient : IUnifiClient
    {
        public JsonNode? Clients { get; init; } = new JsonArray();

        public JsonNode? Devices { get; init; } = new JsonObject { ["data"] = new JsonArray() };

        public int PrivateReadCount { get; private set; }

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
            PrivateReadCount++;
            Assert.Equal("default", internalSiteReference);
            return Task.FromResult(Devices?.DeepClone());
        }

        public Task<JsonNode?> ReadPrivateClientsAsync(string internalSiteReference, CancellationToken cancellationToken)
        {
            PrivateReadCount++;
            Assert.Equal("default", internalSiteReference);
            return Task.FromResult(Clients?.DeepClone());
        }

        public Task<JsonNode?> ReadClientHistoryAsync(string internalSiteReference, int withinHours, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
