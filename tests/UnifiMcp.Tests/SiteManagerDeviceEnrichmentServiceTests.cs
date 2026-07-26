using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class SiteManagerDeviceEnrichmentServiceTests
{
    [Fact]
    public async Task Joins_unique_devices_by_normalized_mac_without_overwriting_local_fields()
    {
        var provider = new JsonObject
        {
            ["data"] = new JsonArray(
                new JsonObject
                {
                    ["hostId"] = "host-1",
                    ["updatedAt"] = "2026-07-25T12:00:00Z",
                    ["devices"] = new JsonArray(
                        new JsonObject
                        {
                            ["id"] = "cloud-device",
                            ["mac"] = "AA-BB-CC-DD-EE-FF",
                            ["status"] = "online",
                            ["version"] = "7.1.2",
                            ["firmwareStatus"] = "updateAvailable",
                            ["updateAvailable"] = "7.2.0",
                            ["note"] = "cloud note site-key"
                        })
                })
        };
        var service = CreateService(
            new FakeSiteManagerClient(_ => Task.FromResult<JsonNode?>(provider)),
            localHostId: "host-1");
        var official = new JsonObject
        {
            ["data"] = new JsonArray(
                new JsonObject
                {
                    ["id"] = "local-device",
                    ["macAddress"] = "aa:bb:cc:dd:ee:ff",
                    ["firmwareVersion"] = "local-authoritative"
                })
        };

        var result = await service.EnrichAsync(
            "getAdoptedDeviceOverviewPage",
            official,
            CancellationToken.None);

        Assert.Equal(
            "local-authoritative",
            result!["data"]![0]!["firmwareVersion"]!.GetValue<string>());
        var enrichment = result["_connector"]!["siteManagerEnrichment"]!;
        Assert.Equal("ok", enrichment["status"]!.GetValue<string>());
        Assert.False(enrichment["overwritesLocalFields"]!.GetValue<bool>());
        var record = Assert.Single(enrichment["records"]!.AsArray())!;
        Assert.Equal("local-device", record["localDeviceId"]!.GetValue<string>());
        Assert.Equal("cloud-device", record["siteManagerDeviceId"]!.GetValue<string>());
        Assert.Equal("7.1.2", record["firmwareVersion"]!.GetValue<string>());
        Assert.Equal("7.2.0", record["updateAvailable"]!.GetValue<string>());
        Assert.DoesNotContain("site-key", record["note"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Duplicate_provider_macs_are_reported_and_not_joined()
    {
        var provider = new JsonObject
        {
            ["data"] = new JsonArray(
                new JsonObject
                {
                    ["hostId"] = "host-1",
                    ["devices"] = new JsonArray(
                        new JsonObject { ["id"] = "cloud-1", ["mac"] = "aa:bb:cc:dd:ee:ff" },
                        new JsonObject { ["id"] = "cloud-2", ["mac"] = "AA-BB-CC-DD-EE-FF" })
                })
        };
        var service = CreateService(
            new FakeSiteManagerClient(_ => Task.FromResult<JsonNode?>(provider)),
            localHostId: "host-1");
        var official = new JsonObject
        {
            ["id"] = "local-device",
            ["macAddress"] = "aa:bb:cc:dd:ee:ff"
        };

        var result = await service.EnrichAsync(
            "getAdoptedDeviceDetails",
            official,
            CancellationToken.None);

        var enrichment = result!["_connector"]!["siteManagerEnrichment"]!;
        Assert.Empty(enrichment["records"]!.AsArray());
        Assert.Equal(
            "aabbccddeeff",
            Assert.Single(enrichment["ambiguousProviderMacs"]!.AsArray())!.GetValue<string>());
    }

    [Fact]
    public async Task Missing_host_mapping_and_cloud_failures_do_not_fail_local_read()
    {
        var withoutMapping = CreateService(
            new FakeSiteManagerClient(_ => Task.FromResult<JsonNode?>(new JsonObject())),
            localHostId: null);
        var official = new JsonObject
        {
            ["id"] = "local-device",
            ["macAddress"] = "aa:bb:cc:dd:ee:ff"
        };

        var unmapped = await withoutMapping.EnrichAsync(
            "getAdoptedDeviceDetails",
            official.DeepClone(),
            CancellationToken.None);
        Assert.Equal(
            "hostMappingRequired",
            unmapped!["_connector"]!["siteManagerEnrichment"]!["status"]!.GetValue<string>());

        var retryAt = new DateTimeOffset(2026, 7, 25, 12, 5, 0, TimeSpan.Zero);
        var failing = CreateService(
            new FakeSiteManagerClient(_ =>
                Task.FromException<JsonNode?>(
                    new SiteManagerApiException(
                        HttpStatusCode.TooManyRequests,
                        "limited",
                        "rate_limit",
                        retryAt))),
            localHostId: "host-1");
        var localResult = await failing.EnrichAsync(
            "getAdoptedDeviceDetails",
            official.DeepClone(),
            CancellationToken.None);

        Assert.Equal("local-device", localResult!["id"]!.GetValue<string>());
        Assert.Equal(
            "rateLimited",
            localResult["_connector"]!["siteManagerEnrichment"]!["status"]!.GetValue<string>());
        Assert.Equal(
            retryAt.ToString("O"),
            localResult["_connector"]!["siteManagerEnrichment"]!["retryAt"]!.GetValue<string>());
    }

    private static SiteManagerDeviceEnrichmentService CreateService(
        ISiteManagerClient client,
        string? localHostId)
    {
        var configuration = new UnifiConfiguration(
            new Uri(UnifiConfiguration.DefaultBaseUrl + "/"),
            "local-key",
            null,
            TimeSpan.FromSeconds(5),
            SiteManagerApiKey: "site-key",
            SiteManagerLocalHostId: localHostId);
        var redactor = new SecretRedactor("local-key", "site-key");
        var reads = new SiteManagerReadService(configuration, client, redactor);
        return new SiteManagerDeviceEnrichmentService(
            configuration,
            reads,
            redactor,
            NullLogger<SiteManagerDeviceEnrichmentService>.Instance);
    }

    private sealed class FakeSiteManagerClient : ISiteManagerClient
    {
        private readonly Func<string, Task<JsonNode?>> _get;

        public FakeSiteManagerClient(Func<string, Task<JsonNode?>> get)
        {
            _get = get;
        }

        public Task<JsonNode?> GetAsync(string relativePath, CancellationToken cancellationToken) =>
            _get(relativePath);

        public Task<JsonNode?> QueryIspMetricsAsync(
            string interval,
            JsonObject body,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public JsonObject Describe() => new();
    }
}
