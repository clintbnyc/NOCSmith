using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class SnapshotServiceTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";
    private const string NotConfiguredCode = "api.firewall.zone-based-firewall-not-configured";

    [Fact]
    public async Task Snapshot_counts_expected_absence_separately_from_failures()
    {
        var client = new SnapshotClient
        {
            PoliciesErrorCode = NotConfiguredCode,
            ZonesErrorCode = NotConfiguredCode,
            FailingOperationId = "getAclRulePage"
        };
        var service = CreateService(client);

        var response = await service.GetAsync(SiteId, CancellationToken.None);
        var data = Assert.IsType<JsonObject>(response.Data);
        var summary = data["_connector"]!["sectionSummary"]!;

        Assert.Equal(15, summary["total"]!.GetValue<int>());
        Assert.Equal(12, summary["succeeded"]!.GetValue<int>());
        Assert.Equal(2, summary["notApplicable"]!.GetValue<int>());
        Assert.Equal(1, summary["failed"]!.GetValue<int>());
        Assert.Contains("12 succeeded, 2 not applicable, 1 failed", response.Summary, StringComparison.Ordinal);

        var policies = data["getFirewallPolicies"]!;
        Assert.True(policies["ok"]!.GetValue<bool>());
        Assert.False(policies["applicable"]!.GetValue<bool>());
        Assert.Equal("notApplicable", policies["status"]!.GetValue<string>());
        Assert.Equal(NotConfiguredCode, policies["reasonCode"]!.GetValue<string>());
        Assert.Equal("getFirewallPolicies", policies["sourceOperationId"]!.GetValue<string>());
        Assert.True(DateTimeOffset.TryParse(policies["observedAt"]!.GetValue<string>(), out _));

        var acl = data["getAclRulePage"]!;
        Assert.False(acl["ok"]!.GetValue<bool>());
        Assert.Equal("failed", acl["status"]!.GetValue<string>());
        Assert.Equal(403, acl["httpStatus"]!.GetValue<int>());
    }

    [Fact]
    public async Task Snapshot_does_not_swallow_an_unexpected_firewall_bad_request()
    {
        var client = new SnapshotClient
        {
            PoliciesErrorCode = "api.firewall.invalid-request",
            ZonesErrorCode = NotConfiguredCode
        };
        var service = CreateService(client);

        var response = await service.GetAsync(SiteId, CancellationToken.None);
        var data = Assert.IsType<JsonObject>(response.Data);
        var summary = data["_connector"]!["sectionSummary"]!;

        Assert.Equal(13, summary["succeeded"]!.GetValue<int>());
        Assert.Equal(1, summary["notApplicable"]!.GetValue<int>());
        Assert.Equal(1, summary["failed"]!.GetValue<int>());
        Assert.Equal("failed", data["getFirewallPolicies"]!["status"]!.GetValue<string>());
        Assert.Equal("api.firewall.invalid-request", data["getFirewallPolicies"]!["errorCode"]!.GetValue<string>());
    }

    private static SnapshotService CreateService(IUnifiClient client)
    {
        var configuration = new UnifiConfiguration(
            new Uri("https://unifi.nutria-newton.ts.net/proxy/network/integration/"),
            "test-api-key",
            SiteId,
            TimeSpan.FromSeconds(5));
        var contracts = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            client,
            NullLogger<ContractProvider>.Instance);
        var resolver = new SiteResolver(configuration, contracts, client);
        var redactor = new SecretRedactor("test-api-key");
        var enrichment = new LegacyReadEnrichmentService(
            configuration,
            client,
            resolver,
            redactor,
            NullLogger<LegacyReadEnrichmentService>.Instance);
        return new SnapshotService(contracts, client, resolver, redactor, enrichment);
    }

    private sealed class SnapshotClient : IUnifiClient
    {
        public string? PoliciesErrorCode { get; init; }

        public string? ZonesErrorCode { get; init; }

        public string? FailingOperationId { get; init; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            var operationId = request.Operation.OperationId;
            if (operationId == "getFirewallPolicies" && PoliciesErrorCode is not null)
            {
                return Failed(HttpStatusCode.BadRequest, PoliciesErrorCode);
            }

            if (operationId == "getFirewallZones" && ZonesErrorCode is not null)
            {
                return Failed(HttpStatusCode.BadRequest, ZonesErrorCode);
            }

            if (operationId == FailingOperationId)
            {
                return Task.FromException<JsonNode?>(
                    new UnifiApiException(HttpStatusCode.Forbidden, "forbidden", "api.auth.forbidden"));
            }

            if (operationId == "getInfo")
            {
                return Task.FromResult<JsonNode?>(new JsonObject { ["applicationVersion"] = "10.4.57" });
            }

            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["offset"] = 0,
                ["limit"] = 200,
                ["count"] = 0,
                ["totalCount"] = 0,
                ["data"] = new JsonArray()
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

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        private static Task<JsonNode?> Failed(HttpStatusCode statusCode, string code) =>
            Task.FromException<JsonNode?>(new UnifiApiException(statusCode, "not configured", code));
    }
}
