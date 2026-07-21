using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Contracts;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class ResponseMetadataTests
{
    [Fact]
    public void Pagination_reports_truncation_explicitly()
    {
        var page = new JsonObject
        {
            ["offset"] = 20,
            ["limit"] = 20,
            ["totalCount"] = 55,
            ["data"] = new JsonArray(JsonValue.Create(1), JsonValue.Create(2))
        };

        var result = ResponseMetadata.AnnotatePagination(page)!;

        Assert.True(ResponseMetadata.IsTruncated(result));
        Assert.Equal(2, result["_connector"]!["returned"]!.GetValue<int>());
        Assert.Equal(55, result["_connector"]!["totalCount"]!.GetValue<int>());
    }

    [Fact]
    public void Device_details_report_fields_missing_from_official_contract()
    {
        var limitations = ResponseMetadata.GetKnownLimitations("getAdoptedDeviceDetails", "10.3.58");

        Assert.Equal(3, limitations.Count);
        var labels = limitations.OfType<JsonObject>().Single(value => value["area"]!.GetValue<string>() == "interfaces.ports.labels");
        var stp = limitations.OfType<JsonObject>().Single(value => value["area"]!.GetValue<string>() == "interfaces.ports.stp");
        var uiRole = limitations.OfType<JsonObject>().Single(value => value["area"]!.GetValue<string>() == "interfaces.ports.stp.uiRole");
        Assert.Equal("official-contract", labels["source"]!.GetValue<string>());
        Assert.Equal("unresolved", labels["resolutionStatus"]!.GetValue<string>());
        Assert.Equal("custom port labels", Assert.Single(labels["missingData"]!.AsArray())!.GetValue<string>());
        Assert.Equal("STP operational/configuration fields", Assert.Single(stp["missingData"]!.AsArray())!.GetValue<string>());
        Assert.Equal("unresolved", uiRole["resolutionStatus"]!.GetValue<string>());
        Assert.Equal(
            "normalized UniFi UI role (Edge versus Participant)",
            Assert.Single(uiRole["stillMissing"]!.AsArray())!.GetValue<string>());
        Assert.Contains("10.3.58", labels["reason"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public void Successful_legacy_enrichment_resolves_only_the_fields_it_can_supply()
    {
        var limitations = ResponseMetadata.GetKnownLimitations(
            "getAdoptedDeviceDetails",
            "10.3.58",
            legacyReadEnrichmentAvailable: true);

        var labels = limitations.OfType<JsonObject>().Single(value => value["area"]!.GetValue<string>() == "interfaces.ports.labels");
        var stp = limitations.OfType<JsonObject>().Single(value => value["area"]!.GetValue<string>() == "interfaces.ports.stp");
        var uiRole = limitations.OfType<JsonObject>().Single(value => value["area"]!.GetValue<string>() == "interfaces.ports.stp.uiRole");
        Assert.Equal("resolved", labels["resolutionStatus"]!.GetValue<string>());
        Assert.Equal("legacyReadEnrichment", labels["resolvedBy"]!.GetValue<string>());
        Assert.Empty(labels["stillMissing"]!.AsArray());
        Assert.Equal("resolved", stp["resolutionStatus"]!.GetValue<string>());
        Assert.Equal("legacyReadEnrichment", stp["resolvedBy"]!.GetValue<string>());
        Assert.Equal("unresolved", uiRole["resolutionStatus"]!.GetValue<string>());
        Assert.Null(uiRole["resolvedBy"]);
    }

    [Fact]
    public void Client_reads_distinguish_controller_reported_type_from_physical_attachment()
    {
        var provider = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            new UnusedClient(),
            NullLogger<ContractProvider>.Instance);
        var observedAt = new DateTimeOffset(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);
        var response = new JsonObject
        {
            ["data"] = new JsonArray(
                new JsonObject
                {
                    ["type"] = "WIRED",
                    ["uplinkDeviceId"] = "switch-id"
                })
        };

        var result = ResponseMetadata.AnnotateCoverage(
            response,
            "getConnectedClientOverviewPage",
            provider,
            observedAt)!;
        var connector = result["_connector"]!;

        Assert.Equal("getConnectedClientOverviewPage", connector["sourceOperationId"]!.GetValue<string>());
        Assert.Equal(observedAt.ToString("O"), connector["observedAt"]!.GetValue<string>());
        Assert.Equal(
            "unknown-when-third-party-bridged",
            connector["topologySemantics"]!["physicalAttachment"]!.GetValue<string>());
        Assert.Single(connector["knownLimitations"]!.AsArray());
    }

    [Fact]
    public void Capabilities_can_enumerate_all_known_response_limitations()
    {
        var limitations = ResponseMetadata.GetAllKnownLimitations("10.3.58");

        Assert.Equal(8, limitations.Count);
        Assert.Contains(
            limitations,
            value => value!["operationId"]!.GetValue<string>() == "getAdoptedDeviceDetails");
        Assert.Contains(
            limitations,
            value => value!["operationId"]!.GetValue<string>() == "getAdoptedDeviceOverviewPage");
        Assert.Contains(
            limitations,
            value => value!["operationId"]!.GetValue<string>() == "getConnectedClientOverviewPage");
        Assert.Contains(
            limitations,
            value => value!["operationId"]!.GetValue<string>() == "getConnectedClientDetails");
    }

    private sealed class UnusedClient : IUnifiClient
    {
        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> MutateAsync(ValidatedRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> GetFixedAsync(string relativePath, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadLegacyClientsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
