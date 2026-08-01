using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Contracts;

namespace UnifiMcp.Tests;

public sealed class ContractProviderTests
{
    [Fact]
    public async Task Matching_live_application_uses_reviewed_embedded_contract()
    {
        var provider = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            new StubControllerClient("10.5.67"),
            NullLogger<ContractProvider>.Instance);

        await provider.RefreshAsync(CancellationToken.None);

        Assert.Equal("10.5.67", provider.LiveApplicationVersion);
        Assert.Equal("10.5.67", provider.Current.Version);
        Assert.Equal("embedded", provider.Current.Source);
        Assert.Equal("embedded-match", provider.Status);
        Assert.Null(provider.LastProbeWarning);
    }

    [Fact]
    public async Task Matching_authenticated_api_docs_contract_is_selected_first()
    {
        var client = new StubControllerClient(
            "10.5.67",
            CreateContract("10.5.67"));
        var provider = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            client,
            NullLogger<ContractProvider>.Instance);

        await provider.RefreshAsync(CancellationToken.None);

        Assert.Equal("controller-match", provider.Status);
        Assert.Equal("controller:/proxy/network/api-docs/integration.json", provider.Current.Source);
        Assert.Equal(new[] { "../api-docs/integration.json" }, client.FixedPaths);
        Assert.Null(provider.LastProbeWarning);
    }

    [Fact]
    public async Task Mismatched_authenticated_api_docs_contract_falls_back_to_reviewed_embedded_contract()
    {
        var provider = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            new StubControllerClient("10.6.0", CreateContract("10.5.67")),
            NullLogger<ContractProvider>.Instance);

        await provider.RefreshAsync(CancellationToken.None);

        Assert.Equal("embedded-fallback", provider.Status);
        Assert.Equal("10.5.67", provider.Current.Version);
        Assert.Contains("no matching controller OpenAPI", provider.LastProbeWarning, StringComparison.Ordinal);
    }

    private static JsonObject CreateContract(string version) => new()
    {
        ["openapi"] = "3.1.0",
        ["info"] = new JsonObject
        {
            ["title"] = "UniFi Network API",
            ["version"] = version
        },
        ["paths"] = new JsonObject
        {
            ["/v1/info"] = new JsonObject
            {
                ["get"] = new JsonObject
                {
                    ["operationId"] = "getInfo",
                    ["responses"] = new JsonObject()
                }
            }
        }
    };

    private sealed class StubControllerClient : IUnifiClient
    {
        private readonly string _liveVersion;
        private readonly JsonObject? _controllerContract;

        public StubControllerClient(string liveVersion, JsonObject? controllerContract = null)
        {
            _liveVersion = liveVersion;
            _controllerContract = controllerContract;
        }

        public List<string> FixedPaths { get; } = new();

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken) =>
            Task.FromResult<JsonNode?>(new JsonObject { ["applicationVersion"] = _liveVersion });

        public Task<JsonNode?> MutateAsync(ValidatedRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> GetFixedAsync(string relativePath, CancellationToken cancellationToken)
        {
            FixedPaths.Add(relativePath);
            return relativePath == "../api-docs/integration.json" && _controllerContract is not null
                ? Task.FromResult<JsonNode?>(_controllerContract.DeepClone())
                : Task.FromException<JsonNode?>(new UnifiApiException(HttpStatusCode.NotFound, "not available"));
        }

        public Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadPrivateClientsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadClientHistoryAsync(
            string internalSiteReference,
            int withinHours,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadNetworkMembersGroupsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
