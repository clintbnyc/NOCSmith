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
            new NewerControllerClient(),
            NullLogger<ContractProvider>.Instance);

        await provider.RefreshAsync(CancellationToken.None);

        Assert.Equal("10.4.57", provider.LiveApplicationVersion);
        Assert.Equal("10.4.57", provider.Current.Version);
        Assert.Equal("embedded", provider.Current.Source);
        Assert.Equal("embedded-match", provider.Status);
        Assert.Null(provider.LastProbeWarning);
    }

    private sealed class NewerControllerClient : IUnifiClient
    {
        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken) =>
            Task.FromResult<JsonNode?>(new JsonObject { ["applicationVersion"] = "10.4.57" });

        public Task<JsonNode?> MutateAsync(ValidatedRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> GetFixedAsync(string relativePath, CancellationToken cancellationToken) =>
            Task.FromException<JsonNode?>(new UnifiApiException(HttpStatusCode.NotFound, "not available"));

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
