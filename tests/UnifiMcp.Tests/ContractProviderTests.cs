using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Contracts;

namespace UnifiMcp.Tests;

public sealed class ContractProviderTests
{
    [Fact]
    public async Task Newer_live_application_is_an_explicit_restricted_fallback()
    {
        var provider = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            new NewerControllerClient(),
            NullLogger<ContractProvider>.Instance);

        await provider.RefreshAsync(CancellationToken.None);

        Assert.Equal("10.4.57", provider.LiveApplicationVersion);
        Assert.Equal("10.3.58", provider.Current.Version);
        Assert.Equal("embedded", provider.Current.Source);
        Assert.Equal("embedded-fallback", provider.Status);
        Assert.Contains("restricted to reviewed embedded 10.3.58", provider.LastProbeWarning, StringComparison.Ordinal);
        Assert.Contains("response fields outside that contract may be unavailable", provider.LastProbeWarning, StringComparison.Ordinal);
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

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
