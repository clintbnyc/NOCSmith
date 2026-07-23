using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;

namespace UnifiMcp.Tests;

public sealed class SiteResolverTests
{
    private const string TargetSiteId = "00000000-0000-0000-0000-000000000201";

    [Fact]
    public async Task Internal_reference_lookup_paginates_until_requested_site_is_found_and_caches_it()
    {
        var client = new PagingSiteClient();
        var configuration = new UnifiConfiguration(
            new Uri("https://unifi.nutria-newton.ts.net/proxy/network/integration/"),
            "test-api-key",
            TargetSiteId,
            TimeSpan.FromSeconds(5));
        var contracts = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            client,
            NullLogger<ContractProvider>.Instance);
        var resolver = new SiteResolver(configuration, contracts, client);

        var first = await resolver.ResolveInternalReferenceAsync(TargetSiteId, CancellationToken.None);
        var cached = await resolver.ResolveInternalReferenceAsync(TargetSiteId, CancellationToken.None);

        Assert.Equal("site-201", first);
        Assert.Equal(first, cached);
        Assert.Collection(
            client.RequestUris,
            request =>
            {
                Assert.Contains("offset=0", request, StringComparison.Ordinal);
                Assert.Contains("limit=200", request, StringComparison.Ordinal);
            },
            request =>
            {
                Assert.Contains("offset=200", request, StringComparison.Ordinal);
                Assert.Contains("limit=200", request, StringComparison.Ordinal);
            });
    }

    private sealed class PagingSiteClient : IUnifiClient
    {
        public List<string> RequestUris { get; } = new();

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            Assert.Equal("getSiteOverviewPage", request.Operation.OperationId);
            RequestUris.Add(request.RelativeUri);

            if (RequestUris.Count == 1)
            {
                return Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["offset"] = 0,
                    ["limit"] = 200,
                    ["count"] = 200,
                    ["totalCount"] = 201,
                    ["data"] = new JsonArray(
                        Enumerable.Range(1, 200)
                            .Select(index => (JsonNode?)new JsonObject
                            {
                                ["id"] = $"page-one-site-{index}",
                                ["internalReference"] = $"page-one-{index}"
                            })
                            .ToArray())
                });
            }

            Assert.Equal(2, RequestUris.Count);
            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["offset"] = 200,
                ["limit"] = 200,
                ["count"] = 1,
                ["totalCount"] = 201,
                ["data"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = TargetSiteId,
                        ["internalReference"] = "site-201"
                    }
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

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
