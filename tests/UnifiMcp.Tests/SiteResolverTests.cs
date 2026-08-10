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

    [Fact]
    public async Task Internal_reference_lookup_rejects_site_totals_above_the_safety_limit()
    {
        var client = new PagingSiteClient { FirstTotalCount = 2001 };
        var resolver = CreateResolver(client);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            resolver.ResolveInternalReferenceAsync(TargetSiteId, CancellationToken.None));

        Assert.Contains("inconsistent or out of bounds", exception.Message, StringComparison.Ordinal);
        Assert.Single(client.RequestUris);
    }

    [Fact]
    public async Task Internal_reference_lookup_rejects_total_count_changes_before_caching_a_match()
    {
        var client = new PagingSiteClient { SecondTotalCount = 202 };
        var resolver = CreateResolver(client);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            resolver.ResolveInternalReferenceAsync(TargetSiteId, CancellationToken.None));

        Assert.Contains("inconsistent or out of bounds", exception.Message, StringComparison.Ordinal);
        Assert.Equal(2, client.RequestUris.Count);
    }

    [Fact]
    public async Task Internal_reference_lookup_stops_after_the_page_safety_limit()
    {
        var client = new PagingSiteClient { ReturnOneSitePerPage = true };
        var resolver = CreateResolver(client);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            resolver.ResolveInternalReferenceAsync(TargetSiteId, CancellationToken.None));

        Assert.Contains("safety limit of 10 pages", exception.Message, StringComparison.Ordinal);
        Assert.Equal(10, client.RequestUris.Count);
    }

    [Fact]
    public async Task Internal_reference_lookup_rejects_a_nonprogressing_page()
    {
        var client = new PagingSiteClient { ReturnEmptyFirstPage = true };
        var resolver = CreateResolver(client);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            resolver.ResolveInternalReferenceAsync(TargetSiteId, CancellationToken.None));

        Assert.Contains("ended before the declared totalCount", exception.Message, StringComparison.Ordinal);
        Assert.Single(client.RequestUris);
    }

    private static SiteResolver CreateResolver(IUnifiClient client)
    {
        var configuration = new UnifiConfiguration(
            new Uri("https://unifi.nutria-newton.ts.net/proxy/network/integration/"),
            "test-api-key",
            TargetSiteId,
            TimeSpan.FromSeconds(5));
        var contracts = new ContractProvider(
            OpenApiContract.LoadEmbedded(),
            client,
            NullLogger<ContractProvider>.Instance);
        return new SiteResolver(configuration, contracts, client);
    }

    private sealed class PagingSiteClient : IUnifiClient
    {
        public List<string> RequestUris { get; } = new();

        public long FirstTotalCount { get; init; } = 201;

        public long SecondTotalCount { get; init; } = 201;

        public bool ReturnOneSitePerPage { get; init; }

        public bool ReturnEmptyFirstPage { get; init; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            Assert.Equal("getSiteOverviewPage", request.Operation.OperationId);
            RequestUris.Add(request.RelativeUri);

            if (ReturnEmptyFirstPage)
            {
                return Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["offset"] = 0,
                    ["limit"] = 200,
                    ["count"] = 0,
                    ["totalCount"] = 1,
                    ["data"] = new JsonArray()
                });
            }

            if (ReturnOneSitePerPage)
            {
                var offset = RequestUris.Count - 1;
                Assert.Contains($"offset={offset}", request.RelativeUri, StringComparison.Ordinal);
                return Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["offset"] = offset,
                    ["limit"] = 200,
                    ["count"] = 1,
                    ["totalCount"] = 11,
                    ["data"] = new JsonArray(new JsonObject
                    {
                        ["id"] = $"slow-site-{offset}",
                        ["internalReference"] = $"slow-reference-{offset}"
                    })
                });
            }

            if (RequestUris.Count == 1)
            {
                return Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["offset"] = 0,
                    ["limit"] = 200,
                    ["count"] = 200,
                    ["totalCount"] = FirstTotalCount,
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
                ["totalCount"] = SecondTotalCount,
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
