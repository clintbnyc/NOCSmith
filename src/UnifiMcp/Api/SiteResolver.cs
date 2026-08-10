using System.Globalization;
using System.Text.Json.Nodes;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;

namespace UnifiMcp.Api;

public sealed class SiteResolver
{
    private const int SitePageSize = 200;
    private const int MaximumSites = 2000;
    private const int MaximumSitePages = 10;

    private readonly UnifiConfiguration _configuration;
    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;
    private readonly Dictionary<string, string> _internalReferences = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _internalReferenceLock = new(1, 1);

    public SiteResolver(UnifiConfiguration configuration, ContractProvider contracts, IUnifiClient client)
    {
        _configuration = configuration;
        _contracts = contracts;
        _client = client;
    }

    public async Task<string> ResolveAsync(string? requestedSiteId, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(requestedSiteId))
        {
            if (!Guid.TryParse(requestedSiteId, out _))
            {
                throw new ContractException("siteId must be a UUID.");
            }

            return requestedSiteId;
        }

        if (!string.IsNullOrWhiteSpace(_configuration.DefaultSiteId))
        {
            return _configuration.DefaultSiteId;
        }

        var contract = _contracts.Current;
        var operation = contract.GetOperation("getSiteOverviewPage", requireRead: true);
        var request = contract.ValidateAndBuild(
            operation,
            null,
            new Dictionary<string, string> { ["offset"] = "0", ["limit"] = "200" },
            null);
        var response = await _client.ReadAsync(request, cancellationToken).ConfigureAwait(false);
        var sites = response?["data"] as JsonArray;
        if (sites is null || sites.Count == 0)
        {
            throw new ContractException("No UniFi sites are available to this API key.");
        }

        if (sites.Count != 1)
        {
            throw new ContractException("Multiple UniFi sites are available. Pass siteId or configure UNIFI_DEFAULT_SITE_ID.");
        }

        return sites[0]?["id"]?.GetValue<string>()
            ?? throw new ContractException("The single UniFi site did not include an id.");
    }

    public async Task<string> ResolveInternalReferenceAsync(
        string siteId,
        CancellationToken cancellationToken)
    {
        await _internalReferenceLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_internalReferences.TryGetValue(siteId, out var cached))
            {
                return cached;
            }

            var contract = _contracts.Current;
            var operation = contract.GetOperation("getSiteOverviewPage", requireRead: true);
            var offset = 0;
            long? expectedTotalCount = null;
            var seenSiteIds = new HashSet<string>(StringComparer.Ordinal);
            var paginationComplete = false;
            for (var pageNumber = 0; pageNumber < MaximumSitePages; pageNumber++)
            {
                var request = contract.ValidateAndBuild(
                    operation,
                    null,
                    new Dictionary<string, string>
                    {
                        ["offset"] = offset.ToString(CultureInfo.InvariantCulture),
                        ["limit"] = SitePageSize.ToString(CultureInfo.InvariantCulture)
                    },
                    null);
                var response = await _client.ReadAsync(request, cancellationToken).ConfigureAwait(false);
                var responseObject = response as JsonObject
                    ?? throw new ContractException("UniFi site overview did not return an object.");
                var sites = responseObject["data"] as JsonArray
                    ?? throw new ContractException("UniFi site overview did not return a data array.");
                var totalCount = ValidatePage(responseObject, sites, offset, expectedTotalCount);
                expectedTotalCount ??= totalCount;

                JsonObject? site = null;
                foreach (var node in sites)
                {
                    if (node is not JsonObject candidate ||
                        candidate["id"] is not JsonValue idValue ||
                        !idValue.TryGetValue<string>(out var candidateId) ||
                        string.IsNullOrWhiteSpace(candidateId))
                    {
                        throw new ContractException(
                            "UniFi site overview returned a site without a valid id.");
                    }

                    if (!seenSiteIds.Add(candidateId))
                    {
                        throw new ContractException(
                            "UniFi site overview pagination returned a duplicate site id.");
                    }

                    if (string.Equals(candidateId, siteId, StringComparison.Ordinal))
                    {
                        site = candidate;
                    }
                }

                if (site is not null)
                {
                    var internalReference = site["internalReference"]?.GetValue<string>();
                    if (string.IsNullOrWhiteSpace(internalReference))
                    {
                        throw new ContractException($"Site {siteId} did not include the private API internalReference.");
                    }

                    _internalReferences[siteId] = internalReference;
                    return internalReference;
                }

                var nextOffset = (long)offset + sites.Count;
                if (nextOffset >= totalCount)
                {
                    paginationComplete = true;
                    break;
                }

                if (sites.Count == 0)
                {
                    throw new ContractException(
                        "UniFi site overview pagination ended before the declared totalCount.");
                }

                offset = (int)nextOffset;
            }

            if (!paginationComplete)
            {
                throw new ContractException(
                    $"UniFi site overview pagination exceeded the safety limit of {MaximumSitePages} pages.");
            }

            throw new ContractException($"Site {siteId} was not found in the sites available to this API key.");
        }
        finally
        {
            _internalReferenceLock.Release();
        }
    }

    public async Task<Dictionary<string, string>> ResolvePathParametersAsync(
        OperationDefinition operation,
        IReadOnlyDictionary<string, string>? supplied,
        CancellationToken cancellationToken)
    {
        var result = supplied is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(supplied, StringComparer.Ordinal);
        if (operation.Parameters.Any(parameter => parameter.Location == "path" && parameter.Name == "siteId") &&
            !result.ContainsKey("siteId"))
        {
            result["siteId"] = await ResolveAsync(null, cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    private static long ValidatePage(
        JsonObject response,
        JsonArray sites,
        int requestedOffset,
        long? expectedTotalCount)
    {
        var count = ReadNonNegativeInteger(response["count"], "count");
        var offset = ReadNonNegativeInteger(response["offset"], "offset");
        var limit = ReadNonNegativeInteger(response["limit"], "limit");
        var totalCount = ReadNonNegativeInteger(response["totalCount"], "totalCount");
        if (count != sites.Count ||
            offset != requestedOffset ||
            limit != SitePageSize ||
            count > limit ||
            totalCount < offset + count ||
            totalCount > MaximumSites ||
            expectedTotalCount is not null && totalCount != expectedTotalCount)
        {
            throw new ContractException(
                "UniFi site overview pagination metadata was inconsistent or out of bounds.");
        }

        return totalCount;
    }

    private static long ReadNonNegativeInteger(JsonNode? node, string field)
    {
        if (node is JsonValue value &&
            (value.TryGetValue<long>(out var longValue) ||
             value.TryGetValue<int>(out var intValue) && (longValue = intValue) >= 0) &&
            longValue >= 0)
        {
            return longValue;
        }

        throw new ContractException(
            $"UniFi site overview did not return a valid nonnegative {field}.");
    }
}
