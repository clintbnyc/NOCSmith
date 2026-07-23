using System.Globalization;
using System.Text.Json.Nodes;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;

namespace UnifiMcp.Api;

public sealed class SiteResolver
{
    private const int SitePageSize = 200;

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
            while (true)
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
                var sites = response?["data"] as JsonArray
                    ?? throw new ContractException("UniFi site overview did not return a data array.");
                var site = sites
                    .OfType<JsonObject>()
                    .SingleOrDefault(candidate =>
                        string.Equals(candidate["id"]?.GetValue<string>(), siteId, StringComparison.Ordinal));
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

                var totalCount = ReadTotalCount(response)
                    ?? throw new ContractException("UniFi site overview did not return a valid totalCount.");
                var nextOffset = (long)offset + sites.Count;
                if (sites.Count == 0 || nextOffset >= totalCount)
                {
                    break;
                }

                if (nextOffset > int.MaxValue)
                {
                    throw new ContractException("UniFi site pagination exceeded the supported offset range.");
                }

                offset = (int)nextOffset;
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

    private static long? ReadTotalCount(JsonNode? response)
    {
        if (response?["totalCount"] is not JsonValue value)
        {
            return null;
        }

        if (value.TryGetValue<long>(out var longValue) && longValue >= 0)
        {
            return longValue;
        }

        return value.TryGetValue<int>(out var intValue) && intValue >= 0
            ? intValue
            : null;
    }
}
