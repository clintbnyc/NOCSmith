using System.Text.Json.Nodes;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;

namespace UnifiMcp.Api;

public sealed class SiteResolver
{
    private readonly UnifiConfiguration _configuration;
    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;

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
}
