using UnifiMcp.Contracts;

namespace UnifiMcp.Tools;

public sealed class DomainReadService
{
    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Operations =
        new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["sites"] = Map(("list", "getSiteOverviewPage")),
            ["devices"] = Map(
                ("pending", "getPendingDevicePage"),
                ("list", "getAdoptedDeviceOverviewPage"),
                ("get", "getAdoptedDeviceDetails"),
                ("statistics", "getAdoptedDeviceLatestStatistics")),
            ["clients"] = Map(("list", "getConnectedClientOverviewPage"), ("get", "getConnectedClientDetails")),
            ["networks"] = Map(
                ("list", "getNetworksOverviewPage"),
                ("get", "getNetworkDetails"),
                ("references", "getNetworkReferences")),
            ["wifi"] = Map(("list", "getWifiBroadcastPage"), ("get", "getWifiBroadcastDetails")),
            ["hotspot"] = Map(("list", "getVouchers"), ("get", "getVoucher")),
            ["firewall"] = Map(
                ("listPolicies", "getFirewallPolicies"),
                ("getPolicy", "getFirewallPolicy"),
                ("policyOrdering", "getFirewallPolicyOrdering"),
                ("listZones", "getFirewallZones"),
                ("getZone", "getFirewallZone")),
            ["acl"] = Map(("list", "getAclRulePage"), ("get", "getAclRule"), ("ordering", "getAclRuleOrdering")),
            ["switching"] = Map(
                ("listLags", "getLagPage"),
                ("getLag", "getLag"),
                ("listMcLagDomains", "getMcLagDomainPage"),
                ("getMcLagDomain", "getMcLagDomain"),
                ("listStacks", "getSwitchStackPage"),
                ("getStack", "getSwitchStack")),
            ["dns"] = Map(("list", "getDnsPolicyPage"), ("get", "getDnsPolicy")),
            ["traffic"] = Map(("list", "getTrafficMatchingLists"), ("get", "getTrafficMatchingList")),
            ["supporting"] = Map(
                ("countries", "getCountries"),
                ("dpiApplications", "getDpiApplications"),
                ("dpiCategories", "getDpiApplicationCategories"),
                ("deviceTags", "getDeviceTagPage"),
                ("radiusProfiles", "getRadiusProfileOverviewPage"),
                ("vpnServers", "getVpnServerPage"),
                ("siteToSiteVpnTunnels", "getSiteToSiteVpnTunnelPage"),
                ("wans", "getWansOverviewPage"))
        };

    private readonly ContractProvider _contracts;
    private readonly ReadService _reads;

    public DomainReadService(ContractProvider contracts, ReadService reads)
    {
        _contracts = contracts;
        _reads = reads;
    }

    public async Task<ToolResponse> ExecuteAsync(
        string domain,
        string action,
        string? siteId,
        string? id,
        int? offset,
        int? limit,
        string? filter,
        CancellationToken cancellationToken)
    {
        if (!Operations.TryGetValue(domain, out var domainOperations) || !domainOperations.TryGetValue(action, out var operationId))
        {
            var allowed = Operations.TryGetValue(domain, out var known)
                ? string.Join(", ", known.Keys.OrderBy(value => value, StringComparer.Ordinal))
                : "none";
            throw new ContractException($"Unsupported {domain} action '{action}'. Allowed actions: {allowed}.");
        }

        var operation = _contracts.Current.GetOperation(operationId, requireRead: true);
        var path = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(siteId))
        {
            path["siteId"] = siteId;
        }

        var remainingPath = operation.Parameters
            .Where(parameter => parameter.Location == "path" && parameter.Name != "siteId")
            .ToArray();
        if (remainingPath.Length > 0)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new ContractException($"Action '{action}' requires id for {remainingPath[0].Name}.");
            }

            if (remainingPath.Length != 1)
            {
                throw new ContractException($"Action '{action}' requires explicit path parameters; use unifi_read_operation.");
            }

            path[remainingPath[0].Name] = id;
        }

        var allowedQuery = operation.Parameters
            .Where(parameter => parameter.Location == "query")
            .Select(parameter => parameter.Name)
            .ToHashSet(StringComparer.Ordinal);
        var query = new Dictionary<string, string>(StringComparer.Ordinal);
        if (offset is not null && allowedQuery.Contains("offset"))
        {
            query["offset"] = offset.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        if (limit is not null && allowedQuery.Contains("limit"))
        {
            query["limit"] = limit.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(filter) && allowedQuery.Contains("filter"))
        {
            query["filter"] = filter;
        }

        return await _reads.ExecuteAsync(operationId, path, query, cancellationToken).ConfigureAwait(false);
    }

    private static IReadOnlyDictionary<string, string> Map(params (string Action, string OperationId)[] values) =>
        values.ToDictionary(value => value.Action, value => value.OperationId, StringComparer.OrdinalIgnoreCase);
}
