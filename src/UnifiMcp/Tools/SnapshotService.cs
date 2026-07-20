using System.Text.Json.Nodes;
using UnifiMcp.Api;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed class SnapshotService
{
    private static readonly string[] SiteOperations =
    {
        "getAdoptedDeviceOverviewPage",
        "getConnectedClientOverviewPage",
        "getNetworksOverviewPage",
        "getWifiBroadcastPage",
        "getFirewallPolicies",
        "getFirewallZones",
        "getAclRulePage",
        "getDnsPolicyPage",
        "getTrafficMatchingLists",
        "getLagPage",
        "getSwitchStackPage",
        "getVpnServerPage",
        "getSiteToSiteVpnTunnelPage",
        "getWansOverviewPage"
    };

    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;

    public SnapshotService(
        ContractProvider contracts,
        IUnifiClient client,
        SiteResolver siteResolver,
        SecretRedactor redactor)
    {
        _contracts = contracts;
        _client = client;
        _siteResolver = siteResolver;
        _redactor = redactor;
    }

    public async Task<ToolResponse> GetAsync(string? siteId, CancellationToken cancellationToken)
    {
        var resolvedSiteId = await _siteResolver.ResolveAsync(siteId, cancellationToken).ConfigureAwait(false);
        var contract = _contracts.Current;
        var sections = new JsonObject
        {
            ["siteId"] = resolvedSiteId,
            ["contractVersion"] = contract.Version
        };

        await AddSectionAsync(sections, "application", "getInfo", null, null, cancellationToken).ConfigureAwait(false);
        foreach (var operationId in SiteOperations)
        {
            var operation = contract.GetOperation(operationId, requireRead: true);
            var queryNames = operation.Parameters.Where(parameter => parameter.Location == "query").Select(parameter => parameter.Name).ToHashSet();
            var query = new Dictionary<string, string>();
            if (queryNames.Contains("offset"))
            {
                query["offset"] = "0";
            }

            if (queryNames.Contains("limit"))
            {
                query["limit"] = "200";
            }

            await AddSectionAsync(
                sections,
                operationId,
                operationId,
                new Dictionary<string, string> { ["siteId"] = resolvedSiteId },
                query,
                cancellationToken).ConfigureAwait(false);
        }

        return new ToolResponse(
            $"UniFi site snapshot completed with {sections.Count - 2} independently collected section(s).",
            _redactor.Redact(sections));
    }

    private async Task AddSectionAsync(
        JsonObject sections,
        string name,
        string operationId,
        IReadOnlyDictionary<string, string>? path,
        IReadOnlyDictionary<string, string>? query,
        CancellationToken cancellationToken)
    {
        var key = ToCamelCase(name);
        try
        {
            var contract = _contracts.Current;
            var operation = contract.GetOperation(operationId, requireRead: true);
            var request = contract.ValidateAndBuild(operation, path, query, null);
            sections[key] = new JsonObject
            {
                ["ok"] = true,
                ["data"] = ResponseMetadata.AnnotatePagination(
                    await _client.ReadAsync(request, cancellationToken).ConfigureAwait(false),
                    query)
            };
        }
        catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException)
        {
            sections[key] = new JsonObject
            {
                ["ok"] = false,
                ["error"] = _redactor.Redact(exception.Message)
            };
        }
    }

    private static string ToCamelCase(string value)
    {
        var words = value.Split(new[] { ' ', '(', ')', '-' }, StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0)
        {
            return value;
        }

        return char.ToLowerInvariant(words[0][0]) + words[0][1..] + string.Concat(words.Skip(1).Select(word => char.ToUpperInvariant(word[0]) + word[1..]));
    }
}
