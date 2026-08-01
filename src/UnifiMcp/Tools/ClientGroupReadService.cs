using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed partial class ClientGroupReadService
{
    private const string FixedResource = "v2/api/site/{site}/network-members-groups";
    private const string ConnectedClientOperationId = "getConnectedClientOverviewPage";
    private const int ConnectedClientPageSize = 200;
    private const int MaximumConnectedClients = 2000;
    private const int MaximumGroups = 500;
    private const int MaximumMembersPerGroup = 5000;
    private const int MaximumTextLength = 4096;

    private readonly UnifiConfiguration _configuration;
    private readonly IUnifiClient _client;
    private readonly ContractProvider _contracts;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;

    public ClientGroupReadService(
        UnifiConfiguration configuration,
        IUnifiClient client,
        ContractProvider contracts,
        SiteResolver siteResolver,
        SecretRedactor redactor)
    {
        _configuration = configuration;
        _client = client;
        _contracts = contracts;
        _siteResolver = siteResolver;
        _redactor = redactor;
    }

    public bool Enabled => _configuration.EnableLegacyReadEnrichment;

    public JsonObject Describe() => new()
    {
        ["enabled"] = Enabled,
        ["readOnly"] = true,
        ["authentication"] = "existing X-API-Key",
        ["fixedResource"] = FixedResource,
        ["verifiedApplicationVersion"] = "10.5.67",
        ["actions"] = new JsonArray("list", "audit"),
        ["auditScope"] = "connected clients returned by the official getConnectedClientOverviewPage operation",
        ["rawPrivateResponsesReturned"] = false
    };

    public async Task<ToolResponse> ReadAsync(
        string action,
        string? requestedSiteId,
        bool includeMembers,
        CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            throw new ConfigurationException(
                "Private client-group reads are disabled. Set UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true to enable the fixed read-only network-members-groups query.");
        }

        if (!string.Equals(action, "list", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(action, "audit", StringComparison.OrdinalIgnoreCase))
        {
            throw new ContractException("Unsupported clientGroups action. Allowed actions: audit, list.");
        }

        var siteId = await _siteResolver.ResolveAsync(requestedSiteId, cancellationToken).ConfigureAwait(false);
        var internalSiteReference = await _siteResolver
            .ResolveInternalReferenceAsync(siteId, cancellationToken)
            .ConfigureAwait(false);
        var response = await _client
            .ReadNetworkMembersGroupsAsync(internalSiteReference, cancellationToken)
            .ConfigureAwait(false);
        var groups = ProjectGroups(response);

        return string.Equals(action, "audit", StringComparison.OrdinalIgnoreCase)
            ? await AuditAsync(siteId, groups, includeMembers, cancellationToken).ConfigureAwait(false)
            : List(siteId, groups, includeMembers);
    }

    private ToolResponse List(string siteId, IReadOnlyList<ClientGroup> groups, bool includeMembers)
    {
        var data = new JsonArray(groups.Select(group => (JsonNode?)ProjectGroup(group, includeMembers)).ToArray());
        var result = new JsonObject
        {
            ["siteId"] = siteId,
            ["count"] = data.Count,
            ["data"] = data,
            ["_connector"] = CreateMetadata("list", includeMembers)
        };
        return new ToolResponse($"Read {data.Count} UniFi client group(s) from the fixed private resource.", result);
    }

    private async Task<ToolResponse> AuditAsync(
        string siteId,
        IReadOnlyList<ClientGroup> groups,
        bool includeMembers,
        CancellationToken cancellationToken)
    {
        var clients = await ReadConnectedClientsAsync(siteId, cancellationToken).ConfigureAwait(false);
        var groupsByMac = groups
            .SelectMany(group => group.Members.Select(member => (member, group)))
            .GroupBy(item => item.member, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                grouping => grouping.Key,
                grouping => grouping.Select(item => item.group).OrderBy(group => group.Name, StringComparer.OrdinalIgnoreCase).ToArray(),
                StringComparer.OrdinalIgnoreCase);
        var connectedMacs = clients
            .Select(client => client.MacAddress)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var clientRecords = new JsonArray();
        var ungroupedRecords = new JsonArray();
        foreach (var client in clients.OrderBy(client => client.Name, StringComparer.OrdinalIgnoreCase))
        {
            groupsByMac.TryGetValue(client.MacAddress, out var assignedGroups);
            assignedGroups ??= Array.Empty<ClientGroup>();
            var record = new JsonObject
            {
                ["id"] = client.Id,
                ["name"] = client.Name,
                ["macAddress"] = client.MacAddress,
                ["groupCount"] = assignedGroups.Length,
                ["groups"] = new JsonArray(assignedGroups
                    .Select(group => (JsonNode?)new JsonObject
                    {
                        ["id"] = group.Id,
                        ["name"] = group.Name
                    })
                    .ToArray())
            };
            clientRecords.Add(record);
            if (assignedGroups.Length == 0)
            {
                ungroupedRecords.Add(record.DeepClone());
            }
        }

        var groupRecords = new JsonArray(groups.Select(group =>
        {
            var connectedMemberCount = group.Members.Count(connectedMacs.Contains);
            var projected = ProjectGroup(group, includeMembers);
            projected["connectedMemberCount"] = connectedMemberCount;
            projected["notCurrentlyConnectedMemberCount"] = group.Members.Count - connectedMemberCount;
            return (JsonNode?)projected;
        }).ToArray());
        var result = new JsonObject
        {
            ["siteId"] = siteId,
            ["groupCount"] = groups.Count,
            ["connectedClientCount"] = clients.Count,
            ["groupedConnectedClientCount"] = clients.Count - ungroupedRecords.Count,
            ["ungroupedConnectedClientCount"] = ungroupedRecords.Count,
            ["groups"] = groupRecords,
            ["clients"] = clientRecords,
            ["ungroupedConnectedClients"] = ungroupedRecords,
            ["_connector"] = CreateMetadata("audit", includeMembers)
        };
        return new ToolResponse(
            $"Audited {clients.Count} connected UniFi client(s): {ungroupedRecords.Count} have no client-group assignment.",
            result);
    }

    private async Task<IReadOnlyList<ConnectedClient>> ReadConnectedClientsAsync(
        string siteId,
        CancellationToken cancellationToken)
    {
        var contract = _contracts.Current;
        var operation = contract.GetOperation(ConnectedClientOperationId, requireRead: true);
        var records = new List<ConnectedClient>();
        var seenMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var offset = 0;

        while (offset < MaximumConnectedClients)
        {
            var request = contract.ValidateAndBuild(
                operation,
                new Dictionary<string, string> { ["siteId"] = siteId },
                new Dictionary<string, string>
                {
                    ["offset"] = offset.ToString(CultureInfo.InvariantCulture),
                    ["limit"] = ConnectedClientPageSize.ToString(CultureInfo.InvariantCulture)
                },
                null);
            var response = await _client.ReadAsync(request, cancellationToken).ConfigureAwait(false);
            if (response?["data"] is not JsonArray page)
            {
                throw new ContractException("Official UniFi connected-client query did not return a data array.");
            }

            for (var index = 0; index < page.Count; index++)
            {
                if (page[index] is not JsonObject record)
                {
                    throw new ContractException(
                        $"Official UniFi connected-client query returned a non-object record at index {index}.");
                }

                var macAddress = ReadMac(record, "macAddress");
                if (macAddress is null)
                {
                    throw new ContractException(
                        $"Official UniFi connected-client record at index {index} did not include a valid MAC address.");
                }

                if (!seenMacs.Add(macAddress))
                {
                    continue;
                }

                var name = ReadText(record, "name")
                    ?? ReadText(record, "hostname")
                    ?? macAddress;
                records.Add(new ConnectedClient(
                    ReadText(record, "id"),
                    SanitizeText(name),
                    macAddress));
            }

            offset += page.Count;
            var totalCount = ReadInteger(response["totalCount"]);
            if (page.Count == 0 ||
                totalCount is not null && offset >= totalCount.Value ||
                totalCount is null && page.Count < ConnectedClientPageSize)
            {
                return records;
            }
        }

        throw new ContractException(
            $"Connected-client audit exceeded the safety limit of {MaximumConnectedClients} records.");
    }

    private IReadOnlyList<ClientGroup> ProjectGroups(JsonNode? response)
    {
        var groups = new List<ClientGroup>();
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        var records = PrivateReadResponseParser.ReadRecords(response);
        if (records.Count > MaximumGroups)
        {
            throw new ContractException(
                $"Private UniFi client-group response exceeded the safety limit of {MaximumGroups} groups.");
        }

        foreach (var record in records)
        {
            var id = ReadText(record, "id")
                ?? throw new ContractException("Private UniFi client-group record did not include id.");
            if (!GroupIdPattern().IsMatch(id))
            {
                throw new ContractException("Private UniFi client-group record included an invalid id.");
            }

            if (!seenIds.Add(id))
            {
                throw new ContractException($"Private UniFi client-group response included duplicate id '{id}'.");
            }

            var name = ReadText(record, "name")
                ?? throw new ContractException($"Private UniFi client-group '{id}' did not include name.");
            if (record["members"] is not JsonArray members)
            {
                throw new ContractException($"Private UniFi client-group '{id}' did not include a members array.");
            }
            if (members.Count > MaximumMembersPerGroup)
            {
                throw new ContractException(
                    $"Private UniFi client-group '{id}' exceeded the safety limit of {MaximumMembersPerGroup} members.");
            }

            var type = ReadText(record, "type")
                ?? throw new ContractException($"Private UniFi client-group '{id}' did not include type.");
            if (!string.Equals(type, "CLIENTS", StringComparison.Ordinal))
            {
                throw new ContractException(
                    $"Private UniFi client-group '{id}' had unsupported type '{SanitizeText(type)}'.");
            }

            var normalizedMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var member in members)
            {
                if (member is not JsonValue value ||
                    !value.TryGetValue<string>(out var text) ||
                    !MacAddressPattern().IsMatch(text.Trim()))
                {
                    throw new ContractException(
                        $"Private UniFi client-group '{id}' included a non-MAC member value.");
                }

                normalizedMembers.Add(text.Trim().ToLowerInvariant());
            }

            groups.Add(new ClientGroup(
                id,
                SanitizeText(name),
                type,
                normalizedMembers.OrderBy(value => value, StringComparer.Ordinal).ToArray()));
        }

        return groups.OrderBy(group => group.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private JsonObject ProjectGroup(ClientGroup group, bool includeMembers)
    {
        var result = new JsonObject
        {
            ["id"] = group.Id,
            ["name"] = group.Name,
            ["type"] = group.Type,
            ["memberCount"] = group.Members.Count
        };
        if (includeMembers)
        {
            result["members"] = new JsonArray(group.Members
                .Select(member => (JsonNode?)JsonValue.Create(member))
                .ToArray());
        }

        return result;
    }

    private static JsonObject CreateMetadata(string action, bool includeMembers) => new()
    {
        ["status"] = "ok",
        ["source"] = "private-v2-network-members-groups-api",
        ["fixedResource"] = FixedResource,
        ["readOnly"] = true,
        ["rawResponseReturned"] = false,
        ["redactionApplied"] = true,
        ["action"] = action,
        ["includeMembers"] = includeMembers,
        ["auditScope"] = action == "audit"
            ? "connected clients returned by the official getConnectedClientOverviewPage operation"
            : null,
        ["knownLimitation"] = action == "audit"
            ? "The official contract exposes connected clients only, so the ungrouped audit cannot identify offline clients that have never been assigned to a group."
            : null,
        ["observedAt"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture)
    };

    private string SanitizeText(string value)
    {
        var redacted = _redactor.Redact(value.Trim());
        return redacted.Length <= MaximumTextLength
            ? redacted
            : redacted[..MaximumTextLength] + "…";
    }

    private static string? ReadText(JsonObject record, string name) =>
        record[name] is JsonValue value &&
        value.TryGetValue<string>(out var text) &&
        !string.IsNullOrWhiteSpace(text)
            ? text.Trim()
            : null;

    private static string? ReadMac(JsonObject record, string name)
    {
        var text = ReadText(record, name);
        return text is not null && MacAddressPattern().IsMatch(text)
            ? text.ToLowerInvariant()
            : null;
    }

    private static int? ReadInteger(JsonNode? value)
    {
        if (value is not JsonValue scalar)
        {
            return null;
        }

        if (scalar.TryGetValue<int>(out var integer))
        {
            return integer;
        }

        return scalar.TryGetValue<long>(out var longValue) && longValue is >= int.MinValue and <= int.MaxValue
            ? (int)longValue
            : null;
    }

    [GeneratedRegex("^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex MacAddressPattern();

    [GeneratedRegex("^[0-9a-fA-F]{24}$", RegexOptions.CultureInvariant)]
    private static partial Regex GroupIdPattern();

    private sealed record ClientGroup(string Id, string Name, string Type, IReadOnlyList<string> Members);

    private sealed record ConnectedClient(string? Id, string Name, string MacAddress);
}
