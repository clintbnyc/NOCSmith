using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Journal;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed partial class ClientHistoryReadService
{
    private const string FixedHistoryResource =
        "v2/api/site/{site}/clients/history?onlyNonBlocked=true&includeUnifiDevices=true&withinHours={withinHours}";
    private const string FixedGroupResource = "v2/api/site/{site}/network-members-groups";
    private const string ConnectedClientOperationId = "getConnectedClientOverviewPage";
    private const int DefaultHistoryHours = 24;
    private const int DefaultLimit = 100;
    private const int MaximumLimit = 200;
    private const int ConnectedClientPageSize = 200;
    private const int MaximumConnectedClients = 2000;
    private const int MaximumHistoryRecords = 10000;
    private const int MaximumGroups = 500;
    private const int MaximumMembersPerGroup = 5000;
    private const int MaximumUniqueGroupMembers = 10000;
    private const int MaximumTotalGroupMemberships = 10000;
    private const int MaximumProjectedGroupReferences = 5000;
    private const int MaximumTextLength = 4096;

    private static readonly int[] SupportedHistoryHours = { 24, 72, 168, 336, 720, 4320 };

    private readonly UnifiConfiguration _configuration;
    private readonly IUnifiClient _client;
    private readonly ContractProvider _contracts;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;
    private readonly ClientObservationCollector _collector;

    public ClientHistoryReadService(
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
        _collector = new ClientObservationCollector(
            configuration,
            client,
            contracts,
            siteResolver,
            redactor,
            new SystemClientJournalClock(),
            new GuidClientCollectionIdGenerator());
    }

    public bool Enabled => _configuration.EnableLegacyReadEnrichment;

    public JsonObject Describe() => new()
    {
        ["enabled"] = Enabled,
        ["readOnly"] = true,
        ["authentication"] = "existing X-API-Key",
        ["fixedResource"] = FixedHistoryResource,
        ["verifiedApplicationVersion"] = "10.5.67",
        ["supportedHistoryHours"] = new JsonArray(
            SupportedHistoryHours.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()),
        ["defaultHistoryHours"] = DefaultHistoryHours,
        ["defaultLimit"] = DefaultLimit,
        ["maximumLimit"] = MaximumLimit,
        ["maximumHistoryRecords"] = MaximumHistoryRecords,
        ["maximumTotalGroupMemberships"] = MaximumTotalGroupMemberships,
        ["maximumProjectedGroupReferences"] = MaximumProjectedGroupReferences,
        ["sourceGrains"] = new JsonArray(
            "official currently connected client overview",
            "time-bounded non-blocked private client history",
            "configured private client-group membership"),
        ["rawPrivateResponsesReturned"] = false
    };

    public async Task<ToolResponse> ReadAsync(
        string? requestedSiteId,
        int? requestedHistoryHours,
        int? requestedOffset,
        int? requestedLimit,
        CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            throw new ConfigurationException(
                "Private client-history reads are disabled. Set UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true to enable the fixed read-only clients/history query.");
        }

        var historyHours = requestedHistoryHours ?? DefaultHistoryHours;
        if (!SupportedHistoryHours.Contains(historyHours))
        {
            throw new ContractException(
                "historyHours must be one of the bounded Network UI values: 24, 72, 168, 336, 720, or 4320.");
        }

        var offset = requestedOffset ?? 0;
        if (offset is < 0 or > MaximumHistoryRecords)
        {
            throw new ContractException($"offset must be between 0 and {MaximumHistoryRecords}.");
        }

        var limit = requestedLimit ?? DefaultLimit;
        if (limit is < 1 or > MaximumLimit)
        {
            throw new ContractException($"limit must be between 1 and {MaximumLimit}.");
        }

        var collection = await _collector
            .CollectForHistoryAsync(requestedSiteId, historyHours, cancellationToken)
            .ConfigureAwait(false);
        var observedAt = collection.StartedAt;
        var siteId = collection.SiteId;

        if (collection.History.Status != CollectionSourceStatus.Complete)
        {
            var exception = ToApiException(collection.History);
            if (exception is not null && !IsUnsupportedResource(exception))
            {
                throw exception;
            }

            return CreateNotSupportedResponse(
                siteId,
                historyHours,
                offset,
                limit,
                observedAt,
                collection.History.ErrorCode == "endpointUnavailable"
                    ? "endpointUnavailable"
                    : "unrecognizedResponseContract",
                collection.History.ErrorCode == "endpointUnavailable"
                    ? "This UniFi Network version does not expose the fixed private client-history GET to the Integration API key."
                    : "The fixed private client-history GET returned an unrecognized response contract; no client data was returned.",
                "private-v2-client-history-api",
                FixedHistoryResource,
                operationId: null,
                exception);
        }

        if (collection.Connected.Status != CollectionSourceStatus.Complete)
        {
            var exception = ToApiException(collection.Connected);
            if (exception is not null && !IsUnsupportedResource(exception))
            {
                throw exception;
            }

            return CreateNotSupportedResponse(
                siteId,
                historyHours,
                offset,
                limit,
                observedAt,
                exception is null
                    ? "unrecognizedResponseContract"
                    : "requiredSourceUnavailable",
                exception is null
                    ? "The official connected-client overview returned an unrecognized pagination or record contract; no client data was returned."
                    : "The official connected-client overview required for current-state classification is unavailable.",
                "official-network-integration-api",
                fixedResource: null,
                ConnectedClientOperationId,
                exception);
        }

        if (collection.Groups.Status != CollectionSourceStatus.Complete)
        {
            var exception = ToApiException(collection.Groups);
            if (exception is not null && !IsUnsupportedResource(exception))
            {
                throw exception;
            }

            return CreateNotSupportedResponse(
                siteId,
                historyHours,
                offset,
                limit,
                observedAt,
                exception is null
                    ? "unrecognizedResponseContract"
                    : "requiredSourceUnavailable",
                exception is null
                    ? "The fixed private client-group GET returned an unrecognized response contract; no client data was returned."
                    : "The fixed private client-group GET required for configured-membership classification is unavailable.",
                "private-v2-network-members-groups-api",
                FixedGroupResource,
                operationId: null,
                exception);
        }

        var connected = new ConnectedReadResult(
            collection.Connected.Records.Select(ToConnectedClient).ToArray(),
            collection.Connected.DuplicateRecordsSuppressed);
        var history = collection.History.Records.Select(ToHistoryClient).ToArray();
        var groups = collection.Groups.Records
            .Select(group => new ClientGroup(group.GroupId, group.Name, group.Members))
            .ToArray();

        try
        {
            return BuildResponse(
                siteId,
                historyHours,
                offset,
                limit,
                observedAt,
                connected,
                history,
                groups,
                collection.History.MaclessTeleportRecordsSuppressed);
        }
        catch (ContractException)
        {
            return CreateNotSupportedResponse(
                siteId,
                historyHours,
                offset,
                limit,
                observedAt,
                "projectionSafetyLimitExceeded",
                "The projected client-history result exceeded a connector safety limit; no client data was returned.",
                "connector-projection",
                fixedResource: null,
                operationId: null,
                exception: null);
        }
    }

    private static ConnectedClient ToConnectedClient(
        NormalizedClientObservation observation)
    {
        var nameSource = observation.Provenance
            .First(value => value.FieldName == "name").SourceField;
        var ipSource = observation.Provenance
            .First(value => value.FieldName == "ipAddress");
        return new ConnectedClient(
            observation.Name ?? observation.MacAddress,
            nameSource,
            observation.MacAddress,
            observation.IpAddress,
            ipSource.Available ? ipSource.SourceField : null,
            observation.ConnectedAtEpochMilliseconds is null
                ? null
                : DateTimeOffset
                    .FromUnixTimeMilliseconds(observation.ConnectedAtEpochMilliseconds.Value)
                    .ToString("O", CultureInfo.InvariantCulture));
    }

    private static HistoryClient ToHistoryClient(
        NormalizedClientObservation observation)
    {
        var nameSource = observation.Provenance
            .First(value => value.FieldName == "name").SourceField;
        var ipSource = observation.Provenance
            .First(value => value.FieldName == "ipAddress");
        return new HistoryClient(
            observation.Name ?? observation.MacAddress,
            nameSource,
            observation.MacAddress,
            observation.IpAddress,
            ipSource.Available ? ipSource.SourceField : null,
            observation.LastSeenEpochMilliseconds is null
                ? null
                : DateTimeOffset
                    .FromUnixTimeMilliseconds(observation.LastSeenEpochMilliseconds.Value)
                    .ToString("O", CultureInfo.InvariantCulture),
            observation.LastSeenEpochMilliseconds / 1000);
    }

    private static UnifiApiException? ToApiException<T>(
        SourceCollection<T> source) =>
        source.HttpStatus is null
            ? null
            : new UnifiApiException(
                (HttpStatusCode)source.HttpStatus.Value,
                source.ErrorMessage ?? "UniFi source read failed.",
                source.ControllerReasonCode);

    private ToolResponse BuildResponse(
        string siteId,
        int historyHours,
        int offset,
        int limit,
        DateTimeOffset observedAt,
        ConnectedReadResult connectedResult,
        IReadOnlyList<HistoryClient> history,
        IReadOnlyList<ClientGroup> groups,
        int maclessTeleportRecordsSuppressed)
    {
        var groupsByMac = groups
            .SelectMany(group => group.Members.Select(member => (member, group)))
            .GroupBy(item => item.member, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                grouping => grouping.Key,
                grouping => grouping
                    .Select(item => item.group)
                    .OrderBy(group => group.Name, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                StringComparer.OrdinalIgnoreCase);
        var connectedByMac = connectedResult.Clients.ToDictionary(
            client => client.MacAddress,
            StringComparer.OrdinalIgnoreCase);
        var historyByMac = history.ToDictionary(
            client => client.MacAddress,
            StringComparer.OrdinalIgnoreCase);

        var historyRecordsAlsoConnected = history
            .Count(client => connectedByMac.ContainsKey(client.MacAddress));
        var offline = history
            .Where(client => !connectedByMac.ContainsKey(client.MacAddress))
            .OrderByDescending(client => client.LastSeenEpochSeconds)
            .ThenBy(client => client.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(client => client.MacAddress, StringComparer.Ordinal)
            .ToArray();
        var groupMembersWithoutHistory = groupsByMac.Keys
            .Where(mac => !connectedByMac.ContainsKey(mac) && !historyByMac.ContainsKey(mac))
            .OrderBy(mac => mac, StringComparer.Ordinal)
            .ToArray();
        var connected = connectedResult.Clients
            .OrderBy(client => client.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(client => client.MacAddress, StringComparer.Ordinal)
            .ToArray();

        var connectedPage = Page(connected, offset, limit);
        var offlinePage = Page(offline, offset, limit);
        var missingPage = Page(groupMembersWithoutHistory, offset, limit);
        ValidateProjectedGroupReferences(
            connectedPage.Select(client => GetGroups(groupsByMac, client.MacAddress)),
            offlinePage.Select(client => GetGroups(groupsByMac, client.MacAddress)),
            missingPage.Select(mac => GetGroups(groupsByMac, mac)));
        var connectedData = new JsonArray(connectedPage
            .Select(client => (JsonNode?)ProjectConnected(client, GetGroups(groupsByMac, client.MacAddress)))
            .ToArray());
        var offlineData = new JsonArray(offlinePage
            .Select(client => (JsonNode?)ProjectOffline(client, GetGroups(groupsByMac, client.MacAddress)))
            .ToArray());
        var missingData = new JsonArray(missingPage
            .Select(mac => (JsonNode?)ProjectGroupMemberWithoutHistory(mac, GetGroups(groupsByMac, mac)))
            .ToArray());

        var pagination = new JsonObject
        {
            ["mode"] = "connector-side per classification over fixed controller collections",
            ["offset"] = offset,
            ["limit"] = limit,
            ["currentlyConnected"] = CreatePageMetadata(connected.Length, connectedData.Count, offset, limit),
            ["offlineWithinWindow"] = CreatePageMetadata(offline.Length, offlineData.Count, offset, limit),
            ["groupMembersWithoutHistory"] = CreatePageMetadata(
                groupMembersWithoutHistory.Length,
                missingData.Count,
                offset,
                limit)
        };
        pagination["truncated"] =
            IsPageTruncated(connected.Length, offset, limit) ||
            IsPageTruncated(offline.Length, offset, limit) ||
            IsPageTruncated(groupMembersWithoutHistory.Length, offset, limit);

        var unavailableFields = new JsonObject
        {
            ["connectedClientLastSeenAt"] = new JsonObject
            {
                ["status"] = "unavailable",
                ["recordCount"] = connected.Length,
                ["reason"] = "The authoritative connected-client overview does not expose last-seen history."
            },
            ["connectedClientIpAddress"] = MissingCount(
                connected.Count(client => client.IpAddress is null),
                connected.Length),
            ["offlineClientIpAddress"] = MissingCount(
                offline.Count(client => client.IpAddress is null),
                offline.Length),
            ["offlineClientLastSeenAt"] = MissingCount(
                offline.Count(client => client.LastSeenAt is null),
                offline.Length),
            ["groupMemberWithoutHistoryFields"] = new JsonObject
            {
                ["status"] = groupMembersWithoutHistory.Length == 0 ? "notApplicable" : "unavailable",
                ["recordCount"] = groupMembersWithoutHistory.Length,
                ["fields"] = new JsonArray("name", "ipAddress", "lastSeenAt", "onlineState"),
                ["reason"] = "Configured membership supplies only a MAC join key and group metadata."
            }
        };

        var result = new JsonObject
        {
            ["siteId"] = siteId,
            ["historyWindow"] = CreateHistoryWindow(historyHours, observedAt),
            ["counts"] = new JsonObject
            {
                ["online"] = connected.Length,
                ["offlineWithinWindow"] = offline.Length,
                ["groupMembersWithoutHistory"] = groupMembersWithoutHistory.Length,
                ["historySourceRecords"] = history.Count,
                ["historyRecordsAlsoCurrentlyConnected"] = historyRecordsAlsoConnected,
                ["maclessTeleportRecordsSuppressed"] = maclessTeleportRecordsSuppressed
            },
            ["currentlyConnectedClients"] = connectedData,
            ["offlineClientsWithinWindow"] = offlineData,
            ["groupMembersWithoutHistory"] = missingData,
            ["_connector"] = new JsonObject
            {
                ["status"] = "ok",
                ["source"] = "private-v2-client-history-api",
                ["controllerApiSources"] = new JsonObject
                {
                    ["currentlyConnected"] = new JsonObject
                    {
                        ["source"] = "official-network-integration-api",
                        ["operationId"] = ConnectedClientOperationId
                    },
                    ["offlineWithinWindow"] = new JsonObject
                    {
                        ["source"] = "private-v2-client-history-api",
                        ["fixedResource"] = FixedHistoryResource
                    },
                    ["configuredGroupMembership"] = new JsonObject
                    {
                        ["source"] = "private-v2-network-members-groups-api",
                        ["fixedResource"] = FixedGroupResource
                    }
                },
                ["readOnly"] = true,
                ["httpMethod"] = "GET",
                ["rawPrivateResponsesReturned"] = false,
                ["redactionApplied"] = true,
                ["pagination"] = pagination,
                ["safetyLimits"] = new JsonObject
                {
                    ["maximumConnectedClients"] = MaximumConnectedClients,
                    ["maximumHistoryRecords"] = MaximumHistoryRecords,
                    ["maximumGroups"] = MaximumGroups,
                    ["maximumMembersPerGroup"] = MaximumMembersPerGroup,
                    ["maximumUniqueGroupMembers"] = MaximumUniqueGroupMembers,
                    ["maximumTotalGroupMemberships"] = MaximumTotalGroupMemberships,
                    ["maximumProjectedGroupReferences"] = MaximumProjectedGroupReferences,
                    ["maximumRecordsPerClassificationPage"] = MaximumLimit
                },
                ["onlineCount"] = connected.Length,
                ["offlineCount"] = offline.Length,
                ["connectedDuplicateMacsSuppressed"] = connectedResult.DuplicateMacCount,
                ["historyRecordsSuppressedBecauseCurrentlyConnected"] = historyRecordsAlsoConnected,
                ["maclessTeleportRecordsSuppressed"] = maclessTeleportRecordsSuppressed,
                ["unavailableFields"] = unavailableFields,
                ["auditScope"] =
                    "Currently connected clients from the official overview at observation time; non-blocked private client-history records within the effective bounded window; and configured CLIENTS group memberships joined only by normalized MAC address.",
                ["knownLimitations"] = new JsonArray(
                    "Blocked clients are excluded by the fixed onlyNonBlocked=true UI query.",
                    "All-time history is intentionally unavailable; the action accepts only bounded Network UI windows.",
                    "MAC-less TELEPORT pseudo-client records are counted and suppressed because the connector cannot safely join them to MAC-keyed client history.",
                    "Configured group membership does not prove current connection, VLAN, topology, firewall policy, ownership, or a history observation.",
                    "History records never overwrite or extend authoritative fields from the current connected-client overview."),
                ["observedAt"] = observedAt.ToString("O", CultureInfo.InvariantCulture)
            }
        };

        return new ToolResponse(
            $"Read {connected.Length} currently connected client(s), {offline.Length} offline record(s) within {historyHours} hours, and {groupMembersWithoutHistory.Length} configured group-member MAC(s) without current or history records.",
            result);
    }

    private async Task<ConnectedReadResult> ReadConnectedClientsAsync(
        string siteId,
        CancellationToken cancellationToken)
    {
        var contract = _contracts.Current;
        var operation = contract.GetOperation(ConnectedClientOperationId, requireRead: true);
        var records = new List<ConnectedClient>();
        var seenMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var duplicateMacCount = 0;
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
            if (response is not JsonObject responseObject ||
                responseObject["data"] is not JsonArray page)
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

                var macAddress = ReadRequiredMac(record, "macAddress", "official connected-client");
                if (!seenMacs.Add(macAddress))
                {
                    duplicateMacCount++;
                    continue;
                }

                var nameSource = FirstTextSource(record, "name", "hostname");
                var name = nameSource.Value ?? macAddress;
                var ipSource = FirstTextSource(record, "ipAddress");
                var ipAddress = ValidateOptionalIp(ipSource.Value, "official connected-client ipAddress");
                records.Add(new ConnectedClient(
                    SanitizeText(name),
                    nameSource.Name ?? "macAddress",
                    macAddress,
                    ipAddress,
                    ipAddress is null ? null : ipSource.Name,
                    ReadOptionalTimestamp(record, "connectedAt")));
            }

            var pageMetadata = ValidateConnectedPageMetadata(
                responseObject,
                page,
                offset,
                ConnectedClientPageSize);
            if (pageMetadata.TotalCount > MaximumConnectedClients)
            {
                throw new ContractException(
                    $"Official connected-client totalCount exceeded the safety limit of {MaximumConnectedClients} records.");
            }

            if (page.Count == 0 && pageMetadata.TotalCount > offset)
            {
                throw new ContractException(
                    "Official connected-client pagination ended before the declared totalCount.");
            }

            offset += page.Count;
            if (offset >= pageMetadata.TotalCount)
            {
                return new ConnectedReadResult(records, duplicateMacCount);
            }
        }

        throw new ContractException(
            $"Connected-client history classification exceeded the safety limit of {MaximumConnectedClients} records.");
    }

    private IReadOnlyList<HistoryClient> ProjectHistory(
        JsonNode? response,
        int historyHours,
        DateTimeOffset observedAt)
    {
        var sourceRecords = PrivateReadResponseParser.ReadRecords(response);
        if (sourceRecords.Count > MaximumHistoryRecords)
        {
            throw new ContractException(
                $"Private UniFi client-history response exceeded the safety limit of {MaximumHistoryRecords} records.");
        }

        var records = new List<HistoryClient>();
        var seenMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in sourceRecords)
        {
            var macAddress = ReadRequiredMac(source, "mac", "private client-history");
            if (!seenMacs.Add(macAddress))
            {
                throw new ContractException(
                    "Private UniFi client-history response included duplicate MAC addresses.");
            }

            var nameSource = FirstTextSource(source, "name", "display_name", "hostname");
            var name = nameSource.Value ?? macAddress;
            var ipSource = FirstTextSource(source, "ip", "last_ip");
            var ipAddress = ValidateOptionalIp(ipSource.Value, "private client-history IP address");
            var (lastSeenAt, lastSeenEpochSeconds) = ReadLastSeen(
                source,
                historyHours,
                observedAt);
            records.Add(new HistoryClient(
                SanitizeText(name),
                nameSource.Name ?? "mac",
                macAddress,
                ipAddress,
                ipAddress is null ? null : ipSource.Name,
                lastSeenAt?.ToString("O", CultureInfo.InvariantCulture),
                lastSeenEpochSeconds));
        }

        return records;
    }

    private IReadOnlyList<ClientGroup> ProjectGroups(JsonNode? response)
    {
        var sourceRecords = PrivateReadResponseParser.ReadRecords(response);
        if (sourceRecords.Count > MaximumGroups)
        {
            throw new ContractException(
                $"Private UniFi client-group response exceeded the safety limit of {MaximumGroups} groups.");
        }

        var groups = new List<ClientGroup>();
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        var uniqueMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var totalMemberships = 0;
        foreach (var source in sourceRecords)
        {
            var id = ReadOptionalText(source, "id")
                ?? throw new ContractException("Private UniFi client-group record did not include id.");
            if (!GroupIdPattern().IsMatch(id) || !seenIds.Add(id))
            {
                throw new ContractException("Private UniFi client-group response included an invalid or duplicate id.");
            }

            var name = ReadOptionalText(source, "name")
                ?? throw new ContractException($"Private UniFi client-group '{id}' did not include name.");
            var type = ReadOptionalText(source, "type")
                ?? throw new ContractException($"Private UniFi client-group '{id}' did not include type.");
            if (!string.Equals(type, "CLIENTS", StringComparison.Ordinal))
            {
                throw new ContractException(
                    $"Private UniFi client-group '{id}' had an unsupported type.");
            }

            if (source["members"] is not JsonArray members)
            {
                throw new ContractException($"Private UniFi client-group '{id}' did not include a members array.");
            }

            if (members.Count > MaximumMembersPerGroup)
            {
                throw new ContractException(
                    $"Private UniFi client-group '{id}' exceeded the member safety limit.");
            }

            totalMemberships = checked(totalMemberships + members.Count);
            if (totalMemberships > MaximumTotalGroupMemberships)
            {
                throw new ContractException(
                    $"Private UniFi client-group response exceeded the safety limit of {MaximumTotalGroupMemberships} total memberships.");
            }

            var normalizedMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var member in members)
            {
                if (member is not JsonValue scalar ||
                    !scalar.TryGetValue<string>(out var text) ||
                    !MacAddressPattern().IsMatch(text.Trim()))
                {
                    throw new ContractException(
                        $"Private UniFi client-group '{id}' included a non-MAC member value.");
                }

                var mac = text.Trim().ToLowerInvariant();
                normalizedMembers.Add(mac);
                uniqueMembers.Add(mac);
            }

            groups.Add(new ClientGroup(
                id,
                SanitizeText(name),
                normalizedMembers.OrderBy(value => value, StringComparer.Ordinal).ToArray()));
        }

        if (uniqueMembers.Count > MaximumUniqueGroupMembers)
        {
            throw new ContractException(
                $"Private UniFi client-group response exceeded the safety limit of {MaximumUniqueGroupMembers} unique members.");
        }

        return groups;
    }

    private JsonObject ProjectConnected(ConnectedClient client, IReadOnlyList<ClientGroup> groups)
    {
        var nameAuthority = client.NameSourceField == "macAddress"
            ? "fallback-identifier"
            : "authoritative-current";
        var provenance = new JsonObject
        {
            ["name"] = FieldProvenance(
                "official-network-integration-api",
                client.NameSourceField,
                nameAuthority),
            ["macAddress"] = FieldProvenance(
                "official-network-integration-api",
                "macAddress",
                "authoritative-current"),
            ["state"] = FieldProvenance(
                "official-network-integration-api",
                "presence in getConnectedClientOverviewPage",
                "authoritative-current"),
            ["classification"] = FieldProvenance(
                "connector-classification",
                "presence in official current overview",
                "derived"),
            ["groups"] = FieldProvenance(
                "private-v2-network-members-groups-api",
                "members joined by macAddress",
                "configured-membership")
        };
        provenance["ipAddress"] = client.IpAddress is not null
            ? FieldProvenance(
                "official-network-integration-api",
                client.IpSourceField!,
                "authoritative-current")
            : UnavailableFieldProvenance(
                "official-network-integration-api",
                "ipAddress",
                "The official current-client record did not include an IP address.");
        provenance["connectedAt"] = client.ConnectedAt is not null
            ? FieldProvenance(
                "official-network-integration-api",
                "connectedAt",
                "authoritative-current")
            : UnavailableFieldProvenance(
                "official-network-integration-api",
                "connectedAt",
                "The official current-client record did not include a connection timestamp.");
        provenance["lastSeenAt"] = UnavailableFieldProvenance(
            "official-network-integration-api",
            "not exposed by getConnectedClientOverviewPage",
            "The authoritative current-client overview does not expose historical last-seen evidence.");

        return new JsonObject
        {
            ["name"] = client.Name,
            ["macAddress"] = client.MacAddress,
            ["ipAddress"] = client.IpAddress,
            ["state"] = "online",
            ["classification"] = "currentlyConnected",
            ["connectedAt"] = client.ConnectedAt,
            ["lastSeenAt"] = null,
            ["groups"] = ProjectGroupReferences(groups),
            ["fieldProvenance"] = provenance
        };
    }

    private JsonObject ProjectOffline(HistoryClient client, IReadOnlyList<ClientGroup> groups)
    {
        var nameAuthority = client.NameSourceField == "mac"
            ? "fallback-identifier"
            : "historical";
        var provenance = new JsonObject
        {
            ["name"] = FieldProvenance(
                "private-v2-client-history-api",
                client.NameSourceField,
                nameAuthority),
            ["macAddress"] = FieldProvenance(
                "private-v2-client-history-api",
                "mac",
                "historical-join-key"),
            ["state"] = FieldProvenance(
                "connector-classification",
                "absent from current official overview and present in bounded history",
                "derived"),
            ["classification"] = FieldProvenance(
                "connector-classification",
                "absent from current official overview and present in bounded history",
                "derived"),
            ["groups"] = FieldProvenance(
                "private-v2-network-members-groups-api",
                "members joined by mac",
                "configured-membership")
        };
        provenance["ipAddress"] = client.IpAddress is not null
            ? FieldProvenance(
                "private-v2-client-history-api",
                client.IpSourceField!,
                "historical")
            : UnavailableFieldProvenance(
                "private-v2-client-history-api",
                "ip or last_ip",
                "The bounded history record did not include an IP address.");
        provenance["lastSeenAt"] = client.LastSeenAt is not null
            ? FieldProvenance(
                "private-v2-client-history-api",
                "last_seen",
                "historical-evidence")
            : UnavailableFieldProvenance(
                "private-v2-client-history-api",
                "last_seen",
                "The bounded history record did not include last-seen evidence.");

        return new JsonObject
        {
            ["name"] = client.Name,
            ["macAddress"] = client.MacAddress,
            ["ipAddress"] = client.IpAddress,
            ["state"] = "offline",
            ["classification"] = "offlineWithinHistoryWindow",
            ["lastSeenAt"] = client.LastSeenAt,
            ["groups"] = ProjectGroupReferences(groups),
            ["fieldProvenance"] = provenance
        };
    }

    private static JsonObject ProjectGroupMemberWithoutHistory(
        string macAddress,
        IReadOnlyList<ClientGroup> groups) => new()
        {
            ["macAddress"] = macAddress,
            ["state"] = "unknown",
            ["classification"] = "configuredGroupMemberWithoutCurrentOrHistoryRecord",
            ["name"] = null,
            ["ipAddress"] = null,
            ["lastSeenAt"] = null,
            ["groups"] = ProjectGroupReferences(groups),
            ["fieldProvenance"] = new JsonObject
            {
                ["macAddress"] = FieldProvenance(
                    "private-v2-network-members-groups-api",
                    "members",
                    "configured-membership-join-key"),
                ["groups"] = FieldProvenance(
                    "private-v2-network-members-groups-api",
                    "id, name, members",
                    "configured-membership"),
                ["state"] = FieldProvenance(
                    "connector-classification",
                    "absent from current official overview and bounded history response",
                    "derived-unavailable"),
                ["classification"] = FieldProvenance(
                    "connector-classification",
                    "configured membership with no current or bounded-history record",
                    "derived"),
                ["name"] = UnavailableFieldProvenance(
                    "private-v2-network-members-groups-api",
                    "not available from configured membership",
                    "Configured membership supplies no client name."),
                ["ipAddress"] = UnavailableFieldProvenance(
                    "private-v2-network-members-groups-api",
                    "not available from configured membership",
                    "Configured membership supplies no IP address."),
                ["lastSeenAt"] = UnavailableFieldProvenance(
                    "private-v2-network-members-groups-api",
                    "not available from configured membership",
                    "Configured membership supplies no last-seen evidence.")
            }
        };

    private static JsonArray ProjectGroupReferences(IReadOnlyList<ClientGroup> groups) =>
        new(groups.Select(group => (JsonNode?)new JsonObject
        {
            ["id"] = group.Id,
            ["name"] = group.Name
        }).ToArray());

    private static JsonObject FieldProvenance(string source, string field, string authority) => new()
    {
        ["source"] = source,
        ["field"] = field,
        ["authority"] = authority,
        ["availability"] = "available"
    };

    private static JsonObject UnavailableFieldProvenance(string source, string field, string reason) => new()
    {
        ["source"] = source,
        ["field"] = field,
        ["authority"] = "unavailable",
        ["availability"] = "unavailable",
        ["reason"] = reason
    };

    private static void ValidateProjectedGroupReferences(
        IEnumerable<IReadOnlyList<ClientGroup>> connectedGroups,
        IEnumerable<IReadOnlyList<ClientGroup>> offlineGroups,
        IEnumerable<IReadOnlyList<ClientGroup>> missingGroups)
    {
        var total = connectedGroups
            .Concat(offlineGroups)
            .Concat(missingGroups)
            .Sum(groups => groups.Count);
        if (total > MaximumProjectedGroupReferences)
        {
            throw new ContractException(
                $"Projected client-history output exceeded the safety limit of {MaximumProjectedGroupReferences} group references.");
        }
    }

    private static JsonObject CreatePageMetadata(int total, int returned, int offset, int limit) => new()
    {
        ["totalCount"] = total,
        ["returnedCount"] = returned,
        ["truncated"] = IsPageTruncated(total, offset, limit),
        ["nextOffset"] = offset + returned < total ? offset + returned : null
    };

    private static bool IsPageTruncated(int total, int offset, int limit) =>
        offset > 0 || offset + limit < total;

    private static T[] Page<T>(IReadOnlyList<T> values, int offset, int limit) =>
        values.Skip(offset).Take(limit).ToArray();

    private static IReadOnlyList<ClientGroup> GetGroups(
        IReadOnlyDictionary<string, ClientGroup[]> groupsByMac,
        string macAddress) =>
        groupsByMac.TryGetValue(macAddress, out var groups)
            ? groups
            : Array.Empty<ClientGroup>();

    private static JsonObject CreateHistoryWindow(int historyHours, DateTimeOffset observedAt) => new()
    {
        ["requestedHours"] = historyHours,
        ["effectiveHours"] = historyHours,
        ["requestedStart"] = observedAt.AddHours(-historyHours).ToString("O", CultureInfo.InvariantCulture),
        ["effectiveStart"] = observedAt.AddHours(-historyHours).ToString("O", CultureInfo.InvariantCulture),
        ["effectiveEnd"] = observedAt.ToString("O", CultureInfo.InvariantCulture),
        ["bounded"] = true,
        ["allTimeAllowed"] = false
    };

    private static JsonObject MissingCount(int missingCount, int recordCount) => new()
    {
        ["status"] = missingCount == 0 ? "available" : "partiallyUnavailable",
        ["missingRecordCount"] = missingCount,
        ["recordCount"] = recordCount
    };

    private static ToolResponse CreateNotSupportedResponse(
        string siteId,
        int historyHours,
        int offset,
        int limit,
        DateTimeOffset observedAt,
        string reasonCode,
        string reason,
        string source,
        string? fixedResource,
        string? operationId,
        UnifiApiException? exception)
    {
        var metadata = new JsonObject
        {
            ["status"] = "notSupported",
            ["source"] = source,
            ["readOnly"] = true,
            ["httpMethod"] = "GET",
            ["rawPrivateResponsesReturned"] = false,
            ["reasonCode"] = reasonCode,
            ["reason"] = reason,
            ["pagination"] = new JsonObject
            {
                ["offset"] = offset,
                ["limit"] = limit,
                ["truncated"] = false
            },
            ["onlineCount"] = 0,
            ["offlineCount"] = 0,
            ["unavailableFields"] = new JsonObject
            {
                ["allClientFields"] = new JsonObject
                {
                    ["status"] = "unavailable",
                    ["reason"] = reason
                }
            },
            ["auditScope"] =
                "No client-history audit was returned because the fixed endpoint or its response contract was unavailable.",
            ["observedAt"] = observedAt.ToString("O", CultureInfo.InvariantCulture)
        };
        if (fixedResource is not null)
        {
            metadata["fixedResource"] = fixedResource;
        }
        if (operationId is not null)
        {
            metadata["operationId"] = operationId;
        }
        if (exception is not null)
        {
            metadata["httpStatus"] = (int)exception.StatusCode;
            metadata["controllerReasonCode"] = exception.Code;
        }

        var result = new JsonObject
        {
            ["siteId"] = siteId,
            ["historyWindow"] = CreateHistoryWindow(historyHours, observedAt),
            ["counts"] = new JsonObject
            {
                ["online"] = 0,
                ["offlineWithinWindow"] = 0,
                ["groupMembersWithoutHistory"] = 0
            },
            ["currentlyConnectedClients"] = new JsonArray(),
            ["offlineClientsWithinWindow"] = new JsonArray(),
            ["groupMembersWithoutHistory"] = new JsonArray(),
            ["_connector"] = metadata
        };
        return new ToolResponse(
            "Private UniFi client-history reads are not supported by this controller response; no client data was returned.",
            result);
    }

    private static bool IsUnsupportedResource(UnifiApiException exception) =>
        exception.StatusCode == HttpStatusCode.NotFound &&
        (string.IsNullOrWhiteSpace(exception.Code) ||
         string.Equals(exception.Code, "api.err.NotFound", StringComparison.Ordinal));

    private static (DateTimeOffset? Value, long? EpochSeconds) ReadLastSeen(
        JsonObject source,
        int historyHours,
        DateTimeOffset observedAt)
    {
        if (source["last_seen"] is null)
        {
            return (null, null);
        }

        if (!TryReadLong(source["last_seen"], out var epochSeconds) || epochSeconds <= 0)
        {
            throw new ContractException(
                "Private UniFi client-history last_seen was not a positive integer epoch timestamp.");
        }

        DateTimeOffset timestamp;
        try
        {
            timestamp = DateTimeOffset.FromUnixTimeSeconds(epochSeconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw new ContractException(
                "Private UniFi client-history last_seen was outside the supported timestamp range.");
        }

        if (timestamp > observedAt.AddMinutes(5))
        {
            throw new ContractException(
                "Private UniFi client-history last_seen was unexpectedly in the future.");
        }

        if (timestamp < observedAt.AddHours(-historyHours).AddMinutes(-5))
        {
            throw new ContractException(
                "Private UniFi client-history last_seen was outside the requested bounded window.");
        }

        return (timestamp, epochSeconds);
    }

    private static string ReadRequiredMac(JsonObject source, string field, string sourceName)
    {
        var text = ReadOptionalText(source, field);
        if (text is null || !MacAddressPattern().IsMatch(text))
        {
            throw new ContractException($"{sourceName} record did not include a valid {field} MAC address.");
        }

        return text.ToLowerInvariant();
    }

    private static string? ValidateOptionalIp(string? value, string sourceName)
    {
        if (value is null)
        {
            return null;
        }

        if (!IPAddress.TryParse(value, out var address) ||
            address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw new ContractException($"{sourceName} was not a valid IPv4 or IPv6 address.");
        }

        return address.ToString();
    }

    private string SanitizeText(string value)
    {
        var redacted = _redactor.Redact(value.Trim());
        return redacted.Length <= MaximumTextLength
            ? redacted
            : redacted[..MaximumTextLength] + "…";
    }

    private static (string? Name, string? Value) FirstTextSource(
        JsonObject source,
        params string[] fields)
    {
        foreach (var field in fields)
        {
            var value = ReadOptionalText(source, field);
            if (value is not null)
            {
                return (field, value);
            }
        }

        return (null, null);
    }

    private static string? ReadOptionalText(JsonObject source, params string[] fields)
    {
        foreach (var field in fields)
        {
            if (source[field] is JsonValue scalar &&
                scalar.TryGetValue<string>(out var text) &&
                !string.IsNullOrWhiteSpace(text))
            {
                return text.Trim();
            }
        }

        return null;
    }

    private static string? ReadOptionalTimestamp(JsonObject source, string field)
    {
        var text = ReadOptionalText(source, field);
        if (text is null)
        {
            return null;
        }

        if (!DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestamp))
        {
            throw new ContractException($"Official UniFi connected-client {field} was not an RFC3339 timestamp.");
        }

        return timestamp.ToString("O", CultureInfo.InvariantCulture);
    }

    private static ConnectedPageMetadata ValidateConnectedPageMetadata(
        JsonObject response,
        JsonArray page,
        int requestedOffset,
        int requestedLimit)
    {
        var count = ReadRequiredNonNegativeLong(response["count"], "count");
        var offset = ReadRequiredNonNegativeLong(response["offset"], "offset");
        var limit = ReadRequiredNonNegativeLong(response["limit"], "limit");
        var totalCount = ReadRequiredNonNegativeLong(response["totalCount"], "totalCount");

        if (count != page.Count)
        {
            throw new ContractException(
                "Official connected-client page count did not match the number of data records.");
        }
        if (offset != requestedOffset)
        {
            throw new ContractException(
                "Official connected-client page offset did not match the requested offset.");
        }
        if (limit != requestedLimit)
        {
            throw new ContractException(
                "Official connected-client page limit did not match the requested limit.");
        }
        if (totalCount < offset + count)
        {
            throw new ContractException(
                "Official connected-client totalCount was smaller than the returned page range.");
        }

        return new ConnectedPageMetadata(totalCount);
    }

    private static long ReadRequiredNonNegativeLong(JsonNode? value, string field)
    {
        if (value is not JsonValue scalar)
        {
            throw new ContractException(
                $"Official connected-client page did not include a valid nonnegative {field}.");
        }

        long number;
        if (!scalar.TryGetValue<long>(out number))
        {
            if (!scalar.TryGetValue<int>(out var integer))
            {
                throw new ContractException(
                    $"Official connected-client page did not include a valid nonnegative {field}.");
            }

            number = integer;
        }

        if (number < 0)
        {
            throw new ContractException(
                $"Official connected-client page did not include a valid nonnegative {field}.");
        }

        return number;
    }

    private static bool TryReadLong(JsonNode? value, out long result)
    {
        result = default;
        if (value is not JsonValue scalar)
        {
            return false;
        }

        if (scalar.TryGetValue<long>(out result))
        {
            return true;
        }

        if (scalar.TryGetValue<int>(out var integer))
        {
            result = integer;
            return true;
        }

        return false;
    }

    [GeneratedRegex("^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex MacAddressPattern();

    [GeneratedRegex("^[0-9a-fA-F]{24}$", RegexOptions.CultureInvariant)]
    private static partial Regex GroupIdPattern();

    private sealed record ConnectedReadResult(
        IReadOnlyList<ConnectedClient> Clients,
        int DuplicateMacCount);

    private sealed record ConnectedPageMetadata(long TotalCount);

    private sealed record ConnectedClient(
        string Name,
        string NameSourceField,
        string MacAddress,
        string? IpAddress,
        string? IpSourceField,
        string? ConnectedAt);

    private sealed record HistoryClient(
        string Name,
        string NameSourceField,
        string MacAddress,
        string? IpAddress,
        string? IpSourceField,
        string? LastSeenAt,
        long? LastSeenEpochSeconds);

    private sealed record ClientGroup(
        string Id,
        string Name,
        IReadOnlyList<string> Members);
}
