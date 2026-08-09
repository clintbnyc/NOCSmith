using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed partial class ClientTrafficReadService
{
    private const string TrafficResource =
        "v2/api/site/{site}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true";
    private const string ConnectedClientOperationId = "getConnectedClientOverviewPage";
    private const int DefaultLimit = 25;
    private const int MaximumLimit = 200;
    private const int ConnectedClientPageSize = 200;
    private const int MaximumConnectedClients = 2000;
    private const int MaximumPrivateClients = 5000;
    private const int MaximumTextLength = 4096;

    private readonly UnifiConfiguration _configuration;
    private readonly IUnifiClient _client;
    private readonly ContractProvider _contracts;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;
    private readonly TimeProvider _timeProvider;

    public ClientTrafficReadService(
        UnifiConfiguration configuration,
        IUnifiClient client,
        ContractProvider contracts,
        SiteResolver siteResolver,
        SecretRedactor redactor,
        TimeProvider? timeProvider = null)
    {
        _configuration = configuration;
        _client = client;
        _contracts = contracts;
        _siteResolver = siteResolver;
        _redactor = redactor;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public bool Enabled => _configuration.EnableLegacyReadEnrichment;

    public JsonObject Describe() => new()
    {
        ["enabled"] = Enabled,
        ["readOnly"] = true,
        ["authentication"] = "existing X-API-Key",
        ["fixedResource"] = TrafficResource,
        ["defaultLimit"] = DefaultLimit,
        ["maximumLimit"] = MaximumLimit,
        ["maximumConnectedClients"] = MaximumConnectedClients,
        ["maximumPrivateClients"] = MaximumPrivateClients,
        ["sortFields"] = new JsonArray("receivedBytes", "transmittedBytes", "combinedBytes"),
        ["rawPrivateResponsesReturned"] = false,
        ["redactionApplied"] = true
    };

    public async Task<ToolResponse> ReadAsync(
        string? requestedSiteId,
        string? sortBy,
        int? limit,
        string? clientMacAddress,
        CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            throw new ConfigurationException(
                "Client traffic reads are disabled. Set UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true to enable the fixed read-only active-client query.");
        }

        var effectiveSort = NormalizeSort(sortBy);
        var effectiveLimit = ValidateLimit(limit);
        var normalizedMac = string.IsNullOrWhiteSpace(clientMacAddress)
            ? null
            : NormalizeRequiredMac(clientMacAddress, "clientMacAddress");
        var siteId = await _siteResolver.ResolveAsync(requestedSiteId, cancellationToken).ConfigureAwait(false);
        var internalSiteReference = await _siteResolver
            .ResolveInternalReferenceAsync(siteId, cancellationToken)
            .ConfigureAwait(false);

        var officialTask = ReadConnectedClientsAsync(siteId, cancellationToken);
        var privateTask = ReadPrivateTrafficSafelyAsync(internalSiteReference, cancellationToken);
        await Task.WhenAll(officialTask, privateTask).ConfigureAwait(false);

        var officialClients = await officialTask.ConfigureAwait(false);
        var privateTraffic = await privateTask.ConfigureAwait(false);

        var observedAt = _timeProvider.GetUtcNow();
        var projected = officialClients
            .Where(client => normalizedMac is null ||
                string.Equals(client.MacAddress, normalizedMac, StringComparison.OrdinalIgnoreCase))
            .Select(client => ProjectClient(
                client,
                privateTraffic.Records.TryGetValue(client.MacAddress, out var traffic) ? traffic : null,
                privateTraffic.Status))
            .ToArray();
        var ranked = projected
            .OrderByDescending(client => ReadSortValue(client, effectiveSort).HasValue)
            .ThenByDescending(client => ReadSortValue(client, effectiveSort))
            .ThenBy(client => client["macAddress"]!.GetValue<string>(), StringComparer.Ordinal)
            .Take(effectiveLimit)
            .ToArray();
        var availableCount = projected.Count(client => ReadSortValue(client, effectiveSort).HasValue);

        var result = new JsonObject
        {
            ["clients"] = new JsonArray(ranked),
            ["_connector"] = new JsonObject
            {
                ["readOnly"] = true,
                ["sources"] = new JsonArray(
                    new JsonObject
                    {
                        ["kind"] = "official-network-integration-api",
                        ["operationId"] = ConnectedClientOperationId,
                        ["authority"] = "current connected-client membership and identity"
                    },
                    new JsonObject
                    {
                        ["kind"] = "private-v2-api",
                        ["fixedResource"] = TrafficResource,
                        ["authority"] = "current controller traffic counters",
                        ["status"] = privateTraffic.Status,
                        ["error"] = privateTraffic.Error
                    }),
                ["rawPrivateResponsesReturned"] = false,
                ["outputProjection"] = "explicit-allowlist",
                ["redactionApplied"] = true,
                ["observedAt"] = observedAt.ToString("O", CultureInfo.InvariantCulture),
                ["sortBy"] = effectiveSort,
                ["sortDirection"] = "descending-null-last",
                ["requestedLimit"] = effectiveLimit,
                ["totalConnectedClients"] = officialClients.Count,
                ["matchingConnectedClients"] = projected.Length,
                ["returnedClients"] = ranked.Length,
                ["clientsWithRequestedSortValue"] = availableCount,
                ["privateRecordsWithoutJoinKeySuppressed"] = privateTraffic.RecordsWithoutJoinKey,
                ["limits"] = new JsonObject
                {
                    ["connectedClients"] = MaximumConnectedClients,
                    ["privateSourceClients"] = MaximumPrivateClients,
                    ["returnedClients"] = MaximumLimit
                },
                ["counterSemantics"] =
                    "receivedBytes/rx_bytes and transmittedBytes/tx_bytes preserve the controller field direction at observation time. The controller observation perspective, reset, rollover, and accounting-window semantics are undocumented, so these values are not labelled upload or download; null means unavailable and zero is preserved as observed.",
                ["rateSemantics"] =
                    "receivedBytesPerSecond and transmittedBytesPerSecond are unavailable. The private rx_bytes-r and tx_bytes-r perspective, unit, and sampling window are not verified, so their values are not projected and no rate is derived from counters.",
                ["versionDriftBehavior"] =
                    "Known counter fields are projected. A missing or unsupported private source, or missing, malformed, negative, or out-of-range fields, produces null values rather than inferred data.",
                ["limitations"] = new JsonArray(
                    "Traffic fields are private and may vary by Network application version.",
                    "Controller rx/tx direction is not normalized to client upload/download without verified source-perspective semantics.",
                    "A current observation is not a historical usage interval and must not be used to infer past bandwidth consumption.",
                    "Only clients present in the complete bounded official connected-client inventory are returned; private-only records never create connected clients.")
            }
        };

        return new ToolResponse(
            $"Returned {ranked.Length} of {projected.Length} currently connected client(s), ranked by {effectiveSort}; {availableCount} had that value available.",
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
        long? expectedTotalCount = null;

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
            if (response is not JsonObject responseObject || responseObject["data"] is not JsonArray page)
            {
                throw new ContractException("Official UniFi connected-client query did not return a data array.");
            }

            var declaredOffset = ReadRequiredNonNegativeInteger(responseObject, "offset");
            var declaredLimit = ReadRequiredNonNegativeInteger(responseObject, "limit");
            var declaredCount = ReadRequiredNonNegativeInteger(responseObject, "count");
            var totalCount = ReadRequiredNonNegativeInteger(responseObject, "totalCount");
            if (declaredOffset != offset ||
                declaredLimit != ConnectedClientPageSize ||
                declaredCount != page.Count ||
                totalCount < offset + page.Count ||
                (expectedTotalCount is not null && totalCount != expectedTotalCount))
            {
                throw new ContractException("Official connected-client pagination metadata was contradictory.");
            }

            expectedTotalCount ??= totalCount;

            if (totalCount > MaximumConnectedClients)
            {
                throw new ContractException(
                    $"Official connected-client totalCount exceeded the safety limit of {MaximumConnectedClients} records.");
            }

            for (var index = 0; index < page.Count; index++)
            {
                if (page[index] is not JsonObject record)
                {
                    throw new ContractException(
                        $"Official connected-client query returned a non-object record at index {index}.");
                }

                var mac = NormalizeRequiredMac(ReadRequiredText(record, "macAddress"), "official macAddress");
                if (!seenMacs.Add(mac))
                {
                    continue;
                }

                var idText = ReadOptionalText(record, "id");
                var id = Guid.TryParse(idText, out var parsedId) ? parsedId.ToString() : null;
                var name = ReadOptionalText(record, "name") ?? ReadOptionalText(record, "hostname") ?? mac;
                records.Add(new ConnectedClient(id, SanitizeText(name), mac));
            }

            if (page.Count == 0 && totalCount > offset)
            {
                throw new ContractException(
                    "Official connected-client pagination ended before the declared totalCount.");
            }

            offset += page.Count;
            if (offset >= totalCount)
            {
                return records;
            }
        }

        throw new ContractException(
            $"Official connected-client inventory exceeded the safety limit of {MaximumConnectedClients} records.");
    }

    private async Task<PrivateTrafficInventory> ReadPrivateTrafficSafelyAsync(
        string internalSiteReference,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await _client.ReadPrivateClientsAsync(internalSiteReference, cancellationToken)
                .ConfigureAwait(false);
            var privateRecords = PrivateReadResponseParser.ReadRecords(response);
            if (privateRecords.Count > MaximumPrivateClients)
            {
                throw new ContractException(
                    $"Private UniFi active-client response exceeded the safety limit of {MaximumPrivateClients} records.");
            }

            var records = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
            var recordsWithoutJoinKey = 0;
            foreach (var privateRecord in privateRecords)
            {
                var mac = ReadMac(privateRecord);
                if (mac is null)
                {
                    recordsWithoutJoinKey++;
                    continue;
                }

                if (!records.TryAdd(mac, privateRecord))
                {
                    throw new ContractException(
                        "Private UniFi active-client response contained duplicate MAC addresses.");
                }
            }

            return new PrivateTrafficInventory(records, "ok", null, recordsWithoutJoinKey);
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is UnifiApiException or
            ContractException or
            HttpRequestException or
            TaskCanceledException or
            InvalidOperationException or
            NotSupportedException)
        {
            return new PrivateTrafficInventory(
                new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase),
                "unavailable",
                _redactor.Redact(exception.Message),
                0);
        }
    }

    private JsonObject ProjectClient(
        ConnectedClient client,
        JsonObject? privateRecord,
        string privateSourceStatus)
    {
        var receivedBytes = ReadNonNegativeInt64(privateRecord, "rx_bytes");
        var transmittedBytes = ReadNonNegativeInt64(privateRecord, "tx_bytes");
        var receivedPackets = ReadNonNegativeInt64(privateRecord, "rx_packets");
        var transmittedPackets = ReadNonNegativeInt64(privateRecord, "tx_packets");
        var combinedBytes = AddIfComplete(receivedBytes, transmittedBytes);

        return new JsonObject
        {
            ["id"] = client.Id,
            ["name"] = client.Name,
            ["macAddress"] = client.MacAddress,
            ["receivedBytes"] = receivedBytes,
            ["transmittedBytes"] = transmittedBytes,
            ["combinedBytes"] = combinedBytes,
            ["receivedPackets"] = receivedPackets,
            ["transmittedPackets"] = transmittedPackets,
            ["receivedBytesPerSecond"] = null,
            ["transmittedBytesPerSecond"] = null,
            ["usageWindow"] = null,
            ["fieldProvenance"] = new JsonObject
            {
                ["identity"] = "official-network-integration-api:getConnectedClientOverviewPage",
                ["receivedBytes"] = CreateFieldProvenance(privateRecord, privateSourceStatus, "rx_bytes", receivedBytes),
                ["transmittedBytes"] = CreateFieldProvenance(privateRecord, privateSourceStatus, "tx_bytes", transmittedBytes),
                ["combinedBytes"] = combinedBytes is null
                    ? CreateUnavailableProvenance("derived from rx_bytes + tx_bytes only when both counters are available")
                    : new JsonObject
                    {
                        ["available"] = true,
                        ["source"] = "connector-derived",
                        ["sourceField"] = "rx_bytes + tx_bytes"
                    },
                ["receivedPackets"] = CreateFieldProvenance(privateRecord, privateSourceStatus, "rx_packets", receivedPackets),
                ["transmittedPackets"] = CreateFieldProvenance(privateRecord, privateSourceStatus, "tx_packets", transmittedPackets),
                ["receivedBytesPerSecond"] = CreateUnavailableProvenance(
                    "rx_bytes-r is suppressed because its perspective, unit, and sampling window are not verified"),
                ["transmittedBytesPerSecond"] = CreateUnavailableProvenance(
                    "tx_bytes-r is suppressed because its perspective, unit, and sampling window are not verified"),
                ["usageWindow"] = CreateUnavailableProvenance(
                    "the fixed active-client response does not provide a verified counter window")
            }
        };
    }

    private static JsonObject CreateFieldProvenance(
        JsonObject? source,
        string sourceStatus,
        string sourceField,
        object? projectedValue) => projectedValue is null
        ? CreateUnavailableProvenance(
            sourceStatus != "ok"
                ? "the optional private traffic source was unavailable"
                : source is null
                ? "no private record matched this official connected client"
                : $"{sourceField} was absent, malformed, negative, or out of range")
        : new JsonObject
        {
            ["available"] = true,
            ["source"] = "private-v2-api",
            ["sourceField"] = sourceField
        };

    private static JsonObject CreateUnavailableProvenance(string reason) => new()
    {
        ["available"] = false,
        ["status"] = "unavailable",
        ["reason"] = reason
    };

    private static long? AddIfComplete(long? left, long? right)
    {
        if (left is null || right is null || left > long.MaxValue - right)
        {
            return null;
        }

        return left.Value + right.Value;
    }

    private static long? ReadSortValue(JsonObject client, string sortBy) =>
        client[sortBy] is JsonValue value && value.TryGetValue<long>(out var result) ? result : null;

    private static string NormalizeSort(string? sortBy)
    {
        var value = string.IsNullOrWhiteSpace(sortBy) ? "combinedBytes" : sortBy.Trim();
        return value.ToLowerInvariant() switch
        {
            "received" or "receivedbytes" or "rx" => "receivedBytes",
            "transmitted" or "transmittedbytes" or "tx" => "transmittedBytes",
            "combined" or "combinedbytes" => "combinedBytes",
            _ => throw new ContractException(
                "sortBy must be receivedBytes, transmittedBytes, or combinedBytes.")
        };
    }

    private static int ValidateLimit(int? requested)
    {
        var value = requested ?? DefaultLimit;
        if (value is < 1 or > MaximumLimit)
        {
            throw new ContractException($"limit must be between 1 and {MaximumLimit}.");
        }

        return value;
    }

    private static long? ReadNonNegativeInt64(JsonObject? source, string field)
    {
        if (source?[field] is not JsonValue value)
        {
            return null;
        }

        if (value.TryGetValue<long>(out var integer))
        {
            return integer >= 0 ? integer : null;
        }

        if (value.TryGetValue<int>(out var intValue))
        {
            return intValue >= 0 ? intValue : null;
        }

        if (value.TryGetValue<decimal>(out var number) &&
            number >= 0 &&
            number <= long.MaxValue &&
            decimal.Truncate(number) == number)
        {
            return decimal.ToInt64(number);
        }

        return value.TryGetValue<string>(out var text) &&
               long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out integer) &&
               integer >= 0
            ? integer
            : null;
    }

    private static long ReadRequiredNonNegativeInteger(JsonObject source, string field)
    {
        var value = ReadNonNegativeInt64(source, field);
        return value ?? throw new ContractException(
            $"Official connected-client pagination field '{field}' was missing or invalid.");
    }

    private static string ReadRequiredText(JsonObject source, string field) =>
        ReadOptionalText(source, field) ?? throw new ContractException(
            $"Official connected-client record did not include {field}.");

    private static string? ReadOptionalText(JsonObject source, string field) =>
        source[field] is JsonValue value &&
        value.TryGetValue<string>(out var text) &&
        !string.IsNullOrWhiteSpace(text)
            ? text.Trim()
            : null;

    private static string? ReadMac(JsonObject source)
    {
        foreach (var field in new[] { "mac", "macAddress" })
        {
            var value = ReadOptionalText(source, field);
            if (value is not null && MacAddressPattern().IsMatch(value))
            {
                return value.ToLowerInvariant();
            }
        }

        return null;
    }

    private static string NormalizeRequiredMac(string value, string field)
    {
        var normalized = value.Trim().ToLowerInvariant();
        if (!MacAddressPattern().IsMatch(normalized))
        {
            throw new ContractException($"{field} must be a colon-delimited MAC address.");
        }

        return normalized;
    }

    private string SanitizeText(string value)
    {
        var redacted = _redactor.Redact(value.Trim());
        return redacted.Length <= MaximumTextLength
            ? redacted
            : redacted[..MaximumTextLength] + "…";
    }

    [GeneratedRegex("^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$", RegexOptions.CultureInvariant)]
    private static partial Regex MacAddressPattern();

    private sealed record ConnectedClient(string? Id, string Name, string MacAddress);

    private sealed record PrivateTrafficInventory(
        IReadOnlyDictionary<string, JsonObject> Records,
        string Status,
        string? Error,
        int RecordsWithoutJoinKey);
}
