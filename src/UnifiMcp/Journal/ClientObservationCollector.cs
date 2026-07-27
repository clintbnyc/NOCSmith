using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Journal;

public interface IClientJournalClock
{
    DateTimeOffset UtcNow { get; }
}

public interface IClientCollectionIdGenerator
{
    string Create();
}

public sealed class SystemClientJournalClock : IClientJournalClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

public sealed class GuidClientCollectionIdGenerator : IClientCollectionIdGenerator
{
    public string Create() => Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture);
}

public sealed partial class ClientObservationCollector
{
    public static readonly int[] SupportedHistoryHours = { 24, 72, 168, 336, 720, 4320 };

    private const string ConnectedOperationId = "getConnectedClientOverviewPage";
    private const int ConnectedPageSize = 200;
    private const int MaximumConnectedClients = 2000;
    private const int MaximumHistoryRecords = 10000;
    private const int MaximumGroups = 500;
    private const int MaximumMembersPerGroup = 5000;
    private const int MaximumTotalMemberships = 10000;
    private const int MaximumUniqueMembers = 10000;
    private const int MaximumTextLength = 512;

    private readonly UnifiConfiguration _configuration;
    private readonly IUnifiClient _client;
    private readonly ContractProvider _contracts;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;
    private readonly IClientJournalClock _clock;
    private readonly IClientCollectionIdGenerator _ids;

    public ClientObservationCollector(
        UnifiConfiguration configuration,
        IUnifiClient client,
        ContractProvider contracts,
        SiteResolver siteResolver,
        SecretRedactor redactor,
        IClientJournalClock clock,
        IClientCollectionIdGenerator ids)
    {
        _configuration = configuration;
        _client = client;
        _contracts = contracts;
        _siteResolver = siteResolver;
        _redactor = redactor;
        _clock = clock;
        _ids = ids;
    }

    public async Task<ClientObservationCollection> CollectAsync(
        string? requestedSiteId,
        int? requestedHistoryHours,
        CancellationToken cancellationToken) =>
        await CollectCoreAsync(
                requestedSiteId,
                requestedHistoryHours,
                requireJournalGate: true,
                cancellationToken)
            .ConfigureAwait(false);

    public async Task<ClientObservationCollection> CollectForHistoryAsync(
        string? requestedSiteId,
        int? requestedHistoryHours,
        CancellationToken cancellationToken) =>
        await CollectCoreAsync(
                requestedSiteId,
                requestedHistoryHours,
                requireJournalGate: false,
                cancellationToken)
            .ConfigureAwait(false);

    private async Task<ClientObservationCollection> CollectCoreAsync(
        string? requestedSiteId,
        int? requestedHistoryHours,
        bool requireJournalGate,
        CancellationToken cancellationToken)
    {
        if (requireJournalGate && !_configuration.EnableClientJournal)
        {
            throw new ConfigurationException(
                "The client observation journal is disabled. Set UNIFI_ENABLE_CLIENT_JOURNAL=true.");
        }

        if (!_configuration.EnableLegacyReadEnrichment)
        {
            throw new ConfigurationException(
                "Explicit collection requires UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true because it uses fixed private read-only sources.");
        }

        var historyHours = requestedHistoryHours ?? 24;
        if (!SupportedHistoryHours.Contains(historyHours))
        {
            throw new ContractException(
                "historyHours must be one of 24, 72, 168, 336, 720, or 4320.");
        }

        var startedAt = _clock.UtcNow;
        var siteId = await _siteResolver.ResolveAsync(requestedSiteId, cancellationToken)
            .ConfigureAwait(false);
        var internalSiteReference = await _siteResolver
            .ResolveInternalReferenceAsync(siteId, cancellationToken)
            .ConfigureAwait(false);

        var history = await CollectHistoryAsync(
                internalSiteReference,
                historyHours,
                startedAt,
                cancellationToken)
            .ConfigureAwait(false);
        SourceCollection<NormalizedClientObservation> connected;
        SourceCollection<NormalizedClientGroup> groups;
        if (!requireJournalGate &&
            history.Status != CollectionSourceStatus.Complete)
        {
            connected = NotAttempted<NormalizedClientObservation>(
                ClientObservationSource.OfficialConnected);
            groups = NotAttempted<NormalizedClientGroup>(
                ClientObservationSource.ConfiguredGroups);
        }
        else
        {
            connected = await CollectConnectedAsync(siteId, cancellationToken)
                .ConfigureAwait(false);
            groups = !requireJournalGate &&
                connected.Status != CollectionSourceStatus.Complete
                    ? NotAttempted<NormalizedClientGroup>(
                        ClientObservationSource.ConfiguredGroups)
                    : await CollectGroupsAsync(internalSiteReference, cancellationToken)
                        .ConfigureAwait(false);
        }

        return new ClientObservationCollection(
            _ids.Create(),
            siteId,
            historyHours,
            startedAt,
            _clock.UtcNow,
            connected,
            history,
            groups);
    }

    private async Task<SourceCollection<NormalizedClientObservation>> CollectConnectedAsync(
        string siteId,
        CancellationToken cancellationToken)
    {
        var records = new List<NormalizedClientObservation>();
        var seenMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var duplicateMacsSuppressed = 0;
        try
        {
            var contract = _contracts.Current;
            var operation = contract.GetOperation(ConnectedOperationId, requireRead: true);
            var offset = 0;
            while (offset < MaximumConnectedClients)
            {
                var request = contract.ValidateAndBuild(
                    operation,
                    new Dictionary<string, string> { ["siteId"] = siteId },
                    new Dictionary<string, string>
                    {
                        ["offset"] = offset.ToString(CultureInfo.InvariantCulture),
                        ["limit"] = ConnectedPageSize.ToString(CultureInfo.InvariantCulture)
                    },
                    null);
                var response = await _client.ReadAsync(request, cancellationToken)
                    .ConfigureAwait(false);
                if (response is not JsonObject responseObject ||
                    responseObject["data"] is not JsonArray page)
                {
                    throw new ContractException(
                        "Official connected-client response did not contain a data array.");
                }

                var total = ValidatePage(responseObject, page, offset);
                foreach (var item in page)
                {
                    if (item is not JsonObject source)
                    {
                        throw new ContractException(
                            "Official connected-client response contained a non-object record.");
                    }

                    var mac = ReadMac(source, "macAddress", "official connected-client");
                    if (!seenMacs.Add(mac))
                    {
                        duplicateMacsSuppressed++;
                        continue;
                    }

                    var name = FirstText(source, "name", "hostname");
                    var ip = FirstText(source, "ipAddress");
                    var connectedAt = ReadRfc3339Milliseconds(source, "connectedAt");
                    records.Add(new NormalizedClientObservation(
                        mac,
                        Sanitize(name.Value ?? mac),
                        NormalizeIp(ip.Value, "official connected-client IP address"),
                        "online",
                        connectedAt,
                        null,
                        new[]
                        {
                            Evidence("name", name.Name ?? "macAddress",
                                name.Value is null ? "fallback-identifier" : "authoritative-current",
                                available: true),
                            Evidence("macAddress", "macAddress", "authoritative-current", true),
                            Evidence("ipAddress", ip.Name ?? "ipAddress", "authoritative-current", ip.Value is not null),
                            Evidence("state", "presence in getConnectedClientOverviewPage", "authoritative-current", true),
                            Evidence("connectedAt", "connectedAt", "authoritative-current", connectedAt is not null),
                            Evidence("lastSeenAt", "not exposed", "unavailable", false)
                        }));
                }

                offset += page.Count;
                if (offset >= total)
                {
                    return Complete(
                        ClientObservationSource.OfficialConnected,
                        records,
                        duplicateMacsSuppressed);
                }

                if (page.Count == 0)
                {
                    throw new ContractException(
                        "Official connected-client pagination ended before totalCount.");
                }
            }

            throw new ContractException(
                $"Official connected-client records exceeded {MaximumConnectedClients}.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsSourceFailure(exception))
        {
            return Incomplete(
                ClientObservationSource.OfficialConnected,
                records,
                SourceErrorCode(exception),
                "The official connected-client source was unavailable or failed validation.",
                exception,
                duplicateMacsSuppressed);
        }
    }

    private async Task<SourceCollection<NormalizedClientObservation>> CollectHistoryAsync(
        string internalSiteReference,
        int historyHours,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken)
    {
        var records = new List<NormalizedClientObservation>();
        try
        {
            var response = await _client
                .ReadClientHistoryAsync(internalSiteReference, historyHours, cancellationToken)
                .ConfigureAwait(false);
            var sourceRecords = PrivateReadResponseParser.ReadRecords(response);
            if (sourceRecords.Count > MaximumHistoryRecords)
            {
                throw new ContractException(
                    $"Private client-history records exceeded {MaximumHistoryRecords}.");
            }

            var seenMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var source in sourceRecords)
            {
                var mac = ReadMac(source, "mac", "private client-history");
                if (!seenMacs.Add(mac))
                {
                    throw new ContractException(
                        "Private client-history response contained duplicate MAC addresses.");
                }

                var name = FirstText(source, "name", "display_name", "hostname");
                var ip = FirstText(source, "ip", "last_ip");
                var lastSeen = ReadLastSeenMilliseconds(source, historyHours, observedAt);
                records.Add(new NormalizedClientObservation(
                    mac,
                    Sanitize(name.Value ?? mac),
                    NormalizeIp(ip.Value, "private client-history IP address"),
                    "historyEvidence",
                    null,
                    lastSeen,
                    new[]
                    {
                        Evidence("name", name.Name ?? "mac",
                            name.Value is null ? "fallback-identifier" : "historical",
                            true),
                        Evidence("macAddress", "mac", "historical-join-key", true),
                        Evidence("ipAddress", ip.Name ?? "ip or last_ip", "historical", ip.Value is not null),
                        Evidence("state", "presence in bounded UI history", "positive-evidence-only", true),
                        Evidence("connectedAt", "not exposed", "unavailable", false),
                        Evidence("lastSeenAt", "last_seen", "historical-evidence", lastSeen is not null)
                    }));
            }

            return Complete(ClientObservationSource.UiHistory, records);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsSourceFailure(exception))
        {
            return Incomplete(
                ClientObservationSource.UiHistory,
                records,
                SourceErrorCode(exception),
                "The bounded UI-history source was unavailable or failed validation.",
                exception);
        }
    }

    private async Task<SourceCollection<NormalizedClientGroup>> CollectGroupsAsync(
        string internalSiteReference,
        CancellationToken cancellationToken)
    {
        var records = new List<NormalizedClientGroup>();
        try
        {
            var response = await _client
                .ReadNetworkMembersGroupsAsync(internalSiteReference, cancellationToken)
                .ConfigureAwait(false);
            var sourceRecords = PrivateReadResponseParser.ReadRecords(response);
            if (sourceRecords.Count > MaximumGroups)
            {
                throw new ContractException(
                    $"Private client-group records exceeded {MaximumGroups}.");
            }

            var ids = new HashSet<string>(StringComparer.Ordinal);
            var uniqueMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var totalMemberships = 0;
            foreach (var source in sourceRecords)
            {
                var id = ReadText(source, "id");
                if (!GroupIdPattern().IsMatch(id) || !ids.Add(id))
                {
                    throw new ContractException(
                        "Private client-group response contained an invalid or duplicate ID.");
                }

                var type = ReadText(source, "type");
                if (!string.Equals(type, "CLIENTS", StringComparison.Ordinal))
                {
                    throw new ContractException(
                        "Private client-group response contained a non-CLIENTS group.");
                }

                if (source["members"] is not JsonArray members ||
                    members.Count > MaximumMembersPerGroup)
                {
                    throw new ContractException(
                        "Private client-group members were missing or exceeded the safety limit.");
                }

                totalMemberships = checked(totalMemberships + members.Count);
                if (totalMemberships > MaximumTotalMemberships)
                {
                    throw new ContractException(
                        "Private group memberships exceeded the aggregate safety limit.");
                }

                var normalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var member in members)
                {
                    if (member is not JsonValue scalar ||
                        !scalar.TryGetValue<string>(out var value) ||
                        !MacAddressPattern().IsMatch(value.Trim()))
                    {
                        throw new ContractException(
                            "Private client-group response contained an invalid member MAC.");
                    }

                    var mac = value.Trim().ToLowerInvariant();
                    normalized.Add(mac);
                    uniqueMembers.Add(mac);
                    if (uniqueMembers.Count > MaximumUniqueMembers)
                    {
                        throw new ContractException(
                            "Private group memberships exceeded the unique-member safety limit.");
                    }
                }

                records.Add(new NormalizedClientGroup(
                    id,
                    Sanitize(ReadText(source, "name")),
                    normalized.OrderBy(value => value, StringComparer.Ordinal).ToArray()));
            }

            return Complete(ClientObservationSource.ConfiguredGroups, records);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsSourceFailure(exception))
        {
            return Incomplete(
                ClientObservationSource.ConfiguredGroups,
                records,
                SourceErrorCode(exception),
                "The configured client-group source was unavailable or failed validation.",
                exception);
        }
    }

    private static SourceCollection<T> Complete<T>(
        ClientObservationSource source,
        IReadOnlyList<T> records,
        int duplicateRecordsSuppressed = 0) =>
        new(
            source,
            CollectionSourceStatus.Complete,
            records,
            null,
            null,
            DuplicateRecordsSuppressed: duplicateRecordsSuppressed);

    private static SourceCollection<T> NotAttempted<T>(
        ClientObservationSource source) =>
        new(
            source,
            CollectionSourceStatus.Failed,
            Array.Empty<T>(),
            "notAttempted",
            "The source was not read because the fail-closed history action had already encountered an incomplete required source.");

    private static SourceCollection<T> Incomplete<T>(
        ClientObservationSource source,
        IReadOnlyList<T> records,
        string errorCode,
        string errorMessage,
        Exception exception,
        int duplicateRecordsSuppressed = 0) =>
        new(
            source,
            records.Count == 0 ? CollectionSourceStatus.Failed : CollectionSourceStatus.Partial,
            records,
            errorCode,
            errorMessage,
            exception is UnifiApiException api ? (int)api.StatusCode : null,
            exception is UnifiApiException apiWithCode ? apiWithCode.Code : null,
            duplicateRecordsSuppressed);

    private static long ValidatePage(JsonObject response, JsonArray page, int requestedOffset)
    {
        var count = ReadNonNegative(response["count"], "count");
        var offset = ReadNonNegative(response["offset"], "offset");
        var limit = ReadNonNegative(response["limit"], "limit");
        var total = ReadNonNegative(response["totalCount"], "totalCount");
        if (count != page.Count ||
            offset != requestedOffset ||
            limit != ConnectedPageSize ||
            total < offset + count ||
            total > MaximumConnectedClients)
        {
            throw new ContractException(
                "Official connected-client pagination metadata was inconsistent or out of bounds.");
        }

        return total;
    }

    private static long ReadNonNegative(JsonNode? node, string field)
    {
        if (node is JsonValue scalar &&
            (scalar.TryGetValue<long>(out var longValue) ||
             scalar.TryGetValue<int>(out var intValue) && (longValue = intValue) >= 0) &&
            longValue >= 0)
        {
            return longValue;
        }

        throw new ContractException(
            $"Official connected-client {field} was not a nonnegative integer.");
    }

    private static string ReadMac(JsonObject source, string field, string sourceName)
    {
        var value = FirstText(source, field).Value;
        if (value is null || !MacAddressPattern().IsMatch(value))
        {
            throw new ContractException(
                $"{sourceName} did not contain a valid {field}.");
        }

        return value.ToLowerInvariant();
    }

    private static string ReadText(JsonObject source, string field) =>
        FirstText(source, field).Value ??
        throw new ContractException($"Private response did not contain {field}.");

    private static (string? Name, string? Value) FirstText(
        JsonObject source,
        params string[] fields)
    {
        foreach (var field in fields)
        {
            if (source[field] is JsonValue scalar &&
                scalar.TryGetValue<string>(out var value) &&
                !string.IsNullOrWhiteSpace(value))
            {
                return (field, value.Trim());
            }
        }

        return (null, null);
    }

    private static string? NormalizeIp(string? value, string sourceName)
    {
        if (value is null)
        {
            return null;
        }

        if (!IPAddress.TryParse(value, out var address) ||
            address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw new ContractException($"{sourceName} was invalid.");
        }

        return address.ToString();
    }

    private static long? ReadRfc3339Milliseconds(JsonObject source, string field)
    {
        var value = FirstText(source, field).Value;
        if (value is null)
        {
            return null;
        }

        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestamp))
        {
            throw new ContractException(
                $"Official connected-client {field} was not RFC3339.");
        }

        return timestamp.ToUnixTimeMilliseconds();
    }

    private static long? ReadLastSeenMilliseconds(
        JsonObject source,
        int historyHours,
        DateTimeOffset observedAt)
    {
        if (source["last_seen"] is null)
        {
            return null;
        }

        if (source["last_seen"] is not JsonValue scalar ||
            !(scalar.TryGetValue<long>(out var value) ||
              scalar.TryGetValue<int>(out var intValue) && (value = intValue) > 0) ||
            value <= 0)
        {
            throw new ContractException(
                "Private client-history last_seen was not a positive epoch timestamp.");
        }

        DateTimeOffset timestamp;
        try
        {
            timestamp = DateTimeOffset.FromUnixTimeSeconds(value);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw new ContractException(
                "Private client-history last_seen was outside the supported range.");
        }

        if (timestamp > observedAt.AddMinutes(5) ||
            timestamp < observedAt.AddHours(-historyHours).AddMinutes(-5))
        {
            throw new ContractException(
                "Private client-history last_seen was outside the bounded history window.");
        }

        return timestamp.ToUnixTimeMilliseconds();
    }

    private string Sanitize(string value)
    {
        var redacted = _redactor.Redact(value.Trim());
        return redacted.Length <= MaximumTextLength
            ? redacted
            : redacted[..MaximumTextLength];
    }

    private static FieldEvidence Evidence(
        string field,
        string sourceField,
        string authority,
        bool available) =>
        new(field, sourceField, authority, available);

    private static bool IsSourceFailure(Exception exception) =>
        exception is UnifiApiException or ContractException;

    private static string SourceErrorCode(Exception exception) =>
        exception is UnifiApiException api
            ? api.StatusCode == HttpStatusCode.NotFound
                ? "endpointUnavailable"
                : "controllerReadFailed"
            : "unrecognizedResponseContract";

    [GeneratedRegex("^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex MacAddressPattern();

    [GeneratedRegex("^[0-9a-fA-F]{24}$", RegexOptions.CultureInvariant)]
    private static partial Regex GroupIdPattern();
}
