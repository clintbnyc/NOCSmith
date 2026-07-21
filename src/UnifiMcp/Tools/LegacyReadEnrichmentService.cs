using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed class LegacyReadEnrichmentService
{
    private const string DeviceDetailsOperationId = "getAdoptedDeviceDetails";
    private const string DeviceOverviewOperationId = "getAdoptedDeviceOverviewPage";
    private const string ClientDetailsOperationId = "getConnectedClientDetails";
    private const string ClientOverviewOperationId = "getConnectedClientOverviewPage";
    private const int MaximumFreeTextLength = 4096;

    private readonly UnifiConfiguration _configuration;
    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;
    private readonly SecretRedactor _redactor;
    private readonly ILogger<LegacyReadEnrichmentService> _logger;
    private readonly Dictionary<string, string> _siteReferences = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _siteReferenceLock = new(1, 1);

    public LegacyReadEnrichmentService(
        UnifiConfiguration configuration,
        ContractProvider contracts,
        IUnifiClient client,
        SecretRedactor redactor,
        ILogger<LegacyReadEnrichmentService> logger)
    {
        _configuration = configuration;
        _contracts = contracts;
        _client = client;
        _redactor = redactor;
        _logger = logger;
    }

    public bool Enabled => _configuration.EnableLegacyReadEnrichment;

    public async Task<JsonNode?> EnrichAsync(
        string operationId,
        IReadOnlyDictionary<string, string>? pathParameters,
        JsonNode? response,
        CancellationToken cancellationToken)
    {
        if (response is not JsonObject responseObject || !IsSupported(operationId))
        {
            return response;
        }

        var connector = GetOrCreateConnector(responseObject);
        if (!Enabled)
        {
            connector["legacyReadEnrichment"] = new JsonObject
            {
                ["status"] = "disabled",
                ["readOnly"] = true
            };
            return responseObject;
        }

        try
        {
            if (pathParameters is null ||
                !pathParameters.TryGetValue("siteId", out var siteId) ||
                string.IsNullOrWhiteSpace(siteId))
            {
                throw new ContractException("Legacy read enrichment requires a resolved siteId.");
            }

            var internalSiteReference = await ResolveInternalSiteReferenceAsync(siteId, cancellationToken)
                .ConfigureAwait(false);
            var enrichment = operationId is DeviceDetailsOperationId or DeviceOverviewOperationId
                ? ProjectDevices(
                    responseObject,
                    await _client.ReadLegacyDevicesAsync(internalSiteReference, cancellationToken).ConfigureAwait(false))
                : ProjectClients(
                    responseObject,
                    await _client.ReadLegacyClientsAsync(internalSiteReference, cancellationToken).ConfigureAwait(false));
            connector["legacyReadEnrichment"] = enrichment;
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            var safeMessage = _redactor.Redact(exception.Message);
            connector["legacyReadEnrichment"] = new JsonObject
            {
                ["status"] = "failed",
                ["readOnly"] = true,
                ["error"] = safeMessage
            };
            _logger.LogWarning("Optional legacy UniFi read enrichment failed for {OperationId}: {Message}", operationId, safeMessage);
        }

        return responseObject;
    }

    public JsonObject Describe() => new()
    {
        ["enabled"] = Enabled,
        ["readOnly"] = true,
        ["authentication"] = "existing X-API-Key",
        ["fixedResources"] = new JsonArray("stat/device", "stat/sta"),
        ["projectedData"] = new JsonArray("port labels", "STP-related state and configuration fields", "device notes/comments", "client notes/comments"),
        ["normalizedUiStpRole"] = CreateUnavailableNormalizedUiStpRole(),
        ["rawLegacyResponsesReturned"] = false
    };

    private async Task<string> ResolveInternalSiteReferenceAsync(string siteId, CancellationToken cancellationToken)
    {
        await _siteReferenceLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_siteReferences.TryGetValue(siteId, out var cached))
            {
                return cached;
            }

            var contract = _contracts.Current;
            var operation = contract.GetOperation("getSiteOverviewPage", requireRead: true);
            var request = contract.ValidateAndBuild(
                operation,
                null,
                new Dictionary<string, string> { ["offset"] = "0", ["limit"] = "200" },
                null);
            var sitesResponse = await _client.ReadAsync(request, cancellationToken).ConfigureAwait(false);
            var site = (sitesResponse?["data"] as JsonArray)?
                .OfType<JsonObject>()
                .SingleOrDefault(candidate => string.Equals(candidate["id"]?.GetValue<string>(), siteId, StringComparison.Ordinal));
            var internalReference = site?["internalReference"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(internalReference))
            {
                throw new ContractException($"Site {siteId} did not include a legacy internalReference.");
            }

            _siteReferences[siteId] = internalReference;
            return internalReference;
        }
        finally
        {
            _siteReferenceLock.Release();
        }
    }

    private JsonObject ProjectDevices(JsonObject officialResponse, JsonNode? legacyResponse)
    {
        var legacyByMac = ReadLegacyRecords(legacyResponse)
            .Where(record => ReadMac(record) is not null)
            .GroupBy(record => ReadMac(record)!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var records = new JsonArray();
        foreach (var official in ReadOfficialRecords(officialResponse))
        {
            var macAddress = ReadMac(official);
            if (macAddress is null || !legacyByMac.TryGetValue(macAddress, out var legacy))
            {
                continue;
            }

            var projected = ProjectDevice(official, legacy);
            if (HasEnrichmentData(projected))
            {
                records.Add(projected);
            }
        }

        var result = CreateSuccess(
            "stat/device",
            records,
            new JsonArray("custom port labels", "STP-related state and configuration fields", "device notes/comments"));
        result["fieldProvenance"] = new JsonObject
        {
            ["label"] = "port_table.name",
            ["stpState"] = "port_table.stp_state",
            ["stpRole"] = "port_table or port_overrides stp_role/stp_port_role when present; raw value only",
            ["isUplink"] = "port_table.is_uplink",
            ["portMode"] = "port_table or port_overrides port_mode/stp_edge when present; raw value only",
            ["stpPortMode"] = "port_overrides.stp_port_mode",
            ["settingPreference"] = "port_overrides.setting_preference"
        };
        result["normalizedUiStpRole"] = CreateUnavailableNormalizedUiStpRole();
        return result;
    }

    private JsonObject ProjectClients(JsonObject officialResponse, JsonNode? legacyResponse)
    {
        var legacyByMac = ReadLegacyRecords(legacyResponse)
            .Where(record => ReadMac(record) is not null)
            .GroupBy(record => ReadMac(record)!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var records = new JsonArray();
        foreach (var official in ReadOfficialRecords(officialResponse))
        {
            var macAddress = ReadMac(official);
            if (macAddress is null || !legacyByMac.TryGetValue(macAddress, out var legacy))
            {
                continue;
            }

            var projected = CreateIdentity(official, macAddress);
            CopyFreeText(legacy, projected);
            if (HasEnrichmentData(projected))
            {
                records.Add(projected);
            }
        }

        return CreateSuccess("stat/sta", records, new JsonArray("client notes/comments"));
    }

    private JsonObject ProjectDevice(JsonObject official, JsonObject legacy)
    {
        var macAddress = ReadMac(official)!;
        var projected = CreateIdentity(official, macAddress);
        CopyFreeText(legacy, projected);

        var overrides = (legacy["port_overrides"] as JsonArray)?
            .OfType<JsonObject>()
            .Where(item => ReadInteger(item["port_idx"]) is not null)
            .GroupBy(item => ReadInteger(item["port_idx"])!.Value)
            .ToDictionary(group => group.Key, group => group.First())
            ?? new Dictionary<int, JsonObject>();
        var ports = new JsonArray();
        foreach (var port in (legacy["port_table"] as JsonArray)?.OfType<JsonObject>() ?? Array.Empty<JsonObject>())
        {
            var index = ReadInteger(port["port_idx"]);
            if (index is null)
            {
                continue;
            }

            var projectedPort = new JsonObject { ["idx"] = index.Value };
            CopyFreeTextScalar(port, projectedPort, "name", "label");
            CopyScalar(port, projectedPort, "stp_state", "stpState");
            CopyFirstScalar(port, projectedPort, new[] { "stp_role", "stp_port_role" }, "stpRole");
            CopyScalar(port, projectedPort, "is_uplink", "isUplink");
            CopyFirstScalar(port, projectedPort, new[] { "port_mode", "stp_edge" }, "portMode");
            CopyFreeText(port, projectedPort);
            if (overrides.TryGetValue(index.Value, out var portOverride))
            {
                CopyScalar(portOverride, projectedPort, "stp_port_mode", "stpPortMode");
                CopyFirstScalar(portOverride, projectedPort, new[] { "stp_role", "stp_port_role" }, "stpRole");
                CopyFirstScalar(portOverride, projectedPort, new[] { "port_mode", "stp_edge" }, "portMode");
                CopyScalar(portOverride, projectedPort, "setting_preference", "settingPreference");
                CopyFreeText(portOverride, projectedPort);
            }

            ports.Add(projectedPort);
        }

        if (ports.Count > 0)
        {
            projected["ports"] = ports;
        }

        return projected;
    }

    private static JsonObject CreateIdentity(JsonObject official, string macAddress)
    {
        var identity = new JsonObject { ["macAddress"] = macAddress };
        if (official["id"] is JsonValue id && id.TryGetValue<string>(out var idText))
        {
            identity["id"] = idText;
        }

        return identity;
    }

    private static bool HasEnrichmentData(JsonObject record) =>
        record.Any(property => property.Key is not "id" and not "macAddress");

    private JsonObject CreateSuccess(string resource, JsonArray records, JsonArray addresses) => new()
    {
        ["status"] = "ok",
        ["readOnly"] = true,
        ["source"] = "legacy-private-api",
        ["fixedResource"] = resource,
        ["rawResponseReturned"] = false,
        ["redactionApplied"] = true,
        ["addresses"] = addresses,
        ["records"] = records
    };

    private static JsonObject CreateUnavailableNormalizedUiStpRole() => new()
    {
        ["field"] = "uiStpRole",
        ["available"] = false,
        ["status"] = "unavailable",
        ["reason"] = "The verified legacy stat/device fields do not reliably distinguish the UniFi UI Edge and Participant roles; no role is inferred from STP state, uplink, STP mode, or setting preference."
    };

    private void CopyFreeText(JsonObject source, JsonObject destination)
    {
        foreach (var name in new[] { "note", "notes", "comment", "comments" })
        {
            if (source[name] is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text))
            {
                destination[name] = SanitizeFreeText(text);
            }
            else if (source[name] is JsonArray array)
            {
                var projected = new JsonArray(array
                    .OfType<JsonValue>()
                    .Select(item => item.TryGetValue<string>(out var itemText) ? JsonValue.Create(SanitizeFreeText(itemText)) : null)
                    .Where(item => item is not null)
                    .ToArray());
                if (projected.Count > 0)
                {
                    destination[name] = projected;
                }
            }
        }
    }

    private bool CopyFreeTextScalar(JsonObject source, JsonObject destination, string sourceName, string destinationName)
    {
        if (source[sourceName] is not JsonValue value ||
            !value.TryGetValue<string>(out var text) ||
            string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        destination[destinationName] = SanitizeFreeText(text);
        return true;
    }

    private string SanitizeFreeText(string value)
    {
        var redacted = _redactor.Redact(value.Trim());
        return redacted.Length <= MaximumFreeTextLength
            ? redacted
            : redacted[..MaximumFreeTextLength] + "…";
    }

    private static void CopyFirstScalar(JsonObject source, JsonObject destination, IEnumerable<string> sourceNames, string destinationName)
    {
        foreach (var sourceName in sourceNames)
        {
            if (CopyScalar(source, destination, sourceName, destinationName))
            {
                return;
            }
        }
    }

    private static bool CopyScalar(JsonObject source, JsonObject destination, string sourceName, string destinationName)
    {
        if (source[sourceName] is not JsonValue scalar)
        {
            return false;
        }

        destination[destinationName] = scalar.DeepClone();
        return true;
    }

    private static IEnumerable<JsonObject> ReadOfficialRecords(JsonObject response)
    {
        if (response["data"] is JsonArray page)
        {
            return page.OfType<JsonObject>();
        }

        return new[] { response };
    }

    private static IEnumerable<JsonObject> ReadLegacyRecords(JsonNode? response)
    {
        if (response?["data"] is not JsonArray data)
        {
            throw new InvalidOperationException("Legacy UniFi read did not return a data array.");
        }

        return data.OfType<JsonObject>();
    }

    private static string? ReadMac(JsonObject record)
    {
        foreach (var name in new[] { "macAddress", "mac" })
        {
            if (record[name] is JsonValue value && value.TryGetValue<string>(out var mac) && !string.IsNullOrWhiteSpace(mac))
            {
                return mac.Trim().ToLowerInvariant();
            }
        }

        return null;
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

        if (scalar.TryGetValue<long>(out var longValue) && longValue is >= int.MinValue and <= int.MaxValue)
        {
            return (int)longValue;
        }

        return scalar.TryGetValue<string>(out var text) &&
               int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out integer)
            ? integer
            : null;
    }

    private static JsonObject GetOrCreateConnector(JsonObject response)
    {
        if (response["_connector"] is JsonObject connector)
        {
            return connector;
        }

        connector = new JsonObject();
        response["_connector"] = connector;
        return connector;
    }

    private static bool IsSupported(string operationId) =>
        operationId is DeviceDetailsOperationId or DeviceOverviewOperationId or ClientDetailsOperationId or ClientOverviewOperationId;
}
