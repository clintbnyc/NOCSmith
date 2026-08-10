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
    private const string LegacyDeviceResource = "stat/device";
    private const string PortProfileResource = "rest/portconf";
    private const string PrivateClientResource = "v2/api/site/{site}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true";
    private const string NetworkOverviewOperationId = "getNetworksOverviewPage";
    private const string DeviceDetailsOperationId = "getAdoptedDeviceDetails";
    private const string DeviceOverviewOperationId = "getAdoptedDeviceOverviewPage";
    private const string ClientDetailsOperationId = "getConnectedClientDetails";
    private const string ClientOverviewOperationId = "getConnectedClientOverviewPage";
    private const int MaximumFreeTextLength = 4096;
    private const int MaximumLegacyDevices = 1000;
    private const int MaximumPortProfiles = 500;
    private const int MaximumPortsPerDevice = 256;
    private const int MaximumNetworks = 200;

    private readonly UnifiConfiguration _configuration;
    private readonly IUnifiClient _client;
    private readonly ContractProvider _contracts;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;
    private readonly ILogger<LegacyReadEnrichmentService> _logger;
    private readonly TimeProvider _timeProvider;

    public LegacyReadEnrichmentService(
        UnifiConfiguration configuration,
        IUnifiClient client,
        ContractProvider contracts,
        SiteResolver siteResolver,
        SecretRedactor redactor,
        ILogger<LegacyReadEnrichmentService> logger,
        TimeProvider? timeProvider = null)
    {
        _configuration = configuration;
        _client = client;
        _contracts = contracts;
        _siteResolver = siteResolver;
        _redactor = redactor;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
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

            var internalSiteReference = await _siteResolver.ResolveInternalReferenceAsync(siteId, cancellationToken)
                .ConfigureAwait(false);
            var enrichment = operationId is DeviceDetailsOperationId or DeviceOverviewOperationId
                ? await EnrichDevicesAsync(
                    operationId,
                    siteId,
                    internalSiteReference,
                    responseObject,
                    cancellationToken).ConfigureAwait(false)
                : ProjectClients(
                    responseObject,
                    await _client.ReadPrivateClientsAsync(internalSiteReference, cancellationToken).ConfigureAwait(false));
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
        ["fixedResources"] = new JsonArray(LegacyDeviceResource, PortProfileResource, PrivateClientResource),
        ["projectedData"] = new JsonArray("port labels", "STP-related state and configuration fields", "native and tagged networks", "port profiles", "PoE configuration and power", "device notes/comments", "client notes/comments"),
        ["limits"] = new JsonObject
        {
            ["legacyDevices"] = MaximumLegacyDevices,
            ["portProfiles"] = MaximumPortProfiles,
            ["portsPerDevice"] = MaximumPortsPerDevice,
            ["officialNetworks"] = MaximumNetworks
        },
        ["normalizedUiStpRole"] = CreateUnavailableNormalizedUiStpRole(),
        ["rawPrivateResponsesReturned"] = false,
        ["rawLegacyResponsesReturned"] = false
    };

    private async Task<JsonObject> EnrichDevicesAsync(
        string operationId,
        string siteId,
        string internalSiteReference,
        JsonObject officialResponse,
        CancellationToken cancellationToken)
    {
        var legacyTask = _client.ReadLegacyDevicesAsync(internalSiteReference, cancellationToken);
        var profilesTask = ReadPortProfilesSafelyAsync(internalSiteReference, cancellationToken);
        var networksTask = ReadNetworksSafelyAsync(siteId, cancellationToken);
        await Task.WhenAll(legacyTask, profilesTask, networksTask).ConfigureAwait(false);
        return ProjectDevices(
            operationId,
            officialResponse,
            await legacyTask.ConfigureAwait(false),
            await profilesTask.ConfigureAwait(false),
            await networksTask.ConfigureAwait(false),
            _timeProvider.GetUtcNow());
    }

    private JsonObject ProjectDevices(
        string operationId,
        JsonObject officialResponse,
        JsonNode? legacyResponse,
        PortProfileInventory portProfiles,
        NetworkInventory networkInventory,
        DateTimeOffset observedAt)
    {
        var legacyRecords = PrivateReadResponseParser.ReadRecords(legacyResponse);
        if (legacyRecords.Count > MaximumLegacyDevices)
        {
            throw new ContractException(
                $"Private device response exceeded the {MaximumLegacyDevices}-record safety limit.");
        }

        var legacyByMac = legacyRecords
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

            var projected = ProjectDevice(operationId, official, legacy, portProfiles, networkInventory);
            if (HasEnrichmentData(projected))
            {
                records.Add(projected);
            }
        }

        var result = CreateSuccess(
            LegacyDeviceResource,
            "legacy-private-api",
            records,
            new JsonArray("custom port labels", "STP-related state and configuration fields", "native and tagged networks", "port profiles", "PoE configuration and power", "device notes/comments"));
        result["observedAt"] = observedAt.ToString("O", CultureInfo.InvariantCulture);
        result["networkInventory"] = new JsonObject
        {
            ["source"] = "official-network-integration-api",
            ["operationId"] = NetworkOverviewOperationId,
            ["status"] = networkInventory.Status,
            ["complete"] = networkInventory.Complete,
            ["count"] = networkInventory.Networks.Count,
            ["limit"] = MaximumNetworks,
            ["error"] = networkInventory.Error
        };
        result["portProfileInventory"] = new JsonObject
        {
            ["source"] = "legacy-private-api",
            ["fixedResource"] = PortProfileResource,
            ["status"] = portProfiles.Status,
            ["count"] = portProfiles.Profiles.Count,
            ["limit"] = MaximumPortProfiles,
            ["error"] = portProfiles.Error
        };
        result["fieldProvenance"] = new JsonObject
        {
            ["label"] = "port_table.name",
            ["stpState"] = "port_table.stp_state",
            ["stpRole"] = "port_table or port_overrides stp_role/stp_port_role when present; raw value only",
            ["isUplink"] = "port_table.is_uplink",
            ["portMode"] = "port_table or port_overrides port_mode/stp_edge when present; raw value only",
            ["stpPortMode"] = "port_overrides.stp_port_mode",
            ["settingPreference"] = "port_overrides.setting_preference",
            ["poePowerWatts"] = "port_table.poe_power",
            ["poeMode"] = "port_overrides or resolved port profile poe_mode",
            ["nativeNetwork"] = "port_overrides or resolved port profile native_networkconf_id joined to official network inventory",
            ["allowedTaggedNetworks"] = "tagged_networkconf_ids, or bounded derivation from forward/tagged_vlan_mgmt and excluded_networkconf_ids, joined to official network inventory",
            ["portProfile"] = "port_overrides or port_table portconf_id joined internally to fixed rest/portconf; private identifiers are not returned"
        };
        result["normalizedUiStpRole"] = CreateUnavailableNormalizedUiStpRole();
        return result;
    }

    private JsonObject ProjectClients(JsonObject officialResponse, JsonNode? legacyResponse)
    {
        var legacyByMac = PrivateReadResponseParser.ReadRecords(legacyResponse)
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

        return CreateSuccess(
            PrivateClientResource,
            "private-v2-api",
            records,
            new JsonArray("client notes/comments"));
    }

    private JsonObject ProjectDevice(
        string operationId,
        JsonObject official,
        JsonObject legacy,
        PortProfileInventory portProfiles,
        NetworkInventory networkInventory)
    {
        var macAddress = ReadMac(official)!;
        var projected = CreateIdentity(official, macAddress);
        CopyFreeText(legacy, projected);

        var overrideRecords = ReadObjectArray(legacy, "port_overrides", MaximumPortsPerDevice);
        var overrides = overrideRecords
            .Where(item => ReadInteger(item["port_idx"]) is not null)
            .GroupBy(item => ReadInteger(item["port_idx"])!.Value)
            .ToDictionary(group => group.Key, group => group.First());
        var officialPorts = ReadObjectArray(official["interfaces"] as JsonObject, "ports", MaximumPortsPerDevice)
            .Where(item => ReadInteger(item["idx"]) is not null)
            .GroupBy(item => ReadInteger(item["idx"])!.Value)
            .ToDictionary(group => group.Key, group => group.First());
        var legacyPorts = ReadObjectArray(legacy, "port_table", MaximumPortsPerDevice);
        var ports = new JsonArray();
        foreach (var port in legacyPorts)
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
            JsonObject? portOverride = null;
            if (overrides.TryGetValue(index.Value, out portOverride))
            {
                CopyScalar(portOverride, projectedPort, "stp_port_mode", "stpPortMode");
                CopyFirstScalar(portOverride, projectedPort, new[] { "stp_role", "stp_port_role" }, "stpRole");
                CopyFirstScalar(portOverride, projectedPort, new[] { "port_mode", "stp_edge" }, "portMode");
                CopyScalar(portOverride, projectedPort, "setting_preference", "settingPreference");
                CopyFreeText(portOverride, projectedPort);
            }

            var profileReference = ReadText(portOverride, "portconf_id") ?? ReadText(port, "portconf_id");
            var profile = ResolvePortProfile(profileReference, portProfiles.Profiles);
            var officialPortOperationId = operationId == DeviceDetailsOperationId
                ? DeviceDetailsOperationId
                : null;
            AddOfficialPortOverview(
                projectedPort,
                officialPorts.TryGetValue(index.Value, out var officialPort) ? officialPort : null,
                officialPortOperationId);
            AddPortConfiguration(
                projectedPort,
                port,
                portOverride,
                profile,
                profileReference,
                portProfiles.Status,
                networkInventory,
                officialPortOperationId);

            ports.Add(projectedPort);
        }

        if (ports.Count > 0)
        {
            projected["ports"] = ports;
        }

        return projected;
    }

    private async Task<NetworkInventory> ReadNetworksSafelyAsync(
        string siteId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await ReadNetworksAsync(siteId, cancellationToken).ConfigureAwait(false);
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
            var safeMessage = _redactor.Redact(exception.Message);
            _logger.LogWarning("Optional official UniFi network inventory read failed: {Message}", safeMessage);
            return new NetworkInventory(
                new Dictionary<string, NetworkRecord>(StringComparer.Ordinal),
                false,
                "unavailable",
                safeMessage);
        }
    }

    private async Task<NetworkInventory> ReadNetworksAsync(
        string siteId,
        CancellationToken cancellationToken)
    {
        var contract = _contracts.Current;
        var operation = contract.GetOperation(NetworkOverviewOperationId, requireRead: true);
        var request = contract.ValidateAndBuild(
            operation,
            new Dictionary<string, string> { ["siteId"] = siteId },
            new Dictionary<string, string>
            {
                ["offset"] = "0",
                ["limit"] = MaximumNetworks.ToString(CultureInfo.InvariantCulture)
            },
            null);
        var response = await _client.ReadAsync(request, cancellationToken).ConfigureAwait(false);
        if (response is not JsonObject responseObject || responseObject["data"] is not JsonArray data)
        {
            throw new ContractException("Official network inventory did not return a data array.");
        }

        if (data.Count > MaximumNetworks)
        {
            throw new ContractException(
                $"Official network inventory exceeded the {MaximumNetworks}-record safety limit.");
        }

        var declaredOffset = ReadInteger(responseObject["offset"]);
        var declaredLimit = ReadInteger(responseObject["limit"]);
        var declaredCount = ReadInteger(responseObject["count"]);
        var totalCount = ReadInteger(responseObject["totalCount"])
            ?? throw new ContractException("Official network inventory did not include a valid totalCount.");
        if (declaredOffset != 0 ||
            declaredLimit != MaximumNetworks ||
            declaredCount != data.Count ||
            totalCount < data.Count ||
            totalCount < 0)
        {
            throw new ContractException("Official network inventory pagination metadata was contradictory.");
        }

        var networks = new Dictionary<string, NetworkRecord>(StringComparer.Ordinal);
        for (var index = 0; index < data.Count; index++)
        {
            if (data[index] is not JsonObject record)
            {
                throw new ContractException(
                    $"Official network inventory returned a non-object record at index {index}.");
            }

            var id = ReadText(record, "id")
                ?? throw new ContractException("Official network inventory record did not include id.");
            var name = ReadText(record, "name")
                ?? throw new ContractException("Official network inventory record did not include name.");
            var vlanId = ReadInteger(record["vlanId"])
                ?? throw new ContractException("Official network inventory record did not include vlanId.");
            if (!networks.TryAdd(id, new NetworkRecord(SanitizeFreeText(name), vlanId)))
            {
                throw new ContractException("Official network inventory returned duplicate IDs.");
            }
        }

        return new NetworkInventory(networks, totalCount == data.Count, "ok", null);
    }

    private async Task<PortProfileInventory> ReadPortProfilesSafelyAsync(
        string internalSiteReference,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await _client.ReadPortProfilesAsync(internalSiteReference, cancellationToken)
                .ConfigureAwait(false);
            return new PortProfileInventory(ProjectPortProfiles(response), "ok", null);
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException or NotSupportedException)
        {
            var safeMessage = _redactor.Redact(exception.Message);
            _logger.LogWarning("Optional legacy UniFi port-profile read failed: {Message}", safeMessage);
            return new PortProfileInventory(
                new Dictionary<string, JsonObject>(StringComparer.Ordinal),
                "unavailable",
                safeMessage);
        }
    }

    private IReadOnlyDictionary<string, JsonObject> ProjectPortProfiles(JsonNode? response)
    {
        var records = PrivateReadResponseParser.ReadRecords(response);
        if (records.Count > MaximumPortProfiles)
        {
            throw new ContractException(
                $"Private port-profile response exceeded the {MaximumPortProfiles}-record safety limit.");
        }

        var profiles = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var record in records)
        {
            var id = ReadText(record, "_id", "id");
            if (id is null)
            {
                throw new ContractException("Private port-profile response contained a record without an ID.");
            }

            if (!profiles.TryAdd(id, record))
            {
                throw new ContractException("Private port-profile response contained duplicate IDs.");
            }
        }

        return profiles;
    }

    private static JsonObject? ResolvePortProfile(
        string? profileReference,
        IReadOnlyDictionary<string, JsonObject> profiles)
    {
        return profileReference is not null && profiles.TryGetValue(profileReference, out var profile)
            ? profile
            : null;
    }

    private void AddOfficialPortOverview(
        JsonObject projectedPort,
        JsonObject? officialPort,
        string? officialPortOperationId)
    {
        var overview = new JsonObject
        {
            ["status"] = officialPort is not null ? "available" : "unavailable",
            ["state"] = CloneScalar(officialPort, "state"),
            ["speedMbps"] = CloneScalar(officialPort, "speedMbps"),
            ["maxSpeedMbps"] = CloneScalar(officialPort, "maxSpeedMbps")
        };
        if (officialPort?["poe"] is JsonObject officialPoe)
        {
            overview["poe"] = new JsonObject
            {
                ["enabled"] = CloneScalar(officialPoe, "enabled"),
                ["standard"] = CloneScalar(officialPoe, "standard"),
                ["state"] = CloneScalar(officialPoe, "state")
            };
        }
        else
        {
            overview["poe"] = null;
        }

        if (officialPort is null)
        {
            overview["reason"] = officialPortOperationId is null
                ? "The current official device overview operation does not expose per-port details."
                : "The official device-details response did not contain this port index.";
        }

        projectedPort["officialOverview"] = overview;
    }

    private void AddPortConfiguration(
        JsonObject projectedPort,
        JsonObject livePort,
        JsonObject? portOverride,
        JsonObject? profile,
        string? profileReference,
        string portProfileStatus,
        NetworkInventory networkInventory,
        string? officialPortOperationId)
    {
        var configurationSources = new[] { portOverride, profile, livePort };
        var nativeNetworkId = ReadFirstText(configurationSources, "native_networkconf_id");
        var taggedNetworkIds = ReadFirstTextArray(
            configurationSources,
            MaximumNetworks,
            "tagged_networkconf_ids",
            "allowed_networkconf_ids",
            "allowed_tagged_networkconf_ids");
        var excludedNetworkIds = ReadFirstTextArray(
            configurationSources,
            MaximumNetworks,
            "excluded_networkconf_ids");
        var taggedMode = SanitizeOptionalText(ReadFirstText(
            configurationSources,
            "tagged_vlan_mgmt",
            "forward"));
        var settingPreference = ReadText(portOverride, "setting_preference");
        var settingPreferenceSource = settingPreference is not null ? "per-port-override" : null;
        if (settingPreference is null)
        {
            settingPreference = ReadText(profile, "setting_preference");
            settingPreferenceSource = settingPreference is not null ? "port-profile" : null;
        }

        if (settingPreference is null)
        {
            settingPreference = ReadText(livePort, "setting_preference");
            settingPreferenceSource = settingPreference is not null ? "legacy-port-table" : "unavailable";
        }

        var derivedTaggedNetworks = false;
        if (taggedNetworkIds is null && networkInventory.Complete)
        {
            var knownIds = networkInventory.Networks.Keys
                .Where(id => !string.Equals(id, nativeNetworkId, StringComparison.Ordinal));
            taggedNetworkIds = taggedMode?.ToLowerInvariant() switch
            {
                "all" or "auto" => knownIds.ToArray(),
                "native" or "block_all" => Array.Empty<string>(),
                "customize" or "custom" when excludedNetworkIds is not null =>
                    knownIds.Except(excludedNetworkIds, StringComparer.Ordinal).ToArray(),
                _ => null
            };
            derivedTaggedNetworks = taggedNetworkIds is not null;
        }

        projectedPort["poePowerWatts"] = ReadNonNegativeDouble(livePort, "poe_power");
        projectedPort["poeMode"] = SanitizeOptionalText(ReadFirstText(configurationSources, "poe_mode"));
        projectedPort["nativeNetwork"] = ProjectNetworkReference(nativeNetworkId, networkInventory);
        projectedPort["taggedNetworkMode"] = taggedMode;
        projectedPort["allowedTaggedNetworks"] = taggedNetworkIds is null
            ? null
            : new JsonArray(taggedNetworkIds
                .Distinct(StringComparer.Ordinal)
                .Take(MaximumNetworks)
                .Select(id => (JsonNode?)ProjectNetworkReference(id, networkInventory))
                .ToArray());
        projectedPort["allowedTaggedNetworksStatus"] = taggedNetworkIds is null
            ? "unavailable"
            : networkInventory.Status != "ok"
                ? "unavailable"
            : taggedNetworkIds.Any(id => !networkInventory.Networks.ContainsKey(id))
                ? "partial"
                : "resolved";
        projectedPort["allowedTaggedNetworksDerived"] = derivedTaggedNetworks;
        projectedPort["portProfile"] = ProjectPortProfile(profileReference, profile, portProfileStatus);
        projectedPort["configuredState"] = new JsonObject
        {
            ["source"] = settingPreferenceSource,
            ["settingPreference"] = SanitizeOptionalText(settingPreference)
        };
        projectedPort["fieldProvenance"] = new JsonObject
        {
            ["officialOverview"] = officialPortOperationId is null
                ? "unavailable: current official operation does not expose per-port details"
                : $"official-network-integration-api:{officialPortOperationId}.interfaces.ports",
            ["poePowerWatts"] = "legacy-private-api:stat/device.port_table.poe_power",
            ["poeMode"] = "legacy-private-api:port_overrides or resolved rest/portconf",
            ["nativeNetwork"] = "private configuration ID joined internally to official getNetworksOverviewPage",
            ["allowedTaggedNetworks"] = derivedTaggedNetworks
                ? "derived from bounded complete official inventory plus private forward/tagged_vlan_mgmt and exclusions"
                : "private tagged network IDs joined internally to official getNetworksOverviewPage",
            ["portProfile"] = "private port_overrides or port_table portconf_id joined internally to fixed rest/portconf"
        };
    }

    private JsonObject ProjectPortProfile(
        string? profileReference,
        JsonObject? profile,
        string portProfileStatus)
    {
        if (profile is not null)
        {
            return new JsonObject
            {
                ["status"] = "resolved",
                ["name"] = ReadText(profile, "name") is { } name ? SanitizeFreeText(name) : null,
                ["source"] = "legacy-private-api:rest/portconf"
            };
        }

        return profileReference is not null && portProfileStatus == "ok"
            ? new JsonObject
            {
                ["status"] = "unresolved",
                ["name"] = null,
                ["reason"] = "The private profile reference was not present in the bounded fixed port-profile response."
            }
            : profileReference is not null
                ? new JsonObject
                {
                    ["status"] = "unavailable",
                    ["name"] = null,
                    ["reason"] = "The bounded fixed port-profile source was unavailable."
                }
                : new JsonObject
                {
                    ["status"] = "unavailable",
                    ["name"] = null,
                    ["reason"] = "No applied port-profile reference was exposed."
                };
    }

    private static JsonObject ProjectNetworkReference(string? id, NetworkInventory inventory)
    {
        if (id is null)
        {
            return new JsonObject
            {
                ["status"] = "unavailable",
                ["name"] = null,
                ["vlanId"] = null
            };
        }

        if (inventory.Status != "ok")
        {
            return new JsonObject
            {
                ["status"] = "unavailable",
                ["name"] = null,
                ["vlanId"] = null,
                ["reason"] = "The bounded official network inventory was unavailable."
            };
        }

        if (inventory.Networks.TryGetValue(id, out var network))
        {
            return new JsonObject
            {
                ["status"] = "resolved",
                ["name"] = network.Name,
                ["vlanId"] = network.VlanId
            };
        }

        return new JsonObject
        {
            ["status"] = "unresolved",
            ["name"] = null,
            ["vlanId"] = null,
            ["reason"] = inventory.Complete
                ? "The private network reference was not present in the complete bounded official inventory."
                : "The private network reference was not present in the incomplete bounded official inventory."
        };
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

    private JsonObject CreateSuccess(string resource, string source, JsonArray records, JsonArray addresses) => new()
    {
        ["status"] = "ok",
        ["readOnly"] = true,
        ["source"] = source,
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

    private string? SanitizeOptionalText(string? value) =>
        value is null ? null : SanitizeFreeText(value);

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

    private static JsonObject[] ReadObjectArray(
        JsonObject? source,
        string field,
        int maximumRecords)
    {
        if (source?[field] is null)
        {
            return Array.Empty<JsonObject>();
        }

        if (source[field] is not JsonArray array)
        {
            throw new ContractException($"Private device field '{field}' was not an array.");
        }

        if (array.Count > maximumRecords)
        {
            throw new ContractException(
                $"Private device field '{field}' exceeded the {maximumRecords}-record safety limit.");
        }

        var records = new JsonObject[array.Count];
        for (var index = 0; index < array.Count; index++)
        {
            records[index] = array[index] as JsonObject
                ?? throw new ContractException(
                    $"Private device field '{field}' returned a non-object record at index {index}.");
        }

        return records;
    }

    private static string? ReadText(JsonObject? source, params string[] fields)
    {
        foreach (var field in fields)
        {
            if (source?[field] is JsonValue value &&
                value.TryGetValue<string>(out var text) &&
                !string.IsNullOrWhiteSpace(text) &&
                text.Trim().Length <= MaximumFreeTextLength)
            {
                return text.Trim();
            }
        }

        return null;
    }

    private static string? ReadFirstText(IEnumerable<JsonObject?> sources, params string[] fields)
    {
        foreach (var source in sources)
        {
            var text = ReadText(source, fields);
            if (text is not null)
            {
                return text;
            }
        }

        return null;
    }

    private static string[]? ReadFirstTextArray(
        IEnumerable<JsonObject?> sources,
        int maximumItems,
        params string[] fields)
    {
        foreach (var source in sources)
        {
            foreach (var field in fields)
            {
                if (source?[field] is null)
                {
                    continue;
                }

                if (source[field] is not JsonArray array)
                {
                    return null;
                }

                if (array.Count > maximumItems)
                {
                    throw new ContractException(
                        $"Private port configuration field '{field}' exceeded the {maximumItems}-item safety limit.");
                }

                var values = new List<string>(array.Count);
                foreach (var item in array)
                {
                    if (item is not JsonValue value ||
                        !value.TryGetValue<string>(out var text) ||
                        string.IsNullOrWhiteSpace(text) ||
                        text.Trim().Length > MaximumFreeTextLength)
                    {
                        return null;
                    }

                    values.Add(text.Trim());
                }

                return values.ToArray();
            }
        }

        return null;
    }

    private static double? ReadNonNegativeDouble(JsonObject source, string field)
    {
        if (source[field] is not JsonValue value)
        {
            return null;
        }

        double number;
        if (!value.TryGetValue<double>(out number) &&
            !(value.TryGetValue<string>(out var text) &&
              double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out number)))
        {
            return null;
        }

        return double.IsFinite(number) && number >= 0 ? number : null;
    }

    private static JsonNode? CloneScalar(JsonObject? source, string field) =>
        source?[field] is JsonValue value ? value.DeepClone() : null;

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

    private sealed record NetworkRecord(string Name, int VlanId);

    private sealed record NetworkInventory(
        IReadOnlyDictionary<string, NetworkRecord> Networks,
        bool Complete,
        string Status,
        string? Error);

    private sealed record PortProfileInventory(
        IReadOnlyDictionary<string, JsonObject> Profiles,
        string Status,
        string? Error);
}
