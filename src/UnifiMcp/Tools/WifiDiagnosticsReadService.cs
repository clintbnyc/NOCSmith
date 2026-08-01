using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed partial class WifiDiagnosticsReadService
{
    private const string ClientResource = "v2/api/site/{site}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true";
    private const string DeviceResource = "stat/device";
    private const int DefaultClientLimit = 100;
    private const int MaximumClientLimit = 200;
    private const int DefaultRadioLimit = 50;
    private const int MaximumRadioLimit = 100;
    private const int MaximumSourceClients = 5000;
    private const int MaximumSourceDevices = 1000;
    private const int MaximumTextLength = 256;

    private readonly UnifiConfiguration _configuration;
    private readonly IUnifiClient _client;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;

    public WifiDiagnosticsReadService(
        UnifiConfiguration configuration,
        IUnifiClient client,
        SiteResolver siteResolver,
        SecretRedactor redactor)
    {
        _configuration = configuration;
        _client = client;
        _siteResolver = siteResolver;
        _redactor = redactor;
    }

    public bool Enabled => _configuration.EnableLegacyReadEnrichment;

    public JsonObject Describe() => new()
    {
        ["enabled"] = Enabled,
        ["readOnly"] = true,
        ["authentication"] = "existing X-API-Key",
        ["fixedResources"] = new JsonArray(ClientResource, DeviceResource),
        ["clientLimit"] = MaximumClientLimit,
        ["radioLimit"] = MaximumRadioLimit,
        ["rawPrivateResponsesReturned"] = false,
        ["redactionApplied"] = true
    };

    public async Task<ToolResponse> ReadAsync(
        string? requestedSiteId,
        string? clientMacAddress,
        int? clientLimit,
        int? radioLimit,
        CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            throw new ConfigurationException(
                "Wi-Fi diagnostics are disabled. Set UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true to enable the fixed read-only client and device queries.");
        }

        var effectiveClientLimit = ValidateLimit(clientLimit, DefaultClientLimit, MaximumClientLimit, "clientLimit");
        var effectiveRadioLimit = ValidateLimit(radioLimit, DefaultRadioLimit, MaximumRadioLimit, "radioLimit");
        var normalizedClientMac = string.IsNullOrWhiteSpace(clientMacAddress)
            ? null
            : NormalizeRequiredMac(clientMacAddress, "clientMacAddress");
        var siteId = await _siteResolver.ResolveAsync(requestedSiteId, cancellationToken).ConfigureAwait(false);
        var internalSiteReference = await _siteResolver
            .ResolveInternalReferenceAsync(siteId, cancellationToken)
            .ConfigureAwait(false);

        var clientsTask = _client.ReadPrivateClientsAsync(internalSiteReference, cancellationToken);
        var devicesTask = _client.ReadLegacyDevicesAsync(internalSiteReference, cancellationToken);
        await Task.WhenAll(clientsTask, devicesTask).ConfigureAwait(false);

        var sourceClients = PrivateReadResponseParser.ReadRecords(await clientsTask.ConfigureAwait(false));
        var sourceDevices = PrivateReadResponseParser.ReadRecords(await devicesTask.ConfigureAwait(false));
        if (sourceClients.Count > MaximumSourceClients)
        {
            throw new ContractException($"Private UniFi client diagnostics exceeded the {MaximumSourceClients} record safety limit.");
        }

        if (sourceDevices.Count > MaximumSourceDevices)
        {
            throw new ContractException($"Private UniFi device diagnostics exceeded the {MaximumSourceDevices} record safety limit.");
        }

        var accessPointNames = sourceDevices
            .Select(device => (MacAddress: ReadMac(device, "mac", "macAddress"), Name: ReadText(device, "name", "displayName")))
            .Where(device => device.MacAddress is not null)
            .GroupBy(device => device.MacAddress!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Name, StringComparer.OrdinalIgnoreCase);
        var projectedClients = sourceClients
            .Select(client => ProjectClient(client, accessPointNames))
            .Where(client => client is not null)
            .Cast<JsonObject>()
            .Where(client => normalizedClientMac is null ||
                string.Equals(client["macAddress"]?.GetValue<string>(), normalizedClientMac, StringComparison.OrdinalIgnoreCase))
            .OrderBy(client => client["macAddress"]!.GetValue<string>(), StringComparer.Ordinal)
            .ToArray();
        var projectedRadios = sourceDevices
            .SelectMany(ProjectRadios)
            .OrderBy(radio => radio["accessPointMacAddress"]!.GetValue<string>(), StringComparer.Ordinal)
            .ThenBy(radio => radio["radioName"]?.GetValue<string>(), StringComparer.Ordinal)
            .ToArray();

        var clients = new JsonArray(projectedClients
            .Take(effectiveClientLimit)
            .Select(client => (JsonNode?)client)
            .ToArray());
        var radios = new JsonArray(projectedRadios
            .Take(effectiveRadioLimit)
            .Select(radio => (JsonNode?)radio)
            .ToArray());
        var result = new JsonObject
        {
            ["siteId"] = siteId,
            ["clients"] = new JsonObject
            {
                ["returned"] = clients.Count,
                ["matched"] = projectedClients.Length,
                ["limit"] = effectiveClientLimit,
                ["truncated"] = projectedClients.Length > clients.Count,
                ["data"] = clients
            },
            ["accessPointRadios"] = new JsonObject
            {
                ["returned"] = radios.Count,
                ["matched"] = projectedRadios.Length,
                ["limit"] = effectiveRadioLimit,
                ["truncated"] = projectedRadios.Length > radios.Count,
                ["data"] = radios
            },
            ["_connector"] = CreateMetadata()
        };

        return new ToolResponse(
            $"Read {clients.Count} current client and {radios.Count} access-point radio diagnostic record(s).",
            _redactor.Redact(result));
    }

    private JsonObject? ProjectClient(
        JsonObject source,
        IReadOnlyDictionary<string, string?> accessPointNames)
    {
        var macAddress = ReadMac(source, "mac", "macAddress");
        if (macAddress is null)
        {
            return null;
        }

        var ipAddress = ReadIpAddress(source, "ip", "ipAddress");
        var noiseFloor = ReadDouble(source, "noise", "noise_floor", "noiseFloor", "noiseFloorDbm");
        var rssi = ReadDouble(source, "signal", "rssi", "rssiDbm");
        var snr = ReadDouble(source, "snr", "snrDb") ??
            (rssi is not null && noiseFloor is not null ? rssi.Value - noiseFloor.Value : null);
        var associatedAt = ReadEpochTimestamp(source, "first_seen", "associated_at", "association_time", "associatedAt");
        var lastSeenAt = ReadEpochTimestamp(source, "last_seen", "lastSeen", "lastSeenAt");
        var roamAt = ReadEpochTimestamp(source, "last_roam", "roam_time", "roamAt");
        var accessPointMacAddress = ReadMac(source, "ap_mac", "apMac", "uplink_mac", "uplinkMac");
        accessPointNames.TryGetValue(accessPointMacAddress ?? string.Empty, out var accessPointName);

        return new JsonObject
        {
            ["macAddress"] = macAddress,
            ["name"] = ReadText(source, "name", "hostname", "displayName"),
            ["wireless"] = ReadWireless(source),
            ["association"] = new JsonObject
            {
                ["accessPointMacAddress"] = accessPointMacAddress,
                ["accessPointName"] = accessPointName,
                ["radioName"] = ReadText(source, "radio", "radio_name", "radioName"),
                ["band"] = ReadBand(source),
                ["channel"] = ReadInteger(source, "channel", "radio_channel", "radioChannel"),
                ["channelWidthMhz"] = ReadChannelWidth(source),
                ["associatedAt"] = associatedAt,
                ["associationDurationSeconds"] = ReadLong(source, "assoc_time", "associationDurationSeconds"),
                ["lastSeenAt"] = lastSeenAt,
                ["lastRoamAt"] = roamAt,
                ["roamCount"] = ReadLong(source, "roam_count", "roamCount"),
                ["roamReason"] = ReadText(source, "roam_reason", "roamReason"),
                ["powerSaveState"] = ReadBoolean(source, "powersave_enabled", "power_save", "powerSave", "powerSaveState")
            },
            ["signal"] = new JsonObject
            {
                ["rssiDbm"] = rssi,
                ["noiseFloorDbm"] = noiseFloor,
                ["snrDb"] = snr,
                ["qualityPercent"] = ReadDouble(source, "satisfaction", "signal_quality", "signalQuality", "qualityPercent"),
                ["qualityClassification"] = ReadText(source, "signal_quality_class", "signalQualityClassification", "qualityClassification"),
                ["signalBalance"] = ReadText(source, "signal_balance", "signalBalance", "signal_balance_status", "signalBalanceClassification")
            },
            ["phy"] = new JsonObject
            {
                ["wifiStandard"] = ReadText(source, "radio_proto", "radioProtocol", "wifi_standard", "wifiStandard"),
                ["rxRateMbps"] = ReadRateMbps(source, new[] { "rx_rate_mbps", "rxRateMbps" }, new[] { "rx_rate", "rxRateKbps" }),
                ["txRateMbps"] = ReadRateMbps(source, new[] { "tx_rate_mbps", "txRateMbps" }, new[] { "tx_rate", "txRateKbps" }),
                ["rxMcs"] = ReadInteger(source, "rx_mcs", "rxMcs"),
                ["txMcs"] = ReadInteger(source, "tx_mcs", "txMcs"),
                ["rxNss"] = ReadInteger(source, "rx_nss", "rxNss", "nss"),
                ["txNss"] = ReadInteger(source, "tx_nss", "txNss", "nss"),
                ["mimo"] = ReadText(source, "mimo", "mimo_mode", "mimoMode")
            },
            ["reliability"] = new JsonObject
            {
                ["rxRetries"] = ReadLong(source, "rx_retries", "wifi_rx_retries", "rxRetries"),
                ["txRetries"] = ReadLong(source, "tx_retries", "wifi_tx_retries", "txRetries"),
                ["rxErrors"] = ReadLong(source, "rx_errors", "wifi_rx_errors", "rxErrors"),
                ["txErrors"] = ReadLong(source, "tx_errors", "wifi_tx_errors", "txErrors"),
                ["rxRetryRatePercent"] = ReadDouble(source, "rx_retry_rate", "rxRetryRate", "rxRetryRatePercent"),
                ["txRetryRatePercent"] = ReadDouble(source, "tx_retry_rate", "txRetryRate", "txRetryRatePercent")
            },
            ["network"] = new JsonObject
            {
                ["ipAddress"] = ipAddress,
                ["dhcpState"] = ReadText(source, "dhcp_state", "dhcpStatus", "dhcpState", "ip_source", "ipSource"),
                ["dhcpLeaseExpiresAt"] = ReadEpochTimestamp(source, "dhcpend_time", "dhcp_lease_expires", "dhcpLeaseExpiresAt"),
                ["dhcpFailureReason"] = ReadText(source, "dhcp_failure_reason", "dhcpFailureReason"),
                ["apipa"] = ReadBoolean(source, "apipa", "is_apipa", "isApipa") ?? IsApipa(ipAddress)
            }
        };
    }

    private IEnumerable<JsonObject> ProjectRadios(JsonObject device)
    {
        var accessPointMac = ReadMac(device, "mac", "macAddress");
        if (accessPointMac is null)
        {
            yield break;
        }

        var configurations = ((device["radio_table"] as JsonArray) ?? device["radioTable"] as JsonArray)?
            .OfType<JsonObject>()
            .ToArray() ?? Array.Empty<JsonObject>();
        var statistics = ((device["radio_table_stats"] as JsonArray) ?? device["radioTableStats"] as JsonArray)?
            .OfType<JsonObject>()
            .ToArray() ?? Array.Empty<JsonObject>();
        var configurationByRadio = configurations
            .Select((radio, index) => (Key: RadioKey(radio, index), Radio: radio))
            .ToDictionary(item => item.Key, item => item.Radio, StringComparer.OrdinalIgnoreCase);
        var statisticsByRadio = statistics
            .Select((radio, index) => (Key: RadioKey(radio, index), Radio: radio))
            .ToDictionary(item => item.Key, item => item.Radio, StringComparer.OrdinalIgnoreCase);
        foreach (var key in configurationByRadio.Keys
            .Union(statisticsByRadio.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            configurationByRadio.TryGetValue(key, out var configuration);
            statisticsByRadio.TryGetValue(key, out var stats);
            var radio = MergeRadio(configuration, stats);
            yield return new JsonObject
            {
                ["accessPointMacAddress"] = accessPointMac,
                ["accessPointName"] = ReadText(device, "name", "displayName"),
                ["radioName"] = ReadText(radio, "radio", "name", "radioName"),
                ["band"] = ReadBand(radio),
                ["channel"] = ReadInteger(radio, "channel", "effective_channel", "effectiveChannel"),
                ["channelWidthMhz"] = ReadChannelWidth(radio),
                ["configuredTransmitPowerDbm"] = configuration is null
                    ? null
                    : ReadDouble(configuration, "tx_power", "configured_tx_power", "configuredTransmitPowerDbm"),
                ["effectiveTransmitPowerDbm"] = stats is null
                    ? ReadDouble(radio, "tx_power_effective", "effective_tx_power", "effectiveTransmitPowerDbm")
                    : ReadDouble(stats, "tx_power", "tx_power_effective", "effective_tx_power", "effectiveTransmitPowerDbm"),
                ["transmitPowerMode"] = ReadText(radio, "tx_power_mode", "transmitPowerMode"),
                ["channelUtilizationPercent"] = ReadDouble(radio, "cu_total", "channel_utilization", "channelUtilization", "channelUtilizationPercent"),
                ["interferencePercent"] = ReadDouble(radio, "cu_other_rx", "interference", "interferencePercent"),
                ["noiseFloorDbm"] = ReadDouble(radio, "noise", "noise_floor", "noiseFloorDbm"),
                ["stationCount"] = ReadInteger(radio, "num_sta", "stationCount"),
                ["rxRetries"] = ReadLong(radio, "rx_retries", "rxRetries"),
                ["txRetries"] = ReadLong(radio, "tx_retries", "txRetries"),
                ["rxErrors"] = ReadLong(radio, "rx_errors", "rxErrors"),
                ["txErrors"] = ReadLong(radio, "tx_errors", "txErrors"),
                ["rxRetryRatePercent"] = ReadDouble(radio, "rx_retry_rate", "rxRetryRatePercent"),
                ["txRetryRatePercent"] = ReadDouble(radio, "tx_retry_rate", "txRetryRatePercent")
            };
        }
    }

    private JsonObject CreateMetadata() => new()
    {
        ["readOnly"] = true,
        ["sources"] = new JsonArray(
            new JsonObject { ["kind"] = "private-v2-api", ["fixedResource"] = ClientResource },
            new JsonObject { ["kind"] = "legacy-private-api", ["fixedResource"] = DeviceResource }),
        ["rawPrivateResponsesReturned"] = false,
        ["outputProjection"] = "explicit-allowlist",
        ["redactionApplied"] = true,
        ["observedAt"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
        ["versionDriftBehavior"] = "Known snake_case and camelCase aliases are projected; unavailable fields are null.",
        ["fieldProvenance"] = new JsonObject
        {
            ["clients"] = ClientResource,
            ["accessPointRadios.configured"] = DeviceResource + ".radio_table",
            ["accessPointRadios.effectiveAndOperational"] = DeviceResource + ".radio_table_stats with radio_table fallback"
        },
        ["derivedFields"] = new JsonObject
        {
            ["signal.snrDb"] = "Derived from RSSI minus noise floor only when both are available; direct controller SNR takes precedence.",
            ["network.apipa"] = "Derived from a validated 169.254.0.0/16 IPv4 address only when no direct controller APIPA field is available."
        },
        ["limitations"] = new JsonArray(
            "Private-field availability and semantics vary by Network application, AP firmware, radio, and client.",
            "A null value means the allowlisted field was unavailable; it is not evidence of a zero value or healthy state.",
            "Controller-reported association identifies the UniFi observation point and does not prove a physical path through third-party bridges.")
    };

    private static int ValidateLimit(int? requested, int defaultValue, int maximum, string name)
    {
        var value = requested ?? defaultValue;
        if (value is < 1 || value > maximum)
        {
            throw new ContractException($"{name} must be between 1 and {maximum}.");
        }

        return value;
    }

    private static string RadioKey(JsonObject radio, int index) =>
        ReadTextValue(radio, "radio", "name", "radioName")?.Trim() ?? $"index:{index}";

    private static JsonObject MergeRadio(JsonObject? configuration, JsonObject? statistics)
    {
        var merged = configuration?.DeepClone().AsObject() ?? new JsonObject();
        if (statistics is null)
        {
            return merged;
        }

        foreach (var property in statistics)
        {
            merged[property.Key] = property.Value?.DeepClone();
        }

        return merged;
    }

    private static string NormalizeRequiredMac(string value, string name) =>
        NormalizeMac(value) ?? throw new ContractException($"{name} must be a colon-delimited MAC address.");

    private static string? ReadMac(JsonObject source, params string[] names)
    {
        var value = ReadTextValue(source, names);
        return value is null ? null : NormalizeMac(value);
    }

    private static string? NormalizeMac(string value)
    {
        var normalized = value.Trim().Replace('-', ':').ToLowerInvariant();
        return MacAddressPattern().IsMatch(normalized) ? normalized : null;
    }

    private string? ReadText(JsonObject source, params string[] names)
    {
        var value = ReadTextValue(source, names);
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var redacted = _redactor.Redact(value.Trim());
        return redacted.Length <= MaximumTextLength ? redacted : redacted[..MaximumTextLength] + "…";
    }

    private static string? ReadTextValue(JsonObject source, params string[] names)
    {
        foreach (var name in names)
        {
            if (source[name] is JsonValue value && value.TryGetValue<string>(out var text))
            {
                return text;
            }
        }

        return null;
    }

    private static int? ReadInteger(JsonObject source, params string[] names)
    {
        var value = ReadLong(source, names);
        return value is >= int.MinValue and <= int.MaxValue ? (int)value.Value : null;
    }

    private static long? ReadLong(JsonObject source, params string[] names)
    {
        foreach (var name in names)
        {
            if (TryReadLong(source[name], out var value))
            {
                return value;
            }
        }

        return null;
    }

    private static bool TryReadLong(JsonNode? node, out long value)
    {
        value = default;
        if (node is not JsonValue scalar)
        {
            return false;
        }

        if (scalar.TryGetValue<long>(out value) || scalar.TryGetValue<int>(out var integer) && (value = integer) == integer)
        {
            return true;
        }

        return scalar.TryGetValue<string>(out var text) &&
            long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static double? ReadDouble(JsonObject source, params string[] names)
    {
        foreach (var name in names)
        {
            if (source[name] is not JsonValue scalar)
            {
                continue;
            }

            if (scalar.TryGetValue<double>(out var number) && double.IsFinite(number))
            {
                return number;
            }

            if (scalar.TryGetValue<long>(out var integer))
            {
                return integer;
            }

            if (scalar.TryGetValue<int>(out var intValue))
            {
                return intValue;
            }

            if (scalar.TryGetValue<decimal>(out var decimalValue))
            {
                return (double)decimalValue;
            }

            if (scalar.TryGetValue<string>(out var text) &&
                double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out number) &&
                double.IsFinite(number))
            {
                return number;
            }
        }

        return null;
    }

    private static bool? ReadBoolean(JsonObject source, params string[] names)
    {
        foreach (var name in names)
        {
            if (source[name] is not JsonValue scalar)
            {
                continue;
            }

            if (scalar.TryGetValue<bool>(out var boolean))
            {
                return boolean;
            }

            if (scalar.TryGetValue<int>(out var integer) && integer is 0 or 1)
            {
                return integer == 1;
            }

            if (scalar.TryGetValue<string>(out var text) && bool.TryParse(text, out boolean))
            {
                return boolean;
            }
        }

        return null;
    }

    private static bool? ReadWireless(JsonObject source)
    {
        var wired = ReadBoolean(source, "is_wired", "isWired");
        if (wired is not null)
        {
            return !wired.Value;
        }

        return ReadMac(source, "ap_mac", "apMac") is not null ? true : null;
    }

    private string? ReadBand(JsonObject source)
    {
        var band = ReadText(source, "band", "radio_band", "radioBand");
        if (band is not null)
        {
            return band;
        }

        var radio = ReadText(source, "radio", "radio_name", "radioName");
        return radio?.ToLowerInvariant() switch
        {
            "ng" or "2g" or "2.4g" => "2.4 GHz",
            "na" or "5g" => "5 GHz",
            "6e" or "6g" => "6 GHz",
            _ => null
        };
    }

    private static int? ReadChannelWidth(JsonObject source)
    {
        var direct = ReadInteger(source, "channel_width", "channelWidth", "channelWidthMhz");
        if (direct is not null)
        {
            return direct;
        }

        var text = ReadTextValue(source, "ht", "channel_width_name", "channelWidthName");
        if (text is null)
        {
            return null;
        }

        var digits = new string(text.Where(char.IsDigit).ToArray());
        return int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    private static double? ReadRateMbps(JsonObject source, string[] directNames, string[] kilobitNames)
    {
        var direct = ReadDouble(source, directNames);
        return direct ?? ReadDouble(source, kilobitNames) / 1000d;
    }

    private static string? ReadEpochTimestamp(JsonObject source, params string[] names)
    {
        var epoch = ReadLong(source, names);
        if (epoch is null)
        {
            return null;
        }

        try
        {
            var instant = epoch.Value > 10_000_000_000
                ? DateTimeOffset.FromUnixTimeMilliseconds(epoch.Value)
                : DateTimeOffset.FromUnixTimeSeconds(epoch.Value);
            return instant.Year >= 2000
                ? instant.ToString("O", CultureInfo.InvariantCulture)
                : null;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static string? ReadIpAddress(JsonObject source, params string[] names)
    {
        var text = ReadTextValue(source, names);
        return IPAddress.TryParse(text, out var address) ? address.ToString() : null;
    }

    private static bool? IsApipa(string? ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return ipAddress is null ? null : false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 169 && bytes[1] == 254;
    }

    [GeneratedRegex("^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex MacAddressPattern();
}
