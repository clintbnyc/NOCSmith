using System.Globalization;
using System.Text.Json.Nodes;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed class LegacyAlertService
{
    private const int DefaultLimit = 50;
    private const int MaximumLimit = 200;
    private const int MaximumTextLength = 4096;

    private static readonly (string Destination, string[] Sources)[] ScalarFields =
    {
        ("id", new[] { "_id", "id" }),
        ("eventKey", new[] { "key" }),
        ("event", new[] { "event", "event_name", "eventName", "title" }),
        ("description", new[] { "description", "msg", "message" }),
        ("severity", new[] { "severity" }),
        ("datetime", new[] { "datetime" }),
        ("time", new[] { "time" }),
        ("utcTime", new[] { "utctime", "utc_time", "utcTime" }),
        ("archived", new[] { "archived" }),
        ("read", new[] { "read", "is_read", "isRead" }),
        ("resolved", new[] { "resolved", "is_resolved", "isResolved" }),
        ("priority", new[] { "priority" }),
        ("category", new[] { "catname", "category" }),
        ("eventType", new[] { "event_type", "eventType" }),
        ("subsystem", new[] { "subsystem" }),
        ("isNegative", new[] { "is_negative", "isNegative" }),
        ("ipAddress", new[] { "ip_address", "ipAddress", "ip", "host_ip" }),
        ("referenceUrl", new[] { "reference", "reference_url", "referenceUrl", "help_url" }),
        ("cefLog", new[] { "cef", "cef_log", "cefLog" })
    };

    private static readonly (string Destination, string[] Sources)[] ContextFields =
    {
        ("host", new[] { "host" }),
        ("device", new[] { "device" }),
        ("accessPoint", new[] { "ap" }),
        ("gateway", new[] { "gw" }),
        ("switch", new[] { "sw" }),
        ("user", new[] { "user" }),
        ("sourceMacAddress", new[] { "src_mac", "sourceMacAddress" }),
        ("destinationMacAddress", new[] { "dst_mac", "destinationMacAddress" }),
        ("radio", new[] { "radio" }),
        ("interface", new[] { "in_iface", "interface" }),
        ("channel", new[] { "channel" }),
        ("duration", new[] { "duration" })
    };

    private readonly UnifiConfiguration _configuration;
    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;

    public LegacyAlertService(
        UnifiConfiguration configuration,
        ContractProvider contracts,
        IUnifiClient client,
        SiteResolver siteResolver,
        SecretRedactor redactor)
    {
        _configuration = configuration;
        _contracts = contracts;
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
        ["fixedResource"] = "stat/alarm",
        ["rawLegacyResponsesReturned"] = false,
        ["defaultLimit"] = DefaultLimit,
        ["maximumLimit"] = MaximumLimit
    };

    public async Task<ToolResponse> ReadAsync(
        string? requestedSiteId,
        bool includeArchived,
        int? requestedLimit,
        CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            throw new ConfigurationException(
                "Legacy alert reads are disabled. Set UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true to enable the fixed read-only stat/alarm resource.");
        }

        var limit = requestedLimit ?? DefaultLimit;
        if (limit is < 1 or > MaximumLimit)
        {
            throw new ContractException($"limit must be between 1 and {MaximumLimit}.");
        }

        var siteId = await _siteResolver.ResolveAsync(requestedSiteId, cancellationToken).ConfigureAwait(false);
        var internalSiteReference = await ResolveInternalSiteReferenceAsync(siteId, cancellationToken).ConfigureAwait(false);
        var response = await _client.ReadLegacyAlertsAsync(internalSiteReference, cancellationToken).ConfigureAwait(false);
        if (response?["data"] is not JsonArray data)
        {
            throw new ContractException("Legacy UniFi alert read did not return a data array.");
        }

        var matching = data
            .OfType<JsonObject>()
            .Where(record => includeArchived || !IsArchived(record))
            .ToArray();
        var records = new JsonArray(matching
            .Take(limit)
            .Select(record => (JsonNode?)Project(record))
            .ToArray());
        var result = new JsonObject
        {
            ["siteId"] = siteId,
            ["count"] = records.Count,
            ["data"] = records,
            ["_connector"] = new JsonObject
            {
                ["source"] = "legacy-private-api",
                ["fixedResource"] = "stat/alarm",
                ["readOnly"] = true,
                ["rawResponseReturned"] = false,
                ["redactionApplied"] = true,
                ["includeArchived"] = includeArchived,
                ["sourceRecordCount"] = data.Count,
                ["matchingRecordCount"] = matching.Length,
                ["truncated"] = matching.Length > records.Count,
                ["observedAt"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture)
            }
        };

        var truncation = matching.Length > records.Count ? " Results are truncated." : string.Empty;
        return new ToolResponse($"Read {records.Count} UniFi alert(s) from the fixed legacy resource.{truncation}", result);
    }

    private async Task<string> ResolveInternalSiteReferenceAsync(string siteId, CancellationToken cancellationToken)
    {
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

        return internalReference;
    }

    private JsonObject Project(JsonObject source)
    {
        var result = new JsonObject();
        CopyFields(source, result, ScalarFields);

        var context = new JsonObject();
        CopyFields(source, context, ContextFields);
        if (context.Count > 0)
        {
            result["context"] = context;
        }

        var clients = ProjectClients(source);
        if (clients.Count > 0)
        {
            result["clients"] = clients;
        }

        return result;
    }

    private JsonArray ProjectClients(JsonObject source)
    {
        var projected = new JsonArray();
        var value = source["clients"] ?? source["affected_clients"] ?? source["affectedClients"];
        var clients = value is JsonArray array ? array : value is null ? null : new JsonArray(value.DeepClone());
        foreach (var client in clients?.Take(50) ?? Array.Empty<JsonNode?>())
        {
            if (client is JsonValue scalar && scalar.TryGetValue<string>(out var text))
            {
                projected.Add(SanitizeText(text));
                continue;
            }

            if (client is not JsonObject clientObject)
            {
                continue;
            }

            var projectedClient = new JsonObject();
            CopyFields(
                clientObject,
                projectedClient,
                new[]
                {
                    ("id", new[] { "id", "_id" }),
                    ("name", new[] { "name", "display_name", "displayName", "hostname" }),
                    ("macAddress", new[] { "mac", "mac_address", "macAddress" }),
                    ("ipAddress", new[] { "ip", "ip_address", "ipAddress" })
                });
            if (projectedClient.Count > 0)
            {
                projected.Add(projectedClient);
            }
        }

        return projected;
    }

    private void CopyFields(
        JsonObject source,
        JsonObject destination,
        IEnumerable<(string Destination, string[] Sources)> fields)
    {
        foreach (var (destinationName, sourceNames) in fields)
        {
            foreach (var sourceName in sourceNames)
            {
                if (source[sourceName] is not JsonValue value)
                {
                    continue;
                }

                if (value.TryGetValue<string>(out var text))
                {
                    destination[destinationName] = SanitizeText(text);
                }
                else
                {
                    destination[destinationName] = value.DeepClone();
                }

                break;
            }
        }
    }

    private string SanitizeText(string value)
    {
        var redacted = _redactor.Redact(value.Trim());
        return redacted.Length <= MaximumTextLength
            ? redacted
            : redacted[..MaximumTextLength] + "…";
    }

    private static bool IsArchived(JsonObject record)
    {
        if (record["archived"] is not JsonValue archived)
        {
            return false;
        }

        if (archived.TryGetValue<bool>(out var boolean))
        {
            return boolean;
        }

        if (archived.TryGetValue<int>(out var integer))
        {
            return integer != 0;
        }

        return archived.TryGetValue<string>(out var text) &&
               (bool.TryParse(text, out boolean) ? boolean : string.Equals(text, "1", StringComparison.Ordinal));
    }
}
