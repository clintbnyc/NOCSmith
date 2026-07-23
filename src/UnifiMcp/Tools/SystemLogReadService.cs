using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed class SystemLogReadService
{
    private const int DefaultLimit = 50;
    private const int MaximumLimit = 50;
    private const int MaximumTextLength = 4096;

    private static readonly (string Destination, string[] Sources)[] ScalarFields =
    {
        ("id", new[] { "_id", "id" }),
        ("eventKey", new[] { "key" }),
        ("event", new[] { "event", "event_name", "eventName", "title" }),
        ("description", new[] { "description", "message_raw", "msg", "message" }),
        ("titleRaw", new[] { "title_raw" }),
        ("severity", new[] { "severity" }),
        ("status", new[] { "status" }),
        ("type", new[] { "type" }),
        ("subcategory", new[] { "subcategory" }),
        ("target", new[] { "target" }),
        ("timestamp", new[] { "timestamp" }),
        ("showOnDashboard", new[] { "show_on_dashboard", "showOnDashboard" }),
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

    private static readonly (string Destination, string[] Sources)[] ParameterFields =
    {
        ("ipAddress", new[] { "IP" }),
        ("referenceUrl", new[] { "LEARN_MORE" }),
        ("object", new[] { "OBJECT" }),
        ("consoleName", new[] { "CONSOLE_NAME" }),
        ("count", new[] { "COUNT" }),
        ("platform", new[] { "PLATFORM" }),
        ("section", new[] { "SECTION" }),
        ("admin", new[] { "ADMIN" }),
        ("adminActivityId", new[] { "ADMIN_ACTIVITY_ID" })
    };

    private readonly UnifiConfiguration _configuration;
    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;

    public SystemLogReadService(
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
        ["queryStylePost"] = true,
        ["authentication"] = "existing X-API-Key",
        ["fixedResource"] = "v2/api/site/{site}/system-log/all",
        ["verifiedApplicationVersion"] = "10.4.57",
        ["rawPrivateResponsesReturned"] = false,
        ["defaultLimit"] = DefaultLimit,
        ["maximumLimit"] = MaximumLimit
    };

    public async Task<ToolResponse> ReadAsync(
        string? requestedSiteId,
        bool includeRead,
        int? requestedLimit,
        CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            throw new ConfigurationException(
                "Private System Logs reads are disabled. Set UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true to enable the fixed read-only system-log/all query.");
        }

        var limit = requestedLimit ?? DefaultLimit;
        if (limit is < 1 or > MaximumLimit)
        {
            throw new ContractException($"limit must be between 1 and {MaximumLimit}.");
        }

        var siteId = await _siteResolver.ResolveAsync(requestedSiteId, cancellationToken).ConfigureAwait(false);
        var internalSiteReference = await ResolveInternalSiteReferenceAsync(siteId, cancellationToken).ConfigureAwait(false);
        JsonNode? response;
        try
        {
            response = await _client.QuerySystemLogsAsync(internalSiteReference, cancellationToken).ConfigureAwait(false);
        }
        catch (UnifiApiException exception) when (IsUnsupportedResource(exception))
        {
            return CreateNotSupportedResponse(siteId, exception);
        }

        if (response?["data"] is not JsonArray data)
        {
            throw new ContractException("Private UniFi System Logs query did not return a data array.");
        }

        var matching = data
            .OfType<JsonObject>()
            .Where(record => includeRead || HasStatus(record, "NEW"))
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
                ["status"] = "ok",
                ["source"] = "private-system-log-api",
                ["fixedResource"] = "v2/api/site/{site}/system-log/all",
                ["readOnly"] = true,
                ["queryStylePost"] = true,
                ["rawResponseReturned"] = false,
                ["redactionApplied"] = true,
                ["includeRead"] = includeRead,
                ["sourceRecordCount"] = data.Count,
                ["matchingRecordCount"] = matching.Length,
                ["sourcePageNumber"] = response["page_number"]?.DeepClone(),
                ["sourceTotalElementCount"] = response["total_element_count"]?.DeepClone(),
                ["sourceTotalPageCount"] = response["total_page_count"]?.DeepClone(),
                ["truncated"] = matching.Length > records.Count || HasAdditionalSourcePages(response),
                ["observedAt"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture)
            }
        };

        var truncation = matching.Length > records.Count || HasAdditionalSourcePages(response)
            ? " Results are truncated to the first controller page."
            : string.Empty;
        return new ToolResponse($"Read {records.Count} UniFi System Log event(s) from the fixed private resource.{truncation}", result);
    }

    private static ToolResponse CreateNotSupportedResponse(string siteId, UnifiApiException exception)
    {
        var result = new JsonObject
        {
            ["siteId"] = siteId,
            ["count"] = 0,
            ["data"] = new JsonArray(),
            ["_connector"] = new JsonObject
            {
                ["status"] = "notSupported",
                ["source"] = "private-system-log-api",
                ["fixedResource"] = "v2/api/site/{site}/system-log/all",
                ["readOnly"] = true,
                ["queryStylePost"] = true,
                ["rawResponseReturned"] = false,
                ["httpStatus"] = (int)exception.StatusCode,
                ["reasonCode"] = exception.Code,
                ["reason"] = "This UniFi Network version does not expose the fixed private System Logs query to the Integration API key."
            }
        };
        return new ToolResponse(
            "Private UniFi System Logs reads are not supported by this Network version; no event data was returned.",
            result);
    }

    private static bool IsUnsupportedResource(UnifiApiException exception) =>
        exception.StatusCode == HttpStatusCode.NotFound &&
        string.Equals(exception.Code, "api.err.NotFound", StringComparison.Ordinal);

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
            throw new ContractException($"Site {siteId} did not include the private API internalReference.");
        }

        return internalReference;
    }

    private JsonObject Project(JsonObject source)
    {
        var result = new JsonObject();
        CopyFields(source, result, ScalarFields);

        var context = new JsonObject();
        CopyFields(source, context, ContextFields);
        if (source["parameters"] is JsonObject parameters)
        {
            CopyFields(parameters, context, ParameterFields);
        }

        if (context.Count > 0)
        {
            result["context"] = context;
        }

        var clients = ProjectClients(source);
        if (clients.Count == 0 && source["parameters"] is JsonObject clientParameters)
        {
            clients = ProjectClients(clientParameters);
        }

        if (clients.Count > 0)
        {
            result["clients"] = clients;
        }

        return result;
    }

    private JsonArray ProjectClients(JsonObject source)
    {
        var projected = new JsonArray();
        var value = source["clients"] ?? source["CLIENTS"] ?? source["affected_clients"] ?? source["affectedClients"];
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

    private static bool HasStatus(JsonObject record, string expected)
    {
        return record["status"] is JsonValue status &&
               status.TryGetValue<string>(out var text) &&
               string.Equals(text, expected, StringComparison.Ordinal);
    }

    private static bool HasAdditionalSourcePages(JsonNode response) =>
        response["total_page_count"] is JsonValue totalPages &&
        totalPages.TryGetValue<int>(out var count) &&
        count > 1;
}
