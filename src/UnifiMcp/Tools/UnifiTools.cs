using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Writes;

namespace UnifiMcp.Tools;

[McpServerToolType]
public static class UnifiTools
{
    [McpServerTool(
        Name = "unifi_get_capabilities",
        Title = "Get UniFi connector capabilities",
        ReadOnly = true,
        Destructive = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description("List the allowlisted UniFi API operations and report the live application and OpenAPI contract versions. Use this before the generic operation tools.")]
    public static Task<ToolResponse> GetCapabilities(
        ContractProvider contracts,
        UnifiConfiguration configuration,
        LegacyReadEnrichmentService legacyEnrichment,
        SiteManagerReadService siteManager,
        SiteManagerDeviceEnrichmentService siteManagerEnrichment,
        SystemLogReadService systemLogs,
        [Description("Probe the live controller contract again before returning capabilities.")] bool refresh = false,
        CancellationToken cancellationToken = default) =>
        Guard(async () =>
        {
            if (refresh)
            {
                await contracts.RefreshAsync(cancellationToken).ConfigureAwait(false);
            }

            var contract = contracts.Current;
            var operations = new JsonArray(contract.Operations
                .OrderBy(operation => operation.OperationId, StringComparer.Ordinal)
                .Select(operation => (JsonNode)new JsonObject
                {
                    ["operationId"] = operation.OperationId,
                    ["method"] = operation.Method.Method,
                    ["path"] = operation.PathTemplate,
                    ["summary"] = operation.Summary,
                    ["tags"] = new JsonArray(operation.Tags.Select(tag => (JsonNode?)JsonValue.Create(tag)).ToArray())
                })
                .ToArray());
            var data = new JsonObject
            {
                ["baseUrl"] = configuration.BaseUri.ToString().TrimEnd('/'),
                ["contractVersion"] = contract.Version,
                ["contractSource"] = contract.Source,
                ["contractStatus"] = contracts.Status,
                ["liveApplicationVersion"] = contracts.LiveApplicationVersion,
                ["readOperations"] = contract.ReadCount,
                ["writeOperations"] = contract.WriteCount,
                ["probeWarning"] = contracts.LastProbeWarning,
                ["knownResponseLimitations"] = ResponseMetadata.GetAllKnownLimitations(contract, legacyEnrichment.Enabled),
                ["legacyReadEnrichment"] = legacyEnrichment.Describe(),
                ["siteManager"] = siteManager.Describe(),
                ["siteManagerDeviceEnrichment"] = siteManagerEnrichment.Describe(),
                ["systemLogs"] = systemLogs.Describe(),
                ["operations"] = operations
            };
            return new ToolResponse(
                $"UniFi contract {contract.Version}: {contract.ReadCount} read and {contract.WriteCount} write operations allowlisted.",
                data);
        });

    [McpServerTool(Name = "unifi_site_manager", Title = "Read UniFi Site Manager fleet data", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read stable-v1 UniFi Site Manager host, site, and device inventory. Actions: hosts, host, sites, devices. Uses cursor pagination, never calls Early Access, SD-WAN, Cloud Connector, or write endpoints.")]
    public static Task<ToolResponse> SiteManager(
        SiteManagerReadService siteManager,
        [Description("hosts, host, sites, or devices.")] string action,
        [Description("Required for host; optional devices filter.")] string? hostId = null,
        [Description("Page size from 1 to 500. Defaults to 500.")] int? pageSize = null,
        [Description("Opaque continuation returned by a previous response.")] string? nextToken = null,
        CancellationToken cancellationToken = default) =>
        Guard(() => siteManager.ReadInventoryAsync(
            action,
            hostId,
            pageSize,
            nextToken,
            cancellationToken));

    [McpServerTool(Name = "unifi_isp_metrics", Title = "Read UniFi Site Manager ISP metrics", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read stable-v1 ISP history. Interval is 5m or 1h. Use duration (24h for 5m; 7d or 30d for 1h) or RFC3339 timestamps. Optional targets is an array of objects containing hostId and siteId.")]
    public static Task<ToolResponse> IspMetrics(
        SiteManagerReadService siteManager,
        [Description("5m or 1h.")] string interval,
        [Description("24h for 5m; 7d or 30d for 1h.")] string? duration = null,
        string? beginTimestamp = null,
        string? endTimestamp = null,
        [Description("Optional array of { hostId, siteId, beginTimestamp?, endTimestamp? }.")] JsonElement? targets = null,
        CancellationToken cancellationToken = default) =>
        Guard(() => siteManager.ReadIspMetricsAsync(
            interval,
            duration,
            beginTimestamp,
            endTimestamp,
            ToNode(targets),
            cancellationToken));

    [McpServerTool(Name = "unifi_get_site_snapshot", Title = "Get UniFi site snapshot", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Collect a recommendation-oriented snapshot of devices, clients, networks, Wi-Fi, firewall, ACL, DNS, switching, VPN, WAN, and traffic-list state. Sections report ok, notApplicable, or failed independently with source operations and observation times.")]
    public static Task<ToolResponse> GetSiteSnapshot(
        SnapshotService snapshots,
        [Description("Optional site UUID. Omit when exactly one site is available or UNIFI_DEFAULT_SITE_ID is set.")] string? siteId = null,
        CancellationToken cancellationToken = default) =>
        Guard(() => snapshots.GetAsync(siteId, cancellationToken));

    [McpServerTool(Name = "unifi_sites", Title = "Read UniFi sites", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read UniFi sites. Supported action: list.")]
    public static Task<ToolResponse> Sites(
        DomainReadService domains,
        [Description("Use list.")] string action = "list",
        int? offset = null,
        int? limit = null,
        string? filter = null,
        CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "sites", action, null, null, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_devices", Title = "Read UniFi devices", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read adopted or pending UniFi devices. Actions: pending, list, get, statistics. When opt-in legacy read enrichment is enabled, list and get responses project port labels, STP-related state and configuration fields, and notes/comments without returning raw legacy data. The normalized UniFi UI Edge/Participant role is unavailable.")]
    public static Task<ToolResponse> Devices(
        DomainReadService domains,
        [Description("pending, list, get, or statistics.")] string action,
        string? siteId = null,
        [Description("Device UUID for get or statistics.")] string? id = null,
        int? offset = null,
        int? limit = null,
        string? filter = null,
        CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "devices", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_clients", Title = "Read UniFi clients", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read connected UniFi clients. Actions: list or get. Client type and uplink are controller-reported observation points; responses warn when third-party bridging prevents a reliable physical attachment inference. Opt-in legacy read enrichment projects client notes/comments.")]
    public static Task<ToolResponse> Clients(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "clients", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_alerts", Title = "Read UniFi alerts", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read projected UniFi System Log events through one fixed query-style POST to v2/api/site/{site}/system-log/all. The operation is read-only, uses the existing Integration API key, accepts no caller-supplied request body, and never returns raw private API records.")]
    public static Task<ToolResponse> Alerts(
        SystemLogReadService systemLogs,
        [Description("Optional site UUID. Omit when exactly one site is available or UNIFI_DEFAULT_SITE_ID is set.")] string? siteId = null,
        [Description("Include records whose controller-supplied status is READ or STALED. When false, only NEW records are returned. Defaults to true.")] bool includeRead = true,
        [Description("Maximum records to return from the first controller page, from 1 to 50. Defaults to 50.")] int? limit = null,
        CancellationToken cancellationToken = default) =>
        Guard(() => systemLogs.ReadAsync(siteId, includeRead, limit, cancellationToken));

    [McpServerTool(Name = "unifi_networks", Title = "Read UniFi networks", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read UniFi networks. Actions: list, get, or references.")]
    public static Task<ToolResponse> Networks(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "networks", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_wifi", Title = "Read UniFi Wi-Fi broadcasts", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read UniFi Wi-Fi broadcasts. Actions: list or get. Secret fields are always redacted.")]
    public static Task<ToolResponse> Wifi(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "wifi", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_hotspot", Title = "Read UniFi hotspot vouchers", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read UniFi hotspot vouchers. Actions: list or get.")]
    public static Task<ToolResponse> Hotspot(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "hotspot", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_firewall", Title = "Read UniFi firewall configuration", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read firewall policies and zones. Actions: listPolicies, getPolicy, policyOrdering, listZones, getZone.")]
    public static Task<ToolResponse> Firewall(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "firewall", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_acl", Title = "Read UniFi ACL rules", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read access-control rules. Actions: list, get, or ordering.")]
    public static Task<ToolResponse> Acl(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "acl", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_switching", Title = "Read UniFi switching state", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read switching resources. Actions: listLags, getLag, listMcLagDomains, getMcLagDomain, listStacks, getStack.")]
    public static Task<ToolResponse> Switching(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "switching", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_dns", Title = "Read UniFi DNS policies", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read DNS policies. Actions: list or get.")]
    public static Task<ToolResponse> Dns(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "dns", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_traffic_lists", Title = "Read UniFi traffic matching lists", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read traffic matching lists. Actions: list or get.")]
    public static Task<ToolResponse> TrafficLists(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "traffic", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_supporting_resources", Title = "Read UniFi supporting resources", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Read supporting resources. Actions: countries, dpiApplications, dpiCategories, deviceTags, radiusProfiles, vpnServers, siteToSiteVpnTunnels, wans.")]
    public static Task<ToolResponse> SupportingResources(DomainReadService domains, string action, string? siteId = null, string? id = null, int? offset = null, int? limit = null, string? filter = null, CancellationToken cancellationToken = default) =>
        ReadDomain(domains, "supporting", action, siteId, id, offset, limit, filter, cancellationToken);

    [McpServerTool(Name = "unifi_read_operation", Title = "Read an allowlisted UniFi API operation", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Execute any GET operation present in unifi_get_capabilities. Arbitrary methods and URLs are rejected.")]
    public static Task<ToolResponse> ReadOperation(
        ReadService reads,
        [Description("Exact GET operationId returned by unifi_get_capabilities.")] string operationId,
        [Description("Named path parameters. siteId may be omitted when it can be resolved safely.")] Dictionary<string, string>? pathParameters = null,
        [Description("Named query parameters allowed by the operation schema.")] Dictionary<string, string>? queryParameters = null,
        CancellationToken cancellationToken = default) =>
        Guard(() => reads.ExecuteAsync(operationId, pathParameters, queryParameters, cancellationToken));

    [McpServerTool(Name = "unifi_preview_device_change", Title = "Preview a UniFi device change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview an allowlisted adoption, unadoption, device action, or port action. This tool performs reads only.")]
    public static Task<ToolResponse> PreviewDeviceChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "UniFi Devices", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_client_change", Title = "Preview a UniFi client change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview an allowlisted client action. This tool performs reads only.")]
    public static Task<ToolResponse> PreviewClientChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "Clients", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_network_change", Title = "Preview a UniFi network change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview a network create, update, or delete. PUT bodies are treated as changes merged onto live state.")]
    public static Task<ToolResponse> PreviewNetworkChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "Networks", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_wifi_change", Title = "Preview a UniFi Wi-Fi change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview a Wi-Fi broadcast create, update, or delete. PUT bodies are treated as changes merged onto live state; secrets are redacted.")]
    public static Task<ToolResponse> PreviewWifiChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "WiFi Broadcasts", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_hotspot_change", Title = "Preview a UniFi hotspot change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview voucher creation or deletion. Bulk deletion binds the preview to the exact matching voucher-list state.")]
    public static Task<ToolResponse> PreviewHotspotChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "Hotspot", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_firewall_change", Title = "Preview a UniFi firewall change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview firewall policy, ordering, or zone changes. PUT bodies are treated as changes merged onto live state.")]
    public static Task<ToolResponse> PreviewFirewallChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "Firewall", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_acl_change", Title = "Preview a UniFi ACL change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview ACL rule or ordering changes. PUT bodies are treated as changes merged onto live state.")]
    public static Task<ToolResponse> PreviewAclChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "Access Control (ACL Rules)", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_dns_change", Title = "Preview a UniFi DNS policy change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview DNS policy creation, update, or deletion. PUT bodies are treated as changes merged onto live state.")]
    public static Task<ToolResponse> PreviewDnsChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "DNS Policies", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_traffic_list_change", Title = "Preview a UniFi traffic-list change", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview traffic matching list creation, update, or deletion. PUT bodies are treated as changes merged onto live state.")]
    public static Task<ToolResponse> PreviewTrafficListChange(WritePlanner planner, ContractProvider contracts, string operationId, Dictionary<string, string>? pathParameters = null, Dictionary<string, string>? queryParameters = null, JsonElement? body = null, bool allowReferenced = false, CancellationToken cancellationToken = default) =>
        PreviewDomain(planner, contracts, "Traffic Matching Lists", operationId, pathParameters, queryParameters, body, allowReferenced, cancellationToken);

    [McpServerTool(Name = "unifi_preview_operation", Title = "Preview an allowlisted UniFi write operation", ReadOnly = true, Destructive = false, OpenWorld = false, UseStructuredContent = true)]
    [Description("Preview any non-GET operation returned by unifi_get_capabilities. This performs reads only. For PUT, set mergeChanges=true to overlay the body onto live state.")]
    public static Task<ToolResponse> PreviewOperation(
        WritePlanner planner,
        string operationId,
        Dictionary<string, string>? pathParameters = null,
        Dictionary<string, string>? queryParameters = null,
        JsonElement? body = null,
        bool mergeChanges = false,
        bool allowReferenced = false,
        CancellationToken cancellationToken = default) =>
        Guard(async () =>
        {
            var preview = await planner.PreviewAsync(operationId, pathParameters, queryParameters, ToNode(body), mergeChanges, allowReferenced, cancellationToken).ConfigureAwait(false);
            return PreviewResponse(preview);
        });

    [McpServerTool(
        Name = "unifi_apply_change",
        Title = "Apply a confirmed UniFi change",
        ReadOnly = false,
        Destructive = true,
        Idempotent = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description("Apply exactly one previously previewed change. Requires the opaque, single-use token returned by a preview tool. Never call without explicit user approval of that preview.")]
    public static Task<ToolResponse> ApplyChange(
        WritePlanner planner,
        [Description("Single-use confirmation token returned by the exact preview the user approved.")] string confirmationToken,
        CancellationToken cancellationToken = default) =>
        Guard(async () =>
        {
            var result = await planner.ApplyAsync(confirmationToken, cancellationToken).ConfigureAwait(false);
            return new ToolResponse(
                $"Applied {result.Summary} ({result.Method} {result.Target}).",
                JsonSerializer.SerializeToNode(result));
        });

    private static Task<ToolResponse> ReadDomain(
        DomainReadService domains,
        string domain,
        string action,
        string? siteId,
        string? id,
        int? offset,
        int? limit,
        string? filter,
        CancellationToken cancellationToken) =>
        Guard(() => domains.ExecuteAsync(domain, action, siteId, id, offset, limit, filter, cancellationToken));

    private static Task<ToolResponse> PreviewDomain(
        WritePlanner planner,
        ContractProvider contracts,
        string requiredTag,
        string operationId,
        Dictionary<string, string>? pathParameters,
        Dictionary<string, string>? queryParameters,
        JsonElement? body,
        bool allowReferenced,
        CancellationToken cancellationToken) =>
        Guard(async () =>
        {
            var operation = contracts.Current.GetOperation(operationId, requireRead: false);
            if (!operation.Tags.Contains(requiredTag, StringComparer.Ordinal))
            {
                throw new ContractException($"Operation '{operationId}' is not in the {requiredTag} domain.");
            }

            var mergeChanges = operation.Method == HttpMethod.Put;
            var preview = await planner.PreviewAsync(operationId, pathParameters, queryParameters, ToNode(body), mergeChanges, allowReferenced, cancellationToken).ConfigureAwait(false);
            return PreviewResponse(preview);
        });

    private static ToolResponse PreviewResponse(ChangePreview preview) =>
        new(
            $"Previewed {preview.Summary} ({preview.Method} {preview.Target}). No mutation was sent. Token expires at {preview.ExpiresAt:O}.",
            JsonSerializer.SerializeToNode(preview));

    private static JsonNode? ToNode(JsonElement? body) =>
        body is null ? null : JsonNode.Parse(body.Value.GetRawText());

    private static async Task<ToolResponse> Guard(Func<Task<ToolResponse>> action)
    {
        try
        {
            return await action().ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is ConfigurationException or
            ContractException or
            UnifiApiException or
            SiteManagerApiException or
            SiteManagerRateLimitQueueException or
            ConfirmationException)
        {
            throw new McpException(exception.Message, exception);
        }
    }
}
