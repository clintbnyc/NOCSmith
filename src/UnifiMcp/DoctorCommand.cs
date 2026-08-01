using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Journal;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp;

public static class DoctorCommand
{
    public static async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            var configuration = UnifiConfiguration.Load();
            var redactor = new SecretRedactor(
                configuration.ApiKey,
                configuration.SiteManagerApiKey);
            using var client = new UnifiClient(configuration, NullLogger<UnifiClient>.Instance);
            using var siteManagerClient = new SiteManagerClient(
                configuration,
                redactor,
                NullLogger<SiteManagerClient>.Instance);
            var siteManager = new SiteManagerReadService(
                configuration,
                siteManagerClient,
                redactor);
            var embedded = OpenApiContract.LoadEmbedded();
            var provider = new ContractProvider(embedded, client, NullLogger<ContractProvider>.Instance);
            await provider.RefreshAsync(cancellationToken).ConfigureAwait(false);

            var infoOperation = provider.Current.GetOperation("getInfo", requireRead: true);
            var info = await client.ReadAsync(
                provider.Current.ValidateAndBuild(infoOperation, null, null, null),
                cancellationToken).ConfigureAwait(false);
            var sitesOperation = provider.Current.GetOperation("getSiteOverviewPage", requireRead: true);
            var sites = await client.ReadAsync(
                provider.Current.ValidateAndBuild(
                    sitesOperation,
                    null,
                    new Dictionary<string, string> { ["offset"] = "0", ["limit"] = "200" },
                    null),
                cancellationToken).ConfigureAwait(false);
            var legacyReadEnrichment = await ProbeLegacyReadEnrichmentAsync(
                configuration,
                client,
                sites,
                redactor,
                cancellationToken).ConfigureAwait(false);
            var clientGroups = await ProbeClientGroupsAsync(
                configuration,
                client,
                provider,
                redactor,
                cancellationToken).ConfigureAwait(false);
            var clientHistory = await ProbeClientHistoryAsync(
                configuration,
                client,
                provider,
                redactor,
                cancellationToken).ConfigureAwait(false);
            var systemLogs = await ProbeSystemLogsAsync(
                configuration,
                client,
                sites,
                redactor,
                cancellationToken).ConfigureAwait(false);
            var siteManagerStatus = await ProbeSiteManagerAsync(
                configuration,
                siteManager,
                redactor,
                cancellationToken).ConfigureAwait(false);
            var journalHealth = new ClientJournalStore(configuration).Inspect();

            var result = new JsonObject
            {
                ["ok"] = true,
                ["baseUrl"] = configuration.BaseUri.ToString().TrimEnd('/'),
                ["apiKeyInjected"] = !string.IsNullOrWhiteSpace(configuration.ApiKey),
                ["tlsValidation"] = "system trust and hostname validation",
                ["liveApplicationVersion"] = provider.LiveApplicationVersion,
                ["contractVersion"] = provider.Current.Version,
                ["contractSource"] = provider.Current.Source,
                ["contractStatus"] = provider.Status,
                ["contractWarning"] = provider.LastProbeWarning,
                ["legacyReadEnrichment"] = legacyReadEnrichment,
                ["clientGroups"] = clientGroups,
                ["clientHistory"] = clientHistory,
                ["clientJournal"] = new JsonObject
                {
                    ["state"] = journalHealth.Oversized && journalHealth.State == "healthy"
                        ? "oversized"
                        : journalHealth.State,
                    ["enabled"] = configuration.EnableClientJournal,
                    ["schemaVersion"] = journalHealth.SchemaVersion,
                    ["walMode"] = journalHealth.WalMode,
                    ["activeBytes"] = journalHealth.ActiveBytes,
                    ["retentionDays"] = journalHealth.RetentionDays,
                    ["maximumMib"] = journalHealth.MaximumMib,
                    ["quarantineSetCount"] = journalHealth.Quarantine.Count,
                    ["readOnlyInspection"] = true
                },
                ["systemLogs"] = systemLogs,
                ["siteManager"] = siteManagerStatus,
                ["application"] = redactor.Redact(info),
                ["siteCount"] = sites?["totalCount"]?.DeepClone()
                    ?? sites?["count"]?.DeepClone()
                    ?? JsonValue.Create((sites?["data"] as JsonArray)?.Count ?? 0)
            };
            Console.Out.WriteLine(result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        catch (Exception exception) when (exception is ConfigurationException or ContractException or UnifiApiException or HttpRequestException or TaskCanceledException)
        {
            var key = Environment.GetEnvironmentVariable("UNIFI_API_KEY");
            var siteKey = Environment.GetEnvironmentVariable("UNIFI_SITE_API_KEY");
            Console.Error.WriteLine(
                "NOCsmith doctor failed: " +
                new SecretRedactor(key, siteKey).Redact(exception.Message));
            return 1;
        }
    }

    private static async Task<JsonObject> ProbeSiteManagerAsync(
        UnifiConfiguration configuration,
        SiteManagerReadService siteManager,
        SecretRedactor redactor,
        CancellationToken cancellationToken)
    {
        if (!configuration.SiteManagerConfigured)
        {
            return new JsonObject
            {
                ["configured"] = false,
                ["status"] = "notConfigured",
                ["readOnly"] = true
            };
        }

        try
        {
            var hosts = await siteManager.ReadInventoryAsync(
                "hosts",
                null,
                500,
                null,
                cancellationToken).ConfigureAwait(false);
            var sites = await siteManager.ReadInventoryAsync(
                "sites",
                null,
                500,
                null,
                cancellationToken).ConfigureAwait(false);
            var devices = await siteManager.ReadInventoryAsync(
                "devices",
                configuration.SiteManagerLocalHostId,
                500,
                null,
                cancellationToken).ConfigureAwait(false);
            var now = DateTimeOffset.UtcNow;
            var ispMetrics = await siteManager.ReadIspMetricsAsync(
                "5m",
                null,
                now.AddMinutes(-5).ToString("O"),
                now.ToString("O"),
                null,
                cancellationToken).ConfigureAwait(false);
            var hostMapping = await siteManager.GetHostMappingStatusAsync(cancellationToken)
                .ConfigureAwait(false);
            var statuses = new[] { hosts, sites, devices, ispMetrics }
                .Select(item => item.Data?["status"]?.GetValue<string>())
                .ToArray();
            var coreReadsHealthy = statuses.All(status =>
                string.Equals(status, "ok", StringComparison.Ordinal));
            var hostMappingRequired =
                !string.IsNullOrWhiteSpace(configuration.SiteManagerLocalHostId);
            var hostMappingHealthy = !hostMappingRequired ||
                string.Equals(
                    hostMapping["status"]?.GetValue<string>(),
                    "mapped",
                    StringComparison.Ordinal);
            return new JsonObject
            {
                ["configured"] = true,
                ["status"] = coreReadsHealthy && hostMappingHealthy
                    ? "ok"
                    : !coreReadsHealthy
                        ? statuses.FirstOrDefault(status =>
                            !string.Equals(status, "ok", StringComparison.Ordinal)) ?? "failed"
                        : "degraded",
                ["readOnly"] = true,
                ["apiVersion"] = "v1-stable",
                ["localHostIdConfigured"] =
                    !string.IsNullOrWhiteSpace(configuration.SiteManagerLocalHostId),
                ["hostMapping"] = hostMapping,
                ["hostRecords"] = CountRecords(hosts.Data),
                ["siteRecords"] = CountRecords(sites.Data),
                ["deviceHostGroups"] = CountRecords(devices.Data),
                ["ispMetricSeries"] = CountRecords(ispMetrics.Data),
                ["ispMetricWindowMinutes"] = 5,
                ["rateLimit"] = siteManager.Describe()["rateLimit"]?.DeepClone()
            };
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SiteManagerApiException or
            SiteManagerRateLimitQueueException or
            ConfigurationException or
            ContractException or
            HttpRequestException or
            TaskCanceledException or
            InvalidOperationException)
        {
            var failed = new JsonObject
            {
                ["configured"] = true,
                ["status"] = exception is SiteManagerApiException { IsRateLimited: true }
                    ? "rateLimited"
                    : "failed",
                ["readOnly"] = true,
                ["error"] = redactor.Redact(exception.Message)
            };
            if (exception is SiteManagerApiException apiException)
            {
                failed["httpStatus"] = (int)apiException.StatusCode;
                failed["errorCode"] = apiException.Code;
                failed["retryAt"] = apiException.RetryAt?.ToString("O");
            }

            return failed;
        }
    }

    private static int CountRecords(JsonNode? response) =>
        (response?["data"] as JsonArray)?.Count ?? 0;

    private static async Task<JsonObject> ProbeLegacyReadEnrichmentAsync(
        UnifiConfiguration configuration,
        UnifiClient client,
        JsonNode? sites,
        SecretRedactor redactor,
        CancellationToken cancellationToken)
    {
        if (!configuration.EnableLegacyReadEnrichment)
        {
            return new JsonObject { ["enabled"] = false, ["status"] = "disabled" };
        }

        try
        {
            var site = (sites?["data"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault()
                ?? throw new ContractException("No site was available for the private read-enrichment probe.");
            var internalReference = site["internalReference"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(internalReference))
            {
                throw new ContractException("The site did not include the private API internalReference.");
            }

            var devices = await client.ReadLegacyDevicesAsync(internalReference, cancellationToken).ConfigureAwait(false);
            var clients = await client.ReadPrivateClientsAsync(internalReference, cancellationToken).ConfigureAwait(false);
            var clientRecordCount = CountPrivateClientRecords(clients);
            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = "ok",
                ["readOnly"] = true,
                ["deviceRecords"] = (devices?["data"] as JsonArray)?.Count ?? 0,
                ["clientRecords"] = clientRecordCount,
                ["deviceSource"] = "legacy-private-api",
                ["clientSource"] = "private-v2-api",
                ["rawResponsesReturned"] = false
            };
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = "failed",
                ["readOnly"] = true,
                ["error"] = redactor.Redact(exception.Message)
            };
        }
    }

    internal static int CountPrivateClientRecords(JsonNode? response) =>
        PrivateReadResponseParser.ReadRecords(response).Count;

    private static async Task<JsonObject> ProbeClientHistoryAsync(
        UnifiConfiguration configuration,
        UnifiClient client,
        ContractProvider contracts,
        SecretRedactor redactor,
        CancellationToken cancellationToken)
    {
        if (!configuration.EnableLegacyReadEnrichment)
        {
            return new JsonObject { ["enabled"] = false, ["status"] = "disabled" };
        }

        try
        {
            var siteResolver = new SiteResolver(configuration, contracts, client);
            var service = new ClientHistoryReadService(
                configuration,
                client,
                contracts,
                siteResolver,
                redactor);
            var response = await service
                .ReadAsync(
                    configuration.DefaultSiteId,
                    requestedHistoryHours: 24,
                    requestedOffset: 0,
                    requestedLimit: 200,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var data = response.Data as JsonObject
                ?? throw new ContractException("Client-history probe did not return an object.");
            var metadata = data["_connector"] as JsonObject
                ?? throw new ContractException("Client-history probe did not return connector metadata.");
            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = metadata["status"]?.DeepClone() ?? JsonValue.Create("failed"),
                ["readOnly"] = true,
                ["historyHours"] = data["historyWindow"]?["effectiveHours"]?.DeepClone(),
                ["onlineRecords"] = data["counts"]?["online"]?.DeepClone(),
                ["offlineRecordsWithinWindow"] = data["counts"]?["offlineWithinWindow"]?.DeepClone(),
                ["maclessTeleportRecordsSuppressed"] =
                    data["counts"]?["maclessTeleportRecordsSuppressed"]?.DeepClone(),
                ["groupMembersWithoutHistoryRecords"] =
                    data["counts"]?["groupMembersWithoutHistory"]?.DeepClone(),
                ["source"] = "private-v2-client-history-api",
                ["rawResponsesReturned"] = false,
                ["reasonCode"] = metadata["reasonCode"]?.DeepClone(),
                ["reason"] = metadata["reason"]?.DeepClone()
            };
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
            InvalidOperationException)
        {
            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = "failed",
                ["readOnly"] = true,
                ["error"] = redactor.Redact(exception.Message)
            };
        }
    }

    private static async Task<JsonObject> ProbeClientGroupsAsync(
        UnifiConfiguration configuration,
        UnifiClient client,
        ContractProvider contracts,
        SecretRedactor redactor,
        CancellationToken cancellationToken)
    {
        if (!configuration.EnableLegacyReadEnrichment)
        {
            return new JsonObject { ["enabled"] = false, ["status"] = "disabled" };
        }

        try
        {
            var siteResolver = new SiteResolver(configuration, contracts, client);
            var service = new Tools.ClientGroupReadService(
                configuration,
                client,
                contracts,
                siteResolver,
                redactor);
            var response = await service
                .ReadAsync("audit", configuration.DefaultSiteId, includeMembers: false, cancellationToken)
                .ConfigureAwait(false);
            var data = response.Data as JsonObject
                ?? throw new ContractException("Client-group audit did not return an object.");
            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = "ok",
                ["readOnly"] = true,
                ["groupRecords"] = data["groupCount"]?.DeepClone(),
                ["connectedClientRecords"] = data["connectedClientCount"]?.DeepClone(),
                ["ungroupedConnectedClientRecords"] = data["ungroupedConnectedClientCount"]?.DeepClone(),
                ["source"] = "private-v2-network-members-groups-api",
                ["rawResponsesReturned"] = false
            };
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = "failed",
                ["readOnly"] = true,
                ["error"] = redactor.Redact(exception.Message)
            };
        }
    }

    private static async Task<JsonObject> ProbeSystemLogsAsync(
        UnifiConfiguration configuration,
        UnifiClient client,
        JsonNode? sites,
        SecretRedactor redactor,
        CancellationToken cancellationToken)
    {
        if (!configuration.EnableLegacyReadEnrichment)
        {
            return new JsonObject { ["enabled"] = false, ["status"] = "disabled" };
        }

        try
        {
            var site = (sites?["data"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault()
                ?? throw new ContractException("No site was available for the private System Logs probe.");
            var internalReference = site["internalReference"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(internalReference))
            {
                throw new ContractException("The site did not include the private API internalReference.");
            }

            var systemLogs = await client.QuerySystemLogsAsync(internalReference, cancellationToken).ConfigureAwait(false);
            if (systemLogs?["data"] is not JsonArray data)
            {
                throw new ContractException("Private UniFi System Logs query did not return a data array.");
            }

            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = "ok",
                ["readOnly"] = true,
                ["queryStylePost"] = true,
                ["alertRecords"] = data.Count,
                ["sourcePageNumber"] = systemLogs["page_number"]?.DeepClone(),
                ["sourceTotalElementCount"] = systemLogs["total_element_count"]?.DeepClone(),
                ["sourceTotalPageCount"] = systemLogs["total_page_count"]?.DeepClone(),
                ["rawResponsesReturned"] = false
            };
        }
        catch (UnifiApiException exception) when (
            exception.StatusCode == HttpStatusCode.NotFound &&
            string.Equals(exception.Code, "api.err.NotFound", StringComparison.Ordinal))
        {
            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = "notSupported",
                ["readOnly"] = true,
                ["httpStatus"] = (int)exception.StatusCode,
                ["reasonCode"] = exception.Code,
                ["reason"] = "This UniFi Network version does not expose the fixed private System Logs query to the Integration API key."
            };
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            return new JsonObject
            {
                ["enabled"] = true,
                ["status"] = "failed",
                ["readOnly"] = true,
                ["error"] = redactor.Redact(exception.Message)
            };
        }
    }
}
