using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp;

public static class DoctorCommand
{
    public static async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            var configuration = UnifiConfiguration.Load();
            var redactor = new SecretRedactor(configuration.ApiKey);
            using var client = new UnifiClient(configuration, NullLogger<UnifiClient>.Instance);
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
            var systemLogs = await ProbeSystemLogsAsync(
                configuration,
                client,
                sites,
                redactor,
                cancellationToken).ConfigureAwait(false);

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
                ["systemLogs"] = systemLogs,
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
            Console.Error.WriteLine("UniFi MCP doctor failed: " + new SecretRedactor(key).Redact(exception.Message));
            return 1;
        }
    }

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

    internal static int CountPrivateClientRecords(JsonNode? response)
    {
        if (response is JsonArray records)
        {
            return records.Count;
        }

        if (response?["data"] is JsonArray data)
        {
            return data.Count;
        }

        throw new ContractException(
            "Private UniFi client read did not return an array or an object containing a data array.");
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
