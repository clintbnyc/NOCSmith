using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed class SiteManagerDeviceEnrichmentService
{
    private const string DeviceDetailsOperationId = "getAdoptedDeviceDetails";
    private const string DeviceOverviewOperationId = "getAdoptedDeviceOverviewPage";
    private const int MaximumFreeTextLength = 4096;

    private readonly UnifiConfiguration _configuration;
    private readonly SiteManagerReadService _siteManager;
    private readonly SecretRedactor _redactor;
    private readonly ILogger<SiteManagerDeviceEnrichmentService> _logger;

    public SiteManagerDeviceEnrichmentService(
        UnifiConfiguration configuration,
        SiteManagerReadService siteManager,
        SecretRedactor redactor,
        ILogger<SiteManagerDeviceEnrichmentService> logger)
    {
        _configuration = configuration;
        _siteManager = siteManager;
        _redactor = redactor;
        _logger = logger;
    }

    public async Task<JsonNode?> EnrichAsync(
        string operationId,
        JsonNode? response,
        CancellationToken cancellationToken)
    {
        if (response is not JsonObject responseObject ||
            operationId is not DeviceDetailsOperationId and not DeviceOverviewOperationId)
        {
            return response;
        }

        var connector = GetOrCreateConnector(responseObject);
        if (!_configuration.SiteManagerConfigured)
        {
            connector["siteManagerEnrichment"] = new JsonObject
            {
                ["status"] = "notConfigured",
                ["readOnly"] = true
            };
            return responseObject;
        }

        if (string.IsNullOrWhiteSpace(_configuration.SiteManagerLocalHostId))
        {
            connector["siteManagerEnrichment"] = new JsonObject
            {
                ["status"] = "hostMappingRequired",
                ["readOnly"] = true,
                ["reason"] = "Set UNIFI_SITE_MANAGER_LOCAL_HOST_ID to enable deterministic local-device enrichment."
            };
            return responseObject;
        }

        try
        {
            var observedAt = DateTimeOffset.UtcNow;
            var groups = await _siteManager.GetAllDevicesForHostAsync(
                _configuration.SiteManagerLocalHostId,
                cancellationToken).ConfigureAwait(false);
            connector["siteManagerEnrichment"] = Project(
                responseObject,
                groups,
                _configuration.SiteManagerLocalHostId,
                observedAt);
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
            var safeMessage = _redactor.Redact(exception.Message);
            var failed = new JsonObject
            {
                ["status"] = exception is SiteManagerApiException { IsRateLimited: true }
                    ? "rateLimited"
                    : "failed",
                ["readOnly"] = true,
                ["error"] = safeMessage
            };
            if (exception is SiteManagerApiException apiException)
            {
                failed["httpStatus"] = (int)apiException.StatusCode;
                failed["errorCode"] = apiException.Code;
                failed["retryAt"] = apiException.RetryAt?.ToString("O", CultureInfo.InvariantCulture);
            }

            connector["siteManagerEnrichment"] = failed;
            _logger.LogWarning(
                "Optional Site Manager enrichment failed for {OperationId}: {Message}",
                operationId,
                safeMessage);
        }

        return responseObject;
    }

    public JsonObject Describe() => new()
    {
        ["configured"] = _configuration.SiteManagerConfigured,
        ["readOnly"] = true,
        ["localHostIdConfigured"] =
            !string.IsNullOrWhiteSpace(_configuration.SiteManagerLocalHostId),
        ["joinKey"] = "normalized device MAC address",
        ["authoritativeSource"] = "local Network API",
        ["projectedFields"] = new JsonArray(
            "cloudStatus",
            "firmwareVersion",
            "firmwareStatus",
            "updateAvailable",
            "note",
            "updatedAt"),
        ["overwritesLocalFields"] = false
    };

    private JsonObject Project(
        JsonObject officialResponse,
        JsonArray groups,
        string hostId,
        DateTimeOffset observedAt)
    {
        var providerRecords = groups
            .OfType<JsonObject>()
            .SelectMany(group =>
            {
                var updatedAt = group["updatedAt"]?.DeepClone();
                return (group["devices"] as JsonArray)?.OfType<JsonObject>()
                    .Select(device => new ProviderDevice(device, updatedAt))
                    ?? Array.Empty<ProviderDevice>();
            })
            .Where(record => NormalizeMac(ReadString(record.Device, "mac")) is not null)
            .GroupBy(
                record => NormalizeMac(ReadString(record.Device, "mac"))!,
                StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);
        var records = new JsonArray();
        var ambiguousMacs = new JsonArray();
        foreach (var provider in providerRecords.Where(item => item.Value.Length > 1))
        {
            ambiguousMacs.Add(provider.Key);
        }

        foreach (var official in ReadOfficialRecords(officialResponse))
        {
            var mac = NormalizeMac(ReadString(official, "macAddress") ?? ReadString(official, "mac"));
            if (mac is null ||
                !providerRecords.TryGetValue(mac, out var matches) ||
                matches.Length != 1)
            {
                continue;
            }

            var projected = ProjectRecord(official, matches[0], mac, observedAt);
            if (projected.Count > 4)
            {
                records.Add(projected);
            }
        }

        return new JsonObject
        {
            ["status"] = "ok",
            ["readOnly"] = true,
            ["source"] = "site-manager-v1",
            ["hostId"] = hostId,
            ["observedAt"] = observedAt.ToString("O", CultureInfo.InvariantCulture),
            ["joinKey"] = "normalized device MAC address",
            ["matchedRecords"] = records.Count,
            ["ambiguousProviderMacs"] = ambiguousMacs,
            ["overwritesLocalFields"] = false,
            ["records"] = records
        };
    }

    private JsonObject ProjectRecord(
        JsonObject official,
        ProviderDevice provider,
        string mac,
        DateTimeOffset observedAt)
    {
        var result = new JsonObject
        {
            ["macAddress"] = mac,
            ["source"] = "site-manager-v1",
            ["observedAt"] = observedAt.ToString("O", CultureInfo.InvariantCulture)
        };
        CopyScalar(official, result, "id", "localDeviceId");
        CopyScalar(provider.Device, result, "id", "siteManagerDeviceId");
        CopyScalar(provider.Device, result, "status", "cloudStatus");
        CopyScalar(provider.Device, result, "version", "firmwareVersion");
        CopyScalar(provider.Device, result, "firmwareStatus", "firmwareStatus");
        CopyScalar(provider.Device, result, "updateAvailable", "updateAvailable");
        CopyFreeText(provider.Device, result, "note");
        if (provider.UpdatedAt is not null)
        {
            result["updatedAt"] = provider.UpdatedAt.DeepClone();
        }

        return result;
    }

    private void CopyFreeText(JsonObject source, JsonObject destination, string name)
    {
        var value = ReadString(source, name);
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var safe = _redactor.Redact(value.Trim());
        destination[name] = safe.Length <= MaximumFreeTextLength
            ? safe
            : safe[..MaximumFreeTextLength] + "…";
    }

    private static void CopyScalar(
        JsonObject source,
        JsonObject destination,
        string sourceName,
        string destinationName)
    {
        if (source[sourceName] is JsonValue value)
        {
            destination[destinationName] = value.DeepClone();
        }
    }

    private static string? ReadString(JsonObject source, string name) =>
        source[name] is JsonValue value && value.TryGetValue<string>(out var text)
            ? text
            : null;

    private static string? NormalizeMac(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = new string(value.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        return normalized.Length == 12 ? normalized : null;
    }

    private static IEnumerable<JsonObject> ReadOfficialRecords(JsonObject response) =>
        response["data"] is JsonArray page
            ? page.OfType<JsonObject>()
            : new[] { response };

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

    private sealed record ProviderDevice(JsonObject Device, JsonNode? UpdatedAt);
}
