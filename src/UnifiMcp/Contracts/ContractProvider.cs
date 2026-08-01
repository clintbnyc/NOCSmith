using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using UnifiMcp.Api;

namespace UnifiMcp.Contracts;

public sealed class ContractProvider
{
    private static readonly ContractLocation[] LocalContractLocations =
    {
        new("../api-docs/integration.json", "/proxy/network/api-docs/integration.json"),
        new("openapi.json", "/proxy/network/integration/openapi.json"),
        new("v1/openapi.json", "/proxy/network/integration/v1/openapi.json"),
        new("swagger.json", "/proxy/network/integration/swagger.json"),
        new("v1/swagger.json", "/proxy/network/integration/v1/swagger.json"),
        new("api-docs", "/proxy/network/integration/api-docs")
    };

    private readonly IUnifiClient _client;
    private readonly ILogger<ContractProvider> _logger;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    public ContractProvider(OpenApiContract embedded, IUnifiClient client, ILogger<ContractProvider> logger)
    {
        Current = embedded;
        _client = client;
        _logger = logger;
    }

    public OpenApiContract Current { get; private set; }

    public string? LiveApplicationVersion { get; private set; }

    public string? LastProbeWarning { get; private set; }

    public string Status => Current.Source.StartsWith("controller:", StringComparison.Ordinal)
        ? "controller-match"
        : string.IsNullOrWhiteSpace(LiveApplicationVersion)
            ? "unverified"
            : string.Equals(Current.Version, LiveApplicationVersion, StringComparison.Ordinal)
                ? "embedded-match"
                : "embedded-fallback";

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var embedded = Current.Source == "embedded" ? Current : OpenApiContract.LoadEmbedded();
            Current = embedded;
            LiveApplicationVersion = null;
            LastProbeWarning = null;

            JsonNode? info;
            try
            {
                var infoOperation = embedded.GetOperation("getInfo", requireRead: true);
                info = await _client.ReadAsync(embedded.ValidateAndBuild(infoOperation, null, null, null), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is UnifiApiException or HttpRequestException or TaskCanceledException)
            {
                LastProbeWarning = $"Live contract probe could not read /v1/info: {exception.Message}";
                _logger.LogWarning("{Warning}", LastProbeWarning);
                return;
            }

            LiveApplicationVersion = FindVersion(info);
            foreach (var location in LocalContractLocations)
            {
                try
                {
                    var candidate = await _client.GetFixedAsync(location.RequestPath, cancellationToken).ConfigureAwait(false);
                    if (candidate is not JsonObject candidateObject || candidateObject["paths"] is not JsonObject)
                    {
                        continue;
                    }

                    var contract = OpenApiContract.Parse(
                        candidateObject.ToJsonString(),
                        "controller:" + location.SourcePath);
                    if (!string.IsNullOrWhiteSpace(LiveApplicationVersion) &&
                        !string.Equals(contract.Version, LiveApplicationVersion, StringComparison.Ordinal))
                    {
                        LastProbeWarning = $"Controller contract {contract.Version} did not match live Network {LiveApplicationVersion}; " +
                            $"operations remain restricted to reviewed embedded {embedded.Version}, and response fields outside that contract may be unavailable.";
                        continue;
                    }

                    Current = contract;
                    LastProbeWarning = null;
                    _logger.LogInformation(
                        "Loaded UniFi Network {Version} contract from {Path}.",
                        contract.Version,
                        location.SourcePath);
                    return;
                }
                catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException)
                {
                    _logger.LogDebug(
                        "UniFi contract probe path {Path} was unavailable: {Message}",
                        location.SourcePath,
                        exception.Message);
                }
            }

            if (!string.Equals(LiveApplicationVersion, embedded.Version, StringComparison.Ordinal))
            {
                LastProbeWarning = $"Live Network is {LiveApplicationVersion ?? "unknown"}; no matching controller OpenAPI was available, so operations remain " +
                    $"restricted to reviewed embedded {embedded.Version}, and response fields outside that contract may be unavailable.";
                _logger.LogWarning("{Warning}", LastProbeWarning);
            }
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private static string? FindVersion(JsonNode? info)
    {
        if (info is not JsonObject obj)
        {
            return null;
        }

        foreach (var name in new[] { "applicationVersion", "version", "networkVersion" })
        {
            if (obj[name] is JsonValue value && value.TryGetValue<string>(out var version))
            {
                return version;
            }
        }

        return null;
    }

    private sealed record ContractLocation(string RequestPath, string SourcePath);
}
