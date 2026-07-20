using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using UnifiMcp.Api;

namespace UnifiMcp.Contracts;

public sealed class ContractProvider
{
    private static readonly string[] LocalContractPaths =
    {
        "openapi.json",
        "v1/openapi.json",
        "swagger.json",
        "v1/swagger.json",
        "api-docs"
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

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var embedded = Current.Source == "embedded" ? Current : OpenApiContract.LoadEmbedded();
            Current = embedded;
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
            foreach (var path in LocalContractPaths)
            {
                try
                {
                    var candidate = await _client.GetFixedAsync(path, cancellationToken).ConfigureAwait(false);
                    if (candidate is not JsonObject candidateObject || candidateObject["paths"] is not JsonObject)
                    {
                        continue;
                    }

                    var contract = OpenApiContract.Parse(candidateObject.ToJsonString(), "controller:" + path);
                    if (!string.IsNullOrWhiteSpace(LiveApplicationVersion) &&
                        !string.Equals(contract.Version, LiveApplicationVersion, StringComparison.Ordinal))
                    {
                        LastProbeWarning = $"Controller contract {contract.Version} did not match live Network {LiveApplicationVersion}; using embedded {embedded.Version}.";
                        continue;
                    }

                    Current = contract;
                    LastProbeWarning = null;
                    _logger.LogInformation("Loaded UniFi Network {Version} contract from {Path}.", contract.Version, path);
                    return;
                }
                catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException)
                {
                    _logger.LogDebug("UniFi contract probe path {Path} was unavailable: {Message}", path, exception.Message);
                }
            }

            if (!string.Equals(LiveApplicationVersion, embedded.Version, StringComparison.Ordinal))
            {
                LastProbeWarning = $"Live Network is {LiveApplicationVersion ?? "unknown"}; controller OpenAPI was unavailable, so operations are restricted to embedded {embedded.Version}.";
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
}
