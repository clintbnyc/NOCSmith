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

            var result = new JsonObject
            {
                ["ok"] = true,
                ["baseUrl"] = configuration.BaseUri.ToString().TrimEnd('/'),
                ["apiKeyInjected"] = !string.IsNullOrWhiteSpace(configuration.ApiKey),
                ["tlsValidation"] = "system trust and hostname validation",
                ["liveApplicationVersion"] = provider.LiveApplicationVersion,
                ["contractVersion"] = provider.Current.Version,
                ["contractSource"] = provider.Current.Source,
                ["contractWarning"] = provider.LastProbeWarning,
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
}
