using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Journal;
using UnifiMcp.Security;

namespace UnifiMcp;

public static class JournalCommand
{
    public const int CompleteExitCode = 0;
    public const int ErrorExitCode = 1;
    public const int UsageExitCode = 2;
    public const int PartialExitCode = 3;
    public const int FailedCollectionExitCode = 4;

    public static async Task<int> RunAsync(
        string[] args,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(args);
            var configuration = UnifiConfiguration.Load();
            var builder = Host.CreateApplicationBuilder(Array.Empty<string>());
            ApplicationServices.ConfigureConsoleLogging(builder.Logging);
            builder.Services.AddUnifiServices(configuration);
            using var host = builder.Build();

            var contracts = host.Services.GetRequiredService<ContractProvider>();
            await contracts.RefreshAsync(cancellationToken).ConfigureAwait(false);
            var journal = host.Services.GetRequiredService<ClientJournalService>();
            var response = await journal
                .CollectAsync(options.SiteId, options.HistoryHours, cancellationToken)
                .ConfigureAwait(false);
            Console.Out.WriteLine(
                response.Data?.ToJsonString(new JsonSerializerOptions { WriteIndented = false }) ??
                "{}");
            return ExitCodeForStatus(
                response.Data?["overallStatus"]?.GetValue<string>());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Console.Error.WriteLine("UniFi MCP journal collection cancelled.");
            return ErrorExitCode;
        }
        catch (Exception exception) when (
            exception is ConfigurationException or
            ContractException or
            ClientCollectionInProgressException or
            ClientJournalSizeException or
            ClientJournalMigrationException or
            ClientJournalUnavailableException or
            IOException or
            UnauthorizedAccessException)
        {
            var redactor = new SecretRedactor(
                Environment.GetEnvironmentVariable("UNIFI_API_KEY"),
                Environment.GetEnvironmentVariable("UNIFI_SITE_API_KEY"),
                Environment.GetEnvironmentVariable("UNIFI_MCP_HTTP_BEARER_TOKEN"));
            Console.Error.WriteLine(
                "UniFi MCP journal collection failed: " +
                redactor.Redact(exception.Message));
            return exception is ConfigurationException or ContractException
                ? UsageExitCode
                : ErrorExitCode;
        }
    }

    internal static JournalCollectOptions Parse(string[] args)
    {
        if (args.Length == 0 ||
            !string.Equals(args[0], "collect", StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigurationException(
                "Usage: unifi-mcp journal collect [--site-id UUID] [--history-hours HOURS].");
        }

        string? siteId = null;
        int? historyHours = null;
        for (var index = 1; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--site-id":
                    siteId = ReadValue(args, ref index, "--site-id");
                    if (!Guid.TryParse(siteId, out _))
                    {
                        throw new ConfigurationException("--site-id must be a UUID.");
                    }

                    break;
                case "--history-hours":
                    var historyText = ReadValue(args, ref index, "--history-hours");
                    if (!int.TryParse(
                            historyText,
                            NumberStyles.None,
                            CultureInfo.InvariantCulture,
                            out var parsedHistoryHours) ||
                        !ClientObservationCollector.SupportedHistoryHours.Contains(
                            parsedHistoryHours))
                    {
                        throw new ConfigurationException(
                            "--history-hours must be one of 24, 72, 168, 336, 720, or 4320.");
                    }

                    historyHours = parsedHistoryHours;
                    break;
                default:
                    throw new ConfigurationException(
                        $"Unknown journal collect option '{args[index]}'.");
            }
        }

        return new JournalCollectOptions(siteId, historyHours);
    }

    internal static int ExitCodeForStatus(string? status) => status switch
    {
        "complete" => CompleteExitCode,
        "partial" => PartialExitCode,
        "failed" => FailedCollectionExitCode,
        _ => ErrorExitCode
    };

    private static string ReadValue(string[] args, ref int index, string option)
    {
        if (++index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
        {
            throw new ConfigurationException($"{option} requires a value.");
        }

        return args[index];
    }
}

internal sealed record JournalCollectOptions(string? SiteId, int? HistoryHours);
