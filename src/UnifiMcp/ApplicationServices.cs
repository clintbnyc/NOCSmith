using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Journal;
using UnifiMcp.Security;
using UnifiMcp.Tools;
using UnifiMcp.Writes;

namespace UnifiMcp;

public static class ApplicationServices
{
    public static IServiceCollection AddUnifiServices(
        this IServiceCollection services,
        UnifiConfiguration configuration)
    {
        services.AddSingleton(configuration);
        services.AddSingleton(OpenApiContract.LoadEmbedded());
        services.AddSingleton(new SecretRedactor(
            configuration.ApiKey,
            configuration.SiteManagerApiKey,
            configuration.McpHttpBearerToken));
        services.AddSingleton<IUnifiClient, UnifiClient>();
        services.AddSingleton<ISiteManagerClient, SiteManagerClient>();
        services.AddSingleton<ContractProvider>();
        services.AddSingleton<SiteResolver>();
        services.AddSingleton<ConfirmationStore>();
        services.AddSingleton<WritePlanner>();
        services.AddSingleton<ReadService>();
        services.AddSingleton<DomainReadService>();
        services.AddSingleton<LegacyReadEnrichmentService>();
        services.AddSingleton<SiteManagerReadService>();
        services.AddSingleton<SiteManagerDeviceEnrichmentService>();
        services.AddSingleton<ClientGroupReadService>();
        services.AddSingleton<WifiDiagnosticsReadService>();
        services.AddSingleton<ClientHistoryReadService>();
        services.AddSingleton<IClientJournalClock, SystemClientJournalClock>();
        services.AddSingleton<IClientCollectionIdGenerator, GuidClientCollectionIdGenerator>();
        services.AddSingleton<ClientObservationCollector>();
        services.AddSingleton<ClientJournalStore>();
        services.AddSingleton<ClientJournalService>();
        services.AddSingleton<SystemLogReadService>();
        services.AddSingleton<SnapshotService>();
        services.AddHostedService<ContractProbeHostedService>();
        return services;
    }

    public static void ConfigureConsoleLogging(ILoggingBuilder logging)
    {
        logging.ClearProviders();
        logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
        logging.SetMinimumLevel(LogLevel.Information);
    }

    public static void ConfigureMcpServer(McpServerOptions options)
    {
        options.ServerInfo = new Implementation
        {
            Name = "unifi-mcp",
            Title = "UniFi Network MCP Connector",
            Version = "1.2.0",
            Description = "Security-first UniFi Network MCP access for inventory, diagnostics, history, and confirmation-bound changes."
        };
        options.ServerInstructions =
            "Use unifi_get_site_snapshot for reviews and grouped read tools for normal queries. " +
            "Use unifi_get_capabilities before generic operations. Every mutation must be previewed first. " +
            "Use unifi_wifi_diagnostics for bounded current client RF, DHCP/APIPA, and access-point radio telemetry. " +
            "Use unifi_site_manager and unifi_isp_metrics for read-only fleet and ISP history. " +
            "Client journal collection is a local write and never changes the controller; journal recovery requires the exact current health fingerprint. " +
            "Never call unifi_apply_change until the user explicitly approves the exact preview; tokens are single-use, expire after five minutes, and are invalidated by state drift. " +
            "Secrets are redacted and arbitrary URLs are prohibited.";
    }
}
