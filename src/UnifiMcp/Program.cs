using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using UnifiMcp;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;
using UnifiMcp.Writes;

string[] applicationArgs;
try
{
    applicationArgs = EnvironmentFileLoader.LoadAndRemoveOption(args);
}
catch (ConfigurationException exception)
{
    Console.Error.WriteLine("UniFi MCP configuration error: " + exception.Message);
    return 2;
}

if (applicationArgs.Length > 0 &&
    string.Equals(applicationArgs[0], "doctor", StringComparison.OrdinalIgnoreCase))
{
    return await DoctorCommand.RunAsync(CancellationToken.None).ConfigureAwait(false);
}

try
{
    var configuration = UnifiConfiguration.Load();
    var builder = Host.CreateApplicationBuilder(applicationArgs);

    builder.Logging.ClearProviders();
    builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
    builder.Logging.SetMinimumLevel(LogLevel.Information);

    builder.Services.AddSingleton(configuration);
    builder.Services.AddSingleton(OpenApiContract.LoadEmbedded());
    builder.Services.AddSingleton(new SecretRedactor(
        configuration.ApiKey,
        configuration.SiteManagerApiKey));
    builder.Services.AddSingleton<IUnifiClient, UnifiClient>();
    builder.Services.AddSingleton<ISiteManagerClient, SiteManagerClient>();
    builder.Services.AddSingleton<ContractProvider>();
    builder.Services.AddSingleton<SiteResolver>();
    builder.Services.AddSingleton<ConfirmationStore>();
    builder.Services.AddSingleton<WritePlanner>();
    builder.Services.AddSingleton<ReadService>();
    builder.Services.AddSingleton<DomainReadService>();
    builder.Services.AddSingleton<LegacyReadEnrichmentService>();
    builder.Services.AddSingleton<SiteManagerReadService>();
    builder.Services.AddSingleton<SiteManagerDeviceEnrichmentService>();
    builder.Services.AddSingleton<ClientGroupReadService>();
    builder.Services.AddSingleton<SystemLogReadService>();
    builder.Services.AddSingleton<SnapshotService>();
    builder.Services.AddHostedService<ContractProbeHostedService>();

    builder.Services
        .AddMcpServer(options =>
        {
            options.ServerInfo = new Implementation
            {
                Name = "unifi-mcp",
                Title = "UniFi Network MCP Connector",
                Version = "1.0.0",
                Description = "Private, contract-validated UniFi Network access with optional read-only Site Manager fleet enrichment."
            };
            options.ServerInstructions =
                "Use unifi_get_site_snapshot for reviews and grouped read tools for normal queries. " +
                "Use unifi_get_capabilities before generic operations. Every mutation must be previewed first. " +
                "Use unifi_site_manager and unifi_isp_metrics for read-only fleet and ISP history. " +
                "Never call unifi_apply_change until the user explicitly approves the exact preview; tokens are single-use, expire after five minutes, and are invalidated by state drift. " +
                "Secrets are redacted and arbitrary URLs are prohibited.";
        })
        .WithStdioServerTransport()
        .WithToolsFromAssembly();

    await builder.Build().RunAsync().ConfigureAwait(false);
    return 0;
}
catch (ConfigurationException exception)
{
    Console.Error.WriteLine("UniFi MCP configuration error: " + exception.Message);
    return 2;
}
