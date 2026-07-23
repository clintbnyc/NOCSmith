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

if (args.Length > 0 && string.Equals(args[0], "doctor", StringComparison.OrdinalIgnoreCase))
{
    return await DoctorCommand.RunAsync(CancellationToken.None).ConfigureAwait(false);
}

try
{
    var configuration = UnifiConfiguration.Load();
    var builder = Host.CreateApplicationBuilder(args);

    builder.Logging.ClearProviders();
    builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
    builder.Logging.SetMinimumLevel(LogLevel.Information);

    builder.Services.AddSingleton(configuration);
    builder.Services.AddSingleton(OpenApiContract.LoadEmbedded());
    builder.Services.AddSingleton(new SecretRedactor(configuration.ApiKey));
    builder.Services.AddSingleton<IUnifiClient, UnifiClient>();
    builder.Services.AddSingleton<ContractProvider>();
    builder.Services.AddSingleton<SiteResolver>();
    builder.Services.AddSingleton<ConfirmationStore>();
    builder.Services.AddSingleton<WritePlanner>();
    builder.Services.AddSingleton<ReadService>();
    builder.Services.AddSingleton<DomainReadService>();
    builder.Services.AddSingleton<LegacyReadEnrichmentService>();
    builder.Services.AddSingleton<LegacyAlertService>();
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
                Description = "Private, contract-validated access to the UniFi Network application on pinode."
            };
            options.ServerInstructions =
                "Use unifi_get_site_snapshot for reviews and grouped read tools for normal queries. " +
                "Use unifi_get_capabilities before generic operations. Every mutation must be previewed first. " +
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
