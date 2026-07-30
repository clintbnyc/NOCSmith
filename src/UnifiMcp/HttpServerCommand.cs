using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;
using UnifiMcp.Configuration;
using UnifiMcp.Journal;

namespace UnifiMcp;

public static class HttpServerCommand
{
    public static async Task<int> RunAsync(
        string[] args,
        CancellationToken cancellationToken)
    {
        if (args.Length != 0)
        {
            throw new ConfigurationException(
                "serve-http does not accept positional arguments.");
        }

        var configuration = UnifiConfiguration.Load() with
        {
            IsScheduledCollectionHost = true
        };
        configuration.RequireHttpServerConfiguration();

        var hostBuilder = Host.CreateDefaultBuilder(Array.Empty<string>())
            .ConfigureLogging(ApplicationServices.ConfigureConsoleLogging)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseUrls(configuration.McpHttpListenUri!.ToString());
                webBuilder.ConfigureServices(services =>
                {
                    services.AddSingleton(TimeProvider.System);
                    services.AddUnifiServices(configuration);
                    services.AddHostedService<ScheduledClientCollectionService>();
                    services
                        .AddMcpServer(ApplicationServices.ConfigureMcpServer)
                        .WithHttpTransport(options => options.Stateless = true)
                        .WithToolsFromAssembly();
                });
                webBuilder.Configure(application =>
                {
                    application.UseRouting();
                    application.UseMiddleware<McpHttpSecurityMiddleware>();
                    application.UseEndpoints(endpoints => endpoints.MapMcp("/mcp"));
                });
            });

        using var host = hostBuilder.Build();
        await host.RunAsync(cancellationToken).ConfigureAwait(false);
        return 0;
    }
}
