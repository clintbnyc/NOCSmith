using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
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
                if (configuration.McpHttpTailscaleSocketPath is { } socketPath)
                {
                    RequirePrivateSocketDirectory(socketPath);
                    webBuilder.ConfigureKestrel(options => options.ListenUnixSocket(socketPath));
                }
                else
                {
                    webBuilder.UseUrls(configuration.McpHttpListenUri!.ToString());
                }
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

    private static void RequirePrivateSocketDirectory(string socketPath)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new ConfigurationException(
                "Tailscale identity authentication requires a Linux Unix socket listener.");
        }

        var directoryPath = Path.GetDirectoryName(socketPath);
        if (string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath))
        {
            throw new ConfigurationException(
                "The Tailscale Unix socket parent directory must already exist.");
        }

        if (new DirectoryInfo(directoryPath).LinkTarget is not null)
        {
            throw new ConfigurationException(
                "The Tailscale Unix socket parent directory must not be a symbolic link.");
        }

        var mode = File.GetUnixFileMode(directoryPath);
        var required =
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.UserExecute;
        var nonPrivate =
            UnixFileMode.GroupRead |
            UnixFileMode.GroupWrite |
            UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead |
            UnixFileMode.OtherWrite |
            UnixFileMode.OtherExecute;
        if ((mode & required) != required || (mode & nonPrivate) != 0)
        {
            throw new ConfigurationException(
                "The Tailscale Unix socket parent directory must have mode 0700.");
        }
    }
}
