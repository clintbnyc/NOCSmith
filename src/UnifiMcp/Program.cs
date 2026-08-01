using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;
using UnifiMcp;
using UnifiMcp.Configuration;

string[] applicationArgs;
try
{
    applicationArgs = EnvironmentFileLoader.LoadAndRemoveOption(args);
}
catch (ConfigurationException exception)
{
    Console.Error.WriteLine("NOCsmith configuration error: " + exception.Message);
    return 2;
}

if (applicationArgs.Length > 0 &&
    string.Equals(applicationArgs[0], "doctor", StringComparison.OrdinalIgnoreCase))
{
    return await DoctorCommand.RunAsync(CancellationToken.None).ConfigureAwait(false);
}

if (applicationArgs.Length > 0 &&
    string.Equals(applicationArgs[0], "journal", StringComparison.OrdinalIgnoreCase))
{
    return await JournalCommand
        .RunAsync(applicationArgs[1..], CancellationToken.None)
        .ConfigureAwait(false);
}

if (applicationArgs.Length > 0 &&
    string.Equals(applicationArgs[0], "serve-http", StringComparison.OrdinalIgnoreCase))
{
    try
    {
        return await HttpServerCommand
            .RunAsync(applicationArgs[1..], CancellationToken.None)
            .ConfigureAwait(false);
    }
    catch (ConfigurationException exception)
    {
        Console.Error.WriteLine("NOCsmith configuration error: " + exception.Message);
        return 2;
    }
}

try
{
    var configuration = UnifiConfiguration.Load();
    var builder = Host.CreateApplicationBuilder(applicationArgs);
    ApplicationServices.ConfigureConsoleLogging(builder.Logging);
    builder.Services.AddUnifiServices(configuration);
    builder.Services
        .AddMcpServer(ApplicationServices.ConfigureMcpServer)
        .WithStdioServerTransport()
        .WithToolsFromAssembly();

    await builder.Build().RunAsync().ConfigureAwait(false);
    return 0;
}
catch (ConfigurationException exception)
{
    Console.Error.WriteLine("NOCsmith configuration error: " + exception.Message);
    return 2;
}
