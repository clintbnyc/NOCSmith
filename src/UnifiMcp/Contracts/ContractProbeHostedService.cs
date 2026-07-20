using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace UnifiMcp.Contracts;

public sealed class ContractProbeHostedService : IHostedService
{
    private readonly ContractProvider _provider;
    private readonly ILogger<ContractProbeHostedService> _logger;

    public ContractProbeHostedService(ContractProvider provider, ILogger<ContractProbeHostedService> logger)
    {
        _provider = provider;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _provider.RefreshAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _logger.LogWarning("UniFi startup contract probe failed; embedded allowlist remains active: {Message}", exception.Message);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
