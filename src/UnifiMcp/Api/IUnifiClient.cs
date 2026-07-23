using System.Text.Json.Nodes;
using UnifiMcp.Contracts;

namespace UnifiMcp.Api;

public interface IUnifiClient
{
    Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken);

    Task<JsonNode?> MutateAsync(ValidatedRequest request, CancellationToken cancellationToken);

    Task<JsonNode?> GetFixedAsync(string relativePath, CancellationToken cancellationToken);

    Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken);

    Task<JsonNode?> ReadPrivateClientsAsync(string internalSiteReference, CancellationToken cancellationToken);

    Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken);
}
