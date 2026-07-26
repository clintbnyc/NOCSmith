using System.Text.Json.Nodes;

namespace UnifiMcp.Api;

public interface ISiteManagerClient
{
    Task<JsonNode?> GetAsync(string relativePath, CancellationToken cancellationToken);

    Task<JsonNode?> QueryIspMetricsAsync(
        string interval,
        JsonObject body,
        CancellationToken cancellationToken);

    JsonObject Describe();
}
