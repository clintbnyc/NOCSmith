using System.Net.Http;
using System.Text.Json.Nodes;

namespace UnifiMcp.Contracts;

public sealed record ParameterDefinition(
    string Name,
    string Location,
    bool Required,
    JsonObject Schema);

public sealed record OperationDefinition(
    string OperationId,
    HttpMethod Method,
    string PathTemplate,
    string Summary,
    string Description,
    IReadOnlyList<string> Tags,
    IReadOnlyList<ParameterDefinition> Parameters,
    JsonObject? RequestSchema,
    bool RequestBodyRequired)
{
    public bool IsRead => Method == HttpMethod.Get;
}
