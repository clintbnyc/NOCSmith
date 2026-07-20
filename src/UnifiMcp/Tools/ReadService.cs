using System.Text.Json.Nodes;
using UnifiMcp.Api;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed class ReadService
{
    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;

    public ReadService(
        ContractProvider contracts,
        IUnifiClient client,
        SiteResolver siteResolver,
        SecretRedactor redactor)
    {
        _contracts = contracts;
        _client = client;
        _siteResolver = siteResolver;
        _redactor = redactor;
    }

    public async Task<ToolResponse> ExecuteAsync(
        string operationId,
        IReadOnlyDictionary<string, string>? pathParameters,
        IReadOnlyDictionary<string, string>? queryParameters,
        CancellationToken cancellationToken)
    {
        var contract = _contracts.Current;
        var operation = contract.GetOperation(operationId, requireRead: true);
        var resolvedPath = await _siteResolver.ResolvePathParametersAsync(operation, pathParameters, cancellationToken)
            .ConfigureAwait(false);
        var request = contract.ValidateAndBuild(operation, resolvedPath, queryParameters, null);
        var response = await _client.ReadAsync(request, cancellationToken).ConfigureAwait(false);
        var redacted = ResponseMetadata.AnnotatePagination(_redactor.Redact(response), queryParameters);
        return new ToolResponse(Summarize(operation.Summary, redacted), redacted);
    }

    private static string Summarize(string summary, JsonNode? response)
    {
        var count = response?["count"]?.GetValue<int?>()
            ?? (response?["data"] as JsonArray)?.Count;
        var truncation = ResponseMetadata.IsTruncated(response)
            ? " Results are truncated; request the next page."
            : string.Empty;
        return count is null
            ? summary + " completed." + truncation
            : $"{summary}: {count} item(s) returned.{truncation}";
    }
}
