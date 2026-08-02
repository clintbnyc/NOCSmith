using System.Text.Json.Nodes;
using UnifiMcp.Api;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Writes;

public sealed class WritePlanner
{
    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;
    private readonly SiteResolver _siteResolver;
    private readonly ConfirmationStore _confirmations;
    private readonly SecretRedactor _redactor;

    public WritePlanner(
        ContractProvider contracts,
        IUnifiClient client,
        SiteResolver siteResolver,
        ConfirmationStore confirmations,
        SecretRedactor redactor)
    {
        _contracts = contracts;
        _client = client;
        _siteResolver = siteResolver;
        _confirmations = confirmations;
        _redactor = redactor;
    }

    public async Task<ChangePreview> PreviewAsync(
        string operationId,
        IReadOnlyDictionary<string, string>? pathParameters,
        IReadOnlyDictionary<string, string>? queryParameters,
        JsonNode? body,
        bool mergeChanges,
        bool allowReferenced,
        CancellationToken cancellationToken)
    {
        var contract = _contracts.Current;
        var operation = contract.GetOperation(operationId, requireRead: false);
        var resolvedPath = await _siteResolver.ResolvePathParametersAsync(operation, pathParameters, cancellationToken)
            .ConfigureAwait(false);
        var stateQuery = string.Equals(operation.OperationId, "deleteVouchers", StringComparison.Ordinal)
            ? BuildBulkVoucherStateQuery(queryParameters)
            : queryParameters;
        var stateRead = BuildStateRead(contract, operation, resolvedPath, stateQuery);
        var before = stateRead is null
            ? null
            : await _client.ReadAsync(stateRead, cancellationToken).ConfigureAwait(false);

        JsonNode? finalBody = body?.DeepClone();
        if (mergeChanges)
        {
            if (operation.Method != HttpMethod.Put)
            {
                throw new ContractException("mergeChanges is supported only for full PUT update operations.");
            }

            if (before is null)
            {
                throw new ContractException("This update cannot be merged because the current resource could not be read.");
            }

            var discriminatorSource = JsonOverlay.Apply(before, body);
            var projected = contract.ProjectToRequestSchema(before, discriminatorSource, operation);
            finalBody = JsonOverlay.Apply(projected, body);
        }

        var warnings = new List<string>();
        var mutationQuery = queryParameters;
        if (string.Equals(operation.OperationId, "deleteVouchers", StringComparison.Ordinal))
        {
            var voucherIds = ValidateBulkVoucherState(before);
            warnings.Add($"Bulk delete resolved exactly {voucherIds.Count} voucher ID(s); apply will re-fetch the original filter and delete only these IDs.");
            mutationQuery = BuildExactVoucherMutationQuery(queryParameters, voucherIds);
        }

        var mutation = contract.ValidateAndBuild(operation, resolvedPath, mutationQuery, finalBody);
        var safetyState = await CheckReferencesAsync(contract, operation, resolvedPath, allowReferenced, warnings, cancellationToken)
            .ConfigureAwait(false);

        if (operation.Method == HttpMethod.Delete)
        {
            warnings.Add("This delete cannot be undone by the connector.");
        }
        else if (operation.PathTemplate.EndsWith("/actions", StringComparison.Ordinal))
        {
            warnings.Add("This action may interrupt clients, ports, or adopted devices.");
        }

        var pending = _confirmations.Add(
            mutation,
            stateRead,
            stateRead is null ? null : CanonicalJson.Hash(before),
            before,
            warnings,
            safetyState?.Request,
            safetyState?.Hash);
        return new ChangePreview(
            operation.OperationId,
            operation.Summary,
            operation.Method.Method,
            _redactor.RedactRequestTarget(mutation.RelativeUri),
            _redactor.Redact(before),
            _redactor.Redact(finalBody),
            warnings,
            pending.Token,
            pending.ExpiresAt);
    }

    public async Task<ChangeResult> ApplyAsync(string confirmationToken, CancellationToken cancellationToken)
    {
        var change = _confirmations.Consume(confirmationToken);
        if (change.StateRead is not null)
        {
            var current = await _client.ReadAsync(change.StateRead, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(CanonicalJson.Hash(current), change.BeforeHash, StringComparison.Ordinal))
            {
                throw new ConfirmationException(
                    "UniFi state changed after preview. The token was consumed without applying; preview the change again.");
            }
        }

        if (change.SafetyRead is not null)
        {
            var currentSafetyState = await _client.ReadAsync(change.SafetyRead, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(CanonicalJson.Hash(currentSafetyState), change.SafetyHash, StringComparison.Ordinal))
            {
                throw new ConfirmationException(
                    "UniFi safety state changed after preview. The token was consumed without applying; preview the change again.");
            }
        }

        var response = await _client.MutateAsync(change.Mutation, cancellationToken).ConfigureAwait(false);
        return new ChangeResult(
            change.Mutation.Operation.OperationId,
            change.Mutation.Operation.Summary,
            change.Mutation.Operation.Method.Method,
            _redactor.RedactRequestTarget(change.Mutation.RelativeUri),
            _redactor.Redact(response));
    }

    private static ValidatedRequest? BuildStateRead(
        OpenApiContract contract,
        OperationDefinition mutation,
        IReadOnlyDictionary<string, string> pathParameters,
        IReadOnlyDictionary<string, string>? queryParameters)
    {
        var candidatePaths = new List<string> { mutation.PathTemplate };
        if (mutation.PathTemplate.EndsWith("/actions", StringComparison.Ordinal))
        {
            candidatePaths.Add(mutation.PathTemplate[..^"/actions".Length]);
            var deviceMarker = "/interfaces/ports/";
            var markerIndex = mutation.PathTemplate.IndexOf(deviceMarker, StringComparison.Ordinal);
            if (markerIndex >= 0)
            {
                candidatePaths.Add(mutation.PathTemplate[..markerIndex]);
            }
        }

        foreach (var candidatePath in candidatePaths)
        {
            var read = contract.Operations.FirstOrDefault(operation =>
                operation.IsRead && string.Equals(operation.PathTemplate, candidatePath, StringComparison.Ordinal));
            if (read is null)
            {
                continue;
            }

            var allowedPathNames = read.Parameters
                .Where(parameter => parameter.Location == "path")
                .Select(parameter => parameter.Name)
                .ToHashSet(StringComparer.Ordinal);
            var filteredPath = pathParameters
                .Where(item => allowedPathNames.Contains(item.Key))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
            var allowedQueryNames = read.Parameters
                .Where(parameter => parameter.Location == "query")
                .Select(parameter => parameter.Name)
                .ToHashSet(StringComparer.Ordinal);
            var filteredQuery = queryParameters?
                .Where(item => allowedQueryNames.Contains(item.Key))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
            return contract.ValidateAndBuild(read, filteredPath, filteredQuery, null);
        }

        return null;
    }

    private async Task<SafetyState?> CheckReferencesAsync(
        OpenApiContract contract,
        OperationDefinition operation,
        IReadOnlyDictionary<string, string> pathParameters,
        bool allowReferenced,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(operation.OperationId, "deleteNetwork", StringComparison.Ordinal))
        {
            return null;
        }

        var referencesOperation = contract.GetOperation("getNetworkReferences", requireRead: true);
        var referencesRequest = contract.ValidateAndBuild(referencesOperation, pathParameters, null, null);
        var references = await _client.ReadAsync(referencesRequest, cancellationToken).ConfigureAwait(false);
        if (references is not JsonObject referenceObject ||
            referenceObject["referenceResources"] is not JsonArray resources)
        {
            throw new ContractException("Network references could not be verified; refusing the delete preview.");
        }

        long count = 0;
        foreach (var resource in resources)
        {
            if (resource is not JsonObject resourceObject ||
                resourceObject["referenceCount"] is not JsonValue countValue ||
                !countValue.TryGetValue<int>(out var resourceCount) ||
                resourceCount < 1)
            {
                throw new ContractException("Network references contained an invalid reference count; refusing the delete preview.");
            }

            count = checked(count + resourceCount);
        }

        var safetyState = new SafetyState(referencesRequest, CanonicalJson.Hash(references));
        if (count <= 0)
        {
            return safetyState;
        }

        if (!allowReferenced)
        {
            throw new ContractException(
                $"Network has {count} known reference(s). Set allowReferenced=true only after reviewing them.");
        }

        warnings.Add($"Override requested: network currently has {count} known reference(s).");
        return safetyState;
    }

    private static IReadOnlyDictionary<string, string> BuildBulkVoucherStateQuery(
        IReadOnlyDictionary<string, string>? mutationQuery)
    {
        var query = mutationQuery is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(mutationQuery, StringComparer.Ordinal);
        query["offset"] = "0";
        query["limit"] = "200";
        return query;
    }

    private static IReadOnlyList<string> ValidateBulkVoucherState(JsonNode? before)
    {
        if (before is not JsonObject page || page["data"] is not JsonArray vouchers)
        {
            throw new ContractException("Bulk voucher deletion could not resolve the matching vouchers exactly.");
        }

        var totalCount = page["totalCount"]?.GetValue<int?>()
            ?? page["count"]?.GetValue<int?>()
            ?? vouchers.Count;
        if (totalCount != vouchers.Count)
        {
            throw new ContractException(
                $"Bulk voucher deletion matched {totalCount} vouchers but only {vouchers.Count} could be resolved in one preview. Narrow the filter or delete vouchers individually.");
        }

        if (vouchers.Count == 0)
        {
            throw new ContractException("Bulk voucher deletion matched no vouchers; refusing an empty delete preview.");
        }

        var ids = new List<string>(vouchers.Count);
        foreach (var voucher in vouchers.OfType<JsonObject>())
        {
            var id = voucher["id"]?.GetValue<string>();
            if (!Guid.TryParse(id, out _))
            {
                throw new ContractException("Bulk voucher deletion returned a voucher without a valid UUID; refusing the preview.");
            }

            ids.Add(id);
        }

        if (vouchers.OfType<JsonObject>().Count() != vouchers.Count)
        {
            throw new ContractException("Bulk voucher deletion returned an unexpected voucher representation; refusing the preview.");
        }

        return ids;
    }

    private static IReadOnlyDictionary<string, string> BuildExactVoucherMutationQuery(
        IReadOnlyDictionary<string, string>? originalQuery,
        IEnumerable<string> voucherIds)
    {
        var query = originalQuery is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(originalQuery, StringComparer.Ordinal);
        query["filter"] = "id.in(" + string.Join(",", voucherIds.OrderBy(id => id, StringComparer.Ordinal)) + ")";
        return query;
    }

    private sealed record SafetyState(ValidatedRequest Request, string Hash);
}
