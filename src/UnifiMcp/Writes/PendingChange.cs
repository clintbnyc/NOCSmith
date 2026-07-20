using System.Text.Json.Nodes;
using UnifiMcp.Contracts;

namespace UnifiMcp.Writes;

public sealed record PendingChange(
    string Token,
    DateTimeOffset ExpiresAt,
    ValidatedRequest Mutation,
    ValidatedRequest? StateRead,
    string? BeforeHash,
    JsonNode? Before,
    IReadOnlyList<string> Warnings,
    ValidatedRequest? SafetyRead,
    string? SafetyHash);

public sealed record ChangePreview(
    string OperationId,
    string Summary,
    string Method,
    string Target,
    JsonNode? Before,
    JsonNode? ProposedBody,
    IReadOnlyList<string> Warnings,
    string ConfirmationToken,
    DateTimeOffset ExpiresAt);

public sealed record ChangeResult(
    string OperationId,
    string Summary,
    string Method,
    string Target,
    JsonNode? Response);
