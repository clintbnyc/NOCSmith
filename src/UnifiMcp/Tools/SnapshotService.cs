using System.Text.Json.Nodes;
using UnifiMcp.Api;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed class SnapshotService
{
    private const string ZoneBasedFirewallNotConfiguredCode = "api.firewall.zone-based-firewall-not-configured";

    private static readonly string[] SiteOperations =
    {
        "getAdoptedDeviceOverviewPage",
        "getConnectedClientOverviewPage",
        "getNetworksOverviewPage",
        "getWifiBroadcastPage",
        "getFirewallPolicies",
        "getFirewallZones",
        "getAclRulePage",
        "getDnsPolicyPage",
        "getTrafficMatchingLists",
        "getLagPage",
        "getSwitchStackPage",
        "getVpnServerPage",
        "getSiteToSiteVpnTunnelPage",
        "getWansOverviewPage"
    };

    private readonly ContractProvider _contracts;
    private readonly IUnifiClient _client;
    private readonly SiteResolver _siteResolver;
    private readonly SecretRedactor _redactor;
    private readonly LegacyReadEnrichmentService _legacyEnrichment;

    public SnapshotService(
        ContractProvider contracts,
        IUnifiClient client,
        SiteResolver siteResolver,
        SecretRedactor redactor,
        LegacyReadEnrichmentService legacyEnrichment)
    {
        _contracts = contracts;
        _client = client;
        _siteResolver = siteResolver;
        _redactor = redactor;
        _legacyEnrichment = legacyEnrichment;
    }

    public async Task<ToolResponse> GetAsync(string? siteId, CancellationToken cancellationToken)
    {
        var snapshotStartedAt = DateTimeOffset.UtcNow;
        var resolvedSiteId = await _siteResolver.ResolveAsync(siteId, cancellationToken).ConfigureAwait(false);
        var contract = _contracts.Current;
        var sections = new JsonObject
        {
            ["siteId"] = resolvedSiteId,
            ["contractVersion"] = contract.Version,
            ["contractStatus"] = _contracts.Status
        };
        var results = new List<SectionCollectionResult>();

        results.Add(await AddSectionAsync(sections, "application", "getInfo", null, null, cancellationToken).ConfigureAwait(false));
        foreach (var operationId in SiteOperations)
        {
            var operation = contract.GetOperation(operationId, requireRead: true);
            var queryNames = operation.Parameters.Where(parameter => parameter.Location == "query").Select(parameter => parameter.Name).ToHashSet();
            var query = new Dictionary<string, string>();
            if (queryNames.Contains("offset"))
            {
                query["offset"] = "0";
            }

            if (queryNames.Contains("limit"))
            {
                query["limit"] = "200";
            }

            results.Add(await AddSectionAsync(
                sections,
                operationId,
                operationId,
                new Dictionary<string, string> { ["siteId"] = resolvedSiteId },
                query,
                cancellationToken).ConfigureAwait(false));
        }

        var succeeded = results.Count(result => result.Status == "ok");
        var notApplicable = results.Count(result => result.Status == "notApplicable");
        var failed = results.Count(result => result.Status == "failed");
        sections["_connector"] = new JsonObject
        {
            ["observedAt"] = snapshotStartedAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            ["completedAt"] = DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            ["contract"] = ResponseMetadata.CreateContractStatus(_contracts),
            ["sectionSummary"] = new JsonObject
            {
                ["total"] = results.Count,
                ["succeeded"] = succeeded,
                ["notApplicable"] = notApplicable,
                ["failed"] = failed
            },
            ["knownResponseLimitations"] = ResponseMetadata.GetAllKnownLimitations(
                contract.Version,
                HasSuccessfulSnapshotDeviceEnrichment(sections))
        };

        return new ToolResponse(
            $"UniFi site snapshot collected {results.Count} section(s): {succeeded} succeeded, {notApplicable} not applicable, {failed} failed.",
            _redactor.Redact(sections));
    }

    private async Task<SectionCollectionResult> AddSectionAsync(
        JsonObject sections,
        string name,
        string operationId,
        IReadOnlyDictionary<string, string>? path,
        IReadOnlyDictionary<string, string>? query,
        CancellationToken cancellationToken)
    {
        var key = ToCamelCase(name);
        try
        {
            var contract = _contracts.Current;
            var operation = contract.GetOperation(operationId, requireRead: true);
            var request = contract.ValidateAndBuild(operation, path, query, null);
            var response = await _client.ReadAsync(request, cancellationToken).ConfigureAwait(false);
            var observedAt = DateTimeOffset.UtcNow;
            var data = ResponseMetadata.AnnotatePagination(response, query);
            data = await _legacyEnrichment.EnrichAsync(operationId, path, data, cancellationToken).ConfigureAwait(false);
            data = ResponseMetadata.AnnotateCoverage(
                data,
                operationId,
                _contracts,
                observedAt,
                HasSuccessfulLegacyEnrichment(data));
            var section = new JsonObject
            {
                ["ok"] = true,
                ["applicable"] = true,
                ["status"] = "ok",
                ["sourceOperationId"] = operationId,
                ["observedAt"] = observedAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                ["data"] = data
            };
            sections[key] = section;
            return new SectionCollectionResult("ok");
        }
        catch (UnifiApiException exception) when (IsExpectedNotApplicable(operationId, exception))
        {
            var observedAt = DateTimeOffset.UtcNow;
            sections[key] = new JsonObject
            {
                ["ok"] = true,
                ["applicable"] = false,
                ["status"] = "notApplicable",
                ["sourceOperationId"] = operationId,
                ["observedAt"] = observedAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                ["reasonCode"] = exception.Code,
                ["reason"] = "Zone-based firewall is not configured on this UniFi site.",
                ["data"] = null
            };
            return new SectionCollectionResult("notApplicable");
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is UnifiApiException or ContractException or HttpRequestException or TaskCanceledException)
        {
            var observedAt = DateTimeOffset.UtcNow;
            var section = new JsonObject
            {
                ["ok"] = false,
                ["applicable"] = true,
                ["status"] = "failed",
                ["sourceOperationId"] = operationId,
                ["observedAt"] = observedAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                ["error"] = _redactor.Redact(exception.Message)
            };
            if (exception is UnifiApiException apiException)
            {
                section["httpStatus"] = (int)apiException.StatusCode;
                section["errorCode"] = apiException.Code;
            }

            sections[key] = section;
            return new SectionCollectionResult("failed");
        }
    }

    private static bool IsExpectedNotApplicable(string operationId, UnifiApiException exception) =>
        (operationId is "getFirewallPolicies" or "getFirewallZones") &&
        exception.StatusCode == System.Net.HttpStatusCode.BadRequest &&
        string.Equals(exception.Code, ZoneBasedFirewallNotConfiguredCode, StringComparison.Ordinal);

    private static bool HasSuccessfulLegacyEnrichment(JsonNode? response) =>
        string.Equals(
            response?["_connector"]?["legacyReadEnrichment"]?["status"]?.GetValue<string>(),
            "ok",
            StringComparison.Ordinal);

    private static bool HasSuccessfulSnapshotDeviceEnrichment(JsonObject sections) =>
        HasSuccessfulLegacyEnrichment(sections["getAdoptedDeviceOverviewPage"]?["data"]);

    private static string ToCamelCase(string value)
    {
        var words = value.Split(new[] { ' ', '(', ')', '-' }, StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0)
        {
            return value;
        }

        return char.ToLowerInvariant(words[0][0]) + words[0][1..] + string.Concat(words.Skip(1).Select(word => char.ToUpperInvariant(word[0]) + word[1..]));
    }

    private sealed record SectionCollectionResult(string Status);
}
