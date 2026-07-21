using System.Globalization;
using System.Text.Json.Nodes;
using UnifiMcp.Contracts;

namespace UnifiMcp.Tools;

public static class ResponseMetadata
{
    private const string DeviceDetailsOperationId = "getAdoptedDeviceDetails";
    private const string DeviceOverviewOperationId = "getAdoptedDeviceOverviewPage";
    private const string ClientDetailsOperationId = "getConnectedClientDetails";
    private const string ClientOverviewOperationId = "getConnectedClientOverviewPage";

    public static JsonNode? AnnotatePagination(
        JsonNode? response,
        IReadOnlyDictionary<string, string>? requestedQuery = null)
    {
        if (response is not JsonObject obj || obj["data"] is not JsonArray data)
        {
            return response;
        }

        var offset = ReadInteger(obj["offset"])
            ?? ReadQueryInteger(requestedQuery, "offset")
            ?? 0;
        var limit = ReadInteger(obj["limit"])
            ?? ReadQueryInteger(requestedQuery, "limit")
            ?? data.Count;
        var totalCount = ReadInteger(obj["totalCount"])
            ?? ReadInteger(obj["count"])
            ?? data.Count;
        var truncated = offset + data.Count < totalCount;

        var connector = GetOrCreateConnector(obj);
        connector["offset"] = offset;
        connector["limit"] = limit;
        connector["returned"] = data.Count;
        connector["totalCount"] = totalCount;
        connector["truncated"] = truncated;
        return obj;
    }

    public static JsonNode? AnnotateCoverage(
        JsonNode? response,
        string operationId,
        ContractProvider contracts,
        DateTimeOffset? observedAt = null,
        bool legacyReadEnrichmentSucceeded = false)
    {
        if (response is not JsonObject obj)
        {
            return response;
        }

        var limitations = GetKnownLimitations(
            operationId,
            contracts.Current.Version,
            legacyReadEnrichmentSucceeded);
        var connector = GetOrCreateConnector(obj);
        connector["sourceOperationId"] = operationId;
        connector["observedAt"] = (observedAt ?? DateTimeOffset.UtcNow).ToString("O", CultureInfo.InvariantCulture);
        if (contracts.Status is "embedded-fallback" || limitations.Count > 0)
        {
            connector["contract"] = CreateContractStatus(contracts);
        }

        if (limitations.Count > 0)
        {
            connector["knownLimitations"] = limitations;
        }

        if (operationId is ClientDetailsOperationId or ClientOverviewOperationId)
        {
            connector["topologySemantics"] = CreateClientTopologySemantics();
        }

        return obj;
    }

    public static JsonObject CreateContractStatus(ContractProvider contracts) => new()
    {
        ["status"] = contracts.Status,
        ["version"] = contracts.Current.Version,
        ["source"] = contracts.Current.Source,
        ["liveApplicationVersion"] = contracts.LiveApplicationVersion,
        ["warning"] = contracts.LastProbeWarning
    };

    public static JsonArray GetKnownLimitations(
        string operationId,
        string contractVersion,
        bool legacyReadEnrichmentAvailable = false)
    {
        var limitations = new JsonArray();
        if (operationId is DeviceDetailsOperationId or DeviceOverviewOperationId &&
            string.Equals(contractVersion, "10.3.58", StringComparison.Ordinal))
        {
            limitations.Add(CreateOfficialContractLimitation(
                operationId,
                "interfaces.ports.labels",
                "custom port labels",
                contractVersion,
                legacyReadEnrichmentAvailable));
            limitations.Add(CreateOfficialContractLimitation(
                operationId,
                "interfaces.ports.stp",
                "STP operational/configuration fields",
                contractVersion,
                legacyReadEnrichmentAvailable));
            limitations.Add(new JsonObject
            {
                ["operationId"] = operationId,
                ["area"] = "interfaces.ports.stp.uiRole",
                ["missingData"] = new JsonArray("STP roles"),
                ["source"] = "official-contract",
                ["scope"] = $"official UniFi Network {contractVersion} response",
                ["resolutionStatus"] = "unresolved",
                ["stillMissing"] = new JsonArray("normalized UniFi UI role (Edge versus Participant)"),
                ["reason"] = "Neither the official response nor the verified legacy projection contains a reliable direct field for the normalized UniFi UI Edge/Participant role."
            });
        }

        if (operationId is ClientDetailsOperationId or ClientOverviewOperationId)
        {
            limitations.Add(new JsonObject
            {
                ["operationId"] = operationId,
                ["area"] = "client topology",
                ["missingData"] = new JsonArray("physical attachment path through third-party bridges"),
                ["source"] = "controller-observation",
                ["scope"] = "controller-reported client topology",
                ["resolutionStatus"] = "unresolved",
                ["stillMissing"] = new JsonArray("physical attachment path through third-party bridges"),
                ["reason"] = "The controller-reported client type and uplink identify UniFi's observation point, not necessarily a direct cable or radio association."
            });
        }

        return limitations;
    }

    public static JsonArray GetAllKnownLimitations(
        string contractVersion,
        bool legacyReadEnrichmentAvailable = false)
    {
        var limitations = new JsonArray();
        foreach (var operationId in new[] { DeviceOverviewOperationId, DeviceDetailsOperationId, ClientOverviewOperationId, ClientDetailsOperationId })
        {
            foreach (var limitation in GetKnownLimitations(operationId, contractVersion, legacyReadEnrichmentAvailable))
            {
                limitations.Add(limitation?.DeepClone());
            }
        }

        return limitations;
    }

    public static bool IsTruncated(JsonNode? response) =>
        response?["_connector"]?["truncated"]?.GetValue<bool>() == true;

    private static JsonObject GetOrCreateConnector(JsonObject obj)
    {
        if (obj["_connector"] is JsonObject connector)
        {
            return connector;
        }

        connector = new JsonObject();
        obj["_connector"] = connector;
        return connector;
    }

    private static JsonObject CreateClientTopologySemantics() => new()
    {
        ["controllerReportedTypeField"] = "type",
        ["controllerReportedUplinkField"] = "uplinkDeviceId",
        ["physicalAttachment"] = "unknown-when-third-party-bridged",
        ["guidance"] = "Do not infer direct switch-port or Wi-Fi-radio attachment from these fields when a third-party bridge is in the path."
    };

    private static JsonObject CreateOfficialContractLimitation(
        string operationId,
        string area,
        string missingData,
        string contractVersion,
        bool legacyReadEnrichmentAvailable)
    {
        var limitation = new JsonObject
        {
            ["operationId"] = operationId,
            ["area"] = area,
            ["missingData"] = new JsonArray(missingData),
            ["source"] = "official-contract",
            ["scope"] = $"official UniFi Network {contractVersion} response",
            ["resolutionStatus"] = legacyReadEnrichmentAvailable ? "resolved" : "unresolved",
            ["stillMissing"] = legacyReadEnrichmentAvailable ? new JsonArray() : new JsonArray(missingData),
            ["reason"] = $"The official UniFi Network {contractVersion} adopted-device schema does not expose this data."
        };
        if (legacyReadEnrichmentAvailable)
        {
            limitation["resolvedBy"] = "legacyReadEnrichment";
        }

        return limitation;
    }

    private static int? ReadInteger(JsonNode? value)
    {
        if (value is not JsonValue scalar)
        {
            return null;
        }

        if (scalar.TryGetValue<int>(out var integer))
        {
            return integer;
        }

        if (scalar.TryGetValue<long>(out var longValue) && longValue is >= int.MinValue and <= int.MaxValue)
        {
            return (int)longValue;
        }

        return scalar.TryGetValue<string>(out var text) &&
               int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out integer)
            ? integer
            : null;
    }

    private static int? ReadQueryInteger(IReadOnlyDictionary<string, string>? query, string name) =>
        query is not null && query.TryGetValue(name, out var value) &&
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
}
