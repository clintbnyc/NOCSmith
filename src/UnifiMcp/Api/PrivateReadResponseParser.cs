using System.Text.Json.Nodes;
using UnifiMcp.Contracts;

namespace UnifiMcp.Api;

internal static class PrivateReadResponseParser
{
    public static IReadOnlyList<JsonObject> ReadRecords(JsonNode? response)
    {
        var data = response switch
        {
            JsonArray rootArray => rootArray,
            JsonObject responseObject when responseObject["data"] is JsonArray wrappedArray => wrappedArray,
            _ => throw new ContractException(
                "Private UniFi read did not return an array or an object containing a data array.")
        };

        var records = new List<JsonObject>(data.Count);
        for (var index = 0; index < data.Count; index++)
        {
            if (data[index] is not JsonObject record)
            {
                throw new ContractException(
                    $"Private UniFi read returned a non-object record at index {index}.");
            }

            records.Add(record);
        }

        return records;
    }

    public static void ValidateCompleteSinglePage(
        JsonNode? response,
        int recordCount,
        string sourceName)
    {
        if (response is not JsonObject responseObject)
        {
            throw new ContractException(
                $"{sourceName} did not include completeness metadata, so absence inference is unavailable.");
        }

        var offset = ReadNonNegativeInteger(responseObject["offset"]);
        var count = ReadNonNegativeInteger(responseObject["count"]);
        var limit = ReadNonNegativeInteger(responseObject["limit"]);
        var totalCount = ReadNonNegativeInteger(responseObject["totalCount"]);
        var hasMore = ReadBoolean(responseObject["hasMore"]);
        if (offset is null || count is null || limit is null || totalCount is null || hasMore is null)
        {
            throw new ContractException(
                $"{sourceName} pagination metadata was missing or invalid, so collection completeness could not be established.");
        }

        if (offset != 0 ||
            count != recordCount ||
            limit == 0 ||
            limit < count ||
            totalCount < offset + count)
        {
            throw new ContractException(
                $"{sourceName} pagination metadata was inconsistent with the returned records.");
        }

        if (hasMore.Value ||
            offset + count < totalCount ||
            HasContinuationToken(responseObject, "nextToken") ||
            HasContinuationToken(responseObject, "nextPageToken") ||
            HasContinuationToken(responseObject, "continuationToken"))
        {
            throw new ContractException(
                $"{sourceName} response was partial; absence inference requires a complete collection.");
        }
    }

    private static long? ReadNonNegativeInteger(JsonNode? node)
    {
        if (node is not JsonValue value)
        {
            return null;
        }

        if (value.TryGetValue<long>(out var longValue) && longValue >= 0)
        {
            return longValue;
        }

        return value.TryGetValue<int>(out var intValue) && intValue >= 0
            ? intValue
            : null;
    }

    private static bool? ReadBoolean(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<bool>(out var boolean)
            ? boolean
            : null;

    private static bool HasContinuationToken(JsonObject response, string field)
    {
        var node = response[field];
        if (node is null)
        {
            return false;
        }

        return node is not JsonValue value ||
            !value.TryGetValue<string>(out var token) ||
            !string.IsNullOrWhiteSpace(token);
    }
}
