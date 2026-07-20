using System.Globalization;
using System.Text.Json.Nodes;

namespace UnifiMcp.Tools;

public static class ResponseMetadata
{
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

        obj["_connector"] = new JsonObject
        {
            ["offset"] = offset,
            ["limit"] = limit,
            ["returned"] = data.Count,
            ["totalCount"] = totalCount,
            ["truncated"] = truncated
        };
        return obj;
    }

    public static bool IsTruncated(JsonNode? response) =>
        response?["_connector"]?["truncated"]?.GetValue<bool>() == true;

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
