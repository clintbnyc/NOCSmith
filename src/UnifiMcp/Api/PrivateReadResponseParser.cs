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
}
