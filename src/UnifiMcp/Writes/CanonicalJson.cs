using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace UnifiMcp.Writes;

public static class CanonicalJson
{
    public static string Hash(JsonNode? node)
    {
        var canonical = Canonicalize(node)?.ToJsonString() ?? "null";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    public static JsonNode? Canonicalize(JsonNode? node)
    {
        return node switch
        {
            null => null,
            JsonObject obj => new JsonObject(obj
                .OrderBy(property => property.Key, StringComparer.Ordinal)
                .Select(property => KeyValuePair.Create(property.Key, Canonicalize(property.Value)))),
            JsonArray array => new JsonArray(array.Select(Canonicalize).ToArray()),
            _ => node.DeepClone()
        };
    }
}
