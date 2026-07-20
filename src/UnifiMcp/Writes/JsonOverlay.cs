using System.Text.Json.Nodes;

namespace UnifiMcp.Writes;

public static class JsonOverlay
{
    public static JsonNode? Apply(JsonNode? target, JsonNode? changes)
    {
        if (changes is not JsonObject changesObject)
        {
            return changes?.DeepClone();
        }

        var result = target is JsonObject targetObject
            ? (JsonObject)targetObject.DeepClone()
            : new JsonObject();

        foreach (var change in changesObject)
        {
            if (change.Value is JsonObject nestedChanges && result[change.Key] is JsonObject nestedTarget)
            {
                result[change.Key] = Apply(nestedTarget, nestedChanges);
            }
            else
            {
                // Deliberately retain explicit null so a full PUT can clear a nullable field.
                result[change.Key] = change.Value?.DeepClone();
            }
        }

        return result;
    }
}
