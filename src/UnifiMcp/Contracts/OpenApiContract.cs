using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace UnifiMcp.Contracts;

public sealed partial class OpenApiContract
{
    private static readonly HashSet<string> SupportedMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "get", "post", "put", "patch", "delete"
    };

    private readonly JsonObject _document;
    private readonly IReadOnlyDictionary<string, OperationDefinition> _operations;

    private OpenApiContract(JsonObject document, string source)
    {
        _document = document;
        Source = source;
        Version = document["info"]?["version"]?.GetValue<string>()
            ?? throw new ContractException("OpenAPI contract is missing info.version.");
        _operations = ParseOperations(document);
    }

    public string Version { get; }

    public string Source { get; }

    public IReadOnlyCollection<OperationDefinition> Operations => _operations.Values.ToArray();

    public int ReadCount => _operations.Values.Count(operation => operation.IsRead);

    public int WriteCount => _operations.Count - ReadCount;

    public static OpenApiContract LoadEmbedded()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("UnifiMcp.Contracts.unifi-network.openapi.json")
            ?? throw new ContractException("Embedded UniFi OpenAPI contract was not found.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd(), "embedded");
    }

    public static OpenApiContract Parse(string json, string source)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(json);
        }
        catch (JsonException exception)
        {
            throw new ContractException("OpenAPI contract is not valid JSON.", exception);
        }

        if (node is not JsonObject document || document["paths"] is not JsonObject)
        {
            throw new ContractException("OpenAPI contract must contain a paths object.");
        }

        return new OpenApiContract(document, source);
    }

    public OperationDefinition GetOperation(string operationId, bool requireRead)
    {
        if (!_operations.TryGetValue(operationId, out var operation))
        {
            throw new ContractException($"Unknown operationId '{operationId}'. Call unifi_get_capabilities for the allowlist.");
        }

        if (requireRead && !operation.IsRead)
        {
            throw new ContractException($"Operation '{operationId}' is a write. Preview it before applying.");
        }

        if (!requireRead && operation.IsRead)
        {
            throw new ContractException($"Operation '{operationId}' is read-only. Use unifi_read_operation.");
        }

        return operation;
    }

    public ValidatedRequest ValidateAndBuild(
        OperationDefinition operation,
        IReadOnlyDictionary<string, string>? pathParameters,
        IReadOnlyDictionary<string, string>? queryParameters,
        JsonNode? body)
    {
        var pathValues = pathParameters ?? new Dictionary<string, string>();
        var queryValues = queryParameters ?? new Dictionary<string, string>();
        var knownPath = operation.Parameters.Where(parameter => parameter.Location == "path").ToDictionary(parameter => parameter.Name);
        var knownQuery = operation.Parameters.Where(parameter => parameter.Location == "query").ToDictionary(parameter => parameter.Name);

        RejectUnknown(pathValues.Keys, knownPath.Keys, "path");
        RejectUnknown(queryValues.Keys, knownQuery.Keys, "query");

        var path = operation.PathTemplate;
        foreach (var parameter in knownPath.Values)
        {
            if (!pathValues.TryGetValue(parameter.Name, out var value) || string.IsNullOrWhiteSpace(value))
            {
                throw new ContractException($"Missing required path parameter '{parameter.Name}'.");
            }

            ValidateScalar(JsonValue.Create(value), parameter.Schema, $"path.{parameter.Name}");
            path = path.Replace("{" + parameter.Name + "}", Uri.EscapeDataString(value), StringComparison.Ordinal);
        }

        foreach (var parameter in knownQuery.Values)
        {
            if (parameter.Required && (!queryValues.TryGetValue(parameter.Name, out var value) || string.IsNullOrWhiteSpace(value)))
            {
                throw new ContractException($"Missing required query parameter '{parameter.Name}'.");
            }

            if (queryValues.TryGetValue(parameter.Name, out var queryValue))
            {
                ValidateScalar(ParseQueryValue(queryValue, parameter.Schema), parameter.Schema, $"query.{parameter.Name}");
            }
        }

        if (operation.RequestBodyRequired && body is null)
        {
            throw new ContractException($"Operation '{operation.OperationId}' requires a JSON request body.");
        }

        if (body is not null)
        {
            if (operation.RequestSchema is null)
            {
                throw new ContractException($"Operation '{operation.OperationId}' does not accept a JSON request body.");
            }

            ValidateSchema(body, operation.RequestSchema, "body");
        }

        var query = string.Join("&", queryValues
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .Select(item => Uri.EscapeDataString(item.Key) + "=" + Uri.EscapeDataString(item.Value)));
        var relativeUri = query.Length == 0 ? path : path + "?" + query;
        return new ValidatedRequest(operation, relativeUri, body?.DeepClone());
    }

    public JsonNode? ProjectToRequestSchema(JsonNode? source, OperationDefinition operation)
    {
        if (source is not JsonObject sourceObject || operation.RequestSchema is null)
        {
            return source?.DeepClone();
        }

        var schema = Resolve(operation.RequestSchema);
        if (schema["properties"] is not JsonObject properties)
        {
            return source.DeepClone();
        }

        var projected = new JsonObject();
        foreach (var property in properties)
        {
            if (sourceObject.TryGetPropertyValue(property.Key, out var value))
            {
                projected[property.Key] = value?.DeepClone();
            }
        }

        return projected;
    }

    private static IReadOnlyDictionary<string, OperationDefinition> ParseOperations(JsonObject document)
    {
        var result = new Dictionary<string, OperationDefinition>(StringComparer.Ordinal);
        foreach (var pathItem in document["paths"]!.AsObject())
        {
            if (pathItem.Value is not JsonObject methods)
            {
                continue;
            }

            foreach (var methodItem in methods.Where(item => SupportedMethods.Contains(item.Key)))
            {
                if (methodItem.Value is not JsonObject operationObject)
                {
                    continue;
                }

                var operationId = operationObject["operationId"]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(operationId))
                {
                    throw new ContractException($"{methodItem.Key.ToUpperInvariant()} {pathItem.Key} is missing operationId.");
                }

                var parameters = new List<ParameterDefinition>();
                if (operationObject["parameters"] is JsonArray parameterArray)
                {
                    foreach (var parameterNode in parameterArray.OfType<JsonObject>())
                    {
                        parameters.Add(new ParameterDefinition(
                            parameterNode["name"]?.GetValue<string>() ?? throw new ContractException("Parameter is missing name."),
                            parameterNode["in"]?.GetValue<string>() ?? throw new ContractException("Parameter is missing location."),
                            parameterNode["required"]?.GetValue<bool>() ?? false,
                            parameterNode["schema"]?.AsObject() ?? new JsonObject()));
                    }
                }

                JsonObject? requestSchema = null;
                var requestBodyRequired = false;
                if (operationObject["requestBody"] is JsonObject requestBody)
                {
                    requestBodyRequired = requestBody["required"]?.GetValue<bool>() ?? false;
                    requestSchema = requestBody["content"]?["application/json"]?["schema"]?.AsObject();
                }

                var tags = operationObject["tags"] is JsonArray tagArray
                    ? tagArray.Select(tag => tag?.GetValue<string>()).Where(tag => tag is not null).Select(tag => tag!).ToArray()
                    : Array.Empty<string>();

                var definition = new OperationDefinition(
                    operationId,
                    new HttpMethod(methodItem.Key.ToUpperInvariant()),
                    pathItem.Key,
                    operationObject["summary"]?.GetValue<string>() ?? operationId,
                    operationObject["description"]?.GetValue<string>() ?? string.Empty,
                    tags,
                    parameters,
                    requestSchema,
                    requestBodyRequired);

                if (!result.TryAdd(operationId, definition))
                {
                    throw new ContractException($"Duplicate operationId '{operationId}'.");
                }
            }
        }

        return result;
    }

    private void ValidateSchema(JsonNode node, JsonObject schemaNode, string path)
    {
        var schema = Resolve(schemaNode);

        if (schema["allOf"] is JsonArray allOf)
        {
            foreach (var part in allOf.OfType<JsonObject>())
            {
                ValidateSchema(node, part, path);
            }
        }

        if (schema["oneOf"] is JsonArray oneOf && !oneOf.OfType<JsonObject>().Any(candidate => IsValid(node, candidate, path)))
        {
            throw new ContractException($"{path} does not match any allowed oneOf schema.");
        }

        if (schema["anyOf"] is JsonArray anyOf && !anyOf.OfType<JsonObject>().Any(candidate => IsValid(node, candidate, path)))
        {
            throw new ContractException($"{path} does not match any allowed anyOf schema.");
        }

        if (node is null)
        {
            if (schema["nullable"]?.GetValue<bool>() == true || AllowsNull(schema))
            {
                return;
            }

            throw new ContractException($"{path} may not be null.");
        }

        var type = GetTypeName(schema);
        switch (type)
        {
            case "object":
                if (node is not JsonObject obj)
                {
                    throw new ContractException($"{path} must be an object.");
                }

                ValidateObject(obj, schema, path);
                break;
            case "array":
                if (node is not JsonArray array)
                {
                    throw new ContractException($"{path} must be an array.");
                }

                if (schema["items"] is JsonObject itemSchema)
                {
                    for (var index = 0; index < array.Count; index++)
                    {
                        if (array[index] is not null)
                        {
                            ValidateSchema(array[index]!, itemSchema, $"{path}[{index}]");
                        }
                    }
                }

                break;
            default:
                ValidateScalar(node, schema, path);
                break;
        }

        if (schema["enum"] is JsonArray enumValues &&
            !enumValues.Any(candidate => JsonNode.DeepEquals(candidate, node)))
        {
            throw new ContractException($"{path} is not one of the allowed values.");
        }
    }

    private void ValidateObject(JsonObject obj, JsonObject schema, string path)
    {
        var required = schema["required"] is JsonArray requiredArray
            ? requiredArray.Select(item => item?.GetValue<string>()).Where(item => item is not null).Select(item => item!).ToHashSet(StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in required)
        {
            if (!obj.ContainsKey(name!))
            {
                throw new ContractException($"{path}.{name} is required.");
            }
        }

        if (schema["properties"] is not JsonObject properties)
        {
            return;
        }

        foreach (var property in obj)
        {
            if (properties[property.Key] is JsonObject propertySchema)
            {
                if (property.Value is not null)
                {
                    ValidateSchema(property.Value, propertySchema, $"{path}.{property.Key}");
                }
            }
            else if (schema["additionalProperties"]?.GetValue<bool>() == false)
            {
                throw new ContractException($"{path}.{property.Key} is not allowed by the contract.");
            }
        }
    }

    private void ValidateScalar(JsonNode? node, JsonObject schemaNode, string path)
    {
        var schema = Resolve(schemaNode);
        var type = GetTypeName(schema);
        var value = node as JsonValue;
        var valid = type switch
        {
            null => true,
            "string" => value is not null && value.TryGetValue<string>(out _),
            "integer" => value is not null && (value.TryGetValue<long>(out _) || value.TryGetValue<int>(out _) || IsIntegerString(value)),
            "number" => value is not null && (value.TryGetValue<double>(out _) || IsNumberString(value)),
            "boolean" => value is not null && (value.TryGetValue<bool>(out _) || IsBooleanString(value)),
            _ => true
        };

        if (!valid)
        {
            throw new ContractException($"{path} must be {type}.");
        }

        if (type is "integer" or "number" && value is not null)
        {
            ValidateNumericBounds(value, schema, path);
        }

        if (type == "string" && value is not null && value.TryGetValue<string>(out var text))
        {
            if (schema["format"]?.GetValue<string>() == "uuid" && !Guid.TryParse(text, out _))
            {
                throw new ContractException($"{path} must be a UUID.");
            }

            if (schema["minLength"]?.GetValue<int?>() is int minLength && text.Length < minLength)
            {
                throw new ContractException($"{path} is shorter than {minLength} characters.");
            }
        }
    }

    private static void ValidateNumericBounds(JsonValue value, JsonObject schema, string path)
    {
        if (!TryReadDecimal(value, out var number))
        {
            throw new ContractException($"{path} must be a finite JSON number.");
        }

        if (schema.ContainsKey("minimum"))
        {
            if (!TryReadDecimal(schema["minimum"], out var minimum))
            {
                throw new ContractException($"The OpenAPI minimum constraint for {path} is invalid.");
            }

            if (number < minimum)
            {
                throw new ContractException($"{path} must be greater than or equal to {minimum.ToString(CultureInfo.InvariantCulture)}.");
            }
        }

        if (schema.ContainsKey("maximum"))
        {
            if (!TryReadDecimal(schema["maximum"], out var maximum))
            {
                throw new ContractException($"The OpenAPI maximum constraint for {path} is invalid.");
            }

            if (number > maximum)
            {
                throw new ContractException($"{path} must be less than or equal to {maximum.ToString(CultureInfo.InvariantCulture)}.");
            }
        }
    }

    private static bool TryReadDecimal(JsonNode? node, out decimal number)
    {
        if (node is JsonValue value)
        {
            if (value.TryGetValue<decimal>(out number))
            {
                return true;
            }

            if (value.TryGetValue<int>(out var integer32))
            {
                number = integer32;
                return true;
            }

            if (value.TryGetValue<long>(out var integer))
            {
                number = integer;
                return true;
            }

            if (value.TryGetValue<uint>(out var unsignedInteger32))
            {
                number = unsignedInteger32;
                return true;
            }

            if (value.TryGetValue<ulong>(out var unsignedInteger64))
            {
                number = unsignedInteger64;
                return true;
            }

            if (value.TryGetValue<double>(out var floatingPoint) && double.IsFinite(floatingPoint))
            {
                try
                {
                    number = (decimal)floatingPoint;
                    return true;
                }
                catch (OverflowException)
                {
                }
            }

            if (value.TryGetValue<string>(out var text) &&
                decimal.TryParse(
                    text,
                    NumberStyles.Float | NumberStyles.AllowThousands,
                    CultureInfo.InvariantCulture,
                    out number))
            {
                return true;
            }
        }

        number = default;
        return false;
    }

    private JsonObject Resolve(JsonObject schema)
    {
        var reference = schema["$ref"]?.GetValue<string>();
        if (reference is null)
        {
            return schema;
        }

        if (!reference.StartsWith("#/", StringComparison.Ordinal))
        {
            throw new ContractException($"External schema reference '{reference}' is not allowed.");
        }

        JsonNode? current = _document;
        foreach (var segment in reference[2..].Split('/'))
        {
            current = current?[segment.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal)];
        }

        return current as JsonObject ?? throw new ContractException($"Schema reference '{reference}' was not found.");
    }

    private bool IsValid(JsonNode node, JsonObject schema, string path)
    {
        try
        {
            ValidateSchema(node, schema, path);
            return true;
        }
        catch (ContractException)
        {
            return false;
        }
    }

    private static void RejectUnknown(IEnumerable<string> actual, IEnumerable<string> allowed, string location)
    {
        var allowlist = allowed.ToHashSet(StringComparer.Ordinal);
        var unknown = actual.FirstOrDefault(name => !allowlist.Contains(name));
        if (unknown is not null)
        {
            throw new ContractException($"Unknown {location} parameter '{unknown}'.");
        }
    }

    private static JsonNode ParseQueryValue(string value, JsonObject schema)
    {
        return GetTypeName(schema) switch
        {
            "integer" when long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var integer) => JsonValue.Create(integer),
            "number" when double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out var number) => JsonValue.Create(number),
            "boolean" when bool.TryParse(value, out var boolean) => JsonValue.Create(boolean),
            _ => JsonValue.Create(value)
        };
    }

    private static string? GetTypeName(JsonObject schema)
    {
        if (schema["type"] is JsonValue value && value.TryGetValue<string>(out var type))
        {
            return type;
        }

        if (schema["type"] is JsonArray array)
        {
            return array.Select(item => item?.GetValue<string>()).FirstOrDefault(item => item != "null");
        }

        return schema.ContainsKey("properties") ? "object" : null;
    }

    private static bool AllowsNull(JsonObject schema) =>
        schema["type"] is JsonArray array && array.Any(item => item?.GetValue<string>() == "null");

    private static bool IsIntegerString(JsonValue value) =>
        value.TryGetValue<string>(out var text) && long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out _);

    private static bool IsNumberString(JsonValue value) =>
        value.TryGetValue<string>(out var text) && double.TryParse(text, NumberStyles.Number, CultureInfo.InvariantCulture, out _);

    private static bool IsBooleanString(JsonValue value) =>
        value.TryGetValue<string>(out var text) && bool.TryParse(text, out _);

    [GeneratedRegex("^\\{(?<name>[^}]+)\\}$", RegexOptions.CultureInvariant)]
    private static partial Regex PathParameterPattern();
}

public sealed record ValidatedRequest(OperationDefinition Operation, string RelativeUri, JsonNode? Body);

public sealed class ContractException : Exception
{
    public ContractException(string message)
        : base(message)
    {
    }

    public ContractException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
