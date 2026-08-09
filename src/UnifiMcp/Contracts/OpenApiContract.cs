using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace UnifiMcp.Contracts;

public sealed partial class OpenApiContract
{
    private const int MaxControllerResponseSchemaNodes = 4096;
    private const int MaxResponseSchemaTraversalStates = 16384;

    private static readonly HashSet<string> SupportedMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "get", "post", "put", "patch", "delete"
    };

    private static readonly HashSet<string> AnnotationOnlySchemaKeywords = new(StringComparer.Ordinal)
    {
        "$comment",
        "default",
        "deprecated",
        "description",
        "example",
        "examples",
        "externalDocs",
        "readOnly",
        "title",
        "writeOnly",
        "xml"
    };

    private readonly JsonObject _requestDocument;
    private readonly JsonObject _responseDocument;
    private readonly IReadOnlyDictionary<string, OperationDefinition> _operations;

    private OpenApiContract(JsonObject document, string source)
        : this(document, document, source)
    {
    }

    private OpenApiContract(JsonObject requestDocument, JsonObject responseDocument, string source)
    {
        _requestDocument = requestDocument;
        _responseDocument = responseDocument;
        Source = source;
        Version = responseDocument["info"]?["version"]?.GetValue<string>()
            ?? throw new ContractException("OpenAPI contract is missing info.version.");
        _operations = ParseOperations(requestDocument);
    }

    public string Version { get; }

    public string Source { get; }

    public IReadOnlyCollection<OperationDefinition> Operations => _operations.Values.ToArray();

    public int ReadCount => _operations.Values.Count(operation => operation.IsRead);

    public int WriteCount => _operations.Count - ReadCount;

    public bool ResponseSchemaContainsPath(string operationId, params string[] propertyPath)
    {
        if (propertyPath.Length == 0)
        {
            throw new ArgumentException("A response property path is required.", nameof(propertyPath));
        }

        var operation = GetOperation(operationId, requireRead: true);
        var methodName = operation.Method.Method.ToLowerInvariant();
        var controllerSchema = GetResponseSchema(_responseDocument, operation, methodName);
        if (controllerSchema is not null)
        {
            return SchemaContainsPath(
                controllerSchema,
                _responseDocument,
                propertyPath,
                0);
        }

        var reviewedSchema = GetResponseSchema(_requestDocument, operation, methodName);
        return reviewedSchema is not null &&
            SchemaContainsPath(
                reviewedSchema,
                _requestDocument,
                propertyPath,
                0);
    }

    internal OpenApiContract RestrictOperationsTo(OpenApiContract reviewedContract)
    {
        var restricted = new OpenApiContract(reviewedContract._requestDocument, _responseDocument, Source);
        restricted.ValidateControllerResponseSchemas();
        return restricted;
    }

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

    public JsonNode? ProjectToRequestSchema(JsonNode? source, OperationDefinition operation) =>
        ProjectToRequestSchema(source, source, operation);

    public JsonNode? ProjectToRequestSchema(
        JsonNode? source,
        JsonNode? discriminatorSource,
        OperationDefinition operation)
    {
        if (operation.RequestSchema is null)
        {
            return source?.DeepClone();
        }

        return ProjectToSchema(
            source,
            discriminatorSource,
            operation.RequestSchema,
            "current resource",
            new HashSet<string>(StringComparer.Ordinal));
    }

    private JsonNode? ProjectToSchema(
        JsonNode? source,
        JsonNode? discriminatorSource,
        JsonObject schemaNode,
        string path,
        HashSet<string> visitedReferences)
    {
        if (source is null)
        {
            return null;
        }

        var reference = schemaNode["$ref"]?.GetValue<string>();
        if (reference is not null && !visitedReferences.Add(reference))
        {
            return source is JsonObject ? new JsonObject() : source.DeepClone();
        }

        var schema = Resolve(schemaNode);
        if (source is JsonArray sourceArray && schema["items"] is JsonObject itemSchema)
        {
            var projectedArray = new JsonArray();
            var discriminatorArray = discriminatorSource as JsonArray;
            for (var index = 0; index < sourceArray.Count; index++)
            {
                projectedArray.Add(ProjectToSchema(
                    sourceArray[index],
                    discriminatorArray is not null && index < discriminatorArray.Count
                        ? discriminatorArray[index]
                        : sourceArray[index],
                    itemSchema,
                    path + "[]",
                    new HashSet<string>(StringComparer.Ordinal)));
            }

            return projectedArray;
        }

        if (source is not JsonObject sourceObject)
        {
            return source.DeepClone();
        }

        var discriminatorObject = discriminatorSource as JsonObject ?? sourceObject;
        var projected = new JsonObject();
        var constrained = false;
        if (schema["allOf"] is JsonArray allOf)
        {
            foreach (var part in allOf.OfType<JsonObject>())
            {
                constrained = true;
                MergeProjection(
                    projected,
                    ProjectToSchema(
                        sourceObject,
                        discriminatorObject,
                        part,
                        path,
                        new HashSet<string>(visitedReferences, StringComparer.Ordinal)));
            }
        }

        if (schema["properties"] is JsonObject properties)
        {
            constrained = true;
            foreach (var property in properties)
            {
                if (property.Value is JsonObject propertySchema &&
                    sourceObject.TryGetPropertyValue(property.Key, out var value))
                {
                    var propertyDiscriminatorSource = discriminatorObject.TryGetPropertyValue(
                        property.Key,
                        out var discriminatorValue)
                        ? discriminatorValue
                        : value;
                    projected[property.Key] = ProjectToSchema(
                        value,
                        propertyDiscriminatorSource,
                        propertySchema,
                        $"{path}.{property.Key}",
                        new HashSet<string>(StringComparer.Ordinal));
                }
            }
        }

        var discriminatorSchema = ResolveDiscriminatorSchema(schema, discriminatorObject, path);
        if (discriminatorSchema is not null)
        {
            constrained = true;
            MergeProjection(
                projected,
                ProjectToSchema(
                    sourceObject,
                    discriminatorObject,
                    discriminatorSchema,
                    path,
                    new HashSet<string>(visitedReferences, StringComparer.Ordinal)));
        }

        return constrained ? projected : source.DeepClone();
    }

    private static void MergeProjection(JsonObject target, JsonNode? projection)
    {
        if (projection is not JsonObject projectedObject)
        {
            return;
        }

        foreach (var property in projectedObject)
        {
            target[property.Key] = property.Value?.DeepClone();
        }
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

    private void ValidateSchema(JsonNode? node, JsonObject schemaNode, string path) =>
        ValidateSchema(
            node,
            schemaNode,
            path,
            new HashSet<string>(StringComparer.Ordinal),
            enforceDeclaredProperties: true);

    private void ValidateSchema(
        JsonNode? node,
        JsonObject schemaNode,
        string path,
        HashSet<string> visitedReferences,
        bool enforceDeclaredProperties)
    {
        var reference = schemaNode["$ref"]?.GetValue<string>();
        if (reference is not null && !visitedReferences.Add(reference))
        {
            return;
        }

        var schema = Resolve(schemaNode);

        if (IsUnconstrainedSchema(schema))
        {
            return;
        }

        if (node is null)
        {
            if (SchemaAllowsNull(schemaNode, new HashSet<string>(StringComparer.Ordinal)))
            {
                return;
            }

            throw new ContractException($"{path} may not be null.");
        }

        if (node is JsonObject declaredObject && enforceDeclaredProperties)
        {
            ValidateDeclaredObjectProperties(declaredObject, schema, path);
        }

        if (schema["allOf"] is JsonArray allOf)
        {
            foreach (var part in allOf.OfType<JsonObject>())
            {
                ValidateSchema(
                    node,
                    part,
                    path,
                    new HashSet<string>(visitedReferences, StringComparer.Ordinal),
                    enforceDeclaredProperties: false);
            }
        }

        if (node is JsonObject discriminatorObject)
        {
            var discriminatorSchema = ResolveDiscriminatorSchema(schema, discriminatorObject, path);
            if (discriminatorSchema is not null)
            {
                ValidateSchema(
                    node,
                    discriminatorSchema,
                    path,
                    new HashSet<string>(visitedReferences, StringComparer.Ordinal),
                    enforceDeclaredProperties: false);
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
                        ValidateSchema(array[index], itemSchema, $"{path}[{index}]");
                    }
                }

                break;
            case "null":
                throw new ContractException($"{path} must be null.");
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

    private JsonObject? ResolveDiscriminatorSchema(JsonObject schema, JsonObject source, string path)
    {
        if (schema["discriminator"] is not JsonObject discriminator)
        {
            return null;
        }

        var propertyName = discriminator["propertyName"]?.GetValue<string>()
            ?? throw new ContractException("OpenAPI discriminator is missing propertyName.");
        if (!source.TryGetPropertyValue(propertyName, out var discriminatorNode) ||
            discriminatorNode is not JsonValue discriminatorValue ||
            !discriminatorValue.TryGetValue<string>(out var selectedValue) ||
            string.IsNullOrWhiteSpace(selectedValue))
        {
            throw new ContractException($"{path}.{propertyName} must select a discriminator variant.");
        }

        if (discriminator["mapping"] is not JsonObject mapping)
        {
            throw new ContractException("OpenAPI discriminator is missing mapping.");
        }

        var mappingKey = selectedValue;
        if (!mapping.ContainsKey(mappingKey) &&
            IsDeclaredDiscriminatorWireValue(schema, propertyName, selectedValue))
        {
            mappingKey = EncodeDiscriminatorValue(selectedValue);
        }

        if (mapping[mappingKey] is not JsonValue mappingValue ||
            !mappingValue.TryGetValue<string>(out var mappedReference) ||
            string.IsNullOrWhiteSpace(mappedReference))
        {
            throw new ContractException(
                $"{path}.{propertyName} value '{selectedValue}' does not select a supported discriminator variant.");
        }

        return new JsonObject { ["$ref"] = mappedReference };
    }

    private bool IsDeclaredDiscriminatorWireValue(JsonObject schema, string propertyName, string selectedValue)
    {
        if (schema["properties"]?[propertyName] is not JsonObject propertySchema)
        {
            return false;
        }

        var resolvedProperty = Resolve(propertySchema);
        return resolvedProperty["enum"] is JsonArray wireValues &&
            wireValues.Any(candidate => candidate is JsonValue value &&
                value.TryGetValue<string>(out var wireValue) &&
                string.Equals(wireValue, selectedValue, StringComparison.Ordinal));
    }

    private static string EncodeDiscriminatorValue(string value) =>
        string.Concat(value.Select(character =>
            char.IsLetterOrDigit(character) ? char.ToUpperInvariant(character) : '_'));

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

        var properties = schema["properties"] as JsonObject;
        foreach (var property in obj)
        {
            if (properties?[property.Key] is JsonObject propertySchema)
            {
                ValidateSchema(property.Value, propertySchema, $"{path}.{property.Key}");
            }
        }
    }

    private void ValidateDeclaredObjectProperties(JsonObject obj, JsonObject schema, string path)
    {
        var propertyPolicy = GetObjectPropertyPolicy(
            schema,
            obj,
            path,
            new HashSet<string>(StringComparer.Ordinal));
        foreach (var property in obj)
        {
            if (!propertyPolicy.DeclaredProperties.Contains(property.Key))
            {
                if (propertyPolicy.AdditionalPropertySchema is not null)
                {
                    ValidateSchema(
                        property.Value,
                        propertyPolicy.AdditionalPropertySchema,
                        $"{path}.{property.Key}");
                }
                else if (!propertyPolicy.AllowsAdditionalProperties)
                {
                    throw new ContractException($"{path}.{property.Key} is not allowed by the contract.");
                }
            }
        }
    }

    private ObjectPropertyPolicy GetObjectPropertyPolicy(
        JsonObject schemaNode,
        JsonObject source,
        string path,
        HashSet<string> visitedReferences)
    {
        var reference = schemaNode["$ref"]?.GetValue<string>();
        if (reference is not null && !visitedReferences.Add(reference))
        {
            return new ObjectPropertyPolicy();
        }

        var schema = Resolve(schemaNode);
        var policy = new ObjectPropertyPolicy();
        if (schema["properties"] is JsonObject properties)
        {
            policy.DeclaredProperties.UnionWith(properties.Select(property => property.Key));
        }

        if (schema["additionalProperties"] is JsonValue additionalValue &&
            additionalValue.TryGetValue<bool>(out var allowsAdditional) &&
            allowsAdditional)
        {
            policy.AllowsAdditionalProperties = true;
        }
        else if (schema["additionalProperties"] is JsonObject additionalSchema)
        {
            policy.AdditionalPropertySchema = additionalSchema;
        }

        if (schema["allOf"] is JsonArray allOf)
        {
            foreach (var part in allOf.OfType<JsonObject>())
            {
                policy.Merge(GetObjectPropertyPolicy(
                    part,
                    source,
                    path,
                    new HashSet<string>(visitedReferences, StringComparer.Ordinal)));
            }
        }

        foreach (var compositionName in new[] { "oneOf", "anyOf" })
        {
            if (schema[compositionName] is not JsonArray composition)
            {
                continue;
            }

            foreach (var candidate in composition.OfType<JsonObject>())
            {
                policy.Merge(GetObjectPropertyPolicy(
                    candidate,
                    source,
                    path,
                    new HashSet<string>(visitedReferences, StringComparer.Ordinal)));
            }
        }

        var discriminatorSchema = ResolveDiscriminatorSchema(schema, source, path);
        if (discriminatorSchema is not null)
        {
            policy.Merge(GetObjectPropertyPolicy(
                discriminatorSchema,
                source,
                path,
                new HashSet<string>(visitedReferences, StringComparer.Ordinal)));
        }

        return policy;
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

    private JsonObject Resolve(JsonObject schema) => Resolve(schema, _requestDocument);

    private static JsonObject Resolve(JsonObject schema, JsonObject document)
    {
        if (!schema.ContainsKey("$ref"))
        {
            return schema;
        }

        if (schema["$ref"] is not JsonValue referenceValue ||
            !referenceValue.TryGetValue<string>(out var reference) ||
            string.IsNullOrWhiteSpace(reference))
        {
            throw new ContractException("Schema reference must be a non-empty string.");
        }

        if (!reference.StartsWith("#/", StringComparison.Ordinal))
        {
            throw new ContractException($"External schema reference '{reference}' is not allowed.");
        }

        JsonNode? current = document;
        foreach (var segment in reference[2..].Split('/'))
        {
            current = current?[segment.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal)];
        }

        return current as JsonObject ?? throw new ContractException($"Schema reference '{reference}' was not found.");
    }

    private static bool SchemaContainsPath(
        JsonObject schemaNode,
        JsonObject schemaDocument,
        IReadOnlyList<string> propertyPath,
        int pathIndex)
    {
        var pending = new Queue<(JsonObject Schema, int PathIndex)>();
        var visited = new Dictionary<JsonObject, HashSet<int>>(ReferenceEqualityComparer.Instance);
        pending.Enqueue((schemaNode, pathIndex));
        var traversalStates = 0;

        while (pending.TryDequeue(out var current))
        {
            if (!visited.TryGetValue(current.Schema, out var visitedIndexes))
            {
                visitedIndexes = new HashSet<int>();
                visited.Add(current.Schema, visitedIndexes);
            }

            if (!visitedIndexes.Add(current.PathIndex))
            {
                continue;
            }

            traversalStates++;
            if (traversalStates > MaxResponseSchemaTraversalStates)
            {
                throw new ContractException(
                    $"Response schema traversal exceeded the {MaxResponseSchemaTraversalStates} state limit.");
            }

            if (current.Schema.ContainsKey("$ref"))
            {
                pending.Enqueue((Resolve(current.Schema, schemaDocument), current.PathIndex));
                continue;
            }

            foreach (var compositionName in new[] { "allOf", "oneOf", "anyOf" })
            {
                if (current.Schema[compositionName] is not JsonArray composition)
                {
                    continue;
                }

                foreach (var candidate in composition.OfType<JsonObject>())
                {
                    pending.Enqueue((candidate, current.PathIndex));
                }
            }

            if (current.Schema["properties"] is not JsonObject properties ||
                properties[propertyPath[current.PathIndex]] is not JsonObject propertySchema)
            {
                continue;
            }

            if (current.PathIndex == propertyPath.Count - 1)
            {
                return true;
            }

            var nextSchema = Resolve(propertySchema, schemaDocument);
            if (nextSchema["items"] is JsonObject items)
            {
                nextSchema = Resolve(items, schemaDocument);
            }

            pending.Enqueue((nextSchema, current.PathIndex + 1));
        }

        return false;
    }

    private void ValidateControllerResponseSchemas()
    {
        var pending = new Queue<JsonObject>();
        foreach (var operation in _operations.Values.Where(operation => operation.IsRead))
        {
            var schema = GetResponseSchema(
                _responseDocument,
                operation,
                operation.Method.Method.ToLowerInvariant());
            if (schema is not null)
            {
                pending.Enqueue(schema);
            }
        }

        var visited = new HashSet<JsonObject>(ReferenceEqualityComparer.Instance);
        while (pending.TryDequeue(out var schema))
        {
            if (!visited.Add(schema))
            {
                continue;
            }

            if (visited.Count > MaxControllerResponseSchemaNodes)
            {
                throw new ContractException(
                    $"Controller response schemas exceed the {MaxControllerResponseSchemaNodes} node limit.");
            }

            if (schema.ContainsKey("$ref"))
            {
                pending.Enqueue(Resolve(schema, _responseDocument));
                continue;
            }

            EnqueueSchemaChildren(schema, pending);
        }
    }

    private static void EnqueueSchemaChildren(JsonObject schema, Queue<JsonObject> pending)
    {
        foreach (var compositionName in new[] { "allOf", "oneOf", "anyOf", "prefixItems" })
        {
            if (schema[compositionName] is JsonArray composition)
            {
                foreach (var candidate in composition.OfType<JsonObject>())
                {
                    pending.Enqueue(candidate);
                }
            }
        }

        foreach (var childName in new[]
        {
            "additionalProperties", "contains", "else", "if", "items", "not", "propertyNames", "then",
            "unevaluatedItems", "unevaluatedProperties"
        })
        {
            if (schema[childName] is JsonObject child)
            {
                pending.Enqueue(child);
            }
        }

        foreach (var childCollectionName in new[] { "dependentSchemas", "patternProperties", "properties" })
        {
            if (schema[childCollectionName] is JsonObject children)
            {
                foreach (var child in children.Select(item => item.Value).OfType<JsonObject>())
                {
                    pending.Enqueue(child);
                }
            }
        }
    }

    private bool IsValid(JsonNode? node, JsonObject schema, string path)
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

        return schema.ContainsKey("properties") || schema.ContainsKey("required") ? "object" : null;
    }

    private static bool AllowsNull(JsonObject schema) =>
        schema["type"] is JsonArray array && array.Any(item => item?.GetValue<string>() == "null");

    private bool SchemaAllowsNull(JsonObject schemaNode, HashSet<string> visitedReferences)
    {
        if (schemaNode["nullable"]?.GetValue<bool>() == true ||
            AllowsNull(schemaNode) ||
            HasNullType(schemaNode) ||
            ReviewedDescriptionAllowsNull(schemaNode))
        {
            return true;
        }

        var reference = schemaNode["$ref"]?.GetValue<string>();
        if (reference is not null && !visitedReferences.Add(reference))
        {
            return false;
        }

        var schema = Resolve(schemaNode);
        if (schema["nullable"]?.GetValue<bool>() == true ||
            AllowsNull(schema) ||
            HasNullType(schema) ||
            ReviewedDescriptionAllowsNull(schema) ||
            IsUnconstrainedSchema(schema) ||
            schema["enum"] is JsonArray enumValues && enumValues.Any(value => value is null))
        {
            return true;
        }

        if (schema["oneOf"] is JsonArray oneOf && oneOf.OfType<JsonObject>().Any(candidate =>
            SchemaAllowsNull(candidate, new HashSet<string>(visitedReferences, StringComparer.Ordinal))))
        {
            return true;
        }

        if (schema["anyOf"] is JsonArray anyOf && anyOf.OfType<JsonObject>().Any(candidate =>
            SchemaAllowsNull(candidate, new HashSet<string>(visitedReferences, StringComparer.Ordinal))))
        {
            return true;
        }

        return schema["allOf"] is JsonArray allOf &&
            allOf.OfType<JsonObject>().Any() &&
            allOf.OfType<JsonObject>().All(candidate =>
                SchemaAllowsNull(candidate, new HashSet<string>(visitedReferences, StringComparer.Ordinal)));
    }

    private static bool HasNullType(JsonObject schema) =>
        schema["type"] is JsonValue typeValue &&
        typeValue.TryGetValue<string>(out var type) &&
        string.Equals(type, "null", StringComparison.Ordinal);

    private static bool ReviewedDescriptionAllowsNull(JsonObject schema)
    {
        if (schema["description"] is not JsonValue descriptionValue ||
            !descriptionValue.TryGetValue<string>(out var description))
        {
            return false;
        }

        // The reviewed UniFi 10.5.67 generator omitted a nullable keyword for a
        // small set of clearable fields while explicitly documenting this wire behavior.
        return description.Contains("omitted or null", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUnconstrainedSchema(JsonObject schema) =>
        schema.Count == 0 || schema.All(property => AnnotationOnlySchemaKeywords.Contains(property.Key));

    private static JsonObject? GetResponseSchema(
        JsonObject document,
        OperationDefinition operation,
        string methodName)
    {
        if (document["paths"] is not JsonObject paths ||
            paths[operation.PathTemplate] is not JsonObject pathItem ||
            pathItem[methodName] is not JsonObject operationObject)
        {
            return null;
        }

        if (!string.Equals(
                operationObject["operationId"]?.GetValue<string>(),
                operation.OperationId,
                StringComparison.Ordinal))
        {
            return null;
        }

        return operationObject?["responses"]?["200"]?["content"]?["application/json"]?["schema"] as JsonObject;
    }

    private static bool IsIntegerString(JsonValue value) =>
        value.TryGetValue<string>(out var text) && long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out _);

    private static bool IsNumberString(JsonValue value) =>
        value.TryGetValue<string>(out var text) && double.TryParse(text, NumberStyles.Number, CultureInfo.InvariantCulture, out _);

    private static bool IsBooleanString(JsonValue value) =>
        value.TryGetValue<string>(out var text) && bool.TryParse(text, out _);

    [GeneratedRegex("^\\{(?<name>[^}]+)\\}$", RegexOptions.CultureInvariant)]
    private static partial Regex PathParameterPattern();

    private sealed class ObjectPropertyPolicy
    {
        public HashSet<string> DeclaredProperties { get; } = new(StringComparer.Ordinal);

        public bool AllowsAdditionalProperties { get; set; }

        public JsonObject? AdditionalPropertySchema { get; set; }

        public void Merge(ObjectPropertyPolicy other)
        {
            DeclaredProperties.UnionWith(other.DeclaredProperties);
            AllowsAdditionalProperties |= other.AllowsAdditionalProperties;
            AdditionalPropertySchema ??= other.AdditionalPropertySchema;
        }
    }
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
