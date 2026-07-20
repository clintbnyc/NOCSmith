using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace UnifiMcp.Security;

public sealed partial class SecretRedactor
{
    private const string Redacted = "<redacted>";
    private readonly string[] _knownSecrets;

    public SecretRedactor(params string?[] knownSecrets)
    {
        _knownSecrets = knownSecrets
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    public JsonNode? Redact(JsonNode? source)
    {
        if (source is null)
        {
            return null;
        }

        return RedactNode(source, null);
    }

    public string Redact(string? value)
    {
        var result = value ?? string.Empty;
        foreach (var secret in _knownSecrets)
        {
            result = result.Replace(secret, Redacted, StringComparison.Ordinal);
        }

        result = BearerPattern().Replace(result, "$1" + Redacted);
        result = ApiKeyPattern().Replace(result, "$1" + Redacted);
        return result;
    }

    public string RedactRequestTarget(string value)
    {
        var querySeparator = value.IndexOf('?', StringComparison.Ordinal);
        if (querySeparator < 0)
        {
            return Redact(value);
        }

        var path = Redact(value[..querySeparator]);
        var parameters = value[(querySeparator + 1)..]
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(parameter =>
            {
                var equals = parameter.IndexOf('=', StringComparison.Ordinal);
                var encodedName = equals < 0 ? parameter : parameter[..equals];
                var name = Uri.UnescapeDataString(encodedName);
                return string.Equals(name, "filter", StringComparison.OrdinalIgnoreCase)
                    ? encodedName + "=" + Uri.EscapeDataString(Redacted)
                    : Redact(parameter);
            });
        return path + "?" + string.Join("&", parameters);
    }

    private JsonNode? RedactNode(JsonNode node, string? propertyName)
    {
        if (propertyName is not null && SensitiveNamePattern().IsMatch(propertyName))
        {
            return JsonValue.Create(Redacted);
        }

        return node switch
        {
            JsonObject obj => RedactObject(obj),
            JsonArray array => new JsonArray(array.Select(item => item is null ? null : RedactNode(item, null)).ToArray()),
            JsonValue value when value.TryGetValue<string>(out var text) => JsonValue.Create(Redact(text)),
            _ => node.DeepClone()
        };
    }

    private JsonObject RedactObject(JsonObject source)
    {
        var result = new JsonObject();
        var isVoucher = source.ContainsKey("code") &&
            (source.ContainsKey("timeLimitMinutes") ||
             source.ContainsKey("authorizedGuestCount") ||
             source.ContainsKey("authorizedGuestLimit"));
        foreach (var property in source)
        {
            result[property.Key] = property.Value is null
                ? null
                : isVoucher && string.Equals(property.Key, "code", StringComparison.OrdinalIgnoreCase)
                    ? JsonValue.Create(Redacted)
                    : RedactNode(property.Value, property.Key);
        }

        return result;
    }

    [GeneratedRegex("(?:password|passwd|passphrase|private.?key|api.?key|secret|token|credential|pre.?shared|psk)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveNamePattern();

    [GeneratedRegex("(?i)(bearer\\s+)[A-Za-z0-9._~+/=-]+")]
    private static partial Regex BearerPattern();

    [GeneratedRegex("(?i)(x-api-key[=:]\\s*)[^\\s,;]+")]
    private static partial Regex ApiKeyPattern();
}
