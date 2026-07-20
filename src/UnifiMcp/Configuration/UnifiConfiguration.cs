using System.Globalization;

namespace UnifiMcp.Configuration;

public sealed record UnifiConfiguration(
    Uri BaseUri,
    string ApiKey,
    string? DefaultSiteId,
    TimeSpan RequestTimeout)
{
    public const string DefaultBaseUrl = "https://unifi.nutria-newton.ts.net/proxy/network/integration";

    public static UnifiConfiguration Load(bool requireApiKey = true)
    {
        var baseUrl = Environment.GetEnvironmentVariable("UNIFI_BASE_URL")?.Trim();
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            baseUrl = DefaultBaseUrl;
        }

        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri) ||
            !string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigurationException("UNIFI_BASE_URL must be an absolute HTTPS URL.");
        }

        if (!string.IsNullOrEmpty(baseUri.UserInfo) ||
            !string.IsNullOrEmpty(baseUri.Query) ||
            !string.IsNullOrEmpty(baseUri.Fragment))
        {
            throw new ConfigurationException("UNIFI_BASE_URL must not include credentials, a query, or a fragment.");
        }

        var normalizedPath = baseUri.AbsolutePath.TrimEnd('/');
        if (!normalizedPath.EndsWith("/proxy/network/integration", StringComparison.Ordinal))
        {
            throw new ConfigurationException("UNIFI_BASE_URL must end with /proxy/network/integration.");
        }

        baseUri = new UriBuilder(baseUri) { Path = normalizedPath + "/" }.Uri;

        var apiKey = Environment.GetEnvironmentVariable("UNIFI_API_KEY")?.Trim() ?? string.Empty;
        if (requireApiKey && string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ConfigurationException(
                "UNIFI_API_KEY is missing. Launch the connector through `op run --env-file .env.op -- ...`.");
        }

        if (apiKey.StartsWith("op://", StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigurationException(
                "UNIFI_API_KEY is still a 1Password reference. Launch through `op run` so it is resolved before startup.");
        }

        var defaultSiteId = Environment.GetEnvironmentVariable("UNIFI_DEFAULT_SITE_ID")?.Trim();
        if (!string.IsNullOrEmpty(defaultSiteId) && !Guid.TryParse(defaultSiteId, out _))
        {
            throw new ConfigurationException("UNIFI_DEFAULT_SITE_ID must be a UUID when set.");
        }

        var timeout = TimeSpan.FromSeconds(30);
        var timeoutText = Environment.GetEnvironmentVariable("UNIFI_TIMEOUT_SECONDS")?.Trim();
        if (!string.IsNullOrEmpty(timeoutText))
        {
            if (!double.TryParse(timeoutText, NumberStyles.Number, CultureInfo.InvariantCulture, out var seconds) ||
                seconds < 1 || seconds > 300)
            {
                throw new ConfigurationException("UNIFI_TIMEOUT_SECONDS must be between 1 and 300.");
            }

            timeout = TimeSpan.FromSeconds(seconds);
        }

        return new UnifiConfiguration(baseUri, apiKey, defaultSiteId, timeout);
    }
}

public sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message)
        : base(message)
    {
    }
}
