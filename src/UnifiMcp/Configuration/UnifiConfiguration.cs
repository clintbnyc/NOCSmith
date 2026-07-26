using System.Globalization;

namespace UnifiMcp.Configuration;

public sealed record UnifiConfiguration(
    Uri BaseUri,
    string ApiKey,
    string? DefaultSiteId,
    TimeSpan RequestTimeout,
    bool EnableLegacyReadEnrichment = false,
    string? SiteManagerApiKey = null,
    string? SiteManagerLocalHostId = null,
    bool EnableClientJournal = false,
    string? ClientJournalDatabasePath = null,
    int ClientJournalRetentionDays = 90,
    int ClientJournalMaximumMib = 256)
{
    public const string DefaultBaseUrl = "https://unifi.nutria-newton.ts.net/proxy/network/integration";
    public const string SiteManagerBaseUrl = "https://api.ui.com/";

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
                "UNIFI_API_KEY is missing. Set it in the process environment or launch with --env-file <path>.");
        }

        if (apiKey.StartsWith("op://", StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigurationException(
                "UNIFI_API_KEY is still a 1Password reference. Use a mounted 1Password Environment file or another runtime injector.");
        }

        var siteManagerApiKey = NullIfWhiteSpace(
            Environment.GetEnvironmentVariable("UNIFI_SITE_API_KEY"));
        if (siteManagerApiKey?.StartsWith("op://", StringComparison.OrdinalIgnoreCase) == true)
        {
            throw new ConfigurationException(
                "UNIFI_SITE_API_KEY is still a 1Password reference. Use a mounted 1Password Environment file or another runtime injector.");
        }

        var siteManagerLocalHostId = NullIfWhiteSpace(
            Environment.GetEnvironmentVariable("UNIFI_SITE_MANAGER_LOCAL_HOST_ID"));
        if (siteManagerLocalHostId is not null &&
            (siteManagerLocalHostId.Length > 512 || siteManagerLocalHostId.Any(char.IsControl)))
        {
            throw new ConfigurationException(
                "UNIFI_SITE_MANAGER_LOCAL_HOST_ID must be an opaque host ID of at most 512 characters without control characters.");
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

        var enableLegacyReadEnrichment = false;
        var legacyReadText = Environment.GetEnvironmentVariable("UNIFI_ENABLE_LEGACY_READ_ENRICHMENT")?.Trim();
        if (!string.IsNullOrEmpty(legacyReadText) &&
            !bool.TryParse(legacyReadText, out enableLegacyReadEnrichment))
        {
            throw new ConfigurationException("UNIFI_ENABLE_LEGACY_READ_ENRICHMENT must be true or false when set.");
        }

        var enableClientJournal = ReadBoolean(
            "UNIFI_ENABLE_CLIENT_JOURNAL",
            defaultValue: false);
        var clientJournalDatabasePath = NullIfWhiteSpace(
            Environment.GetEnvironmentVariable("UNIFI_CLIENT_JOURNAL_DB_PATH"));
        if (enableClientJournal)
        {
            if (clientJournalDatabasePath is null)
            {
                throw new ConfigurationException(
                    "UNIFI_CLIENT_JOURNAL_DB_PATH is required when UNIFI_ENABLE_CLIENT_JOURNAL=true.");
            }

            if (!Path.IsPathFullyQualified(clientJournalDatabasePath))
            {
                throw new ConfigurationException(
                    "UNIFI_CLIENT_JOURNAL_DB_PATH must be an absolute local filesystem path.");
            }

            if (clientJournalDatabasePath.Any(char.IsControl))
            {
                throw new ConfigurationException(
                    "UNIFI_CLIENT_JOURNAL_DB_PATH must not contain control characters.");
            }

            clientJournalDatabasePath = Path.GetFullPath(clientJournalDatabasePath);
        }

        var clientJournalRetentionDays = ReadBoundedInteger(
            "UNIFI_CLIENT_JOURNAL_RETENTION_DAYS",
            defaultValue: 90,
            minimum: 1,
            maximum: 3650);
        var clientJournalMaximumMib = ReadBoundedInteger(
            "UNIFI_CLIENT_JOURNAL_MAX_MIB",
            defaultValue: 256,
            minimum: 16,
            maximum: 4096);

        return new UnifiConfiguration(
            baseUri,
            apiKey,
            defaultSiteId,
            timeout,
            enableLegacyReadEnrichment,
            siteManagerApiKey,
            siteManagerLocalHostId,
            enableClientJournal,
            clientJournalDatabasePath,
            clientJournalRetentionDays,
            clientJournalMaximumMib);
    }

    public bool SiteManagerConfigured => !string.IsNullOrWhiteSpace(SiteManagerApiKey);

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool ReadBoolean(string name, bool defaultValue)
    {
        var text = Environment.GetEnvironmentVariable(name)?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return defaultValue;
        }

        if (!bool.TryParse(text, out var value))
        {
            throw new ConfigurationException($"{name} must be true or false when set.");
        }

        return value;
    }

    private static int ReadBoundedInteger(
        string name,
        int defaultValue,
        int minimum,
        int maximum)
    {
        var text = Environment.GetEnvironmentVariable(name)?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return defaultValue;
        }

        if (!int.TryParse(
                text,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var value) ||
            value < minimum ||
            value > maximum)
        {
            throw new ConfigurationException(
                $"{name} must be an integer between {minimum} and {maximum}.");
        }

        return value;
    }
}

public sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message)
        : base(message)
    {
    }
}
