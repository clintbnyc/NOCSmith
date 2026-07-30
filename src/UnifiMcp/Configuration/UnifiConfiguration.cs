using System.Globalization;
using System.Net;

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
    int ClientJournalMaximumMib = 256,
    bool EnableScheduledCollection = false,
    int ScheduledCollectionIntervalMinutes = 60,
    string? ScheduledCollectionSiteId = null,
    int ScheduledCollectionHistoryHours = 24,
    McpHttpAuthenticationMode HttpAuthenticationMode = McpHttpAuthenticationMode.Bearer,
    string? McpHttpBearerToken = null,
    IReadOnlySet<string>? McpHttpTailscaleAllowedUsers = null,
    Uri? McpHttpPublicUri = null,
    Uri? McpHttpListenUri = null,
    bool IsScheduledCollectionHost = false)
{
    public const string DefaultBaseUrl = "https://unifi.nutria-newton.ts.net/proxy/network/integration";
    public const string SiteManagerBaseUrl = "https://api.ui.com/";
    public const string DefaultMcpHttpListenUrl = "http://0.0.0.0:8080";

    private static readonly HashSet<int> SupportedScheduledHistoryHours =
        new() { 24, 72, 168, 336, 720, 4320 };

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
        var enableScheduledCollection = ReadBoolean(
            "UNIFI_ENABLE_SCHEDULED_COLLECTION",
            defaultValue: false);
        var scheduledCollectionIntervalMinutes = ReadBoundedInteger(
            "UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES",
            defaultValue: 60,
            minimum: 5,
            maximum: 1440);
        var scheduledCollectionSiteId = NullIfWhiteSpace(
            Environment.GetEnvironmentVariable("UNIFI_SCHEDULED_COLLECTION_SITE_ID"));
        if (scheduledCollectionSiteId is not null &&
            !Guid.TryParse(scheduledCollectionSiteId, out _))
        {
            throw new ConfigurationException(
                "UNIFI_SCHEDULED_COLLECTION_SITE_ID must be a UUID when set.");
        }

        var scheduledCollectionHistoryHours = ReadBoundedInteger(
            "UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS",
            defaultValue: 24,
            minimum: 24,
            maximum: 4320);
        if (!SupportedScheduledHistoryHours.Contains(scheduledCollectionHistoryHours))
        {
            throw new ConfigurationException(
                "UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS must be one of 24, 72, 168, 336, 720, or 4320.");
        }

        if (enableScheduledCollection &&
            (!enableClientJournal || !enableLegacyReadEnrichment))
        {
            throw new ConfigurationException(
                "Scheduled collection requires both UNIFI_ENABLE_CLIENT_JOURNAL=true and UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true.");
        }

        var mcpHttpAuthenticationMode = ReadMcpHttpAuthenticationMode();
        var mcpHttpBearerToken = NullIfWhiteSpace(
            Environment.GetEnvironmentVariable("UNIFI_MCP_HTTP_BEARER_TOKEN"));
        if (mcpHttpBearerToken is not null)
        {
            if (mcpHttpBearerToken.StartsWith("op://", StringComparison.OrdinalIgnoreCase))
            {
                throw new ConfigurationException(
                    "UNIFI_MCP_HTTP_BEARER_TOKEN is still a 1Password reference. Use a runtime injector.");
            }

            if (mcpHttpBearerToken.Length is < 32 or > 4096 ||
                mcpHttpBearerToken.Any(value => char.IsControl(value) || char.IsWhiteSpace(value)))
            {
                throw new ConfigurationException(
                    "UNIFI_MCP_HTTP_BEARER_TOKEN must contain 32 to 4096 visible non-whitespace characters.");
            }
        }

        var mcpHttpTailscaleAllowedUsers = ReadTailscaleAllowedUsers();
        var mcpHttpPublicUri = ReadHttpUri(
            "UNIFI_MCP_HTTP_PUBLIC_URL",
            Environment.GetEnvironmentVariable("UNIFI_MCP_HTTP_PUBLIC_URL"),
            requireHttps: true,
            requiredPath: "/mcp");
        var mcpHttpListenUri = ReadHttpUri(
            "UNIFI_MCP_HTTP_LISTEN_URL",
            Environment.GetEnvironmentVariable("UNIFI_MCP_HTTP_LISTEN_URL") ??
                DefaultMcpHttpListenUrl,
            requireHttps: false,
            requiredPath: "/");

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
            clientJournalMaximumMib,
            enableScheduledCollection,
            scheduledCollectionIntervalMinutes,
            scheduledCollectionSiteId,
            scheduledCollectionHistoryHours,
            mcpHttpAuthenticationMode,
            mcpHttpBearerToken,
            mcpHttpTailscaleAllowedUsers,
            mcpHttpPublicUri,
            mcpHttpListenUri);
    }

    public bool SiteManagerConfigured => !string.IsNullOrWhiteSpace(SiteManagerApiKey);

    public TimeSpan ScheduledCollectionInterval =>
        TimeSpan.FromMinutes(ScheduledCollectionIntervalMinutes);

    public void RequireHttpServerConfiguration()
    {
        if (McpHttpPublicUri is null)
        {
            throw new ConfigurationException(
                "UNIFI_MCP_HTTP_PUBLIC_URL is required for serve-http.");
        }

        if (HttpAuthenticationMode == McpHttpAuthenticationMode.Bearer &&
            string.IsNullOrWhiteSpace(McpHttpBearerToken))
        {
            throw new ConfigurationException(
                "UNIFI_MCP_HTTP_BEARER_TOKEN is required when UNIFI_MCP_HTTP_AUTH_MODE=bearer.");
        }

        if (HttpAuthenticationMode == McpHttpAuthenticationMode.Tailscale)
        {
            if (McpHttpTailscaleAllowedUsers is null ||
                McpHttpTailscaleAllowedUsers.Count == 0)
            {
                throw new ConfigurationException(
                    "UNIFI_MCP_TAILSCALE_ALLOWED_USERS is required when UNIFI_MCP_HTTP_AUTH_MODE=tailscale.");
            }

            if (McpHttpListenUri is null ||
                !IPAddress.TryParse(McpHttpListenUri.Host, out var listenAddress) ||
                !IPAddress.IsLoopback(listenAddress))
            {
                throw new ConfigurationException(
                    "Tailscale identity authentication requires UNIFI_MCP_HTTP_LISTEN_URL to use an explicit loopback IP address.");
            }
        }
    }

    private static McpHttpAuthenticationMode ReadMcpHttpAuthenticationMode()
    {
        var text = Environment.GetEnvironmentVariable("UNIFI_MCP_HTTP_AUTH_MODE")?.Trim();
        return text?.ToLowerInvariant() switch
        {
            null or "" or "bearer" => McpHttpAuthenticationMode.Bearer,
            "tailscale" => McpHttpAuthenticationMode.Tailscale,
            _ => throw new ConfigurationException(
                "UNIFI_MCP_HTTP_AUTH_MODE must be bearer or tailscale when set.")
        };
    }

    private static IReadOnlySet<string> ReadTailscaleAllowedUsers()
    {
        var text = NullIfWhiteSpace(
            Environment.GetEnvironmentVariable("UNIFI_MCP_TAILSCALE_ALLOWED_USERS"));
        if (text is null)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        var users = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawUser in text.Split(',', StringSplitOptions.TrimEntries))
        {
            if (string.IsNullOrWhiteSpace(rawUser) ||
                rawUser.Length > 320 ||
                rawUser.Any(value => char.IsControl(value) || char.IsWhiteSpace(value)))
            {
                throw new ConfigurationException(
                    "UNIFI_MCP_TAILSCALE_ALLOWED_USERS must be a comma-separated list of non-empty identities without whitespace or control characters.");
            }

            users.Add(rawUser);
        }

        if (users.Count > 32)
        {
            throw new ConfigurationException(
                "UNIFI_MCP_TAILSCALE_ALLOWED_USERS accepts at most 32 identities.");
        }

        return users;
    }

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

    private static Uri? ReadHttpUri(
        string name,
        string? text,
        bool requireHttps,
        string requiredPath)
    {
        text = NullIfWhiteSpace(text);
        if (text is null)
        {
            return null;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) ||
            (requireHttps
                ? !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                : uri.Scheme is not ("http" or "https")) ||
            string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ConfigurationException(
                $"{name} must be an absolute {(requireHttps ? "HTTPS" : "HTTP or HTTPS")} URL without credentials, a query, or a fragment.");
        }

        var normalizedPath = uri.AbsolutePath.TrimEnd('/');
        if (normalizedPath.Length == 0)
        {
            normalizedPath = "/";
        }

        if (!string.Equals(normalizedPath, requiredPath, StringComparison.Ordinal))
        {
            throw new ConfigurationException($"{name} must use the exact path {requiredPath}.");
        }

        return new UriBuilder(uri) { Path = requiredPath }.Uri;
    }
}

public sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message)
        : base(message)
    {
    }
}

public enum McpHttpAuthenticationMode
{
    Bearer,
    Tailscale
}
