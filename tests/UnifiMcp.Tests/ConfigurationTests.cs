using UnifiMcp.Configuration;

namespace UnifiMcp.Tests;

[Collection("Environment")]
public sealed class ConfigurationTests
{
    [Fact]
    public void Defaults_to_tailscale_service_and_requires_injected_key()
    {
        using var environment = new EnvironmentScope(
            ("UNIFI_BASE_URL", null),
            ("UNIFI_API_KEY", "test-key"),
            ("UNIFI_DEFAULT_SITE_ID", null),
            ("UNIFI_TIMEOUT_SECONDS", null),
            ("UNIFI_ENABLE_LEGACY_READ_ENRICHMENT", null),
            ("UNIFI_ENABLE_CLIENT_JOURNAL", null),
            ("UNIFI_CLIENT_JOURNAL_DB_PATH", null),
            ("UNIFI_CLIENT_JOURNAL_RETENTION_DAYS", null),
            ("UNIFI_CLIENT_JOURNAL_MAX_MIB", null),
            ("UNIFI_ENABLE_SCHEDULED_COLLECTION", null),
            ("UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES", null),
            ("UNIFI_SCHEDULED_COLLECTION_SITE_ID", null),
            ("UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS", null),
            ("UNIFI_MCP_HTTP_AUTH_MODE", null),
            ("UNIFI_MCP_HTTP_BEARER_TOKEN", null),
            ("UNIFI_MCP_TAILSCALE_ALLOWED_USERS", null),
            ("UNIFI_MCP_HTTP_PUBLIC_URL", null),
            ("UNIFI_MCP_HTTP_LISTEN_URL", null),
            ("UNIFI_SITE_API_KEY", null),
            ("UNIFI_SITE_MANAGER_LOCAL_HOST_ID", null));

        var configuration = UnifiConfiguration.Load();

        Assert.Equal("https://unifi.nutria-newton.ts.net/proxy/network/integration/", configuration.BaseUri.ToString());
        Assert.False(configuration.EnableLegacyReadEnrichment);
        Assert.False(configuration.EnableClientJournal);
        Assert.Null(configuration.ClientJournalDatabasePath);
        Assert.Equal(90, configuration.ClientJournalRetentionDays);
        Assert.Equal(256, configuration.ClientJournalMaximumMib);
        Assert.False(configuration.EnableScheduledCollection);
        Assert.Equal(60, configuration.ScheduledCollectionIntervalMinutes);
        Assert.Equal(
            "http://0.0.0.0:8080/",
            configuration.McpHttpListenUri!.ToString());
        Assert.False(configuration.SiteManagerConfigured);
    }

    [Fact]
    public void Site_manager_configuration_is_optional_and_preserves_opaque_host_id()
    {
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "test-key"),
            ("UNIFI_SITE_API_KEY", "site-key"),
            ("UNIFI_SITE_MANAGER_LOCAL_HOST_ID", "console-id:123"));

        var configuration = UnifiConfiguration.Load();

        Assert.True(configuration.SiteManagerConfigured);
        Assert.Equal("site-key", configuration.SiteManagerApiKey);
        Assert.Equal("console-id:123", configuration.SiteManagerLocalHostId);
    }

    [Fact]
    public void Rejects_unresolved_site_manager_reference_and_invalid_host_id()
    {
        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_SITE_API_KEY", "op://Private/UniFi/Site Manager")))
        {
            var exception = Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
            Assert.Contains("UNIFI_SITE_API_KEY", exception.Message, StringComparison.Ordinal);
        }

        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_SITE_API_KEY", "site-key"),
                   ("UNIFI_SITE_MANAGER_LOCAL_HOST_ID", "bad\nhost")))
        {
            Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
        }
    }

    [Fact]
    public void Rejects_unresolved_1password_reference()
    {
        using var environment = new EnvironmentScope(("UNIFI_API_KEY", "op://Private/UniFi/API Key"));

        var exception = Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());

        Assert.Contains("still a 1Password reference", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_non_https_or_wrong_api_path()
    {
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "test-key"),
            ("UNIFI_BASE_URL", "http://unifi.nutria-newton.ts.net/"));

        Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
    }

    [Fact]
    public void Legacy_read_enrichment_requires_an_explicit_boolean_opt_in()
    {
        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_ENABLE_LEGACY_READ_ENRICHMENT", "true")))
        {
            Assert.True(UnifiConfiguration.Load().EnableLegacyReadEnrichment);
        }

        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_ENABLE_LEGACY_READ_ENRICHMENT", "yes")))
        {
            Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
        }
    }

    [Fact]
    public void Client_journal_requires_opt_in_and_an_absolute_path()
    {
        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_ENABLE_CLIENT_JOURNAL", "true"),
                   ("UNIFI_CLIENT_JOURNAL_DB_PATH", null)))
        {
            Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
        }

        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_ENABLE_CLIENT_JOURNAL", "true"),
                   ("UNIFI_CLIENT_JOURNAL_DB_PATH", "relative.db")))
        {
            Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
        }

        var absolute = Path.Combine(Path.GetTempPath(), "unifi-journal", "client.db");
        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_ENABLE_CLIENT_JOURNAL", "true"),
                   ("UNIFI_CLIENT_JOURNAL_DB_PATH", absolute),
                   ("UNIFI_CLIENT_JOURNAL_RETENTION_DAYS", "3650"),
                   ("UNIFI_CLIENT_JOURNAL_MAX_MIB", "4096")))
        {
            var configuration = UnifiConfiguration.Load();
            Assert.True(configuration.EnableClientJournal);
            Assert.Equal(Path.GetFullPath(absolute), configuration.ClientJournalDatabasePath);
            Assert.Equal(3650, configuration.ClientJournalRetentionDays);
            Assert.Equal(4096, configuration.ClientJournalMaximumMib);
        }
    }

    [Theory]
    [InlineData("UNIFI_CLIENT_JOURNAL_RETENTION_DAYS", "0")]
    [InlineData("UNIFI_CLIENT_JOURNAL_RETENTION_DAYS", "3651")]
    [InlineData("UNIFI_CLIENT_JOURNAL_MAX_MIB", "15")]
    [InlineData("UNIFI_CLIENT_JOURNAL_MAX_MIB", "4097")]
    public void Rejects_invalid_client_journal_settings(string name, string value)
    {
        var path = Path.Combine(Path.GetTempPath(), "unifi-journal", "client.db");
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "test-key"),
            ("UNIFI_ENABLE_CLIENT_JOURNAL", "true"),
            ("UNIFI_CLIENT_JOURNAL_DB_PATH", path),
            (name, value));

        Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
    }

    [Fact]
    public void Rejects_invalid_client_journal_gate()
    {
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "test-key"),
            ("UNIFI_ENABLE_CLIENT_JOURNAL", "yes"));

        Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
    }

    [Fact]
    public void Scheduled_collection_requires_explicit_journal_and_private_read_gates()
    {
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "test-key"),
            ("UNIFI_ENABLE_SCHEDULED_COLLECTION", "true"),
            ("UNIFI_ENABLE_CLIENT_JOURNAL", "false"),
            ("UNIFI_ENABLE_LEGACY_READ_ENRICHMENT", "true"));

        var exception = Assert.Throws<ConfigurationException>(
            () => UnifiConfiguration.Load());

        Assert.Contains(
            "requires both",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Scheduled_collection_accepts_bounded_explicit_settings()
    {
        var path = Path.Combine(Path.GetTempPath(), "unifi-journal", "client.db");
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "test-key"),
            ("UNIFI_ENABLE_CLIENT_JOURNAL", "true"),
            ("UNIFI_CLIENT_JOURNAL_DB_PATH", path),
            ("UNIFI_ENABLE_LEGACY_READ_ENRICHMENT", "true"),
            ("UNIFI_ENABLE_SCHEDULED_COLLECTION", "true"),
            ("UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES", "90"),
            ("UNIFI_SCHEDULED_COLLECTION_SITE_ID", "6cc5f1b8-cec7-4c50-9b92-805b73892756"),
            ("UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS", "72"));

        var configuration = UnifiConfiguration.Load();

        Assert.True(configuration.EnableScheduledCollection);
        Assert.Equal(TimeSpan.FromMinutes(90), configuration.ScheduledCollectionInterval);
        Assert.Equal(
            "6cc5f1b8-cec7-4c50-9b92-805b73892756",
            configuration.ScheduledCollectionSiteId);
        Assert.Equal(72, configuration.ScheduledCollectionHistoryHours);
    }

    [Theory]
    [InlineData("UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES", "4")]
    [InlineData("UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES", "1441")]
    [InlineData("UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS", "25")]
    [InlineData("UNIFI_SCHEDULED_COLLECTION_SITE_ID", "not-a-uuid")]
    public void Rejects_invalid_scheduled_collection_settings(string name, string value)
    {
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "test-key"),
            (name, value));

        Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
    }

    [Fact]
    public void Http_server_requires_a_strong_injected_token_and_exact_public_url()
    {
        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_MCP_HTTP_BEARER_TOKEN", "too-short"),
                   ("UNIFI_MCP_HTTP_PUBLIC_URL", "https://unifi-mcp.example.test/mcp")))
        {
            Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
        }

        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_MCP_HTTP_BEARER_TOKEN", new string('a', 32)),
                   ("UNIFI_MCP_HTTP_PUBLIC_URL", "http://unifi-mcp.example.test/mcp")))
        {
            Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
        }

        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_MCP_HTTP_BEARER_TOKEN", new string('a', 32)),
                   ("UNIFI_MCP_HTTP_PUBLIC_URL", "https://unifi-mcp.example.test/wrong")))
        {
            Assert.Throws<ConfigurationException>(() => UnifiConfiguration.Load());
        }
    }

    [Fact]
    public void Http_server_configuration_is_opt_in_and_validated_on_use()
    {
        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_MCP_HTTP_BEARER_TOKEN", null),
                   ("UNIFI_MCP_HTTP_PUBLIC_URL", null)))
        {
            var configuration = UnifiConfiguration.Load();
            Assert.Throws<ConfigurationException>(
                configuration.RequireHttpServerConfiguration);
        }

        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_MCP_HTTP_BEARER_TOKEN", new string('a', 32)),
                   ("UNIFI_MCP_HTTP_PUBLIC_URL", "https://unifi-mcp.example.test/mcp"),
                   ("UNIFI_MCP_HTTP_LISTEN_URL", "http://127.0.0.1:9090")))
        {
            var configuration = UnifiConfiguration.Load();
            configuration.RequireHttpServerConfiguration();
            Assert.Equal(
                "https://unifi-mcp.example.test/mcp",
                configuration.McpHttpPublicUri!.ToString());
            Assert.Equal(
                "http://127.0.0.1:9090/",
                configuration.McpHttpListenUri!.ToString());
        }
    }

    [Fact]
    public void Tailscale_http_auth_requires_loopback_and_an_explicit_user_allowlist()
    {
        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_MCP_HTTP_AUTH_MODE", "tailscale"),
                   ("UNIFI_MCP_TAILSCALE_ALLOWED_USERS", "clint@example.test"),
                   ("UNIFI_MCP_HTTP_PUBLIC_URL", "https://unifi-mcp.example.test/mcp"),
                   ("UNIFI_MCP_HTTP_LISTEN_URL", "http://0.0.0.0:8080")))
        {
            var configuration = UnifiConfiguration.Load();
            Assert.Throws<ConfigurationException>(
                configuration.RequireHttpServerConfiguration);
        }

        using (new EnvironmentScope(
                   ("UNIFI_API_KEY", "test-key"),
                   ("UNIFI_MCP_HTTP_AUTH_MODE", "tailscale"),
                   ("UNIFI_MCP_TAILSCALE_ALLOWED_USERS", "clint@example.test,other@example.test"),
                   ("UNIFI_MCP_HTTP_BEARER_TOKEN", null),
                   ("UNIFI_MCP_HTTP_PUBLIC_URL", "https://unifi-mcp.example.test/mcp"),
                   ("UNIFI_MCP_HTTP_LISTEN_URL", "http://127.0.0.1:8080")))
        {
            var configuration = UnifiConfiguration.Load();
            configuration.RequireHttpServerConfiguration();
            Assert.Equal(
                McpHttpAuthenticationMode.Tailscale,
                configuration.HttpAuthenticationMode);
            Assert.Contains(
                "CLINT@EXAMPLE.TEST",
                configuration.McpHttpTailscaleAllowedUsers!);
        }
    }

    [Theory]
    [InlineData("unknown", "clint@example.test")]
    [InlineData("tailscale", null)]
    [InlineData("tailscale", "bad user")]
    public void Rejects_invalid_http_authentication_settings(
        string mode,
        string? users)
    {
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "test-key"),
            ("UNIFI_MCP_HTTP_AUTH_MODE", mode),
            ("UNIFI_MCP_TAILSCALE_ALLOWED_USERS", users),
            ("UNIFI_MCP_HTTP_PUBLIC_URL", "https://unifi-mcp.example.test/mcp"),
            ("UNIFI_MCP_HTTP_LISTEN_URL", "http://127.0.0.1:8080"));

        Assert.Throws<ConfigurationException>(() =>
        {
            var configuration = UnifiConfiguration.Load();
            configuration.RequireHttpServerConfiguration();
        });
    }
}

[CollectionDefinition("Environment", DisableParallelization = true)]
public sealed class EnvironmentCollection
{
}

internal sealed class EnvironmentScope : IDisposable
{
    private readonly Dictionary<string, string?> _original = new(StringComparer.Ordinal);

    public EnvironmentScope(params (string Name, string? Value)[] values)
    {
        foreach (var (name, value) in values)
        {
            _original[name] = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
        }
    }

    public void Dispose()
    {
        foreach (var item in _original)
        {
            Environment.SetEnvironmentVariable(item.Key, item.Value);
        }
    }
}
