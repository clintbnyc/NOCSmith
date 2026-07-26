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
            ("UNIFI_SITE_API_KEY", null),
            ("UNIFI_SITE_MANAGER_LOCAL_HOST_ID", null));

        var configuration = UnifiConfiguration.Load();

        Assert.Equal("https://unifi.nutria-newton.ts.net/proxy/network/integration/", configuration.BaseUri.ToString());
        Assert.False(configuration.EnableLegacyReadEnrichment);
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
