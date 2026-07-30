using UnifiMcp.Configuration;

namespace UnifiMcp.Tests;

[Collection("Environment")]
public sealed class EnvironmentFileLoaderTests
{
    private static readonly string[] SupportedVariableNames =
    {
        "UNIFI_API_KEY",
        "UNIFI_BASE_URL",
        "UNIFI_DEFAULT_SITE_ID",
        "UNIFI_TIMEOUT_SECONDS",
        "UNIFI_ENABLE_LEGACY_READ_ENRICHMENT",
        "UNIFI_ENABLE_CLIENT_JOURNAL",
        "UNIFI_CLIENT_JOURNAL_DB_PATH",
        "UNIFI_CLIENT_JOURNAL_RETENTION_DAYS",
        "UNIFI_CLIENT_JOURNAL_MAX_MIB",
        "UNIFI_ENABLE_SCHEDULED_COLLECTION",
        "UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES",
        "UNIFI_SCHEDULED_COLLECTION_SITE_ID",
        "UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS",
        "UNIFI_MCP_HTTP_AUTH_MODE",
        "UNIFI_MCP_HTTP_BEARER_TOKEN",
        "UNIFI_MCP_TAILSCALE_ALLOWED_USERS",
        "UNIFI_MCP_HTTP_PUBLIC_URL",
        "UNIFI_MCP_HTTP_LISTEN_URL",
        "UNIFI_MCP_TAILSCALE_SOCKET_PATH",
        "UNIFI_SITE_API_KEY",
        "UNIFI_SITE_MANAGER_LOCAL_HOST_ID",
        "UNRELATED_VARIABLE"
    };

    [Fact]
    public void Loads_supported_variables_and_removes_split_option()
    {
        using var environment = ClearSupportedVariables();
        using var envFile = TemporaryEnvFile.Create(
            "UNIFI_API_KEY=file-key\n" +
            "UNIFI_BASE_URL=https://example.test/proxy/network/integration\n" +
            "UNIFI_DEFAULT_SITE_ID=6cc5f1b8-cec7-4c50-9b92-805b73892756\n" +
            "UNIFI_TIMEOUT_SECONDS=45\n" +
            "UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true\n" +
            "UNIFI_ENABLE_CLIENT_JOURNAL=true\n" +
            "UNIFI_CLIENT_JOURNAL_DB_PATH=/tmp/unifi-journal/client.db\n" +
            "UNIFI_CLIENT_JOURNAL_RETENTION_DAYS=120\n" +
            "UNIFI_CLIENT_JOURNAL_MAX_MIB=512\n" +
            "UNIFI_ENABLE_SCHEDULED_COLLECTION=true\n" +
            "UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES=60\n" +
            "UNIFI_SCHEDULED_COLLECTION_SITE_ID=6cc5f1b8-cec7-4c50-9b92-805b73892756\n" +
            "UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS=24\n" +
            "UNIFI_MCP_HTTP_AUTH_MODE=bearer\n" +
            "UNIFI_MCP_HTTP_BEARER_TOKEN=abcdefghijklmnopqrstuvwxyz012345\n" +
            "UNIFI_MCP_TAILSCALE_ALLOWED_USERS=clint@example.test\n" +
            "UNIFI_MCP_HTTP_PUBLIC_URL=https://unifi-mcp.example.test/mcp\n" +
            "UNIFI_MCP_HTTP_LISTEN_URL=http://0.0.0.0:8080\n" +
            "UNIFI_MCP_TAILSCALE_SOCKET_PATH=/var/run/unifi-mcp/mcp.sock\n" +
            "UNIFI_SITE_API_KEY=site-manager-key\n" +
            "UNIFI_SITE_MANAGER_LOCAL_HOST_ID=host:123\n" +
            "UNRELATED_VARIABLE=must-not-be-imported\n");

        var remainingArgs = EnvironmentFileLoader.LoadAndRemoveOption(
            new[] { "--env-file", envFile.Path, "doctor" });

        Assert.Equal(new[] { "doctor" }, remainingArgs);
        Assert.Equal("file-key", Environment.GetEnvironmentVariable("UNIFI_API_KEY"));
        Assert.Equal(
            "https://example.test/proxy/network/integration",
            Environment.GetEnvironmentVariable("UNIFI_BASE_URL"));
        Assert.Equal("45", Environment.GetEnvironmentVariable("UNIFI_TIMEOUT_SECONDS"));
        Assert.Equal("true", Environment.GetEnvironmentVariable("UNIFI_ENABLE_LEGACY_READ_ENRICHMENT"));
        Assert.Equal("true", Environment.GetEnvironmentVariable("UNIFI_ENABLE_CLIENT_JOURNAL"));
        Assert.Equal(
            "/tmp/unifi-journal/client.db",
            Environment.GetEnvironmentVariable("UNIFI_CLIENT_JOURNAL_DB_PATH"));
        Assert.Equal("120", Environment.GetEnvironmentVariable("UNIFI_CLIENT_JOURNAL_RETENTION_DAYS"));
        Assert.Equal("512", Environment.GetEnvironmentVariable("UNIFI_CLIENT_JOURNAL_MAX_MIB"));
        Assert.Equal("true", Environment.GetEnvironmentVariable("UNIFI_ENABLE_SCHEDULED_COLLECTION"));
        Assert.Equal(
            "60",
            Environment.GetEnvironmentVariable("UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES"));
        Assert.Equal(
            "https://unifi-mcp.example.test/mcp",
            Environment.GetEnvironmentVariable("UNIFI_MCP_HTTP_PUBLIC_URL"));
        Assert.Equal(
            "/var/run/unifi-mcp/mcp.sock",
            Environment.GetEnvironmentVariable("UNIFI_MCP_TAILSCALE_SOCKET_PATH"));
        Assert.Equal("site-manager-key", Environment.GetEnvironmentVariable("UNIFI_SITE_API_KEY"));
        Assert.Equal("host:123", Environment.GetEnvironmentVariable("UNIFI_SITE_MANAGER_LOCAL_HOST_ID"));
        Assert.Null(Environment.GetEnvironmentVariable("UNRELATED_VARIABLE"));
    }

    [Fact]
    public void Loads_equals_option_without_overwriting_inherited_variables()
    {
        using var environment = new EnvironmentScope(
            ("UNIFI_API_KEY", "inherited-key"),
            ("UNIFI_BASE_URL", null));
        using var envFile = TemporaryEnvFile.Create(
            "UNIFI_API_KEY=file-key\n" +
            "UNIFI_BASE_URL=https://example.test/proxy/network/integration\n");

        var remainingArgs = EnvironmentFileLoader.LoadAndRemoveOption(
            new[] { $"--env-file={envFile.Path}", "doctor" });

        Assert.Equal(new[] { "doctor" }, remainingArgs);
        Assert.Equal("inherited-key", Environment.GetEnvironmentVariable("UNIFI_API_KEY"));
        Assert.Equal(
            "https://example.test/proxy/network/integration",
            Environment.GetEnvironmentVariable("UNIFI_BASE_URL"));
    }

    [Theory]
    [InlineData("--env-file")]
    [InlineData("--env-file=")]
    public void Rejects_missing_env_file_path(string option)
    {
        var exception = Assert.Throws<ConfigurationException>(
            () => EnvironmentFileLoader.LoadAndRemoveOption(new[] { option }));

        Assert.Contains("requires a file path", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_duplicate_env_file_options()
    {
        var exception = Assert.Throws<ConfigurationException>(
            () => EnvironmentFileLoader.LoadAndRemoveOption(
                new[] { "--env-file=first.env", "--env-file", "second.env" }));

        Assert.Contains("only be specified once", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Does_not_expose_invalid_file_contents_in_error()
    {
        const string sensitiveFragment = "do-not-return-this-value";
        using var envFile = TemporaryEnvFile.Create($"UNIFI_API_KEY=\"{sensitiveFragment}");

        var exception = Assert.Throws<ConfigurationException>(
            () => EnvironmentFileLoader.LoadAndRemoveOption(new[] { $"--env-file={envFile.Path}" }));

        Assert.DoesNotContain(sensitiveFragment, exception.Message, StringComparison.Ordinal);
        Assert.Contains("valid dotenv assignments", exception.Message, StringComparison.Ordinal);
    }

    private static EnvironmentScope ClearSupportedVariables()
    {
        return new EnvironmentScope(
            SupportedVariableNames.Select(name => (name, (string?)null)).ToArray());
    }
}

internal sealed class TemporaryEnvFile : IDisposable
{
    private TemporaryEnvFile(string path)
    {
        Path = path;
    }

    public string Path { get; }

    public static TemporaryEnvFile Create(string contents)
    {
        var path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"unifi-mcp-{Guid.NewGuid():N}.env");
        File.WriteAllText(path, contents);
        return new TemporaryEnvFile(path);
    }

    public void Dispose()
    {
        File.Delete(Path);
    }
}
