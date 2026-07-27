using System.Net;
using Microsoft.AspNetCore.Http;
using UnifiMcp.Configuration;

namespace UnifiMcp.Tests;

public sealed class McpHttpSecurityMiddlewareTests
{
    private const string Token = "abcdefghijklmnopqrstuvwxyz012345";
    private static readonly Uri PublicUri =
        new("https://unifi-mcp.example.test/mcp");

    [Theory]
    [InlineData("unifi-mcp.example.test", true)]
    [InlineData("UNIFI-MCP.EXAMPLE.TEST", true)]
    [InlineData("attacker.example.test", false)]
    [InlineData("", false)]
    public void Validates_the_exact_public_host(string host, bool expected)
    {
        Assert.Equal(
            expected,
            McpHttpRequestValidator.IsAllowedHost(host, PublicUri));
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("https://unifi-mcp.example.test", true)]
    [InlineData("https://UNIFI-MCP.EXAMPLE.TEST", true)]
    [InlineData("https://attacker.example.test", false)]
    [InlineData("null", false)]
    [InlineData("https://unifi-mcp.example.test, https://attacker.example.test", false)]
    public void Validates_origin_when_the_client_supplies_one(
        string? origin,
        bool expected)
    {
        Assert.Equal(
            expected,
            McpHttpRequestValidator.IsAllowedOrigin(origin, PublicUri));
    }

    [Fact]
    public async Task Allows_only_matching_host_origin_and_bearer_token()
    {
        var nextCalled = false;
        var middleware = new McpHttpSecurityMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            Configuration());
        var context = new DefaultHttpContext();
        context.Request.Path = "/mcp";
        context.Request.Host = new HostString("unifi-mcp.example.test");
        context.Request.Headers.Origin = "https://unifi-mcp.example.test";
        context.Request.Headers.Authorization = "Bearer " + Token;

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("attacker.example.test", "Bearer abcdefghijklmnopqrstuvwxyz012345", 403)]
    [InlineData("unifi-mcp.example.test", "Bearer wrong-token-value-that-is-long-enough", 401)]
    [InlineData("unifi-mcp.example.test", "", 401)]
    public async Task Rejects_invalid_host_or_authorization(
        string host,
        string authorization,
        int expectedStatus)
    {
        var middleware = new McpHttpSecurityMiddleware(
            _ => throw new InvalidOperationException("Request must not pass."),
            Configuration());
        var context = new DefaultHttpContext();
        context.Request.Path = "/mcp";
        context.Request.Host = new HostString(host);
        context.Request.Headers.Authorization = authorization;

        await middleware.InvokeAsync(context);

        Assert.Equal(expectedStatus, context.Response.StatusCode);
    }

    [Fact]
    public async Task Allows_an_allowlisted_tailscale_identity_from_loopback()
    {
        var nextCalled = false;
        var middleware = new McpHttpSecurityMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            TailscaleConfiguration());
        var context = TailscaleContext("clint@example.test", IPAddress.Loopback);

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("other@example.test", "127.0.0.1")]
    [InlineData("clint@example.test", "172.17.0.1")]
    [InlineData("", "127.0.0.1")]
    public async Task Rejects_untrusted_tailscale_identity_or_proxy(
        string login,
        string remoteAddress)
    {
        var middleware = new McpHttpSecurityMiddleware(
            _ => throw new InvalidOperationException("Request must not pass."),
            TailscaleConfiguration());
        var context = TailscaleContext(login, IPAddress.Parse(remoteAddress));

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("WWW-Authenticate"));
    }

    private static UnifiConfiguration Configuration() =>
        new(
            new Uri("https://example.test/proxy/network/integration/"),
            "api-key",
            null,
            TimeSpan.FromSeconds(5),
            McpHttpBearerToken: Token,
            McpHttpPublicUri: PublicUri,
            McpHttpListenUri: new Uri("http://0.0.0.0:8080/"));

    private static UnifiConfiguration TailscaleConfiguration() =>
        new(
            new Uri("https://example.test/proxy/network/integration/"),
            "api-key",
            null,
            TimeSpan.FromSeconds(5),
            HttpAuthenticationMode: McpHttpAuthenticationMode.Tailscale,
            McpHttpTailscaleAllowedUsers: new HashSet<string>(
                new[] { "clint@example.test" },
                StringComparer.OrdinalIgnoreCase),
            McpHttpPublicUri: PublicUri,
            McpHttpListenUri: new Uri("http://127.0.0.1:8080/"));

    private static DefaultHttpContext TailscaleContext(
        string login,
        IPAddress remoteAddress)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = remoteAddress;
        context.Request.Path = "/mcp";
        context.Request.Host = new HostString("unifi-mcp.example.test");
        if (!string.IsNullOrEmpty(login))
        {
            context.Request.Headers["Tailscale-User-Login"] = login;
        }

        return context;
    }
}
