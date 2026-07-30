using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using UnifiMcp.Configuration;

namespace UnifiMcp;

public sealed class McpHttpSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly UnifiConfiguration _configuration;
    private readonly byte[]? _expectedTokenHash;

    public McpHttpSecurityMiddleware(
        RequestDelegate next,
        UnifiConfiguration configuration)
    {
        _next = next;
        _configuration = configuration;
        _configuration.RequireHttpServerConfiguration();
        _expectedTokenHash = configuration.McpHttpBearerToken is null
            ? null
            : Hash(configuration.McpHttpBearerToken);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments("/mcp"))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        context.Response.OnStarting(() =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return Task.CompletedTask;
        });

        if (!McpHttpRequestValidator.IsAllowedHost(
                context.Request.Host.Value,
                _configuration.McpHttpPublicUri!))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        if (!McpHttpRequestValidator.IsAllowedOrigin(
                context.Request.Headers.Origin,
                _configuration.McpHttpPublicUri!))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        if (!IsAuthenticated(context))
        {
            if (_configuration.HttpAuthenticationMode ==
                McpHttpAuthenticationMode.Bearer)
            {
                context.Response.Headers.WWWAuthenticate = "Bearer";
            }

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    private bool IsAuthenticated(HttpContext context)
    {
        if (_configuration.HttpAuthenticationMode ==
            McpHttpAuthenticationMode.Tailscale)
        {
            return context.Connection.RemoteIpAddress is null &&
                context.Request.Headers.TryGetValue(
                    "Tailscale-User-Login",
                    out var loginValues) &&
                loginValues.Count == 1 &&
                _configuration.McpHttpTailscaleAllowedUsers!.Contains(
                    loginValues[0]!);
        }

        return TryReadBearerToken(
                context.Request.Headers.Authorization,
                out var token) &&
            _expectedTokenHash is not null &&
            CryptographicOperations.FixedTimeEquals(
                Hash(token),
                _expectedTokenHash);
    }

    private static bool TryReadBearerToken(string? header, out string token)
    {
        token = string.Empty;
        if (!AuthenticationHeaderValue.TryParse(header, out var parsed) ||
            !string.Equals(parsed.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(parsed.Parameter))
        {
            return false;
        }

        token = parsed.Parameter;
        return true;
    }

    private static byte[] Hash(string value) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(value));
}

internal static class McpHttpRequestValidator
{
    public static bool IsAllowedHost(string? host, Uri publicUri) =>
        !string.IsNullOrWhiteSpace(host) &&
        string.Equals(host, publicUri.Authority, StringComparison.OrdinalIgnoreCase);

    public static bool IsAllowedOrigin(string? origin, Uri publicUri)
    {
        if (string.IsNullOrWhiteSpace(origin))
        {
            return true;
        }

        if (origin.Contains(',', StringComparison.Ordinal) ||
            !Uri.TryCreate(origin, UriKind.Absolute, out var originUri) ||
            !string.IsNullOrEmpty(originUri.UserInfo) ||
            !string.IsNullOrEmpty(originUri.Query) ||
            !string.IsNullOrEmpty(originUri.Fragment))
        {
            return false;
        }

        return string.Equals(
            originUri.GetLeftPart(UriPartial.Authority),
            publicUri.GetLeftPart(UriPartial.Authority),
            StringComparison.OrdinalIgnoreCase);
    }
}
