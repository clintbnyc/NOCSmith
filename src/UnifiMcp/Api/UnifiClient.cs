using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Api;

public sealed class UnifiClient : IUnifiClient, IDisposable
{
    private static readonly HashSet<HttpStatusCode> RetryableStatuses = new()
    {
        HttpStatusCode.TooManyRequests,
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable,
        HttpStatusCode.GatewayTimeout
    };

    private readonly HttpClient _httpClient;
    private readonly string _apiKey;
    private readonly SecretRedactor _redactor;
    private readonly ILogger<UnifiClient> _logger;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public UnifiClient(
        UnifiConfiguration configuration,
        ILogger<UnifiClient> logger,
        HttpMessageHandler? handler = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _apiKey = configuration.ApiKey;
        _redactor = new SecretRedactor(_apiKey);
        _logger = logger;
        _delay = delay ?? Task.Delay;
        _httpClient = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: true);
        _httpClient.BaseAddress = configuration.BaseUri;
        _httpClient.Timeout = configuration.RequestTimeout;
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("unifi-mcp", "1.0"));
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
    {
        if (!request.Operation.IsRead)
        {
            throw new InvalidOperationException("ReadAsync cannot execute a mutation.");
        }

        return SendWithReadRetriesAsync(request.Operation.Method, request.RelativeUri, request.Body, cancellationToken);
    }

    public Task<JsonNode?> MutateAsync(ValidatedRequest request, CancellationToken cancellationToken)
    {
        if (request.Operation.IsRead)
        {
            throw new InvalidOperationException("MutateAsync cannot execute a GET operation.");
        }

        return SendOnceAsync(request.Operation.Method, request.RelativeUri, request.Body, cancellationToken);
    }

    public Task<JsonNode?> GetFixedAsync(string relativePath, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(relativePath) || IsExternalUri(relativePath))
        {
            throw new ArgumentException("Fixed API path must be relative.", nameof(relativePath));
        }

        return SendWithReadRetriesAsync(HttpMethod.Get, relativePath, null, cancellationToken);
    }

    public Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Get,
            BuildLegacyReadPath(internalSiteReference, "stat/device"),
            null,
            cancellationToken);

    public Task<JsonNode?> ReadLegacyClientsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Get,
            BuildLegacyReadPath(internalSiteReference, "stat/sta"),
            null,
            cancellationToken);

    public Task<JsonNode?> ReadLegacyAlertsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Get,
            BuildLegacyReadPath(internalSiteReference, "stat/alarm"),
            null,
            cancellationToken);

    public void Dispose() => _httpClient.Dispose();

    private async Task<JsonNode?> SendWithReadRetriesAsync(
        HttpMethod method,
        string relativeUri,
        JsonNode? body,
        CancellationToken cancellationToken)
    {
        const int maximumAttempts = 3;
        Exception? lastException = null;

        for (var attempt = 1; attempt <= maximumAttempts; attempt++)
        {
            try
            {
                return await SendOnceAsync(method, relativeUri, body, cancellationToken, allowRetryStatus: attempt < maximumAttempts)
                    .ConfigureAwait(false);
            }
            catch (RetryableUnifiException exception) when (attempt < maximumAttempts)
            {
                lastException = exception;
                var delay = exception.RetryAfter ?? TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt - 1));
                if (delay > TimeSpan.FromSeconds(30))
                {
                    delay = TimeSpan.FromSeconds(30);
                }

                _logger.LogWarning("UniFi read returned {StatusCode}; retrying attempt {Attempt}.", (int)exception.StatusCode, attempt + 1);
                await _delay(delay, cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException exception) when (attempt < maximumAttempts)
            {
                lastException = exception;
                _logger.LogWarning("UniFi read transport failed; retrying attempt {Attempt}.", attempt + 1);
                await _delay(TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt - 1)), cancellationToken).ConfigureAwait(false);
            }
        }

        throw lastException ?? new InvalidOperationException("UniFi read retry loop ended unexpectedly.");
    }

    private async Task<JsonNode?> SendOnceAsync(
        HttpMethod method,
        string relativeUri,
        JsonNode? body,
        CancellationToken cancellationToken,
        bool allowRetryStatus = false)
    {
        if (IsExternalUri(relativeUri))
        {
            throw new InvalidOperationException("Absolute request URLs are prohibited.");
        }

        using var request = new HttpRequestMessage(method, relativeUri.TrimStart('/'));
        request.Headers.TryAddWithoutValidation("X-API-Key", _apiKey);
        if (body is not null)
        {
            request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        }

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested && allowRetryStatus)
        {
            throw new RetryableUnifiException(HttpStatusCode.RequestTimeout, null);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new UnifiApiException(HttpStatusCode.RequestTimeout, "UniFi request timed out.");
        }

        using (response)
        {
            var content = response.Content is null
                ? string.Empty
                : await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                if (allowRetryStatus && RetryableStatuses.Contains(response.StatusCode))
                {
                    throw new RetryableUnifiException(response.StatusCode, response.Headers.RetryAfter?.Delta);
                }

                var detail = ExtractErrorDetail(content);
                var errorCode = ExtractErrorCode(content);
                var message = response.StatusCode switch
                {
                    HttpStatusCode.Unauthorized => "UniFi rejected the API key (401). Verify the Network Integration key and 1Password reference.",
                    HttpStatusCode.Forbidden => "UniFi denied this operation (403). Verify the API key's account permissions.",
                    HttpStatusCode.TooManyRequests => "UniFi rate-limited the request (429). Try again after the reported interval.",
                    _ => $"UniFi returned HTTP {(int)response.StatusCode} ({response.ReasonPhrase}).{detail}"
                };

                throw new UnifiApiException(response.StatusCode, _redactor.Redact(message), errorCode);
            }

            if (string.IsNullOrWhiteSpace(content))
            {
                return null;
            }

            try
            {
                return JsonNode.Parse(content);
            }
            catch (JsonException exception)
            {
                throw new UnifiApiException(response.StatusCode, $"UniFi returned invalid JSON: {_redactor.Redact(exception.Message)}");
            }
        }
    }

    private string ExtractErrorDetail(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return string.Empty;
        }

        try
        {
            var node = JsonNode.Parse(content);
            var redacted = _redactor.Redact(node)?.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
            return string.IsNullOrWhiteSpace(redacted) ? string.Empty : " Response: " + redacted;
        }
        catch (JsonException)
        {
            var shortened = content.Length > 500 ? content[..500] + "…" : content;
            return " Response: " + _redactor.Redact(shortened);
        }
    }

    private string? ExtractErrorCode(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return null;
        }

        try
        {
            var code = JsonNode.Parse(content)?["code"]?.GetValue<string>();
            return string.IsNullOrWhiteSpace(code) ? null : _redactor.Redact(code);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private static bool IsExternalUri(string value) =>
        value.StartsWith("//", StringComparison.Ordinal) ||
        (Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
         (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps));

    private static string BuildLegacyReadPath(string internalSiteReference, string fixedResource)
    {
        if (string.IsNullOrWhiteSpace(internalSiteReference) ||
            internalSiteReference.Length > 64 ||
            internalSiteReference.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            throw new ArgumentException("Legacy UniFi site reference contains unsupported characters.", nameof(internalSiteReference));
        }

        return $"../api/s/{Uri.EscapeDataString(internalSiteReference)}/{fixedResource}";
    }

    private sealed class RetryableUnifiException : Exception
    {
        public RetryableUnifiException(HttpStatusCode statusCode, TimeSpan? retryAfter)
        {
            StatusCode = statusCode;
            RetryAfter = retryAfter;
        }

        public HttpStatusCode StatusCode { get; }

        public TimeSpan? RetryAfter { get; }
    }
}
