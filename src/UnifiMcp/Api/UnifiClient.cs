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
    private const int MaximumContractResponseBytes = 2 * 1024 * 1024;
    private const int MaximumApiResponseBytes = 16 * 1024 * 1024;

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
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("nocsmith", "1.0"));
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
    {
        if (!request.Operation.IsRead)
        {
            throw new InvalidOperationException("ReadAsync cannot execute a mutation.");
        }

        return SendWithReadRetriesAsync(
            request.Operation.Method,
            request.RelativeUri,
            request.Body,
            cancellationToken,
            MaximumApiResponseBytes);
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

        return SendWithReadRetriesAsync(
            HttpMethod.Get,
            relativePath,
            null,
            cancellationToken,
            MaximumContractResponseBytes);
    }

    public Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Get,
            BuildLegacyReadPath(internalSiteReference, "stat/device"),
            null,
            cancellationToken,
            MaximumApiResponseBytes);

    public Task<JsonNode?> ReadPortProfilesAsync(string internalSiteReference, CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Get,
            BuildLegacyReadPath(internalSiteReference, "rest/portconf"),
            null,
            cancellationToken,
            MaximumApiResponseBytes);

    public Task<JsonNode?> ReadPrivateClientsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Get,
            BuildPrivateClientReadPath(internalSiteReference),
            null,
            cancellationToken,
            MaximumApiResponseBytes);

    public Task<JsonNode?> ReadClientHistoryAsync(
        string internalSiteReference,
        int withinHours,
        CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Get,
            BuildClientHistoryReadPath(internalSiteReference, withinHours),
            null,
            cancellationToken,
            MaximumApiResponseBytes);

    public Task<JsonNode?> ReadNetworkMembersGroupsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Get,
            BuildNetworkMembersGroupsReadPath(internalSiteReference),
            null,
            cancellationToken,
            MaximumApiResponseBytes);

    public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
        SendWithReadRetriesAsync(
            HttpMethod.Post,
            BuildSystemLogReadPath(internalSiteReference),
            new JsonObject(),
            cancellationToken,
            MaximumApiResponseBytes);

    public void Dispose() => _httpClient.Dispose();

    private async Task<JsonNode?> SendWithReadRetriesAsync(
        HttpMethod method,
        string relativeUri,
        JsonNode? body,
        CancellationToken cancellationToken,
        int? maximumResponseBytes = null)
    {
        const int maximumAttempts = 3;
        Exception? lastException = null;

        for (var attempt = 1; attempt <= maximumAttempts; attempt++)
        {
            try
            {
                return await SendOnceAsync(
                        method,
                        relativeUri,
                        body,
                        cancellationToken,
                        allowRetryStatus: attempt < maximumAttempts,
                        maximumResponseBytes)
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
        bool allowRetryStatus = false,
        int? maximumResponseBytes = null)
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
            if (response.Content is { } responseContent && maximumResponseBytes is { } responseByteLimit)
            {
                if (responseContent.Headers.ContentLength > responseByteLimit)
                {
                    throw ResponseSizeLimitExceeded(responseByteLimit);
                }

                var bufferedContent = await ReadBoundedContentAsync(
                        responseContent,
                        responseByteLimit,
                        cancellationToken)
                    .ConfigureAwait(false);
                response.Content = bufferedContent;
                responseContent.Dispose();
            }

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
                    HttpStatusCode.Unauthorized => "UniFi rejected the API key (401). Verify the Network Integration key in the mounted 1Password Environment.",
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

    private static async Task<HttpContent> ReadBoundedContentAsync(
        HttpContent content,
        int maximumResponseBytes,
        CancellationToken cancellationToken)
    {
        using var buffer = new BoundedMemoryStream(maximumResponseBytes);
        await content.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);

        var bufferedContent = new ByteArrayContent(buffer.ToArray());
        foreach (var header in content.Headers)
        {
            if (!header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                bufferedContent.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        return bufferedContent;
    }

    private static ContractException ResponseSizeLimitExceeded(int maximumResponseBytes) =>
        new($"UniFi response exceeded the {maximumResponseBytes}-byte safety limit.");

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
        var encodedSiteReference = EncodeInternalSiteReference(internalSiteReference);
        return $"../api/s/{encodedSiteReference}/{fixedResource}";
    }

    private static string BuildSystemLogReadPath(string internalSiteReference)
    {
        var encodedSiteReference = EncodeInternalSiteReference(internalSiteReference);
        return $"../v2/api/site/{encodedSiteReference}/system-log/all";
    }

    private static string BuildPrivateClientReadPath(string internalSiteReference)
    {
        var encodedSiteReference = EncodeInternalSiteReference(internalSiteReference);
        return $"../v2/api/site/{encodedSiteReference}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true";
    }

    private static string BuildClientHistoryReadPath(string internalSiteReference, int withinHours)
    {
        if (withinHours is not (24 or 72 or 168 or 336 or 720 or 4320))
        {
            throw new ArgumentOutOfRangeException(
                nameof(withinHours),
                "Client history window must match a bounded Network UI value.");
        }

        var encodedSiteReference = EncodeInternalSiteReference(internalSiteReference);
        return $"../v2/api/site/{encodedSiteReference}/clients/history?onlyNonBlocked=true&includeUnifiDevices=true&withinHours={withinHours}";
    }

    private static string BuildNetworkMembersGroupsReadPath(string internalSiteReference)
    {
        var encodedSiteReference = EncodeInternalSiteReference(internalSiteReference);
        return $"../v2/api/site/{encodedSiteReference}/network-members-groups";
    }

    private static string EncodeInternalSiteReference(string internalSiteReference)
    {
        if (string.IsNullOrWhiteSpace(internalSiteReference) ||
            internalSiteReference.Length > 64 ||
            internalSiteReference.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            throw new ArgumentException("Private UniFi site reference contains unsupported characters.", nameof(internalSiteReference));
        }

        return Uri.EscapeDataString(internalSiteReference);
    }

    private sealed class BoundedMemoryStream : MemoryStream
    {
        private readonly int _maximumBytes;

        public BoundedMemoryStream(int maximumBytes)
            : base(Math.Min(maximumBytes, 81920))
        {
            _maximumBytes = maximumBytes;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            EnsureCapacity(count);
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            EnsureCapacity(buffer.Length);
            base.Write(buffer);
        }

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        private void EnsureCapacity(int bytesToWrite)
        {
            if (bytesToWrite > _maximumBytes - Length)
            {
                throw ResponseSizeLimitExceeded(_maximumBytes);
            }
        }
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
