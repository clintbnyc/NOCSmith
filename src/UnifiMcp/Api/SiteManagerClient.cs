using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using UnifiMcp.Configuration;
using UnifiMcp.Security;

namespace UnifiMcp.Api;

public sealed class SiteManagerClient : ISiteManagerClient, IDisposable
{
    private const int MaximumAttempts = 3;
    private const int MaximumConcurrentRequests = 4;
    private const int MaximumConcurrencyQueue = 100;
    private const int MaximumResponseBytes = 10 * 1024 * 1024;
    private static readonly TimeSpan MaximumRetryWait =
        SiteManagerRateLimiter.DefaultMaximumProviderWait;

    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;
    private readonly SecretRedactor _redactor;
    private readonly ILogger<SiteManagerClient> _logger;
    private readonly SiteManagerRateLimiter _rateLimiter;
    private readonly SemaphoreSlim _concurrency =
        new(MaximumConcurrentRequests, MaximumConcurrentRequests);
    private readonly Func<DateTimeOffset> _getUtcNow;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly Func<int, TimeSpan> _backoff;
    private int _waitingForConcurrency;

    public SiteManagerClient(
        UnifiConfiguration configuration,
        SecretRedactor redactor,
        ILogger<SiteManagerClient> logger,
        HttpMessageHandler? handler = null,
        SiteManagerRateLimiter? rateLimiter = null,
        Func<DateTimeOffset>? getUtcNow = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null,
        Func<int, TimeSpan>? backoff = null)
    {
        _apiKey = configuration.SiteManagerApiKey;
        _redactor = redactor;
        _logger = logger;
        _getUtcNow = getUtcNow ?? (() => DateTimeOffset.UtcNow);
        _delay = delay ?? Task.Delay;
        _rateLimiter = rateLimiter ?? new SiteManagerRateLimiter(
            getUtcNow: _getUtcNow,
            delay: _delay);
        _backoff = backoff ?? (attempt =>
            TimeSpan.FromMilliseconds((250 * Math.Pow(2, attempt - 1)) + Random.Shared.Next(0, 101)));
        _httpClient = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: true);
        _httpClient.BaseAddress = new Uri(UnifiConfiguration.SiteManagerBaseUrl);
        _httpClient.Timeout = configuration.RequestTimeout;
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("nocsmith", "1.0"));
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public Task<JsonNode?> GetAsync(string relativePath, CancellationToken cancellationToken)
    {
        ValidateStableReadPath(relativePath);
        return SendWithRetriesAsync(HttpMethod.Get, relativePath, null, cancellationToken);
    }

    public Task<JsonNode?> QueryIspMetricsAsync(
        string interval,
        JsonObject body,
        CancellationToken cancellationToken)
    {
        if (interval is not "5m" and not "1h")
        {
            throw new ArgumentException("Site Manager ISP metric interval must be 5m or 1h.", nameof(interval));
        }

        return SendWithRetriesAsync(
            HttpMethod.Post,
            $"v1/isp-metrics/{interval}/query",
            body,
            cancellationToken);
    }

    public JsonObject Describe() => new()
    {
        ["configured"] = !string.IsNullOrWhiteSpace(_apiKey),
        ["baseUrl"] = UnifiConfiguration.SiteManagerBaseUrl.TrimEnd('/'),
        ["apiVersion"] = "v1-stable",
        ["readOnly"] = true,
        ["maximumAttempts"] = MaximumAttempts,
        ["maximumRetryWaitSeconds"] = MaximumRetryWait.TotalSeconds,
        ["maximumConcurrentRequests"] = MaximumConcurrentRequests,
        ["concurrencyQueueLimit"] = MaximumConcurrencyQueue,
        ["waitingForConcurrency"] = Volatile.Read(ref _waitingForConcurrency),
        ["rateLimit"] = _rateLimiter.Describe()
    };

    public void Dispose()
    {
        _concurrency.Dispose();
        _httpClient.Dispose();
    }

    private async Task<JsonNode?> SendWithRetriesAsync(
        HttpMethod method,
        string relativePath,
        JsonNode? body,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_apiKey))
        {
            throw new ConfigurationException(
                "UNIFI_SITE_API_KEY is not configured. Add it to the mounted 1Password Environment to use Site Manager reads.");
        }

        Exception? lastException = null;
        for (var attempt = 1; attempt <= MaximumAttempts; attempt++)
        {
            AttemptResponse response;
            try
            {
                response = await SendOnceAsync(
                    method,
                    relativePath,
                    body,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                var exception = new SiteManagerApiException(
                    HttpStatusCode.RequestTimeout,
                    "UniFi Site Manager request timed out.");
                if (attempt == MaximumAttempts)
                {
                    throw exception;
                }

                lastException = exception;
                await DelayForRetryAsync(_backoff(attempt), attempt, cancellationToken).ConfigureAwait(false);
                continue;
            }
            catch (HttpRequestException exception)
            {
                if (attempt == MaximumAttempts)
                {
                    throw new SiteManagerApiException(
                        HttpStatusCode.ServiceUnavailable,
                        "UniFi Site Manager transport failed after three attempts.");
                }

                lastException = exception;
                await DelayForRetryAsync(_backoff(attempt), attempt, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (response.IsSuccess)
            {
                return response.Value;
            }

            var retryAt = response.RetryAt;
            var retryDelay = retryAt is null ? _backoff(attempt) : retryAt.Value - _getUtcNow();
            if (retryDelay < TimeSpan.Zero)
            {
                retryDelay = TimeSpan.Zero;
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                var exception = CreateApiException(response.StatusCode, response.Content, retryAt);
                _rateLimiter.DeferUntil(retryAt ?? (_getUtcNow() + retryDelay));
                if (attempt == MaximumAttempts || retryDelay > MaximumRetryWait)
                {
                    throw exception;
                }

                lastException = exception;
                await DelayForRetryAsync(retryDelay, attempt, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if ((int)response.StatusCode is >= 500 and <= 599 && attempt < MaximumAttempts)
            {
                if (retryDelay > MaximumRetryWait)
                {
                    throw CreateApiException(response.StatusCode, response.Content, retryAt);
                }

                lastException = CreateApiException(response.StatusCode, response.Content, retryAt);
                await DelayForRetryAsync(retryDelay, attempt, cancellationToken).ConfigureAwait(false);
                continue;
            }

            throw CreateApiException(response.StatusCode, response.Content, retryAt);
        }

        if (lastException is SiteManagerApiException apiException)
        {
            throw apiException;
        }

        throw new SiteManagerApiException(
            HttpStatusCode.ServiceUnavailable,
            "UniFi Site Manager transport failed after three attempts.");
    }

    private async Task<AttemptResponse> SendOnceAsync(
        HttpMethod method,
        string relativePath,
        JsonNode? body,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await _rateLimiter.WaitForAvailabilityAsync(cancellationToken).ConfigureAwait(false);
            await WaitForConcurrencyAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_rateLimiter.TryAcquirePermit())
                {
                    continue;
                }

                using var request = new HttpRequestMessage(method, relativePath);
                request.Headers.TryAddWithoutValidation("X-API-Key", _apiKey);
                if (body is not null)
                {
                    request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
                }

                using var response = await _httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false);
                var content = await ReadBoundedContentAsync(response, cancellationToken).ConfigureAwait(false);
                return response.IsSuccessStatusCode
                    ? new AttemptResponse(
                        true,
                        ParseResponse(content, response.StatusCode),
                        response.StatusCode,
                        content,
                        null)
                    : new AttemptResponse(
                        false,
                        null,
                        response.StatusCode,
                        content,
                        ReadRetryAt(response.Headers.RetryAfter));
            }
            finally
            {
                _concurrency.Release();
            }
        }
    }

    private async Task WaitForConcurrencyAsync(CancellationToken cancellationToken)
    {
        if (_concurrency.Wait(0))
        {
            return;
        }

        var waiting = Interlocked.Increment(ref _waitingForConcurrency);
        if (waiting > MaximumConcurrencyQueue)
        {
            Interlocked.Decrement(ref _waitingForConcurrency);
            throw new SiteManagerRateLimitQueueException(
                $"The Site Manager concurrency queue is full ({MaximumConcurrencyQueue} waiting request(s)).");
        }

        try
        {
            await _concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _waitingForConcurrency);
        }
    }

    private async Task DelayForRetryAsync(
        TimeSpan delay,
        int attempt,
        CancellationToken cancellationToken)
    {
        _logger.LogWarning(
            "UniFi Site Manager read is retrying attempt {Attempt} after {DelayMilliseconds} ms.",
            attempt + 1,
            delay.TotalMilliseconds);
        await _delay(delay, cancellationToken).ConfigureAwait(false);
    }

    private SiteManagerApiException CreateApiException(
        HttpStatusCode statusCode,
        string content,
        DateTimeOffset? retryAt)
    {
        var code = ExtractErrorCode(content);
        var detail = ExtractErrorDetail(content);
        var message = statusCode switch
        {
            HttpStatusCode.Unauthorized =>
                "UniFi Site Manager rejected the API key (401). Verify UNIFI_SITE_API_KEY in the mounted 1Password Environment.",
            HttpStatusCode.Forbidden =>
                "UniFi Site Manager denied this read (403). Verify the API key account permissions.",
            HttpStatusCode.TooManyRequests =>
                retryAt is null
                    ? "UniFi Site Manager rate-limited the request (429)."
                    : $"UniFi Site Manager rate-limited the request (429); retry at {retryAt.Value:O}.",
            _ => $"UniFi Site Manager returned HTTP {(int)statusCode}.{detail}"
        };
        return new SiteManagerApiException(statusCode, _redactor.Redact(message), code, retryAt);
    }

    private DateTimeOffset? ReadRetryAt(RetryConditionHeaderValue? retryAfter)
    {
        if (retryAfter?.Date is DateTimeOffset date)
        {
            return date;
        }

        return retryAfter?.Delta is TimeSpan delta
            ? _getUtcNow() + delta
            : null;
    }

    private string? ExtractErrorCode(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return null;
        }

        try
        {
            var code = JsonNode.Parse(content)?["code"]?.ToString();
            return string.IsNullOrWhiteSpace(code) ? null : _redactor.Redact(code);
        }
        catch (JsonException)
        {
            return null;
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
            var redacted = _redactor.Redact(JsonNode.Parse(content))?.ToJsonString();
            return string.IsNullOrWhiteSpace(redacted) ? string.Empty : " Response: " + redacted;
        }
        catch (JsonException)
        {
            var shortened = content.Length > 500 ? content[..500] + "…" : content;
            return " Response: " + _redactor.Redact(shortened);
        }
    }

    private static JsonNode? ParseResponse(string content, HttpStatusCode statusCode)
    {
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
            throw new SiteManagerApiException(
                statusCode,
                $"UniFi Site Manager returned invalid JSON: {exception.Message}");
        }
    }

    private static async Task<string> ReadBoundedContentAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content is null)
        {
            return string.Empty;
        }

        if (response.Content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw new SiteManagerApiException(
                response.StatusCode,
                "UniFi Site Manager response exceeded the 10 MiB connector limit.");
        }

        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var destination = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (destination.Length + read > MaximumResponseBytes)
            {
                throw new SiteManagerApiException(
                    response.StatusCode,
                    "UniFi Site Manager response exceeded the 10 MiB connector limit.");
            }

            destination.Write(buffer, 0, read);
        }

        return Encoding.UTF8.GetString(destination.ToArray());
    }

    private static void ValidateStableReadPath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) ||
            relativePath.StartsWith("/", StringComparison.Ordinal) ||
            Uri.TryCreate(relativePath, UriKind.Absolute, out _) ||
            !relativePath.StartsWith("v1/", StringComparison.Ordinal) ||
            relativePath.StartsWith("v1/connector/", StringComparison.Ordinal) ||
            relativePath.StartsWith("v1/sd-wan-", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Site Manager reads must use an allowlisted stable v1 relative path.",
                nameof(relativePath));
        }
    }

    private sealed record AttemptResponse(
        bool IsSuccess,
        JsonNode? Value,
        HttpStatusCode StatusCode,
        string Content,
        DateTimeOffset? RetryAt);
}
