using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Security;

namespace UnifiMcp.Tests;

public sealed class SiteManagerClientTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 25, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Get_uses_fixed_stable_base_and_site_manager_key()
    {
        var handler = new RecordingHandler(_ =>
            JsonResponse(HttpStatusCode.OK, "{\"data\":[]}"));
        using var client = CreateClient(handler);

        await client.GetAsync("v1/hosts?pageSize=500", CancellationToken.None);

        var request = Assert.Single(handler.Requests);
        Assert.Equal("GET", request.Method);
        Assert.Equal("https://api.ui.com/v1/hosts?pageSize=500", request.Uri);
        Assert.Equal("site-manager-key", request.ApiKey);
        Assert.Null(request.Body);
    }

    [Theory]
    [InlineData("ea/hosts")]
    [InlineData("v1/connector/consoles/id/network/integration/v1/sites")]
    [InlineData("v1/sd-wan-configs")]
    [InlineData("https://example.invalid/v1/hosts")]
    public async Task Get_rejects_excluded_or_external_surfaces(string path)
    {
        var handler = new RecordingHandler(_ =>
            JsonResponse(HttpStatusCode.OK, "{}"));
        using var client = CreateClient(handler);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.GetAsync(path, CancellationToken.None));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Rate_limit_honors_delta_retry_after()
    {
        var attempts = 0;
        var delays = new List<TimeSpan>();
        var handler = new RecordingHandler(_ =>
        {
            attempts++;
            if (attempts == 1)
            {
                var response = JsonResponse(HttpStatusCode.TooManyRequests, "{\"code\":\"rate_limit\"}");
                response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
                return response;
            }

            return JsonResponse(HttpStatusCode.OK, "{\"data\":[]}");
        });
        using var client = CreateClient(
            handler,
            delay: (value, _) =>
            {
                delays.Add(value);
                return Task.CompletedTask;
            });

        await client.GetAsync("v1/hosts", CancellationToken.None);

        Assert.Equal(2, attempts);
        Assert.Equal(TimeSpan.FromSeconds(7), Assert.Single(delays));
    }

    [Fact]
    public async Task Rate_limit_honors_http_date_retry_after()
    {
        var attempts = 0;
        var delays = new List<TimeSpan>();
        var handler = new RecordingHandler(_ =>
        {
            attempts++;
            if (attempts == 1)
            {
                var response = JsonResponse(HttpStatusCode.TooManyRequests, "{}");
                response.Headers.RetryAfter = new RetryConditionHeaderValue(Now.AddSeconds(11));
                return response;
            }

            return JsonResponse(HttpStatusCode.OK, "{}");
        });
        using var client = CreateClient(
            handler,
            delay: (value, _) =>
            {
                delays.Add(value);
                return Task.CompletedTask;
            });

        await client.GetAsync("v1/sites", CancellationToken.None);

        Assert.Equal(TimeSpan.FromSeconds(11), Assert.Single(delays));
    }

    [Fact]
    public async Task Long_retry_after_returns_retry_at_without_an_early_retry()
    {
        var retryAt = Now.AddMinutes(6);
        var delays = new List<TimeSpan>();
        var handler = new RecordingHandler(_ =>
        {
            var response = JsonResponse(HttpStatusCode.TooManyRequests, "{}");
            response.Headers.RetryAfter = new RetryConditionHeaderValue(retryAt);
            return response;
        });
        using var client = CreateClient(
            handler,
            delay: (value, _) =>
            {
                delays.Add(value);
                return Task.CompletedTask;
            });

        var exception = await Assert.ThrowsAsync<SiteManagerApiException>(() =>
            client.GetAsync("v1/devices", CancellationToken.None));

        Assert.True(exception.IsRateLimited);
        Assert.Equal(retryAt, exception.RetryAt);
        Assert.Single(handler.Requests);
        Assert.Empty(delays);
        Assert.True(
            client.Describe()["rateLimit"]!["providerCooldownActive"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Long_provider_cooldown_rejects_subsequent_requests_before_dispatch()
    {
        var retryAt = Now.AddMinutes(6);
        var delays = new List<TimeSpan>();
        var handler = new RecordingHandler(_ =>
        {
            var response = JsonResponse(HttpStatusCode.TooManyRequests, "{}");
            response.Headers.RetryAfter = new RetryConditionHeaderValue(retryAt);
            return response;
        });
        using var client = CreateClient(
            handler,
            delay: (value, _) =>
            {
                delays.Add(value);
                return Task.CompletedTask;
            });
        await Assert.ThrowsAsync<SiteManagerApiException>(() =>
            client.GetAsync("v1/hosts", CancellationToken.None));

        var subsequent = await Assert.ThrowsAsync<SiteManagerApiException>(() =>
            client.GetAsync("v1/sites", CancellationToken.None));

        Assert.True(subsequent.IsRateLimited);
        Assert.Equal("provider_cooldown", subsequent.Code);
        Assert.Equal(retryAt, subsequent.RetryAt);
        Assert.Single(handler.Requests);
        Assert.Empty(delays);
        Assert.Equal(
            0,
            client.Describe()["waitingForConcurrency"]!.GetValue<int>());
    }

    [Fact]
    public async Task Bounded_provider_cooldown_waits_without_occupying_concurrency_slots()
    {
        var now = Now;
        var retryAt = now.AddSeconds(30);
        var releaseCooldown = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var limiter = new SiteManagerRateLimiter(
            permitLimit: 10,
            getUtcNow: () => now,
            delay: async (_, cancellationToken) =>
            {
                await releaseCooldown.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                now = retryAt;
            });
        limiter.DeferUntil(retryAt);
        var handler = new CountingHandler();
        using var client = CreateClient(
            handler,
            rateLimiter: limiter,
            getUtcNow: () => now);
        var requests = Enumerable.Range(0, 5)
            .Select(_ => client.GetAsync("v1/hosts", CancellationToken.None))
            .ToArray();
        await WaitUntilAsync(() =>
            limiter.Describe()["waitingRequests"]!.GetValue<int>() == requests.Length);

        Assert.Equal(
            0,
            client.Describe()["waitingForConcurrency"]!.GetValue<int>());
        Assert.Equal(0, handler.Attempts);

        releaseCooldown.SetResult(true);
        await Task.WhenAll(requests);

        Assert.Equal(requests.Length, handler.Attempts);
    }

    [Fact]
    public async Task Cancellation_precedes_long_provider_cooldown_rejection()
    {
        var limiter = new SiteManagerRateLimiter(getUtcNow: () => Now);
        limiter.DeferUntil(Now.AddMinutes(6));
        var handler = new RecordingHandler(_ =>
            JsonResponse(HttpStatusCode.OK, "{\"data\":[]}"));
        using var client = CreateClient(
            handler,
            rateLimiter: limiter,
            getUtcNow: () => Now);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.GetAsync("v1/hosts", cancellation.Token));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Missing_retry_after_uses_bounded_backoff_and_exhausts_after_three_attempts()
    {
        var delays = new List<TimeSpan>();
        var handler = new RecordingHandler(_ =>
            JsonResponse(HttpStatusCode.TooManyRequests, "{}"));
        using var client = CreateClient(
            handler,
            delay: (value, _) =>
            {
                delays.Add(value);
                return Task.CompletedTask;
            },
            backoff: attempt => TimeSpan.FromMilliseconds(attempt * 100));

        await Assert.ThrowsAsync<SiteManagerApiException>(() =>
            client.GetAsync("v1/hosts", CancellationToken.None));

        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal(
            new[] { TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200) },
            delays);
    }

    [Fact]
    public async Task Malformed_retry_after_uses_backoff_instead_of_retrying_immediately()
    {
        var attempts = 0;
        var delays = new List<TimeSpan>();
        var handler = new RecordingHandler(_ =>
        {
            attempts++;
            if (attempts == 1)
            {
                var response = JsonResponse(HttpStatusCode.TooManyRequests, "{}");
                response.Headers.TryAddWithoutValidation("Retry-After", "not-a-valid-delay");
                return response;
            }

            return JsonResponse(HttpStatusCode.OK, "{}");
        });
        using var client = CreateClient(
            handler,
            delay: (value, _) =>
            {
                delays.Add(value);
                return Task.CompletedTask;
            },
            backoff: _ => TimeSpan.FromMilliseconds(250));

        await client.GetAsync("v1/hosts", CancellationToken.None);

        Assert.Equal(TimeSpan.FromMilliseconds(250), Assert.Single(delays));
    }

    [Fact]
    public async Task Cancellation_interrupts_retry_wait()
    {
        var handler = new RecordingHandler(_ =>
        {
            var response = JsonResponse(HttpStatusCode.TooManyRequests, "{}");
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(1));
            return response;
        });
        using var client = CreateClient(
            handler,
            delay: (_, cancellationToken) =>
                Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken));
        using var cancellation = new CancellationTokenSource();
        var request = client.GetAsync("v1/hosts", cancellation.Token);

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Retries_5xx_and_read_only_isp_query_post()
    {
        var attempts = 0;
        var handler = new RecordingHandler(_ =>
        {
            attempts++;
            return attempts == 1
                ? JsonResponse(HttpStatusCode.InternalServerError, "{}")
                : JsonResponse(HttpStatusCode.OK, "{\"data\":{\"metrics\":[]}}");
        });
        using var client = CreateClient(
            handler,
            delay: (_, _) => Task.CompletedTask,
            backoff: _ => TimeSpan.Zero);

        await client.QueryIspMetricsAsync(
            "5m",
            new JsonObject { ["sites"] = new JsonArray() },
            CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, request =>
        {
            Assert.Equal("POST", request.Method);
            Assert.Equal("https://api.ui.com/v1/isp-metrics/5m/query", request.Uri);
            Assert.Contains("\"sites\"", request.Body, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Authentication_error_redacts_both_api_keys()
    {
        var handler = new RecordingHandler(_ =>
            JsonResponse(
                HttpStatusCode.BadRequest,
                "{\"message\":\"local-key site-manager-key\",\"apiKey\":\"site-manager-key\"}"));
        using var client = CreateClient(handler);

        var exception = await Assert.ThrowsAsync<SiteManagerApiException>(() =>
            client.GetAsync("v1/hosts", CancellationToken.None));

        Assert.DoesNotContain("local-key", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("site-manager-key", exception.Message, StringComparison.Ordinal);
        Assert.Contains("<redacted>", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Missing_key_fails_without_sending_a_request()
    {
        var handler = new RecordingHandler(_ =>
            JsonResponse(HttpStatusCode.OK, "{}"));
        using var client = CreateClient(handler, siteManagerKey: null);

        await Assert.ThrowsAsync<ConfigurationException>(() =>
            client.GetAsync("v1/hosts", CancellationToken.None));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Exhausted_transport_failure_is_normalized()
    {
        var handler = new ThrowingHandler();
        using var client = CreateClient(
            handler,
            delay: (_, _) => Task.CompletedTask,
            backoff: _ => TimeSpan.Zero);

        var exception = await Assert.ThrowsAsync<SiteManagerApiException>(() =>
            client.GetAsync("v1/hosts", CancellationToken.None));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, exception.StatusCode);
        Assert.Equal("UniFi Site Manager transport failed after three attempts.", exception.Message);
        Assert.Equal(3, handler.Attempts);
    }

    [Fact]
    public async Task Concurrency_queue_is_bounded()
    {
        using var cancellation = new CancellationTokenSource();
        var handler = new BlockingHandler();
        using var client = CreateClient(handler);
        var active = Enumerable.Range(0, 4)
            .Select(_ => client.GetAsync("v1/hosts", cancellation.Token))
            .ToArray();
        await WaitUntilAsync(() => handler.Attempts == 4);
        var queued = Enumerable.Range(0, 100)
            .Select(_ => client.GetAsync("v1/sites", cancellation.Token))
            .ToArray();
        await WaitUntilAsync(() =>
            client.Describe()["waitingForConcurrency"]!.GetValue<int>() == 100);

        await Assert.ThrowsAsync<SiteManagerRateLimitQueueException>(() =>
            client.GetAsync("v1/devices", cancellation.Token));

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Task.WhenAll(active.Concat(queued)));
    }

    private static SiteManagerClient CreateClient(
        HttpMessageHandler handler,
        string? siteManagerKey = "site-manager-key",
        Func<TimeSpan, CancellationToken, Task>? delay = null,
        Func<int, TimeSpan>? backoff = null,
        SiteManagerRateLimiter? rateLimiter = null,
        Func<DateTimeOffset>? getUtcNow = null)
    {
        var now = Now;
        var underlyingDelay = delay ??
            ((TimeSpan value, CancellationToken cancellationToken) =>
                Task.Delay(value, cancellationToken));
        async Task DelayAndAdvance(TimeSpan value, CancellationToken cancellationToken)
        {
            await underlyingDelay(value, cancellationToken).ConfigureAwait(false);
            now += value;
        }

        var clock = getUtcNow ?? (() => now);
        var limiter = rateLimiter ?? new SiteManagerRateLimiter(
            getUtcNow: () => now,
            delay: DelayAndAdvance);
        return new SiteManagerClient(
            new UnifiConfiguration(
                new Uri(UnifiConfiguration.DefaultBaseUrl + "/"),
                "local-key",
                null,
                TimeSpan.FromSeconds(5),
                SiteManagerApiKey: siteManagerKey),
            new SecretRedactor("local-key", siteManagerKey),
            NullLogger<SiteManagerClient>.Instance,
            handler,
            limiter,
            clock,
            DelayAndAdvance,
            backoff);
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 1_000; attempt++)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(1).ConfigureAwait(false);
        }

        throw new TimeoutException("The expected concurrent test state was not reached.");
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _response;

        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> response)
        {
            _response = response;
        }

        public List<RecordedRequest> Requests { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(new RecordedRequest(
                request.Method.Method,
                request.RequestUri!.ToString(),
                request.Headers.GetValues("X-API-Key").Single(),
                request.Content is null
                    ? null
                    : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)));
            return _response(request);
        }
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        public int Attempts { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Attempts++;
            throw new HttpRequestException("simulated transport failure");
        }
    }

    private sealed class BlockingHandler : HttpMessageHandler
    {
        private int _attempts;

        public int Attempts => Volatile.Read(ref _attempts);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _attempts);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("The blocking handler should only exit through cancellation.");
        }
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        private int _attempts;

        public int Attempts => Volatile.Read(ref _attempts);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _attempts);
            return Task.FromResult(
                JsonResponse(HttpStatusCode.OK, "{\"data\":[]}"));
        }
    }

    private sealed record RecordedRequest(
        string Method,
        string Uri,
        string ApiKey,
        string? Body);
}
