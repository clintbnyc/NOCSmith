using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;

namespace UnifiMcp.Tests;

public sealed class UnifiClientTests
{
    [Fact]
    public async Task Read_uses_tailscale_base_url_and_api_key_header()
    {
        var handler = new RecordingHandler(_ => JsonResponse(HttpStatusCode.OK, "{\"version\":\"10.4.57\"}"));
        using var client = CreateClient(handler);
        var request = Request("getInfo", requireRead: true);

        await client.ReadAsync(request, CancellationToken.None);

        var sent = Assert.Single(handler.Requests);
        Assert.Equal("https://unifi.nutria-newton.ts.net/proxy/network/integration/v1/info", sent.Uri);
        Assert.Equal("test-api-key", sent.ApiKey);
        Assert.Equal("GET", sent.Method);
    }

    [Fact]
    public async Task Read_retries_transient_status_but_mutation_does_not()
    {
        var readAttempts = 0;
        var handler = new RecordingHandler(_ =>
        {
            readAttempts++;
            return readAttempts == 1
                ? JsonResponse(HttpStatusCode.ServiceUnavailable, "{\"message\":\"wait\"}")
                : JsonResponse(HttpStatusCode.OK, "{\"ok\":true}");
        });
        using var client = CreateClient(handler, (_, _) => Task.CompletedTask);

        await client.ReadAsync(Request("getInfo", requireRead: true), CancellationToken.None);
        Assert.Equal(2, handler.Requests.Count);

        var mutationHandler = new RecordingHandler(_ => JsonResponse(HttpStatusCode.ServiceUnavailable, "{}"));
        using var mutationClient = CreateClient(mutationHandler, (_, _) => Task.CompletedTask);
        await Assert.ThrowsAsync<UnifiApiException>(() =>
            mutationClient.MutateAsync(DeviceActionRequest(), CancellationToken.None));
        Assert.Single(mutationHandler.Requests);
    }

    [Fact]
    public async Task Read_honors_rate_limit_retry_after()
    {
        var attempts = 0;
        var delays = new List<TimeSpan>();
        var handler = new RecordingHandler(_ =>
        {
            attempts++;
            if (attempts > 1)
            {
                return JsonResponse(HttpStatusCode.OK, "{\"ok\":true}");
            }

            var response = JsonResponse(HttpStatusCode.TooManyRequests, "{}");
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(2));
            return response;
        });
        using var client = CreateClient(handler, (delay, _) =>
        {
            delays.Add(delay);
            return Task.CompletedTask;
        });

        await client.ReadAsync(Request("getInfo", requireRead: true), CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(TimeSpan.FromSeconds(2), Assert.Single(delays));
    }

    [Fact]
    public async Task Read_retries_timeouts_but_mutation_does_not()
    {
        var readAttempts = 0;
        var readHandler = new RecordingHandler(_ =>
        {
            readAttempts++;
            if (readAttempts == 1)
            {
                throw new TaskCanceledException("simulated timeout");
            }

            return JsonResponse(HttpStatusCode.OK, "{\"ok\":true}");
        });
        using var readClient = CreateClient(readHandler, (_, _) => Task.CompletedTask);

        await readClient.ReadAsync(Request("getInfo", requireRead: true), CancellationToken.None);
        Assert.Equal(2, readHandler.Requests.Count);

        var mutationHandler = new RecordingHandler(_ => throw new TaskCanceledException("simulated timeout"));
        using var mutationClient = CreateClient(mutationHandler, (_, _) => Task.CompletedTask);
        var exception = await Assert.ThrowsAsync<UnifiApiException>(() =>
            mutationClient.MutateAsync(DeviceActionRequest(), CancellationToken.None));

        Assert.Contains("timed out", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Single(mutationHandler.Requests);
    }

    [Fact]
    public async Task Error_never_exposes_api_key()
    {
        var handler = new RecordingHandler(_ =>
            JsonResponse(HttpStatusCode.BadRequest, "{\"apiKey\":\"test-api-key\"}"));
        using var client = CreateClient(handler);

        var exception = await Assert.ThrowsAsync<UnifiApiException>(() =>
            client.ReadAsync(Request("getInfo", requireRead: true), CancellationToken.None));

        Assert.DoesNotContain("test-api-key", exception.Message, StringComparison.Ordinal);
        Assert.Contains("redacted", exception.Message, StringComparison.Ordinal);
    }

    private static UnifiClient CreateClient(
        HttpMessageHandler handler,
        Func<TimeSpan, CancellationToken, Task>? delay = null) =>
        new(
            new UnifiConfiguration(
                new Uri("https://unifi.nutria-newton.ts.net/proxy/network/integration/"),
                "test-api-key",
                null,
                TimeSpan.FromSeconds(5)),
            NullLogger<UnifiClient>.Instance,
            handler,
            delay);

    private static ValidatedRequest Request(string operationId, bool requireRead)
    {
        var contract = OpenApiContract.LoadEmbedded();
        return contract.ValidateAndBuild(contract.GetOperation(operationId, requireRead), null, null, null);
    }

    private static ValidatedRequest DeviceActionRequest()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("executeAdoptedDeviceAction", requireRead: false);
        return contract.ValidateAndBuild(
            operation,
            new Dictionary<string, string>
            {
                ["siteId"] = "00000000-0000-0000-0000-000000000001",
                ["deviceId"] = "00000000-0000-0000-0000-000000000002"
            },
            null,
            new JsonObject { ["action"] = "RESTART" });
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _response;

        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> response)
        {
            _response = response;
        }

        public List<RecordedRequest> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new RecordedRequest(
                request.Method.Method,
                request.RequestUri!.ToString(),
                request.Headers.GetValues("X-API-Key").Single()));
            return Task.FromResult(_response(request));
        }
    }

    private sealed record RecordedRequest(string Method, string Uri, string ApiKey);
}
