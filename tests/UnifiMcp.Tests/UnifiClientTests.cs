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

    [Fact]
    public async Task Error_preserves_machine_readable_unifi_code()
    {
        var handler = new RecordingHandler(_ =>
            JsonResponse(
                HttpStatusCode.BadRequest,
                "{\"code\":\"api.firewall.zone-based-firewall-not-configured\",\"message\":\"not configured\"}"));
        using var client = CreateClient(handler);

        var exception = await Assert.ThrowsAsync<UnifiApiException>(() =>
            client.ReadAsync(SiteRequest("getFirewallPolicies"), CancellationToken.None));

        Assert.Equal(HttpStatusCode.BadRequest, exception.StatusCode);
        Assert.Equal("api.firewall.zone-based-firewall-not-configured", exception.Code);
    }

    [Fact]
    public async Task Private_reads_use_only_fixed_resources_and_an_empty_system_log_query()
    {
        var handler = new RecordingHandler(_ => JsonResponse(HttpStatusCode.OK, "{\"data\":[]}"));
        using var client = CreateClient(handler);

        await client.ReadLegacyDevicesAsync("default", CancellationToken.None);
        await client.ReadPrivateClientsAsync("default", CancellationToken.None);
        await client.ReadNetworkMembersGroupsAsync("default", CancellationToken.None);
        await client.QuerySystemLogsAsync("default", CancellationToken.None);

        Assert.Collection(
            handler.Requests,
            request =>
            {
                Assert.Equal("GET", request.Method);
                Assert.Equal("https://unifi.nutria-newton.ts.net/proxy/network/api/s/default/stat/device", request.Uri);
                Assert.Equal("test-api-key", request.ApiKey);
                Assert.Null(request.Body);
            },
            request =>
            {
                Assert.Equal("GET", request.Method);
                Assert.Equal(
                    "https://unifi.nutria-newton.ts.net/proxy/network/v2/api/site/default/clients/active?includeTrafficUsage=true&includeUnifiDevices=true",
                    request.Uri);
                Assert.Equal("test-api-key", request.ApiKey);
                Assert.Null(request.Body);
            },
            request =>
            {
                Assert.Equal("GET", request.Method);
                Assert.Equal(
                    "https://unifi.nutria-newton.ts.net/proxy/network/v2/api/site/default/network-members-groups",
                    request.Uri);
                Assert.Equal("test-api-key", request.ApiKey);
                Assert.Null(request.Body);
            },
            request =>
            {
                Assert.Equal("POST", request.Method);
                Assert.Equal("https://unifi.nutria-newton.ts.net/proxy/network/v2/api/site/default/system-log/all", request.Uri);
                Assert.Equal("test-api-key", request.ApiKey);
                Assert.Equal("{}", request.Body);
            });
    }

    [Fact]
    public async Task System_log_query_retries_as_a_read_operation()
    {
        var attempts = 0;
        var handler = new RecordingHandler(_ =>
        {
            attempts++;
            return attempts == 1
                ? JsonResponse(HttpStatusCode.ServiceUnavailable, "{\"message\":\"wait\"}")
                : JsonResponse(HttpStatusCode.OK, "{\"data\":[]}");
        });
        using var client = CreateClient(handler, (_, _) => Task.CompletedTask);

        await client.QuerySystemLogsAsync("default", CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, request =>
        {
            Assert.Equal("POST", request.Method);
            Assert.Equal("{}", request.Body);
        });
    }

    [Fact]
    public async Task Private_reads_reject_path_shaping_site_references()
    {
        var handler = new RecordingHandler(_ => JsonResponse(HttpStatusCode.OK, "{\"data\":[]}"));
        using var client = CreateClient(handler);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ReadLegacyDevicesAsync("../default", CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ReadNetworkMembersGroupsAsync("../default", CancellationToken.None));

        Assert.Empty(handler.Requests);
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

    private static ValidatedRequest SiteRequest(string operationId)
    {
        var contract = OpenApiContract.LoadEmbedded();
        return contract.ValidateAndBuild(
            contract.GetOperation(operationId, requireRead: true),
            new Dictionary<string, string>
            {
                ["siteId"] = "00000000-0000-0000-0000-000000000001"
            },
            null,
            null);
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

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
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

    private sealed record RecordedRequest(string Method, string Uri, string ApiKey, string? Body);
}
