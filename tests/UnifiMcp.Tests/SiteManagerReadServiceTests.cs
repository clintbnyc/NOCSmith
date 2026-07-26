using System.Net;
using System.Text.Json.Nodes;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class SiteManagerReadServiceTests
{
    [Fact]
    public async Task Inventory_uses_500_item_cursor_pages_and_returns_safe_continuation()
    {
        var client = new FakeSiteManagerClient
        {
            Get = _ => Task.FromResult<JsonNode?>(new JsonObject
            {
                ["data"] = new JsonArray(
                    new JsonObject
                    {
                        ["id"] = "host-1",
                        ["hardwareId"] = "hardware-1",
                        ["userData"] = new JsonObject
                        {
                            ["email"] = "private@example.test",
                            ["permissions"] = new JsonObject { ["network"] = "admin" }
                        },
                        ["reportedState"] = new JsonObject
                        {
                            ["name"] = "Home",
                            ["state"] = "connected",
                            ["location"] = new JsonObject { ["text"] = "Private location" },
                            ["prefetch"] = new JsonArray("large-ui-asset.js")
                        }
                    }),
                ["httpStatusCode"] = 200,
                ["traceId"] = "trace-1",
                ["nextToken"] = "cursor:abc"
            })
        };
        var service = CreateService(client);

        var response = await service.ReadInventoryAsync(
            "hosts",
            null,
            null,
            null,
            CancellationToken.None);

        Assert.Equal("v1/hosts?pageSize=500", Assert.Single(client.GetPaths));
        Assert.Equal("cursor:abc", response.Data!["pagination"]!["continuation"]!.GetValue<string>());
        Assert.True(response.Data["pagination"]!["truncated"]!.GetValue<bool>());
        Assert.Equal("trace-1", response.Data["provider"]!["traceId"]!.GetValue<string>());
        var projected = Assert.Single(response.Data["data"]!.AsArray())!;
        Assert.Equal("Home", projected["reportedState"]!["name"]!.GetValue<string>());
        Assert.Null(projected["userData"]);
        Assert.Null(projected["reportedState"]!["location"]);
        Assert.Null(projected["reportedState"]!["prefetch"]);
        Assert.DoesNotContain("private@example.test", response.Data.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inventory_encodes_cursor_and_device_host_filter()
    {
        var client = new FakeSiteManagerClient();
        var service = CreateService(client);

        await service.ReadInventoryAsync(
            "devices",
            "host:id/1",
            200,
            "next token",
            CancellationToken.None);

        Assert.Equal(
            "v1/devices?pageSize=200&nextToken=next%20token&hostIds%5B%5D=host%3Aid%2F1",
            Assert.Single(client.GetPaths));
    }

    [Fact]
    public async Task Identical_discovery_requests_are_cached()
    {
        var client = new FakeSiteManagerClient();
        var service = CreateService(client);

        await service.ReadInventoryAsync("sites", null, null, null, CancellationToken.None);
        await service.ReadInventoryAsync("sites", null, null, null, CancellationToken.None);

        Assert.Single(client.GetPaths);
    }

    [Fact]
    public async Task Discovery_cache_expires_after_five_minutes()
    {
        var clock = new MutableTimeProvider(
            new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero));
        var client = new FakeSiteManagerClient();
        var service = CreateService(client, clock);

        await service.ReadInventoryAsync("sites", null, null, null, CancellationToken.None);
        clock.Advance(TimeSpan.FromMinutes(5).Add(TimeSpan.FromTicks(1)));
        await service.ReadInventoryAsync("sites", null, null, null, CancellationToken.None);

        Assert.Equal(2, client.GetPaths.Count);
    }

    [Fact]
    public async Task Concurrent_identical_discovery_requests_are_coalesced()
    {
        var release = new TaskCompletionSource<JsonNode?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new FakeSiteManagerClient
        {
            Get = _ => release.Task
        };
        var service = CreateService(client);

        var first = service.ReadInventoryAsync("hosts", null, null, null, CancellationToken.None);
        var second = service.ReadInventoryAsync("hosts", null, null, null, CancellationToken.None);
        release.SetResult(new JsonObject { ["data"] = new JsonArray() });
        await Task.WhenAll(first, second);

        Assert.Single(client.GetPaths);
    }

    [Fact]
    public async Task Cancelled_waiter_does_not_leave_stale_inflight_data_after_cache_expiry()
    {
        var clock = new MutableTimeProvider(
            new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero));
        var release = new TaskCompletionSource<JsonNode?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new FakeSiteManagerClient
        {
            Get = _ => release.Task
        };
        var service = CreateService(client, clock);
        using var cancellation = new CancellationTokenSource();
        var first = service.ReadInventoryAsync(
            "hosts",
            null,
            null,
            null,
            cancellation.Token);

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        release.SetResult(new JsonObject { ["data"] = new JsonArray() });
        await Task.Yield();
        await Task.Yield();

        clock.Advance(TimeSpan.FromMinutes(5).Add(TimeSpan.FromTicks(1)));
        await service.ReadInventoryAsync("hosts", null, null, null, CancellationToken.None);

        Assert.Equal(2, client.GetPaths.Count);
    }

    [Fact]
    public async Task Isp_metrics_support_get_duration_and_targeted_query()
    {
        var client = new FakeSiteManagerClient();
        var service = CreateService(client);

        await service.ReadIspMetricsAsync(
            "5m",
            "24h",
            null,
            null,
            null,
            CancellationToken.None);
        await service.ReadIspMetricsAsync(
            "1h",
            null,
            "2026-07-24T12:00:00Z",
            "2026-07-25T12:00:00Z",
            new JsonArray(
                new JsonObject { ["hostId"] = "host-1", ["siteId"] = "site-1" }),
            CancellationToken.None);

        Assert.Equal("v1/isp-metrics/5m?duration=24h", Assert.Single(client.GetPaths));
        var query = Assert.Single(client.Queries);
        Assert.Equal("1h", query.Interval);
        var site = Assert.Single(query.Body["sites"]!.AsArray())!;
        Assert.Equal("host-1", site["hostId"]!.GetValue<string>());
        Assert.Equal("2026-07-24T12:00:00Z", site["beginTimestamp"]!.GetValue<string>());
    }

    [Fact]
    public async Task Targeted_duration_is_converted_to_an_explicit_time_range()
    {
        var client = new FakeSiteManagerClient();
        var service = CreateService(client);

        await service.ReadIspMetricsAsync(
            "1h",
            "7d",
            null,
            null,
            new JsonArray(
                new JsonObject { ["hostId"] = "host-1", ["siteId"] = "site-1" }),
            CancellationToken.None);

        var site = Assert.Single(Assert.Single(client.Queries).Body["sites"]!.AsArray())!;
        Assert.Equal("2026-07-18T12:00:00.0000000+00:00", site["beginTimestamp"]!.GetValue<string>());
        Assert.Equal("2026-07-25T12:00:00.0000000+00:00", site["endTimestamp"]!.GetValue<string>());
    }

    [Fact]
    public async Task Rate_limit_is_returned_as_structured_data()
    {
        var retryAt = new DateTimeOffset(2026, 7, 25, 12, 5, 0, TimeSpan.Zero);
        var client = new FakeSiteManagerClient
        {
            Get = _ => Task.FromException<JsonNode?>(
                new SiteManagerApiException(
                    HttpStatusCode.TooManyRequests,
                    "limited",
                    "rate_limit",
                    retryAt))
        };
        var service = CreateService(client);

        var response = await service.ReadInventoryAsync(
            "hosts",
            null,
            null,
            null,
            CancellationToken.None);

        Assert.Equal("rateLimited", response.Data!["status"]!.GetValue<string>());
        Assert.Equal(retryAt.ToString("O"), response.Data["retryAt"]!.GetValue<string>());
    }

    [Fact]
    public async Task Device_enrichment_fetches_all_pages_for_the_exact_host()
    {
        var client = new FakeSiteManagerClient
        {
            Get = path =>
            {
                if (!path.Contains("nextToken", StringComparison.Ordinal))
                {
                    return Task.FromResult<JsonNode?>(new JsonObject
                    {
                        ["data"] = new JsonArray(
                            new JsonObject
                            {
                                ["hostId"] = "host-1",
                                ["devices"] = new JsonArray()
                            },
                            new JsonObject
                            {
                                ["hostId"] = "other-host",
                                ["devices"] = new JsonArray()
                            }),
                        ["nextToken"] = "page-2"
                    });
                }

                return Task.FromResult<JsonNode?>(new JsonObject
                {
                    ["data"] = new JsonArray(
                        new JsonObject
                        {
                            ["hostId"] = "host-1",
                            ["devices"] = new JsonArray()
                        })
                });
            }
        };
        var service = CreateService(client);

        var groups = await service.GetAllDevicesForHostAsync(
            "host-1",
            CancellationToken.None);

        Assert.Equal(2, groups.Count);
        Assert.Equal(2, client.GetPaths.Count);
        Assert.All(
            groups,
            group => Assert.Equal("host-1", group!["hostId"]!.GetValue<string>()));
    }

    [Fact]
    public async Task Host_mapping_is_verified_across_cursor_pages()
    {
        var client = new FakeSiteManagerClient
        {
            Get = path => Task.FromResult<JsonNode?>(
                path.Contains("nextToken", StringComparison.Ordinal)
                    ? new JsonObject
                    {
                        ["data"] = new JsonArray(
                            new JsonObject { ["id"] = "host-2" })
                    }
                    : new JsonObject
                    {
                        ["data"] = new JsonArray(
                            new JsonObject { ["id"] = "host-1" }),
                        ["nextToken"] = "page-2"
                    })
        };
        var service = CreateService(client, localHostId: "host-2");

        var status = await service.GetHostMappingStatusAsync(CancellationToken.None);

        Assert.Equal("mapped", status["status"]!.GetValue<string>());
        Assert.True(status["verified"]!.GetValue<bool>());
        Assert.Equal(2, client.GetPaths.Count);
    }

    [Fact]
    public async Task Configured_host_mapping_reports_not_found()
    {
        var client = new FakeSiteManagerClient
        {
            Get = _ => Task.FromResult<JsonNode?>(new JsonObject
            {
                ["data"] = new JsonArray(
                    new JsonObject { ["id"] = "different-host" })
            })
        };
        var service = CreateService(client, localHostId: "missing-host");

        var status = await service.GetHostMappingStatusAsync(CancellationToken.None);

        Assert.Equal("notFound", status["status"]!.GetValue<string>());
        Assert.True(status["configured"]!.GetValue<bool>());
        Assert.True(status["verified"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Invalid_metric_combinations_are_rejected_before_network_access()
    {
        var client = new FakeSiteManagerClient();
        var service = CreateService(client);

        await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadIspMetricsAsync(
                "5m",
                "7d",
                null,
                null,
                null,
                CancellationToken.None));

        Assert.Empty(client.GetPaths);
        Assert.Empty(client.Queries);
    }

    [Fact]
    public async Task Metric_target_properties_must_be_strings()
    {
        var client = new FakeSiteManagerClient();
        var service = CreateService(client);

        var exception = await Assert.ThrowsAsync<ContractException>(() =>
            service.ReadIspMetricsAsync(
                "5m",
                null,
                "2026-07-25T11:00:00Z",
                "2026-07-25T12:00:00Z",
                new JsonArray(
                    new JsonObject { ["hostId"] = 123, ["siteId"] = "site-1" }),
                CancellationToken.None));

        Assert.Equal("hostId must be a string.", exception.Message);
        Assert.Empty(client.Queries);
    }

    private static SiteManagerReadService CreateService(
        FakeSiteManagerClient client,
        TimeProvider? timeProvider = null,
        string? localHostId = null)
    {
        var configuration = new UnifiConfiguration(
            new Uri(UnifiConfiguration.DefaultBaseUrl + "/"),
            "local-key",
            null,
            TimeSpan.FromSeconds(5),
            SiteManagerApiKey: "site-key",
            SiteManagerLocalHostId: localHostId);
        return new SiteManagerReadService(
            configuration,
            client,
            new SecretRedactor("local-key", "site-key"),
            timeProvider ?? new FixedTimeProvider(
                new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero)));
    }

    private sealed class FakeSiteManagerClient : ISiteManagerClient
    {
        public Func<string, Task<JsonNode?>> Get { get; init; } =
            _ => Task.FromResult<JsonNode?>(new JsonObject
            {
                ["data"] = new JsonArray(),
                ["httpStatusCode"] = 200
            });

        public List<string> GetPaths { get; } = new();

        public List<QueryRequest> Queries { get; } = new();

        public Task<JsonNode?> GetAsync(string relativePath, CancellationToken cancellationToken)
        {
            GetPaths.Add(relativePath);
            return Get(relativePath);
        }

        public Task<JsonNode?> QueryIspMetricsAsync(
            string interval,
            JsonObject body,
            CancellationToken cancellationToken)
        {
            Queries.Add(new QueryRequest(interval, body.DeepClone().AsObject()));
            return Task.FromResult<JsonNode?>(new JsonObject
            {
                ["data"] = new JsonObject { ["metrics"] = new JsonArray() },
                ["httpStatusCode"] = 200
            });
        }

        public JsonObject Describe() => new()
        {
            ["configured"] = true,
            ["rateLimit"] = new JsonObject()
        };
    }

    private sealed record QueryRequest(string Interval, JsonObject Body);

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }

    private sealed class MutableTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow;

        public MutableTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan value)
        {
            _utcNow += value;
        }
    }
}
