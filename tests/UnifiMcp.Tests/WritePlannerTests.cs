using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;
using UnifiMcp.Writes;

namespace UnifiMcp.Tests;

public sealed class WritePlannerTests
{
    private const string SiteId = "00000000-0000-0000-0000-000000000001";
    private const string DeviceId = "00000000-0000-0000-0000-000000000002";

    [Fact]
    public async Task Preview_is_read_only_and_apply_sends_exactly_one_mutation()
    {
        var fixture = CreateFixture();

        var preview = await fixture.Planner.PreviewAsync(
            "executeAdoptedDeviceAction",
            Paths(),
            null,
            new JsonObject { ["action"] = "RESTART" },
            mergeChanges: false,
            allowReferenced: false,
            CancellationToken.None);

        Assert.Equal(1, fixture.Client.ReadCount);
        Assert.Equal(0, fixture.Client.MutationCount);

        var result = await fixture.Planner.ApplyAsync(preview.ConfirmationToken, CancellationToken.None);

        Assert.Equal("executeAdoptedDeviceAction", result.OperationId);
        Assert.Equal(2, fixture.Client.ReadCount);
        Assert.Equal(1, fixture.Client.MutationCount);
        await Assert.ThrowsAsync<ConfirmationException>(() =>
            fixture.Planner.ApplyAsync(preview.ConfirmationToken, CancellationToken.None));
    }

    [Fact]
    public async Task Apply_rejects_state_drift_without_mutating()
    {
        var fixture = CreateFixture();
        var preview = await fixture.Planner.PreviewAsync(
            "executeAdoptedDeviceAction",
            Paths(),
            null,
            new JsonObject { ["action"] = "RESTART" },
            false,
            false,
            CancellationToken.None);
        fixture.Client.State = new JsonObject { ["id"] = DeviceId, ["state"] = "OFFLINE" };

        var exception = await Assert.ThrowsAsync<ConfirmationException>(() =>
            fixture.Planner.ApplyAsync(preview.ConfirmationToken, CancellationToken.None));

        Assert.Contains("state changed", exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, fixture.Client.MutationCount);
    }

    [Fact]
    public void Confirmation_token_expires_and_is_consumed()
    {
        var time = new ManualTimeProvider(DateTimeOffset.Parse("2026-07-20T12:00:00Z"));
        var store = new ConfirmationStore(time, TimeSpan.FromMinutes(5));
        var mutation = DeviceMutation();
        var pending = store.Add(mutation, null, null, null, Array.Empty<string>());
        time.Advance(TimeSpan.FromMinutes(6));

        Assert.Throws<ConfirmationException>(() => store.Consume(pending.Token));
        Assert.Throws<ConfirmationException>(() => store.Consume(pending.Token));
    }

    [Fact]
    public void Overlay_preserves_absent_fields_and_retains_explicit_null()
    {
        var target = new JsonObject
        {
            ["name"] = "Office",
            ["enabled"] = true,
            ["nested"] = new JsonObject { ["one"] = 1, ["two"] = 2 }
        };
        var changes = new JsonObject
        {
            ["name"] = null,
            ["nested"] = new JsonObject { ["two"] = 3 }
        };

        var result = JsonOverlay.Apply(target, changes)!.AsObject();

        Assert.True(result.ContainsKey("name"));
        Assert.Null(result["name"]);
        Assert.True(result["enabled"]!.GetValue<bool>());
        Assert.Equal(1, result["nested"]!["one"]!.GetValue<int>());
        Assert.Equal(3, result["nested"]!["two"]!.GetValue<int>());
    }

    [Fact]
    public async Task Bulk_voucher_preview_resolves_exact_ids_and_redacts_codes()
    {
        var fixture = CreateFixture();
        fixture.Client.State = new JsonObject
        {
            ["totalCount"] = 1,
            ["data"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = DeviceId,
                    ["code"] = "4861409510",
                    ["timeLimitMinutes"] = 15
                }
            }
        };

        var preview = await fixture.Planner.PreviewAsync(
            "deleteVouchers",
            new Dictionary<string, string> { ["siteId"] = SiteId },
            new Dictionary<string, string> { ["filter"] = "name.eq('codex-test')" },
            null,
            false,
            false,
            CancellationToken.None);

        Assert.Contains("limit=200", fixture.Client.LastRead!.RelativeUri, StringComparison.Ordinal);
        Assert.Contains("offset=0", fixture.Client.LastRead.RelativeUri, StringComparison.Ordinal);
        Assert.Contains(preview.Warnings, warning => warning.Contains("resolved exactly 1", StringComparison.Ordinal));
        Assert.DoesNotContain("4861409510", preview.Before!.ToJsonString(), StringComparison.Ordinal);
        Assert.Contains("filter=%3Credacted%3E", preview.Target, StringComparison.Ordinal);

        await fixture.Planner.ApplyAsync(preview.ConfirmationToken, CancellationToken.None);

        var mutationTarget = Uri.UnescapeDataString(fixture.Client.LastMutation!.RelativeUri);
        Assert.Contains($"id.in({DeviceId})", mutationTarget, StringComparison.Ordinal);
        Assert.DoesNotContain("name.eq", mutationTarget, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Bulk_voucher_preview_rejects_a_truncated_match_set()
    {
        var fixture = CreateFixture();
        fixture.Client.State = new JsonObject
        {
            ["totalCount"] = 2,
            ["data"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = DeviceId,
                    ["code"] = "4861409510",
                    ["timeLimitMinutes"] = 15
                }
            }
        };

        var exception = await Assert.ThrowsAsync<ContractException>(() => fixture.Planner.PreviewAsync(
            "deleteVouchers",
            new Dictionary<string, string> { ["siteId"] = SiteId },
            new Dictionary<string, string> { ["filter"] = "name.eq('codex-test')" },
            null,
            false,
            false,
            CancellationToken.None));

        Assert.Contains("only 1 could be resolved", exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, fixture.Client.MutationCount);
    }

    [Fact]
    public async Task Network_delete_without_references_remains_supported()
    {
        var fixture = CreateFixture();
        fixture.Client.ReadResponse = request => request.Operation.OperationId switch
        {
            "getNetworkDetails" => new JsonObject { ["id"] = DeviceId, ["name"] = "Office" },
            "getNetworkReferences" => new JsonObject { ["referenceResources"] = new JsonArray() },
            _ => fixture.Client.State
        };

        var preview = await fixture.Planner.PreviewAsync(
            "deleteNetwork",
            new Dictionary<string, string> { ["siteId"] = SiteId, ["networkId"] = DeviceId },
            null,
            null,
            false,
            false,
            CancellationToken.None);
        await fixture.Planner.ApplyAsync(preview.ConfirmationToken, CancellationToken.None);

        Assert.Equal(1, fixture.Client.MutationCount);
    }

    [Fact]
    public async Task Network_delete_refuses_an_unverifiable_reference_response()
    {
        var fixture = CreateFixture();
        fixture.Client.ReadResponse = request => request.Operation.OperationId switch
        {
            "getNetworkDetails" => new JsonObject { ["id"] = DeviceId, ["name"] = "Office" },
            "getNetworkReferences" => new JsonObject(),
            _ => fixture.Client.State
        };

        var exception = await Assert.ThrowsAsync<ContractException>(() => fixture.Planner.PreviewAsync(
            "deleteNetwork",
            new Dictionary<string, string> { ["siteId"] = SiteId, ["networkId"] = DeviceId },
            null,
            null,
            false,
            false,
            CancellationToken.None));

        Assert.Contains("could not be verified", exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, fixture.Client.MutationCount);
    }

    [Fact]
    public async Task Network_delete_counts_references_and_rechecks_them_before_apply()
    {
        var fixture = CreateFixture();
        var referenceCount = 2;
        fixture.Client.ReadResponse = request => request.Operation.OperationId switch
        {
            "getNetworkDetails" => new JsonObject { ["id"] = DeviceId, ["name"] = "Office" },
            "getNetworkReferences" => NetworkReferences(referenceCount),
            _ => fixture.Client.State
        };
        var paths = new Dictionary<string, string> { ["siteId"] = SiteId, ["networkId"] = DeviceId };

        var exception = await Assert.ThrowsAsync<ContractException>(() => fixture.Planner.PreviewAsync(
            "deleteNetwork",
            paths,
            new Dictionary<string, string> { ["force"] = "true" },
            null,
            false,
            false,
            CancellationToken.None));
        Assert.Contains("2 known reference", exception.Message, StringComparison.Ordinal);

        var preview = await fixture.Planner.PreviewAsync(
            "deleteNetwork",
            paths,
            new Dictionary<string, string> { ["force"] = "true" },
            null,
            false,
            true,
            CancellationToken.None);
        Assert.Contains(preview.Warnings, warning => warning.Contains("2 known reference", StringComparison.Ordinal));

        referenceCount = 3;
        await Assert.ThrowsAsync<ConfirmationException>(() =>
            fixture.Planner.ApplyAsync(preview.ConfirmationToken, CancellationToken.None));
        Assert.Equal(0, fixture.Client.MutationCount);
    }

    private static Fixture CreateFixture()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var client = new FakeUnifiClient
        {
            State = new JsonObject { ["id"] = DeviceId, ["state"] = "ONLINE" }
        };
        var provider = new ContractProvider(contract, client, NullLogger<ContractProvider>.Instance);
        var configuration = new UnifiConfiguration(new Uri(UnifiConfiguration.DefaultBaseUrl + "/"), "test-key", SiteId, TimeSpan.FromSeconds(5));
        var resolver = new SiteResolver(configuration, provider, client);
        var planner = new WritePlanner(provider, client, resolver, new ConfirmationStore(), new SecretRedactor("test-key"));
        return new Fixture(planner, client);
    }

    private static Dictionary<string, string> Paths() => new()
    {
        ["siteId"] = SiteId,
        ["deviceId"] = DeviceId
    };

    private static JsonObject NetworkReferences(int count) => new()
    {
        ["referenceResources"] = new JsonArray
        {
            new JsonObject
            {
                ["resourceType"] = "WIFI",
                ["referenceCount"] = count
            }
        }
    };

    private static ValidatedRequest DeviceMutation()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("executeAdoptedDeviceAction", requireRead: false);
        return contract.ValidateAndBuild(operation, Paths(), null, new JsonObject { ["action"] = "RESTART" });
    }

    private sealed record Fixture(WritePlanner Planner, FakeUnifiClient Client);

    private sealed class FakeUnifiClient : IUnifiClient
    {
        public JsonNode? State { get; set; }

        public Func<ValidatedRequest, JsonNode?>? ReadResponse { get; set; }

        public int ReadCount { get; private set; }

        public int MutationCount { get; private set; }

        public ValidatedRequest? LastRead { get; private set; }

        public ValidatedRequest? LastMutation { get; private set; }

        public Task<JsonNode?> ReadAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            ReadCount++;
            LastRead = request;
            var response = ReadResponse is null ? State : ReadResponse(request);
            return Task.FromResult(response?.DeepClone());
        }

        public Task<JsonNode?> MutateAsync(ValidatedRequest request, CancellationToken cancellationToken)
        {
            MutationCount++;
            LastMutation = request;
            return Task.FromResult<JsonNode?>(new JsonObject { ["accepted"] = true });
        }

        public Task<JsonNode?> GetFixedAsync(string relativePath, CancellationToken cancellationToken) =>
            Task.FromResult<JsonNode?>(null);

        public Task<JsonNode?> ReadLegacyDevicesAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> ReadLegacyClientsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<JsonNode?> QuerySystemLogsAsync(string internalSiteReference, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow;

        public ManualTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan amount) => _utcNow = _utcNow.Add(amount);
    }
}
