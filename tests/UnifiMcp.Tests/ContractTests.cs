using System.Text.Json.Nodes;
using UnifiMcp.Contracts;

namespace UnifiMcp.Tests;

public sealed class ContractTests
{
    [Fact]
    public void Embedded_contract_contains_every_published_operation()
    {
        var contract = OpenApiContract.LoadEmbedded();

        Assert.Equal("10.5.67", contract.Version);
        Assert.Equal(41, contract.ReadCount);
        Assert.Equal(32, contract.WriteCount);
        Assert.Equal(73, contract.Operations.Count);
        Assert.Equal(73, contract.Operations.Select(operation => operation.OperationId).Distinct().Count());
    }

    [Fact]
    public void Response_capability_detection_follows_schema_paths()
    {
        var contract = OpenApiContract.LoadEmbedded();

        Assert.True(contract.ResponseSchemaContainsPath(
            "getAdoptedDeviceDetails",
            "interfaces",
            "ports",
            "state"));
        Assert.False(contract.ResponseSchemaContainsPath(
            "getAdoptedDeviceDetails",
            "interfaces",
            "ports",
            "stpState"));
    }

    [Fact]
    public void Private_read_resources_remain_outside_the_official_contract()
    {
        var paths = OpenApiContract.LoadEmbedded().Operations
            .Select(operation => operation.PathTemplate)
            .ToHashSet(StringComparer.Ordinal);

        Assert.DoesNotContain(paths, path => path.Contains("clients/history", StringComparison.Ordinal));
        Assert.DoesNotContain(paths, path => path.Contains("network-members-groups", StringComparison.Ordinal));
        Assert.DoesNotContain(paths, path => path.Contains("system-log", StringComparison.Ordinal));
    }

    [Fact]
    public void Read_lookup_rejects_write_operation()
    {
        var contract = OpenApiContract.LoadEmbedded();

        var exception = Assert.Throws<ContractException>(() =>
            contract.GetOperation("createNetwork", requireRead: true));

        Assert.Contains("is a write", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validation_rejects_unknown_query_parameter()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("getSiteOverviewPage", requireRead: true);

        var exception = Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(
                operation,
                null,
                new Dictionary<string, string> { ["redirect"] = "https://example.invalid" },
                null));

        Assert.Contains("Unknown query parameter", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Action_body_is_schema_validated()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("executeAdoptedDeviceAction", requireRead: false);
        var path = new Dictionary<string, string>
        {
            ["siteId"] = "00000000-0000-0000-0000-000000000001",
            ["deviceId"] = "00000000-0000-0000-0000-000000000002"
        };

        Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(operation, path, null, new JsonObject()));

        var request = contract.ValidateAndBuild(
            operation,
            path,
            null,
            new JsonObject { ["action"] = "RESTART" });
        Assert.Equal("/v1/sites/00000000-0000-0000-0000-000000000001/devices/00000000-0000-0000-0000-000000000002/actions", request.RelativeUri);
    }

    [Fact]
    public void Numeric_schema_bounds_are_enforced()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("createVouchers", requireRead: false);
        var path = new Dictionary<string, string>
        {
            ["siteId"] = "00000000-0000-0000-0000-000000000001"
        };

        Assert.Throws<ContractException>(() => contract.ValidateAndBuild(
            operation,
            path,
            null,
            new JsonObject { ["name"] = "test", ["timeLimitMinutes"] = 0, ["count"] = 1 }));
        Assert.Throws<ContractException>(() => contract.ValidateAndBuild(
            operation,
            path,
            null,
            new JsonObject { ["name"] = "test", ["timeLimitMinutes"] = 1, ["count"] = 1001 }));

        var request = contract.ValidateAndBuild(
            operation,
            path,
            null,
            new JsonObject { ["name"] = "test", ["timeLimitMinutes"] = 1, ["count"] = 1000 });
        Assert.NotNull(request.Body);
    }
}
