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
    public void Validation_rejects_undeclared_body_property_by_default()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("executeAdoptedDeviceAction", requireRead: false);
        var path = new Dictionary<string, string>
        {
            ["siteId"] = "00000000-0000-0000-0000-000000000001",
            ["deviceId"] = "00000000-0000-0000-0000-000000000002"
        };

        var exception = Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(
                operation,
                path,
                null,
                new JsonObject
                {
                    ["action"] = "RESTART",
                    ["redirect"] = "https://example.invalid"
                }));

        Assert.Contains("body.redirect", exception.Message, StringComparison.Ordinal);
        Assert.Contains("not allowed", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validation_rejects_explicit_null_for_nonnullable_property()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("createVouchers", requireRead: false);
        var path = new Dictionary<string, string>
        {
            ["siteId"] = "00000000-0000-0000-0000-000000000001"
        };

        var exception = Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(
                operation,
                path,
                null,
                new JsonObject
                {
                    ["name"] = "test",
                    ["timeLimitMinutes"] = 1,
                    ["count"] = null
                }));

        Assert.Contains("body.count", exception.Message, StringComparison.Ordinal);
        Assert.Contains("may not be null", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validation_rejects_explicit_null_for_nonnullable_array_item()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("updateAclRuleOrdering", requireRead: false);
        var path = new Dictionary<string, string>
        {
            ["siteId"] = "00000000-0000-0000-0000-000000000001"
        };

        var exception = Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(
                operation,
                path,
                null,
                new JsonObject
                {
                    ["orderedAclRuleIds"] = new JsonArray((JsonNode?)null)
                }));

        Assert.Contains("body.orderedAclRuleIds[0]", exception.Message, StringComparison.Ordinal);
        Assert.Contains("may not be null", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validation_accepts_explicit_null_when_schema_declares_it_nullable()
    {
        var document = new JsonObject
        {
            ["openapi"] = "3.1.0",
            ["info"] = new JsonObject { ["title"] = "test", ["version"] = "1" },
            ["paths"] = new JsonObject
            {
                ["/things"] = new JsonObject
                {
                    ["post"] = new JsonObject
                    {
                        ["operationId"] = "setThing",
                        ["requestBody"] = new JsonObject
                        {
                            ["required"] = true,
                            ["content"] = new JsonObject
                            {
                                ["application/json"] = new JsonObject
                                {
                                    ["schema"] = new JsonObject
                                    {
                                        ["type"] = "object",
                                        ["properties"] = new JsonObject
                                        {
                                            ["note"] = new JsonObject
                                            {
                                                ["type"] = new JsonArray("string", "null")
                                            },
                                            ["legacyNote"] = new JsonObject
                                            {
                                                ["type"] = "string",
                                                ["nullable"] = true
                                            },
                                            ["nullOnly"] = new JsonObject { ["type"] = "null" },
                                            ["anything"] = new JsonObject()
                                        }
                                    }
                                }
                            }
                        },
                        ["responses"] = new JsonObject()
                    }
                }
            }
        };
        var contract = OpenApiContract.Parse(document.ToJsonString(), "test");
        var operation = contract.GetOperation("setThing", requireRead: false);
        var body = new JsonObject
        {
            ["note"] = null,
            ["legacyNote"] = null,
            ["nullOnly"] = null,
            ["anything"] = null
        };

        var nonNullException = Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(
                operation,
                null,
                null,
                new JsonObject { ["nullOnly"] = "not-null" }));
        var request = contract.ValidateAndBuild(operation, null, null, body);
        var unconstrainedObjectRequest = contract.ValidateAndBuild(
            operation,
            null,
            null,
            new JsonObject
            {
                ["anything"] = new JsonObject { ["arbitraryNestedField"] = true }
            });

        Assert.Contains("body.nullOnly must be null", nonNullException.Message, StringComparison.Ordinal);
        Assert.True(JsonNode.DeepEquals(body, request.Body));
        Assert.NotNull(unconstrainedObjectRequest.Body);
    }

    [Fact]
    public void Discriminator_normalization_rejects_aliases_without_declared_wire_enum()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("executeAdoptedDeviceAction", requireRead: false);
        var path = new Dictionary<string, string>
        {
            ["siteId"] = "00000000-0000-0000-0000-000000000001",
            ["deviceId"] = "00000000-0000-0000-0000-000000000002"
        };

        var exception = Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(
                operation,
                path,
                null,
                new JsonObject { ["action"] = "restart" }));

        Assert.Contains("does not select a supported discriminator variant", exception.Message, StringComparison.Ordinal);
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

    [Fact]
    public void Gateway_network_validation_follows_discriminator_required_fields()
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("updateNetwork", requireRead: false);
        var path = new Dictionary<string, string>
        {
            ["siteId"] = "00000000-0000-0000-0000-000000000001",
            ["networkId"] = "00000000-0000-0000-0000-000000000002"
        };
        var incompleteGatewayBody = new JsonObject
        {
            ["enabled"] = true,
            ["management"] = "GATEWAY",
            ["name"] = "Office",
            ["vlanId"] = 20
        };

        var exception = Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(operation, path, null, incompleteGatewayBody));

        Assert.Contains("cellularBackupEnabled", exception.Message, StringComparison.Ordinal);
        Assert.Contains("required", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("tcp")]
    [InlineData("ax.25")]
    [InlineData("idpr-cmtp")]
    public void Firewall_policy_validation_accepts_named_protocol_wire_values(string protocolName)
    {
        var contract = OpenApiContract.LoadEmbedded();
        var operation = contract.GetOperation("createFirewallPolicy", requireRead: false);
        var path = new Dictionary<string, string>
        {
            ["siteId"] = "00000000-0000-0000-0000-000000000001"
        };
        var body = new JsonObject
        {
            ["action"] = new JsonObject { ["type"] = "BLOCK" },
            ["destination"] = new JsonObject
            {
                ["zoneId"] = "00000000-0000-0000-0000-000000000002"
            },
            ["enabled"] = true,
            ["ipProtocolScope"] = new JsonObject
            {
                ["ipVersion"] = "IPV4",
                ["protocolFilter"] = new JsonObject
                {
                    ["type"] = "NAMED_PROTOCOL",
                    ["matchOpposite"] = false,
                    ["protocol"] = new JsonObject { ["name"] = protocolName }
                }
            },
            ["loggingEnabled"] = false,
            ["name"] = "Allow DNS",
            ["source"] = new JsonObject
            {
                ["zoneId"] = "00000000-0000-0000-0000-000000000003"
            }
        };

        var bodyWithNestedUnknown = body.DeepClone().AsObject();
        bodyWithNestedUnknown["source"]!["controllerOnlyField"] = true;
        var exception = Assert.Throws<ContractException>(() =>
            contract.ValidateAndBuild(operation, path, null, bodyWithNestedUnknown));
        var request = contract.ValidateAndBuild(operation, path, null, body);

        Assert.Contains("body.source.controllerOnlyField", exception.Message, StringComparison.Ordinal);
        Assert.True(JsonNode.DeepEquals(body, request.Body));
    }
}
