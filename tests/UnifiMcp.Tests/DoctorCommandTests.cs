using System.Text.Json.Nodes;
using UnifiMcp.Contracts;

namespace UnifiMcp.Tests;

public sealed class DoctorCommandTests
{
    [Fact]
    public void Count_private_client_records_accepts_a_root_array()
    {
        var response = new JsonArray
        {
            new JsonObject { ["id"] = "client-1" },
            new JsonObject { ["id"] = "client-2" }
        };

        Assert.Equal(2, DoctorCommand.CountPrivateClientRecords(response));
    }

    [Fact]
    public void Count_private_client_records_accepts_a_wrapped_data_array()
    {
        var response = new JsonObject
        {
            ["data"] = new JsonArray
            {
                new JsonObject { ["id"] = "client-1" },
                new JsonObject { ["id"] = "client-2" }
            }
        };

        Assert.Equal(2, DoctorCommand.CountPrivateClientRecords(response));
    }

    [Fact]
    public void Count_private_client_records_rejects_an_unexpected_shape()
    {
        var response = new JsonObject { ["data"] = new JsonObject() };

        var exception = Assert.Throws<ContractException>(
            () => DoctorCommand.CountPrivateClientRecords(response));

        Assert.Contains("data array", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Count_private_client_records_rejects_non_object_array_entries()
    {
        var response = new JsonArray
        {
            new JsonObject { ["id"] = "client-1" },
            JsonValue.Create("not-a-client-record")
        };

        var exception = Assert.Throws<ContractException>(
            () => DoctorCommand.CountPrivateClientRecords(response));

        Assert.Contains("non-object record at index 1", exception.Message, StringComparison.Ordinal);
    }
}
