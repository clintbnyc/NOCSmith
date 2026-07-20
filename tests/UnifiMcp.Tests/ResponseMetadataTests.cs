using System.Text.Json.Nodes;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class ResponseMetadataTests
{
    [Fact]
    public void Pagination_reports_truncation_explicitly()
    {
        var page = new JsonObject
        {
            ["offset"] = 20,
            ["limit"] = 20,
            ["totalCount"] = 55,
            ["data"] = new JsonArray(JsonValue.Create(1), JsonValue.Create(2))
        };

        var result = ResponseMetadata.AnnotatePagination(page)!;

        Assert.True(ResponseMetadata.IsTruncated(result));
        Assert.Equal(2, result["_connector"]!["returned"]!.GetValue<int>());
        Assert.Equal(55, result["_connector"]!["totalCount"]!.GetValue<int>());
    }
}
