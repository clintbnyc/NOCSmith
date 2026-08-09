using System.Text.Json.Nodes;
using UnifiMcp.Contracts;

namespace UnifiMcp.Tools;

internal sealed record SystemLogPageMetadata(
    int? PageNumber,
    int? TotalElementCount,
    int? TotalPageCount)
{
    private const int MaximumMetadataValue = 1_000_000_000;

    public bool HasAdditionalPages =>
        TotalPageCount is int totalPages && totalPages > 1;

    public static SystemLogPageMetadata Read(JsonObject response, int pageRecordCount)
    {
        var pageNumber = ReadOptionalBoundedInteger(response, "page_number");
        var totalElementCount = ReadOptionalBoundedInteger(response, "total_element_count");
        var totalPageCount = ReadOptionalBoundedInteger(response, "total_page_count");

        if (totalElementCount is int elementCount && elementCount < pageRecordCount)
        {
            throw new ContractException(
                "Private UniFi System Logs total_element_count was smaller than the returned page.");
        }

        if (totalPageCount is 0 && pageRecordCount > 0)
        {
            throw new ContractException(
                "Private UniFi System Logs total_page_count was zero for a non-empty page.");
        }

        if (pageNumber is int page && totalPageCount is int pages)
        {
            var validPage = pages == 0 ? page == 0 : page < pages;
            if (!validPage)
            {
                throw new ContractException(
                    "Private UniFi System Logs page_number was inconsistent with total_page_count.");
            }
        }

        return new SystemLogPageMetadata(pageNumber, totalElementCount, totalPageCount);
    }

    private static int? ReadOptionalBoundedInteger(JsonObject response, string propertyName)
    {
        var node = response[propertyName];
        if (node is null)
        {
            return null;
        }

        if (node is not JsonValue value ||
            !value.TryGetValue<int>(out var number) ||
            number < 0 ||
            number > MaximumMetadataValue)
        {
            throw new ContractException(
                $"Private UniFi System Logs {propertyName} must be a non-negative integer no greater than {MaximumMetadataValue}.");
        }

        return number;
    }
}
