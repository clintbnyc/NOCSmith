using System.Reflection;
using ModelContextProtocol.Server;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class ToolMetadataTests
{
    [Fact]
    public void Journal_write_metadata_distinguishes_collection_and_recovery()
    {
        var tools = typeof(UnifiTools)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Select(method => new
            {
                Method = method,
                Attribute = method.GetCustomAttribute<McpServerToolAttribute>()
            })
            .Where(item => item.Attribute is not null)
            .ToArray();

        Assert.Equal(35, tools.Length);
        foreach (var tool in tools)
        {
            if (string.Equals(tool.Attribute!.Name, "unifi_collect_client_observations", StringComparison.Ordinal))
            {
                Assert.False(tool.Attribute.ReadOnly);
                Assert.False(tool.Attribute.Destructive);
                Assert.False(tool.Attribute.Idempotent);
            }
            else if (string.Equals(tool.Attribute.Name, "unifi_apply_change", StringComparison.Ordinal) ||
                     string.Equals(tool.Attribute.Name, "unifi_recover_client_journal", StringComparison.Ordinal))
            {
                Assert.False(tool.Attribute.ReadOnly);
                Assert.True(tool.Attribute.Destructive);
                Assert.False(tool.Attribute.Idempotent);
            }
            else
            {
                Assert.True(tool.Attribute!.ReadOnly, tool.Attribute.Name);
                Assert.False(tool.Attribute.Destructive, tool.Attribute.Name);
            }
        }

        var openWorldTools = tools
            .Where(tool => tool.Attribute!.OpenWorld)
            .Select(tool => tool.Attribute!.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            new[]
            {
                "unifi_devices",
                "unifi_get_capabilities",
                "unifi_get_site_snapshot",
                "unifi_isp_metrics",
                "unifi_read_operation",
                "unifi_site_manager"
            },
            openWorldTools);
    }
}
