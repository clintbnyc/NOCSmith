using System.Reflection;
using ModelContextProtocol.Server;
using UnifiMcp.Tools;

namespace UnifiMcp.Tests;

public sealed class ToolMetadataTests
{
    [Fact]
    public void Only_apply_is_marked_as_a_destructive_write()
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

        Assert.Equal(27, tools.Length);
        foreach (var tool in tools)
        {
            if (string.Equals(tool.Attribute!.Name, "unifi_apply_change", StringComparison.Ordinal))
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
    }
}
