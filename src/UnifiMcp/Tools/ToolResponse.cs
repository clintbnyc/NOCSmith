using System.Text.Json.Nodes;

namespace UnifiMcp.Tools;

public sealed record ToolResponse(string Summary, JsonNode? Data);
