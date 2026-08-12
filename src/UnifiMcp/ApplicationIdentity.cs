using System.Reflection;

namespace UnifiMcp;

internal static class ApplicationIdentity
{
    private static readonly Assembly ApplicationAssembly =
        typeof(ApplicationIdentity).Assembly;

    public static string InformationalVersion { get; } =
        ApplicationAssembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion
        ?? ApplicationAssembly.GetName().Version?.ToString(3)
        ?? "unknown";

    public static string Version { get; } = InformationalVersion.Split('+', 2)[0];
}
