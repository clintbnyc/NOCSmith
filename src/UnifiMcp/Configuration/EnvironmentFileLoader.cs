using DotNetEnv;

namespace UnifiMcp.Configuration;

public static class EnvironmentFileLoader
{
    private const string EnvFileOption = "--env-file";

    private static readonly HashSet<string> SupportedVariables = new(StringComparer.Ordinal)
    {
        "UNIFI_API_KEY",
        "UNIFI_BASE_URL",
        "UNIFI_DEFAULT_SITE_ID",
        "UNIFI_TIMEOUT_SECONDS",
        "UNIFI_ENABLE_LEGACY_READ_ENRICHMENT",
        "UNIFI_ENABLE_CLIENT_JOURNAL",
        "UNIFI_CLIENT_JOURNAL_DB_PATH",
        "UNIFI_CLIENT_JOURNAL_RETENTION_DAYS",
        "UNIFI_CLIENT_JOURNAL_MAX_MIB",
        "UNIFI_ENABLE_SCHEDULED_COLLECTION",
        "UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES",
        "UNIFI_SCHEDULED_COLLECTION_SITE_ID",
        "UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS",
        "UNIFI_MCP_HTTP_AUTH_MODE",
        "UNIFI_MCP_HTTP_BEARER_TOKEN",
        "UNIFI_MCP_TAILSCALE_ALLOWED_USERS",
        "UNIFI_MCP_HTTP_PUBLIC_URL",
        "UNIFI_MCP_HTTP_LISTEN_URL",
        "UNIFI_MCP_TAILSCALE_SOCKET_PATH",
        "UNIFI_SITE_API_KEY",
        "UNIFI_SITE_MANAGER_LOCAL_HOST_ID"
    };

    public static string[] LoadAndRemoveOption(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        string? envFilePath = null;
        var remainingArgs = new List<string>(args.Length);

        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            if (string.Equals(argument, EnvFileOption, StringComparison.Ordinal))
            {
                if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]))
                {
                    throw new ConfigurationException("--env-file requires a file path.");
                }

                SetEnvFilePath(ref envFilePath, args[++index]);
                continue;
            }

            if (argument.StartsWith(EnvFileOption + "=", StringComparison.Ordinal))
            {
                var path = argument[(EnvFileOption.Length + 1)..];
                if (string.IsNullOrWhiteSpace(path))
                {
                    throw new ConfigurationException("--env-file requires a file path.");
                }

                SetEnvFilePath(ref envFilePath, path);
                continue;
            }

            remainingArgs.Add(argument);
        }

        if (envFilePath is not null)
        {
            LoadSupportedVariables(Path.GetFullPath(envFilePath));
        }

        return remainingArgs.ToArray();
    }

    private static void SetEnvFilePath(ref string? currentPath, string path)
    {
        if (currentPath is not null)
        {
            throw new ConfigurationException("--env-file may only be specified once.");
        }

        currentPath = path;
    }

    private static void LoadSupportedVariables(string path)
    {
        IEnumerable<KeyValuePair<string, string>> parsedVariables;
        try
        {
            parsedVariables = Env.NoEnvVars().Load(path).ToArray();
        }
        catch (Exception)
        {
            throw new ConfigurationException(
                $"Unable to load environment file '{path}'. Verify that it exists, is authorized, and contains valid dotenv assignments.");
        }

        var selectedVariables = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, value) in parsedVariables)
        {
            if (SupportedVariables.Contains(name))
            {
                selectedVariables[name] = value;
            }
        }

        foreach (var (name, value) in selectedVariables)
        {
            if (Environment.GetEnvironmentVariable(name) is null)
            {
                Environment.SetEnvironmentVariable(name, value);
            }
        }
    }
}
