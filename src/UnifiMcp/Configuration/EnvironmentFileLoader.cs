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
        "UNIFI_ENABLE_LEGACY_READ_ENRICHMENT"
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
