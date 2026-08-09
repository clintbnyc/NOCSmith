using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;
using UnifiMcp.Api;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Security;

namespace UnifiMcp.Tools;

public sealed class SiteManagerReadService
{
    private const int DefaultPageSize = 500;
    private const int MaximumPageSize = 500;
    private const int MaximumTargetCount = 500;
    private const int MaximumPagesForEnrichment = 100;
    private const int MaximumPagesForHostMapping = 100;
    private const int MaximumOpaqueIdLength = 4096;
    private const int MaximumCacheEntries = 16;
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);

    private readonly UnifiConfiguration _configuration;
    private readonly ISiteManagerClient _client;
    private readonly SecretRedactor _redactor;
    private readonly TimeProvider _timeProvider;
    private readonly object _cacheGate = new();
    private readonly Dictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Lazy<Task<CachedRead>>> _inflight = new(StringComparer.Ordinal);
    private long _cacheAccessSequence;

    public SiteManagerReadService(
        UnifiConfiguration configuration,
        ISiteManagerClient client,
        SecretRedactor redactor,
        TimeProvider? timeProvider = null)
    {
        _configuration = configuration;
        _client = client;
        _redactor = redactor;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<ToolResponse> ReadInventoryAsync(
        string action,
        string? hostId,
        int? pageSize,
        string? nextToken,
        CancellationToken cancellationToken) =>
        ExecuteSafelyAsync(
            async () =>
            {
                var normalizedAction = action.Trim().ToLowerInvariant();
                var size = ValidatePageSize(pageSize);
                ValidateOpaqueValue(nextToken, "nextToken", allowNull: true);
                ValidateOpaqueValue(hostId, "hostId", allowNull: true);

                string relativePath;
                switch (normalizedAction)
                {
                    case "hosts":
                        RejectHostId(hostId, normalizedAction);
                        relativePath = BuildPagePath("v1/hosts", size, nextToken, null);
                        break;
                    case "host":
                        if (string.IsNullOrWhiteSpace(hostId))
                        {
                            throw new ContractException("Site Manager action 'host' requires hostId.");
                        }

                        if (pageSize is not null || nextToken is not null)
                        {
                            throw new ContractException("Site Manager action 'host' does not accept pagination parameters.");
                        }

                        relativePath = "v1/hosts/" + Uri.EscapeDataString(hostId);
                        break;
                    case "sites":
                        RejectHostId(hostId, normalizedAction);
                        relativePath = BuildPagePath("v1/sites", size, nextToken, null);
                        break;
                    case "devices":
                        relativePath = BuildPagePath("v1/devices", size, nextToken, hostId);
                        break;
                    default:
                        throw new ContractException(
                            "Unsupported Site Manager action. Allowed actions: hosts, host, sites, devices.");
                }

                var response = await GetCachedAsync(
                    relativePath,
                    () => _client.GetAsync(relativePath, CancellationToken.None),
                    cancellationToken).ConfigureAwait(false);
                return CreateInventoryResponse(
                    normalizedAction,
                    size,
                    response.Value,
                    response.ObservedAt);
            });

    public Task<ToolResponse> ReadIspMetricsAsync(
        string interval,
        string? duration,
        string? beginTimestamp,
        string? endTimestamp,
        JsonNode? targets,
        CancellationToken cancellationToken) =>
        ExecuteSafelyAsync(
            async () =>
            {
                ValidateMetricParameters(interval, duration, beginTimestamp, endTimestamp);
                var observedAt = _timeProvider.GetUtcNow();
                JsonNode? response;
                if (targets is null)
                {
                    var path = BuildMetricPath(interval, duration, beginTimestamp, endTimestamp);
                    response = await _client.GetAsync(path, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    var body = BuildMetricQueryBody(
                        interval,
                        duration,
                        beginTimestamp,
                        endTimestamp,
                        targets,
                        observedAt);
                    response = await _client.QueryIspMetricsAsync(interval, body, cancellationToken)
                        .ConfigureAwait(false);
                }

                var data = new JsonObject
                {
                    ["status"] = "ok",
                    ["source"] = "site-manager-v1",
                    ["readOnly"] = true,
                    ["observedAt"] = observedAt.ToString("O", CultureInfo.InvariantCulture),
                    ["interval"] = interval,
                    ["data"] = _redactor.Redact(response?["data"]),
                    ["provider"] = CreateProviderMetadata(response)
                };
                var seriesCount = CountMetricSeries(response?["data"]);
                return new ToolResponse(
                    $"UniFi Site Manager returned {seriesCount} ISP metric series.",
                    data);
            });

    public async Task<JsonArray> GetAllDevicesForHostAsync(
        string hostId,
        CancellationToken cancellationToken)
    {
        ValidateOpaqueValue(hostId, "hostId", allowNull: false);
        var result = new JsonArray();
        string? nextToken = null;
        for (var page = 0; page < MaximumPagesForEnrichment; page++)
        {
            var path = BuildPagePath("v1/devices", DefaultPageSize, nextToken, hostId);
            var cached = await GetCachedAsync(
                path,
                () => _client.GetAsync(path, CancellationToken.None),
                cancellationToken).ConfigureAwait(false);
            var response = cached.Value;
            if (response?["data"] is not JsonArray groups)
            {
                throw new ContractException("Site Manager devices response did not contain a data array.");
            }

            foreach (var group in groups.OfType<JsonObject>())
            {
                if (string.Equals(group["hostId"]?.GetValue<string>(), hostId, StringComparison.Ordinal))
                {
                    result.Add(ProjectDeviceGroup(group));
                }
            }

            nextToken = ReadContinuation(response);
            if (nextToken is null)
            {
                return result;
            }
        }

        throw new ContractException(
            $"Site Manager device enrichment exceeded {MaximumPagesForEnrichment} pages.");
    }

    public async Task<JsonObject> GetHostMappingStatusAsync(CancellationToken cancellationToken)
    {
        if (!_configuration.SiteManagerConfigured)
        {
            return new JsonObject
            {
                ["status"] = "siteManagerNotConfigured",
                ["configured"] = false,
                ["verified"] = true
            };
        }

        if (string.IsNullOrWhiteSpace(_configuration.SiteManagerLocalHostId))
        {
            return new JsonObject
            {
                ["status"] = "notConfigured",
                ["configured"] = false,
                ["verified"] = true
            };
        }

        try
        {
            string? nextToken = null;
            for (var page = 0; page < MaximumPagesForHostMapping; page++)
            {
                var path = BuildPagePath("v1/hosts", DefaultPageSize, nextToken, null);
                var cached = await GetCachedAsync(
                    path,
                    () => _client.GetAsync(path, CancellationToken.None),
                    cancellationToken).ConfigureAwait(false);
                var response = cached.Value;
                if (response?["data"] is not JsonArray hosts)
                {
                    throw new ContractException("Site Manager hosts response did not contain a data array.");
                }

                if (hosts
                    .OfType<JsonObject>()
                    .Any(host => string.Equals(
                        host["id"]?.GetValue<string>(),
                        _configuration.SiteManagerLocalHostId,
                        StringComparison.Ordinal)))
                {
                    return new JsonObject
                    {
                        ["status"] = "mapped",
                        ["configured"] = true,
                        ["verified"] = true,
                        ["source"] = "site-manager-v1"
                    };
                }

                nextToken = ReadContinuation(response);
                if (nextToken is null)
                {
                    return new JsonObject
                    {
                        ["status"] = "notFound",
                        ["configured"] = true,
                        ["verified"] = true,
                        ["source"] = "site-manager-v1"
                    };
                }
            }

            throw new ContractException(
                $"Site Manager host-mapping verification exceeded {MaximumPagesForHostMapping} pages.");
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SiteManagerApiException or
            SiteManagerRateLimitQueueException or
            ConfigurationException or
            ContractException or
            HttpRequestException or
            TaskCanceledException or
            InvalidOperationException)
        {
            var failed = new JsonObject
            {
                ["status"] = exception is SiteManagerApiException { IsRateLimited: true }
                    ? "rateLimited"
                    : "failed",
                ["configured"] = true,
                ["verified"] = false,
                ["error"] = _redactor.Redact(exception.Message)
            };
            if (exception is SiteManagerApiException apiException)
            {
                failed["httpStatus"] = (int)apiException.StatusCode;
                failed["errorCode"] = apiException.Code;
                failed["retryAt"] = apiException.RetryAt?.ToString("O", CultureInfo.InvariantCulture);
            }

            return failed;
        }
    }

    public JsonObject Describe()
    {
        var description = _client.Describe();
        description["localHostIdConfigured"] =
            !string.IsNullOrWhiteSpace(_configuration.SiteManagerLocalHostId);
        description["localHostId"] = string.IsNullOrWhiteSpace(_configuration.SiteManagerLocalHostId)
            ? null
            : "<configured>";
        description["hostMapping"] = new JsonObject
        {
            ["status"] = string.IsNullOrWhiteSpace(_configuration.SiteManagerLocalHostId)
                ? "notConfigured"
                : "configuredUnverified",
            ["configured"] = !string.IsNullOrWhiteSpace(_configuration.SiteManagerLocalHostId),
            ["verified"] = false
        };
        description["cacheSeconds"] = CacheDuration.TotalSeconds;
        description["maximumCacheEntries"] = MaximumCacheEntries;
        description["cachedEntries"] = GetCachedEntryCount();
        description["pageSize"] = DefaultPageSize;
        description["maximumPageSize"] = MaximumPageSize;
        description["supportedInventoryActions"] =
            new JsonArray("hosts", "host", "sites", "devices");
        description["ispMetricIntervals"] = new JsonArray("5m", "1h");
        description["excludedSurfaces"] =
            new JsonArray("Early Access endpoints", "SD-WAN", "Cloud Connector proxy");
        return description;
    }

    private async Task<ToolResponse> ExecuteSafelyAsync(Func<Task<ToolResponse>> operation)
    {
        try
        {
            return await operation().ConfigureAwait(false);
        }
        catch (SiteManagerApiException exception) when (exception.IsRateLimited)
        {
            return new ToolResponse(
                "UniFi Site Manager rate-limited the request; no early retry was sent.",
                new JsonObject
                {
                    ["status"] = "rateLimited",
                    ["source"] = "site-manager-v1",
                    ["readOnly"] = true,
                    ["httpStatus"] = (int)exception.StatusCode,
                    ["errorCode"] = exception.Code,
                    ["retryAt"] = exception.RetryAt?.ToString("O", CultureInfo.InvariantCulture),
                    ["error"] = _redactor.Redact(exception.Message)
                });
        }
    }

    private async Task<CachedRead> GetCachedAsync(
        string key,
        Func<Task<JsonNode?>> factory,
        CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var cached = TryReadCached(key, now);
        if (cached is not null)
        {
            return cached;
        }

        var lazy = _inflight.GetOrAdd(
            key,
            _ => new Lazy<Task<CachedRead>>(
                async () =>
                {
                    var observedAt = _timeProvider.GetUtcNow();
                    var value = await factory().ConfigureAwait(false);
                    StoreCached(key, value, observedAt);
                    return new CachedRead(value, observedAt);
                },
                LazyThreadSafetyMode.ExecutionAndPublication));
        var task = lazy.Value;
        _ = task.ContinueWith(
            _ => _inflight.TryRemove(
                new KeyValuePair<string, Lazy<Task<CachedRead>>>(key, lazy)),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        var value = await task.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new CachedRead(value.Value?.DeepClone(), value.ObservedAt);
    }

    private CachedRead? TryReadCached(
        string key,
        DateTimeOffset now)
    {
        JsonNode? cachedValue;
        DateTimeOffset observedAt;
        lock (_cacheGate)
        {
            RemoveExpiredCacheEntries(now);
            if (!_cache.TryGetValue(key, out var cached))
            {
                return null;
            }

            _cache[key] = cached with { LastAccessSequence = NextCacheAccessSequence() };
            cachedValue = cached.Value;
            observedAt = cached.ObservedAt;
        }

        return new CachedRead(cachedValue?.DeepClone(), observedAt);
    }

    private void StoreCached(
        string key,
        JsonNode? value,
        DateTimeOffset observedAt)
    {
        var cachedValue = value?.DeepClone();
        lock (_cacheGate)
        {
            var now = _timeProvider.GetUtcNow();
            RemoveExpiredCacheEntries(now);
            if (!_cache.ContainsKey(key) && _cache.Count >= MaximumCacheEntries)
            {
                var leastRecentlyUsed = _cache
                    .OrderBy(entry => entry.Value.LastAccessSequence)
                    .ThenBy(entry => entry.Key, StringComparer.Ordinal)
                    .First();
                _cache.Remove(leastRecentlyUsed.Key);
            }

            _cache[key] = new CacheEntry(
                cachedValue,
                observedAt,
                now + CacheDuration,
                NextCacheAccessSequence());
        }
    }

    private int GetCachedEntryCount()
    {
        lock (_cacheGate)
        {
            RemoveExpiredCacheEntries(_timeProvider.GetUtcNow());
            return _cache.Count;
        }
    }

    private void RemoveExpiredCacheEntries(DateTimeOffset now)
    {
        foreach (var key in _cache
            .Where(entry => entry.Value.ExpiresAt <= now)
            .Select(entry => entry.Key)
            .ToArray())
        {
            _cache.Remove(key);
        }
    }

    private long NextCacheAccessSequence() => ++_cacheAccessSequence;

    private ToolResponse CreateInventoryResponse(
        string action,
        int pageSize,
        JsonNode? response,
        DateTimeOffset observedAt)
    {
        var continuation = ReadContinuation(response);
        var safeContinuation = continuation is null
            ? null
            : _redactor.Redact(continuation);
        var providerData = ProjectInventoryData(action, response?["data"]);
        var returned = providerData is JsonArray array ? array.Count : providerData is null ? 0 : 1;
        var data = new JsonObject
        {
            ["status"] = "ok",
            ["source"] = "site-manager-v1",
            ["readOnly"] = true,
            ["observedAt"] = observedAt.ToString("O", CultureInfo.InvariantCulture),
            ["action"] = action,
            ["data"] = _redactor.Redact(providerData),
            ["provider"] = CreateProviderMetadata(response)
        };
        if (action is not "host")
        {
            data["pagination"] = new JsonObject
            {
                ["pageSize"] = pageSize,
                ["returned"] = returned,
                ["truncated"] = continuation is not null,
                ["continuation"] = safeContinuation
            };
        }

        return new ToolResponse(
            $"UniFi Site Manager {action}: {returned} item(s) returned.",
            data);
    }

    private JsonObject CreateProviderMetadata(JsonNode? response) => new()
    {
        ["httpStatusCode"] = response?["httpStatusCode"]?.DeepClone(),
        ["traceId"] = response?["traceId"] is JsonValue trace &&
            trace.TryGetValue<string>(out var traceText)
            ? _redactor.Redact(traceText)
            : null
    };

    private JsonNode? ProjectInventoryData(string action, JsonNode? providerData)
    {
        if (action == "host")
        {
            return providerData is JsonObject host ? ProjectHost(host) : null;
        }

        if (providerData is not JsonArray array)
        {
            return null;
        }

        return action switch
        {
            "hosts" => new JsonArray(
                array.OfType<JsonObject>()
                    .Select(host => (JsonNode?)ProjectHost(host))
                    .ToArray()),
            "sites" => new JsonArray(
                array.OfType<JsonObject>()
                    .Select(site => (JsonNode?)ProjectSite(site))
                    .ToArray()),
            "devices" => new JsonArray(
                array.OfType<JsonObject>()
                    .Select(group => (JsonNode?)ProjectDeviceGroup(group))
                    .ToArray()),
            _ => null
        };
    }

    private static JsonObject ProjectHost(JsonObject source)
    {
        var result = new JsonObject();
        CopySelected(
            source,
            result,
            "id",
            "hardwareId",
            "type",
            "ipAddress",
            "owner",
            "isBlocked",
            "registrationTime",
            "lastConnectionStateChange",
            "latestBackupTime");
        if (source["reportedState"] is JsonObject reportedState)
        {
            var projectedState = new JsonObject();
            CopySelected(
                reportedState,
                projectedState,
                "name",
                "state",
                "version",
                "releaseChannel",
                "cloudSystemLogState");
            if (reportedState["hardware"] is JsonObject hardware)
            {
                var projectedHardware = new JsonObject();
                CopySelected(
                    hardware,
                    projectedHardware,
                    "name",
                    "shortname",
                    "firmwareVersion",
                    "mac");
                projectedState["hardware"] = projectedHardware;
            }

            if (reportedState["controllers"] is JsonArray controllers)
            {
                projectedState["controllers"] = new JsonArray(
                    controllers
                        .OfType<JsonObject>()
                        .Select(controller =>
                        {
                            var projected = new JsonObject();
                            CopySelected(
                                controller,
                                projected,
                                "name",
                                "state",
                                "status",
                                "version",
                                "releaseChannel",
                                "updatable",
                                "updateAvailable");
                            return (JsonNode?)projected;
                        })
                        .ToArray());
            }

            result["reportedState"] = projectedState;
        }

        return result;
    }

    private JsonObject ProjectSite(JsonObject source)
    {
        var result = new JsonObject();
        CopySelected(source, result, "siteId", "hostId", "permission", "isOwner");
        if (source["meta"] is JsonObject meta)
        {
            var projectedMeta = new JsonObject();
            CopySelected(meta, projectedMeta, "name", "desc", "timezone", "gatewayMac");
            result["meta"] = projectedMeta;
        }

        if (source["statistics"] is JsonObject statistics)
        {
            result["statistics"] = _redactor.Redact(statistics);
        }

        return result;
    }

    private static JsonObject ProjectDeviceGroup(JsonObject source)
    {
        var result = new JsonObject();
        CopySelected(source, result, "hostId", "hostName", "updatedAt");
        if (source["devices"] is JsonArray devices)
        {
            result["devices"] = new JsonArray(
                devices
                    .OfType<JsonObject>()
                    .Select(device =>
                    {
                        var projected = new JsonObject();
                        CopySelected(
                            device,
                            projected,
                            "id",
                            "mac",
                            "name",
                            "model",
                            "shortname",
                            "ip",
                            "productLine",
                            "status",
                            "version",
                            "firmwareStatus",
                            "updateAvailable",
                            "isConsole",
                            "isManaged",
                            "startupTime",
                            "adoptionTime",
                            "note");
                        return (JsonNode?)projected;
                    })
                    .ToArray());
        }

        return result;
    }

    private static void CopySelected(
        JsonObject source,
        JsonObject destination,
        params string[] propertyNames)
    {
        foreach (var name in propertyNames)
        {
            if (source.TryGetPropertyValue(name, out var value))
            {
                destination[name] = value?.DeepClone();
            }
        }
    }

    private static string? ReadContinuation(JsonNode? response)
    {
        var continuation = response?["nextToken"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(continuation))
        {
            return null;
        }

        ValidateOpaqueValue(continuation, "provider nextToken", allowNull: false);
        return continuation;
    }

    private static int ValidatePageSize(int? pageSize)
    {
        var value = pageSize ?? DefaultPageSize;
        if (value is < 1 or > MaximumPageSize)
        {
            throw new ContractException(
                $"Site Manager pageSize must be between 1 and {MaximumPageSize}.");
        }

        return value;
    }

    private static void RejectHostId(string? hostId, string action)
    {
        if (!string.IsNullOrWhiteSpace(hostId))
        {
            throw new ContractException($"Site Manager action '{action}' does not accept hostId.");
        }
    }

    private static string BuildPagePath(
        string resource,
        int pageSize,
        string? nextToken,
        string? hostId)
    {
        var query = new List<string>
        {
            "pageSize=" + pageSize.ToString(CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrWhiteSpace(nextToken))
        {
            query.Add("nextToken=" + Uri.EscapeDataString(nextToken));
        }

        if (!string.IsNullOrWhiteSpace(hostId))
        {
            query.Add("hostIds%5B%5D=" + Uri.EscapeDataString(hostId));
        }

        return resource + "?" + string.Join("&", query);
    }

    private static string BuildMetricPath(
        string interval,
        string? duration,
        string? beginTimestamp,
        string? endTimestamp)
    {
        var query = new List<string>();
        AddQuery(query, "duration", duration);
        AddQuery(query, "beginTimestamp", beginTimestamp);
        AddQuery(query, "endTimestamp", endTimestamp);
        return $"v1/isp-metrics/{interval}" +
            (query.Count == 0 ? string.Empty : "?" + string.Join("&", query));
    }

    private static JsonObject BuildMetricQueryBody(
        string interval,
        string? duration,
        string? beginTimestamp,
        string? endTimestamp,
        JsonNode targets,
        DateTimeOffset observedAt)
    {
        if (targets is not JsonArray targetArray || targetArray.Count is < 1 or > MaximumTargetCount)
        {
            throw new ContractException(
                $"Site Manager metric targets must be an array containing 1 to {MaximumTargetCount} objects.");
        }

        var (resolvedBegin, resolvedEnd) = ResolveMetricRange(
            interval,
            duration,
            beginTimestamp,
            endTimestamp,
            observedAt);
        var sites = new JsonArray();
        foreach (var target in targetArray)
        {
            if (target is not JsonObject targetObject)
            {
                throw new ContractException("Each Site Manager metric target must be an object.");
            }

            var hostId = RequiredOpaqueProperty(targetObject, "hostId");
            var siteId = RequiredOpaqueProperty(targetObject, "siteId");
            var projected = new JsonObject
            {
                ["hostId"] = hostId,
                ["siteId"] = siteId
            };
            var targetBegin = ReadOptionalTimestamp(targetObject, "beginTimestamp") ?? resolvedBegin;
            var targetEnd = ReadOptionalTimestamp(targetObject, "endTimestamp") ?? resolvedEnd;
            ValidateTimestampOrder(targetBegin, targetEnd);
            if (targetBegin is not null)
            {
                projected["beginTimestamp"] = targetBegin;
            }

            if (targetEnd is not null)
            {
                projected["endTimestamp"] = targetEnd;
            }

            sites.Add(projected);
        }

        return new JsonObject { ["sites"] = sites };
    }

    private static (string? Begin, string? End) ResolveMetricRange(
        string interval,
        string? duration,
        string? beginTimestamp,
        string? endTimestamp,
        DateTimeOffset observedAt)
    {
        if (duration is null)
        {
            return (beginTimestamp, endTimestamp);
        }

        var window = duration switch
        {
            "24h" => TimeSpan.FromHours(24),
            "7d" => TimeSpan.FromDays(7),
            "30d" => TimeSpan.FromDays(30),
            _ => throw new ContractException($"Unsupported {interval} metric duration '{duration}'.")
        };
        return (
            (observedAt - window).ToString("O", CultureInfo.InvariantCulture),
            observedAt.ToString("O", CultureInfo.InvariantCulture));
    }

    private static void ValidateMetricParameters(
        string interval,
        string? duration,
        string? beginTimestamp,
        string? endTimestamp)
    {
        if (interval is not "5m" and not "1h")
        {
            throw new ContractException("Site Manager ISP metric interval must be 5m or 1h.");
        }

        if (duration is not null)
        {
            var allowed = interval == "5m"
                ? string.Equals(duration, "24h", StringComparison.Ordinal)
                : duration is "7d" or "30d";
            if (!allowed)
            {
                throw new ContractException(
                    interval == "5m"
                        ? "5m Site Manager metrics support duration 24h."
                        : "1h Site Manager metrics support duration 7d or 30d.");
            }

            if (beginTimestamp is not null || endTimestamp is not null)
            {
                throw new ContractException(
                    "Site Manager metric duration cannot be combined with beginTimestamp or endTimestamp.");
            }
        }

        ValidateTimestamp(beginTimestamp, "beginTimestamp");
        ValidateTimestamp(endTimestamp, "endTimestamp");
        ValidateTimestampOrder(beginTimestamp, endTimestamp);
    }

    private static void ValidateTimestamp(string? value, string name)
    {
        if (value is not null &&
            !DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out _))
        {
            throw new ContractException($"{name} must be an RFC3339 timestamp.");
        }
    }

    private static void ValidateTimestampOrder(string? begin, string? end)
    {
        if (begin is not null &&
            end is not null &&
            DateTimeOffset.Parse(begin, CultureInfo.InvariantCulture) >
            DateTimeOffset.Parse(end, CultureInfo.InvariantCulture))
        {
            throw new ContractException("beginTimestamp must not be later than endTimestamp.");
        }
    }

    private static string RequiredOpaqueProperty(JsonObject target, string name)
    {
        var value = ReadOptionalString(target, name);
        ValidateOpaqueValue(value, name, allowNull: false);
        return value!;
    }

    private static string? ReadOptionalTimestamp(JsonObject target, string name)
    {
        var value = ReadOptionalString(target, name);
        ValidateTimestamp(value, name);
        return value;
    }

    private static string? ReadOptionalString(JsonObject target, string name)
    {
        if (!target.TryGetPropertyValue(name, out var node) || node is null)
        {
            return null;
        }

        if (node is not JsonValue value || !value.TryGetValue<string>(out var text))
        {
            throw new ContractException($"{name} must be a string.");
        }

        return text;
    }

    private static void ValidateOpaqueValue(string? value, string name, bool allowNull)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            if (allowNull)
            {
                return;
            }

            throw new ContractException($"{name} is required.");
        }

        if (value.Length > MaximumOpaqueIdLength || value.Any(char.IsControl))
        {
            throw new ContractException(
                $"{name} must be at most {MaximumOpaqueIdLength} characters without control characters.");
        }
    }

    private static void AddQuery(List<string> query, string name, string? value)
    {
        if (value is not null)
        {
            query.Add(Uri.EscapeDataString(name) + "=" + Uri.EscapeDataString(value));
        }
    }

    private static int CountMetricSeries(JsonNode? data)
    {
        if (data is JsonArray array)
        {
            return array.Count;
        }

        return (data?["metrics"] as JsonArray)?.Count ?? 0;
    }

    private sealed record CacheEntry(
        JsonNode? Value,
        DateTimeOffset ObservedAt,
        DateTimeOffset ExpiresAt,
        long LastAccessSequence);

    private sealed record CachedRead(
        JsonNode? Value,
        DateTimeOffset ObservedAt);
}
