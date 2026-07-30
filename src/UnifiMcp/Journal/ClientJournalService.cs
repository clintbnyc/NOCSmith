using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using UnifiMcp.Configuration;
using UnifiMcp.Contracts;
using UnifiMcp.Tools;

namespace UnifiMcp.Journal;

public sealed partial class ClientJournalService
{
    private const int DefaultLimit = 100;
    private const int MaximumLimit = 200;
    private const int MaximumOffset = 1_000_000;
    private const int MaximumHistoryDays = 3650;

    private readonly UnifiConfiguration _configuration;
    private readonly ClientObservationCollector _collector;
    private readonly ClientJournalStore _store;

    public ClientJournalService(
        UnifiConfiguration configuration,
        ClientObservationCollector collector,
        ClientJournalStore store)
    {
        _configuration = configuration;
        _collector = collector;
        _store = store;
    }

    public JsonObject Describe() => new()
    {
        ["enabled"] = _configuration.EnableClientJournal,
        ["automaticCollection"] = _configuration.EnableScheduledCollection,
        ["createsAtStartup"] = _configuration.EnableScheduledCollection,
        ["rawControllerResponsesStored"] = false,
        ["databaseEncryption"] = false,
        ["retentionDays"] = _configuration.ClientJournalRetentionDays,
        ["maximumMib"] = _configuration.ClientJournalMaximumMib,
        ["collectionRequiresPrivateReadGate"] = true,
        ["queryRequiresPrivateReadGate"] = false,
        ["sources"] = new JsonArray(
            "officialConnected",
            "uiHistory",
            "configuredGroups")
    };

    public async Task<ToolResponse> CollectAsync(
        string? siteId,
        int? historyHours,
        CancellationToken cancellationToken)
    {
        using var lease = _store.AcquireCollectionLease();
        var collection = await _collector
            .CollectAsync(siteId, historyHours, cancellationToken)
            .ConfigureAwait(false);
        await _store.PersistAsync(collection, cancellationToken).ConfigureAwait(false);

        var data = new JsonObject
        {
            ["collectionId"] = collection.CollectionId,
            ["siteId"] = collection.SiteId,
            ["startedAt"] = collection.StartedAt.ToString("O", CultureInfo.InvariantCulture),
            ["completedAt"] = collection.CompletedAt.ToString("O", CultureInfo.InvariantCulture),
            ["historyHours"] = collection.HistoryHours,
            ["overallStatus"] = ClientJournalValues.Status(collection.OverallStatus),
            ["sources"] = new JsonArray(
                SourceSummary(collection.Connected),
                SourceSummary(collection.History),
                SourceSummary(collection.Groups)),
            ["storedClientRowsReturned"] = false,
            ["automaticCollection"] = false
        };
        return new ToolResponse(
            $"Stored client observation collection {collection.CollectionId} with status {ClientJournalValues.Status(collection.OverallStatus)}.",
            data);
    }

    public Task<ToolResponse> HealthAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var health = _store.Inspect();
        var data = new JsonObject
        {
            ["state"] = health.Oversized && health.State == "healthy"
                ? "oversized"
                : health.State,
            ["enabled"] = _configuration.EnableClientJournal,
            ["schemaVersion"] = health.SchemaVersion,
            ["supportedSchemaVersion"] = health.SupportedSchemaVersion,
            ["walMode"] = health.WalMode,
            ["activeBytes"] = health.ActiveBytes,
            ["maximumBytes"] = checked((long)health.MaximumMib * 1024L * 1024L),
            ["retentionDays"] = health.RetentionDays,
            ["corruptionFingerprint"] = health.CorruptionFingerprint,
            ["reason"] = health.Reason,
            ["lastCollections"] = new JsonArray(
                health.LastCollections.Select(value => (JsonNode?)new JsonObject
                {
                    ["collectionId"] = value.CollectionId,
                    ["siteId"] = value.SiteId,
                    ["completedAt"] = ClientJournalValues.Rfc3339(value.CompletedAtMilliseconds),
                    ["overallStatus"] = value.OverallStatus
                }).ToArray()),
            ["sourceSuccessRates"] = new JsonArray(
                health.SourceSuccessRates.Select(value => (JsonNode?)new JsonObject
                {
                    ["source"] = value.SourceKind,
                    ["collections"] = value.CollectionCount,
                    ["completeCollections"] = value.CompleteCount,
                    ["completeRate"] = value.CollectionCount == 0
                        ? null
                        : Math.Round((double)value.CompleteCount / value.CollectionCount, 6)
                }).ToArray()),
            ["quarantine"] = new JsonObject
            {
                ["setCount"] = health.Quarantine.Count,
                ["bytes"] = health.Quarantine.Bytes,
                ["includedInActiveSizeCap"] = false
            },
            ["containsClientData"] = false,
            ["filesystemMutated"] = false
        };
        return Task.FromResult(new ToolResponse(
            $"Client journal health state: {data["state"]}.",
            data));
    }

    public Task<ToolResponse> ChangesAsync(
        string? requestedSiteId,
        string? sinceTimestamp,
        int? requestedHistoryHours,
        int? requestedOffset,
        int? requestedLimit,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureEnabledForQuery();
        var historyHours = ValidateHistoryHours(requestedHistoryHours);
        var offset = ValidateOffset(requestedOffset);
        var limit = ValidateLimit(requestedLimit);
        var since = ParseTimestamp(sinceTimestamp, "sinceTimestamp");
        var collections = _store.ReadCollections();
        var siteId = ResolveStoredSite(requestedSiteId, collections);
        var siteCollections = collections
            .Where(value => string.Equals(value.SiteId, siteId, StringComparison.Ordinal))
            .ToArray();

        var changes = new List<ClientChange>();
        var comparisons = new JsonArray();
        CompareClientSource(
            ClientObservationSource.OfficialConnected,
            historyHours: null,
            since,
            siteCollections,
            changes,
            comparisons);
        CompareClientSource(
            ClientObservationSource.UiHistory,
            historyHours,
            since,
            siteCollections,
            changes,
            comparisons);
        CompareGroupSource(
            since,
            siteCollections,
            changes,
            comparisons);

        var ordered = changes
            .OrderBy(value => value.Source, StringComparer.Ordinal)
            .ThenBy(value => value.ChangeType, StringComparer.Ordinal)
            .ThenBy(value => value.Key, StringComparer.Ordinal)
            .ThenBy(value => value.Field, StringComparer.Ordinal)
            .ToArray();
        var page = ordered.Skip(offset).Take(limit).ToArray();
        var data = new JsonObject
        {
            ["siteId"] = siteId,
            ["sinceTimestamp"] = since?.ToString("O", CultureInfo.InvariantCulture),
            ["baselineMode"] = since is null
                ? "previousSuccessfulCollection"
                : "latestCompleteAtOrBeforeSinceTimestamp",
            ["historyHours"] = historyHours,
            ["comparisons"] = comparisons,
            ["changes"] = new JsonArray(page.Select(value => value.ToJson()).ToArray()),
            ["pagination"] = Pagination(ordered.Length, page.Length, offset, limit),
            ["absenceSemantics"] =
                "Absence is compared only between complete source-specific snapshots. No result is described as removed.",
            ["offlineDerivation"] =
                "Offline is derived only when officialConnected and uiHistory were both complete in the same collection.",
            ["deterministicOrdering"] = "source, changeType, key, field"
        };
        return Task.FromResult(new ToolResponse(
            $"Found {ordered.Length} source-safe client journal change(s); returned {page.Length}.",
            data));
    }

    public Task<ToolResponse> HistoryAsync(
        string macAddress,
        string? requestedSiteId,
        string? fromTimestamp,
        string? toTimestamp,
        int? requestedOffset,
        int? requestedLimit,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureEnabledForQuery();
        var mac = NormalizeMac(macAddress);
        var from = ParseTimestamp(fromTimestamp, "fromTimestamp");
        var to = ParseTimestamp(toTimestamp, "toTimestamp");
        if (from is not null && to is not null && from > to)
        {
            throw new ContractException("fromTimestamp must not be later than toTimestamp.");
        }

        if (from is not null && to is not null &&
            to.Value - from.Value > TimeSpan.FromDays(MaximumHistoryDays))
        {
            throw new ContractException(
                $"The requested history interval must not exceed {MaximumHistoryDays} days.");
        }

        var offset = ValidateOffset(requestedOffset);
        var limit = ValidateLimit(requestedLimit);
        var siteId = ResolveStoredSite(requestedSiteId, _store.ReadSiteIds());
        var storedPage = _store.ReadClientHistoryPage(
            mac,
            siteId,
            from?.ToUnixTimeMilliseconds(),
            to?.ToUnixTimeMilliseconds(),
            offset,
            limit);
        var page = storedPage.Rows
            .Select(value => ToHistoryOutput(value, mac))
            .ToArray();
        var data = new JsonObject
        {
            ["siteId"] = siteId,
            ["macAddress"] = mac,
            ["fromTimestamp"] = from?.ToString("O", CultureInfo.InvariantCulture),
            ["toTimestamp"] = to?.ToString("O", CultureInfo.InvariantCulture),
            ["observations"] = new JsonArray(page.Select(value => (JsonNode?)value.Value).ToArray()),
            ["pagination"] = Pagination(storedPage.Total, page.Length, offset, limit),
            ["semantics"] =
                "Partial records are positive evidence only. Missing collections or missing rows never imply offline, disconnection, membership removal, or device removal."
        };
        return Task.FromResult(new ToolResponse(
            $"Found {storedPage.Total} source-grained observation(s) for {mac}; returned {page.Length}.",
            data));
    }

    public async Task<ToolResponse> RecoverAsync(
        string corruptionFingerprint,
        CancellationToken cancellationToken)
    {
        using var lease = _store.AcquireCollectionLease();
        await _store.RecoverAsync(corruptionFingerprint, cancellationToken)
            .ConfigureAwait(false);
        var health = _store.Inspect();
        return new ToolResponse(
            "The corrupt client journal set was quarantined and a fresh migrated journal was initialized.",
            new JsonObject
            {
                ["state"] = health.State,
                ["schemaVersion"] = health.SchemaVersion,
                ["quarantined"] = true,
                ["automaticRecovery"] = false,
                ["clientRowsReturned"] = false
            });
    }

    private void CompareClientSource(
        ClientObservationSource source,
        int? historyHours,
        DateTimeOffset? since,
        IReadOnlyList<StoredCollection> collections,
        ICollection<ClientChange> output,
        JsonArray comparisons)
    {
        var sourceName = ClientJournalValues.Source(source);
        var candidates = collections
            .Where(value => historyHours is null || value.HistoryHours == historyHours)
            .Where(value => value.Sources.Any(item =>
                string.Equals(item.SourceKind, sourceName, StringComparison.Ordinal) &&
                string.Equals(item.Status, "complete", StringComparison.Ordinal)))
            .OrderBy(value => value.CompletedAtMilliseconds)
            .ThenBy(value => value.CollectionId, StringComparer.Ordinal)
            .ToArray();
        var pair = SelectPair(candidates, since);
        comparisons.Add(Comparison(sourceName, pair.Baseline, pair.Target, historyHours));
        if (pair.Baseline is null || pair.Target is null)
        {
            return;
        }

        var before = _store.ReadSnapshot(pair.Baseline.CollectionId, sourceName).Clients
            .ToDictionary(value => value.MacAddress, StringComparer.OrdinalIgnoreCase);
        var after = _store.ReadSnapshot(pair.Target.CollectionId, sourceName).Clients
            .ToDictionary(value => value.MacAddress, StringComparer.OrdinalIgnoreCase);
        var entered = source == ClientObservationSource.OfficialConnected
            ? "connectedObserved"
            : "enteredHistoryWindow";
        var left = source == ClientObservationSource.OfficialConnected
            ? "noLongerConnected"
            : "leftHistoryWindow";
        foreach (var mac in after.Keys.Except(before.Keys, StringComparer.OrdinalIgnoreCase))
        {
            var derivedState = source == ClientObservationSource.UiHistory &&
                pair.Target is not null &&
                IsOfflineAtCompleteJointSnapshot(pair.Target, mac)
                    ? "offline"
                    : null;
            output.Add(new ClientChange(
                sourceName,
                entered,
                mac,
                derivedState is null ? null : "state",
                null,
                derivedState));
        }

        foreach (var mac in before.Keys.Except(after.Keys, StringComparer.OrdinalIgnoreCase))
        {
            output.Add(new ClientChange(sourceName, left, mac, null, null, null));
        }

        foreach (var mac in before.Keys.Intersect(after.Keys, StringComparer.OrdinalIgnoreCase))
        {
            AddFieldChange(output, sourceName, mac, "name", before[mac].Name, after[mac].Name);
            AddFieldChange(output, sourceName, mac, "ipAddress", before[mac].IpAddress, after[mac].IpAddress);
            AddFieldChange(
                output,
                sourceName,
                mac,
                "connectedAt",
                Rfc3339OrNull(before[mac].ConnectedAtMilliseconds),
                Rfc3339OrNull(after[mac].ConnectedAtMilliseconds));
            AddFieldChange(
                output,
                sourceName,
                mac,
                "lastSeenAt",
                Rfc3339OrNull(before[mac].LastSeenAtMilliseconds),
                Rfc3339OrNull(after[mac].LastSeenAtMilliseconds));
        }
    }

    private void CompareGroupSource(
        DateTimeOffset? since,
        IReadOnlyList<StoredCollection> collections,
        ICollection<ClientChange> output,
        JsonArray comparisons)
    {
        var source = ClientJournalValues.Source(ClientObservationSource.ConfiguredGroups);
        var candidates = collections
            .Where(value => value.Sources.Any(item =>
                item.SourceKind == source && item.Status == "complete"))
            .OrderBy(value => value.CompletedAtMilliseconds)
            .ThenBy(value => value.CollectionId, StringComparer.Ordinal)
            .ToArray();
        var pair = SelectPair(candidates, since);
        comparisons.Add(Comparison(source, pair.Baseline, pair.Target, null));
        if (pair.Baseline is null || pair.Target is null)
        {
            return;
        }

        var before = _store.ReadSnapshot(pair.Baseline.CollectionId, source).Groups
            .ToDictionary(value => value.GroupId, StringComparer.Ordinal);
        var after = _store.ReadSnapshot(pair.Target.CollectionId, source).Groups
            .ToDictionary(value => value.GroupId, StringComparer.Ordinal);
        foreach (var groupId in before.Keys.Intersect(after.Keys, StringComparer.Ordinal))
        {
            if (!string.Equals(before[groupId].Name, after[groupId].Name, StringComparison.Ordinal))
            {
                output.Add(new ClientChange(
                    source,
                    "groupRenamed",
                    groupId,
                    "name",
                    before[groupId].Name,
                    after[groupId].Name));
            }

            foreach (var mac in after[groupId].Members.Except(
                         before[groupId].Members,
                         StringComparer.OrdinalIgnoreCase))
            {
                output.Add(new ClientChange(
                    source,
                    "membershipAdded",
                    groupId + "/" + mac,
                    "membership",
                    null,
                    mac));
            }

            foreach (var mac in before[groupId].Members.Except(
                         after[groupId].Members,
                         StringComparer.OrdinalIgnoreCase))
            {
                output.Add(new ClientChange(
                    source,
                    "membershipNoLongerConfigured",
                    groupId + "/" + mac,
                    "membership",
                    mac,
                    null));
            }
        }

        foreach (var groupId in after.Keys.Except(before.Keys, StringComparer.Ordinal))
        {
            foreach (var mac in after[groupId].Members)
            {
                output.Add(new ClientChange(
                    source,
                    "membershipAdded",
                    groupId + "/" + mac,
                    "membership",
                    null,
                    mac));
            }
        }

        foreach (var groupId in before.Keys.Except(after.Keys, StringComparer.Ordinal))
        {
            foreach (var mac in before[groupId].Members)
            {
                output.Add(new ClientChange(
                    source,
                    "membershipNoLongerConfigured",
                    groupId + "/" + mac,
                    "membership",
                    mac,
                    null));
            }
        }
    }

    private bool IsOfflineAtCompleteJointSnapshot(
        StoredCollection collection,
        string macAddress)
    {
        var connectedSource = ClientJournalValues.Source(ClientObservationSource.OfficialConnected);
        var historySource = ClientJournalValues.Source(ClientObservationSource.UiHistory);
        if (!collection.Sources.Any(source =>
                source.SourceKind == connectedSource && source.Status == "complete") ||
            !collection.Sources.Any(source =>
                source.SourceKind == historySource && source.Status == "complete"))
        {
            return false;
        }

        var connected = _store.ReadSnapshot(collection.CollectionId, connectedSource).Clients
            .Select(value => value.MacAddress)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return !connected.Contains(macAddress);
    }

    private static HistoryOutput ToHistoryOutput(
        StoredClientHistoryEntry value,
        string mac)
    {
        var source = ClientJournalValues.Source(ClientObservationSource.ConfiguredGroups);
        if (string.Equals(value.SourceKind, source, StringComparison.Ordinal))
        {
            return new HistoryOutput(
                value.CompletedAtMilliseconds,
                value.CollectionId,
                source,
                new JsonObject
                {
                    ["collectionId"] = value.CollectionId,
                    ["observedAt"] = ClientJournalValues.Rfc3339(value.CompletedAtMilliseconds),
                    ["source"] = source,
                    ["sourceStatus"] = value.SourceStatus,
                    ["macAddress"] = mac,
                    ["groups"] = new JsonArray(value.Groups.Select(group => (JsonNode?)new JsonObject
                    {
                        ["id"] = group.GroupId,
                        ["name"] = group.Name
                    }).ToArray()),
                    ["fieldProvenance"] = new JsonObject
                    {
                        ["macAddress"] = new JsonObject
                        {
                            ["sourceField"] = "members",
                            ["authority"] = "configured-membership",
                            ["available"] = true
                        },
                        ["groups"] = new JsonObject
                        {
                            ["sourceField"] = "id, name, members",
                            ["authority"] = "configured-membership",
                            ["available"] = true
                        }
                    },
                    ["gapInferenceAllowed"] = false
                });
        }

        return new HistoryOutput(
            value.CompletedAtMilliseconds,
            value.CollectionId,
            value.SourceKind,
            new JsonObject
            {
                ["collectionId"] = value.CollectionId,
                ["observedAt"] = ClientJournalValues.Rfc3339(value.CompletedAtMilliseconds),
                ["source"] = value.SourceKind,
                ["sourceStatus"] = value.SourceStatus,
                ["historyHours"] = value.HistoryHours,
                ["name"] = value.Name,
                ["macAddress"] = mac,
                ["ipAddress"] = value.IpAddress,
                ["stateEvidence"] = value.State,
                ["connectedAt"] = Rfc3339OrNull(value.ConnectedAtMilliseconds),
                ["lastSeenAt"] = Rfc3339OrNull(value.LastSeenAtMilliseconds),
                ["fieldProvenance"] = Provenance(value.Provenance),
                ["gapInferenceAllowed"] = false
            });
    }

    private string ResolveStoredSite(
        string? requestedSiteId,
        IReadOnlyList<StoredCollection> collections)
    {
        var candidate = string.IsNullOrWhiteSpace(requestedSiteId)
            ? _configuration.DefaultSiteId
            : requestedSiteId.Trim();
        if (candidate is not null)
        {
            if (!Guid.TryParse(candidate, out _))
            {
                throw new ContractException("siteId must be a UUID when provided.");
            }

            return candidate;
        }

        var sites = collections
            .Select(value => value.SiteId)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        return sites.Length switch
        {
            0 => throw new ClientJournalUnavailableException(
                "The client journal has no collections."),
            1 => sites[0],
            _ => throw new ContractException(
                "siteId is required because the journal contains more than one site.")
        };
    }

    private string ResolveStoredSite(
        string? requestedSiteId,
        IReadOnlyList<string> sites)
    {
        var candidate = string.IsNullOrWhiteSpace(requestedSiteId)
            ? _configuration.DefaultSiteId
            : requestedSiteId.Trim();
        if (candidate is not null)
        {
            if (!Guid.TryParse(candidate, out _))
            {
                throw new ContractException("siteId must be a UUID when provided.");
            }

            return candidate;
        }

        return sites.Count switch
        {
            0 => throw new ClientJournalUnavailableException(
                "The client journal has no collections."),
            1 => sites[0],
            _ => throw new ContractException(
                "siteId is required because the journal contains more than one site.")
        };
    }

    private static CollectionPair SelectPair(
        IReadOnlyList<StoredCollection> candidates,
        DateTimeOffset? since)
    {
        if (since is null)
        {
            return candidates.Count >= 2
                ? new CollectionPair(candidates[^2], candidates[^1])
                : new CollectionPair(null, candidates.LastOrDefault());
        }

        var baseline = candidates
            .LastOrDefault(value =>
                value.CompletedAtMilliseconds <= since.Value.ToUnixTimeMilliseconds());
        var target = candidates.LastOrDefault();
        if (baseline is not null &&
            target is not null &&
            string.Equals(baseline.CollectionId, target.CollectionId, StringComparison.Ordinal))
        {
            target = null;
        }

        return new CollectionPair(baseline, target);
    }

    private static JsonObject Comparison(
        string source,
        StoredCollection? baseline,
        StoredCollection? target,
        int? historyHours) =>
        new()
        {
            ["source"] = source,
            ["historyHours"] = historyHours,
            ["baselineCollectionId"] = baseline?.CollectionId,
            ["baselineObservedAt"] = baseline is null
                ? null
                : ClientJournalValues.Rfc3339(baseline.CompletedAtMilliseconds),
            ["targetCollectionId"] = target?.CollectionId,
            ["targetObservedAt"] = target is null
                ? null
                : ClientJournalValues.Rfc3339(target.CompletedAtMilliseconds),
            ["comparisonAvailable"] = baseline is not null && target is not null,
            ["absenceCompared"] = baseline is not null && target is not null
        };

    private static void AddFieldChange(
        ICollection<ClientChange> output,
        string source,
        string mac,
        string field,
        string? before,
        string? after)
    {
        if (!string.Equals(before, after, StringComparison.Ordinal))
        {
            output.Add(new ClientChange(
                source,
                "fieldChanged",
                mac,
                field,
                before,
                after));
        }
    }

    private static JsonObject SourceSummary<T>(SourceCollection<T> source)
    {
        var result = new JsonObject
        {
            ["source"] = ClientJournalValues.Source(source.Source),
            ["status"] = ClientJournalValues.Status(source.Status),
            ["recordCount"] = source.Records.Count,
            ["duplicateRecordsSuppressed"] = source.DuplicateRecordsSuppressed,
            ["errorCode"] = source.ErrorCode,
            ["errorMessage"] = source.ErrorMessage,
            ["httpStatus"] = source.HttpStatus,
            ["controllerReasonCode"] = source.ControllerReasonCode,
            ["absenceInferenceAllowed"] = source.Status == CollectionSourceStatus.Complete
        };
        if (source.Records is IReadOnlyList<NormalizedClientGroup> groups)
        {
            result["membershipCount"] = groups.Sum(group => group.Members.Count);
        }

        return result;
    }

    private static JsonObject Provenance(IReadOnlyList<FieldEvidence> values)
    {
        var result = new JsonObject();
        foreach (var value in values)
        {
            result[value.FieldName] = new JsonObject
            {
                ["sourceField"] = value.SourceField,
                ["authority"] = value.Authority,
                ["available"] = value.Available
            };
        }

        return result;
    }

    private void EnsureEnabledForQuery()
    {
        if (!_configuration.EnableClientJournal)
        {
            throw new ConfigurationException(
                "The client observation journal is disabled. Set UNIFI_ENABLE_CLIENT_JOURNAL=true.");
        }
    }

    private static int ValidateHistoryHours(int? value)
    {
        var result = value ?? 24;
        if (!ClientObservationCollector.SupportedHistoryHours.Contains(result))
        {
            throw new ContractException(
                "historyHours must be one of 24, 72, 168, 336, 720, or 4320.");
        }

        return result;
    }

    private static int ValidateOffset(int? value)
    {
        var result = value ?? 0;
        if (result is < 0 or > MaximumOffset)
        {
            throw new ContractException(
                $"offset must be between 0 and {MaximumOffset}.");
        }

        return result;
    }

    private static int ValidateLimit(int? value)
    {
        var result = value ?? DefaultLimit;
        if (result is < 1 or > MaximumLimit)
        {
            throw new ContractException(
                $"limit must be between 1 and {MaximumLimit}.");
        }

        return result;
    }

    private static DateTimeOffset? ParseTimestamp(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim();
        if (!Rfc3339OffsetPattern().IsMatch(text) ||
            !DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestamp))
        {
            throw new ContractException($"{field} must be an RFC3339 timestamp.");
        }

        return timestamp;
    }

    private static string NormalizeMac(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !MacAddressPattern().IsMatch(value.Trim()))
        {
            throw new ContractException(
                "macAddress must contain six colon-separated hexadecimal octets.");
        }

        return value.Trim().ToLowerInvariant();
    }

    private static string? Rfc3339OrNull(long? value) =>
        value is null ? null : ClientJournalValues.Rfc3339(value.Value);

    private static JsonObject Pagination(
        int total,
        int returned,
        int offset,
        int limit) =>
        new()
        {
            ["total"] = total,
            ["returned"] = returned,
            ["offset"] = offset,
            ["limit"] = limit,
            ["truncated"] = offset > 0 || offset + returned < total,
            ["nextOffset"] = offset + returned < total ? offset + returned : null
        };

    private sealed record CollectionPair(
        StoredCollection? Baseline,
        StoredCollection? Target);

    private sealed record ClientChange(
        string Source,
        string ChangeType,
        string Key,
        string? Field,
        string? Before,
        string? After)
    {
        public JsonNode ToJson() => new JsonObject
        {
            ["source"] = Source,
            ["changeType"] = ChangeType,
            ["key"] = Key,
            ["field"] = Field,
            ["before"] = Before,
            ["after"] = After
        };
    }

    private sealed record HistoryOutput(
        long CompletedAtMilliseconds,
        string CollectionId,
        string Source,
        JsonObject Value);

    [GeneratedRegex("^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex MacAddressPattern();

    [GeneratedRegex("(?:[zZ]|[+-][0-9]{2}:[0-9]{2})$", RegexOptions.CultureInvariant)]
    private static partial Regex Rfc3339OffsetPattern();
}
