using System.Globalization;

namespace UnifiMcp.Journal;

public enum ClientObservationSource
{
    OfficialConnected,
    UiHistory,
    ConfiguredGroups
}

public enum CollectionSourceStatus
{
    Complete,
    Partial,
    Failed
}

public sealed record FieldEvidence(
    string FieldName,
    string SourceField,
    string Authority,
    bool Available);

public sealed record NormalizedClientObservation(
    string MacAddress,
    string? Name,
    string? IpAddress,
    string? State,
    long? ConnectedAtEpochMilliseconds,
    long? LastSeenEpochMilliseconds,
    IReadOnlyList<FieldEvidence> Provenance);

public sealed record NormalizedClientGroup(
    string GroupId,
    string Name,
    IReadOnlyList<string> Members);

public sealed record SourceCollection<T>(
    ClientObservationSource Source,
    CollectionSourceStatus Status,
    IReadOnlyList<T> Records,
    string? ErrorCode,
    string? ErrorMessage,
    int? HttpStatus = null,
    string? ControllerReasonCode = null,
    int DuplicateRecordsSuppressed = 0)
{
    public bool HasUsableEvidence => Records.Count > 0 || Status == CollectionSourceStatus.Complete;
}

public sealed record ClientObservationCollection(
    string CollectionId,
    string SiteId,
    int HistoryHours,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    SourceCollection<NormalizedClientObservation> Connected,
    SourceCollection<NormalizedClientObservation> History,
    SourceCollection<NormalizedClientGroup> Groups)
{
    public CollectionSourceStatus OverallStatus
    {
        get
        {
            if (Connected.Status == CollectionSourceStatus.Complete &&
                History.Status == CollectionSourceStatus.Complete &&
                Groups.Status == CollectionSourceStatus.Complete)
            {
                return CollectionSourceStatus.Complete;
            }

            return Connected.HasUsableEvidence ||
                History.HasUsableEvidence ||
                Groups.HasUsableEvidence
                    ? CollectionSourceStatus.Partial
                    : CollectionSourceStatus.Failed;
        }
    }
}

internal static class ClientJournalValues
{
    public static string Source(ClientObservationSource source) => source switch
    {
        ClientObservationSource.OfficialConnected => "officialConnected",
        ClientObservationSource.UiHistory => "uiHistory",
        ClientObservationSource.ConfiguredGroups => "configuredGroups",
        _ => throw new ArgumentOutOfRangeException(nameof(source))
    };

    public static string Status(CollectionSourceStatus status) =>
        status.ToString().ToLowerInvariant();

    public static long EpochMilliseconds(DateTimeOffset value) =>
        value.ToUniversalTime().ToUnixTimeMilliseconds();

    public static string Rfc3339(long epochMilliseconds) =>
        DateTimeOffset.FromUnixTimeMilliseconds(epochMilliseconds)
            .ToString("O", CultureInfo.InvariantCulture);
}
