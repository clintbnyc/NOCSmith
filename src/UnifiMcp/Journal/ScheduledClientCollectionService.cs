using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UnifiMcp.Configuration;
using UnifiMcp.Security;

namespace UnifiMcp.Journal;

public sealed class ScheduledClientCollectionService : BackgroundService
{
    private readonly UnifiConfiguration _configuration;
    private readonly ClientJournalService _journal;
    private readonly ClientJournalStore _store;
    private readonly SecretRedactor _redactor;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<ScheduledClientCollectionService> _logger;

    public ScheduledClientCollectionService(
        UnifiConfiguration configuration,
        ClientJournalService journal,
        ClientJournalStore store,
        SecretRedactor redactor,
        TimeProvider timeProvider,
        ILogger<ScheduledClientCollectionService> logger)
    {
        _configuration = configuration;
        _journal = journal;
        _store = store;
        _redactor = redactor;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_configuration.EnableScheduledCollection)
        {
            return;
        }

        await Task.Yield();
        _logger.LogInformation(
            "Scheduled client collection enabled every {IntervalMinutes} minute(s).",
            _configuration.ScheduledCollectionIntervalMinutes);

        var initialDelay = GetInitialDelayOrRetry();
        if (initialDelay > TimeSpan.Zero)
        {
            await Task.Delay(initialDelay, _timeProvider, stoppingToken).ConfigureAwait(false);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var response = await _journal.CollectAsync(
                        _configuration.ScheduledCollectionSiteId,
                        _configuration.ScheduledCollectionHistoryHours,
                        stoppingToken)
                    .ConfigureAwait(false);
                var status = response.Data?["overallStatus"]?.GetValue<string>() ?? "unknown";
                var collectionId = response.Data?["collectionId"]?.GetValue<string>() ?? "unknown";
                _logger.LogInformation(
                    "Scheduled client collection {CollectionId} completed with status {Status}.",
                    collectionId,
                    status);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (ClientCollectionInProgressException)
            {
                _logger.LogWarning(
                    "Scheduled client collection skipped because another collection is in progress.");
            }
            catch (Exception exception)
            {
                _logger.LogError(
                    "Scheduled client collection failed closed: {Message}",
                    _redactor.Redact(exception.Message));
            }

            await Task.Delay(
                    _configuration.ScheduledCollectionInterval,
                    _timeProvider,
                    stoppingToken)
                .ConfigureAwait(false);
        }
    }

    internal TimeSpan GetInitialDelayOrRetry()
    {
        try
        {
            return GetInitialDelay();
        }
        catch (Exception exception)
        {
            _logger.LogError(
                "Scheduled client collection startup inspection failed closed: {Message}",
                _redactor.Redact(exception.Message));
            return _configuration.ScheduledCollectionInterval;
        }
    }

    private TimeSpan GetInitialDelay()
    {
        var inspection = _store.Inspect();
        if (inspection.State is "disabled" or "notInitialized" or "migrationRequired")
        {
            return TimeSpan.Zero;
        }

        if (inspection.State is not ("healthy" or "oversized"))
        {
            _logger.LogError(
                "Scheduled client collection is deferred because journal health is {State}.",
                inspection.State);
            return _configuration.ScheduledCollectionInterval;
        }

        var scheduledSiteId = string.IsNullOrWhiteSpace(_configuration.ScheduledCollectionSiteId)
            ? _configuration.DefaultSiteId
            : _configuration.ScheduledCollectionSiteId;
        var lastCompletedAt = _store.GetLatestCollectionCompletionMilliseconds(
            scheduledSiteId,
            _configuration.ScheduledCollectionHistoryHours);
        if (lastCompletedAt <= 0)
        {
            return TimeSpan.Zero;
        }

        return ScheduledCollectionPlanner.DelayUntilDue(
            DateTimeOffset.FromUnixTimeMilliseconds(lastCompletedAt),
            _timeProvider.GetUtcNow(),
            _configuration.ScheduledCollectionInterval);
    }
}

internal static class ScheduledCollectionPlanner
{
    public static TimeSpan DelayUntilDue(
        DateTimeOffset lastCompletedAt,
        DateTimeOffset now,
        TimeSpan interval)
    {
        if (interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(interval));
        }

        var dueAt = lastCompletedAt + interval;
        return dueAt <= now ? TimeSpan.Zero : dueAt - now;
    }
}
