using System.Collections.Concurrent;
using System.Security.Cryptography;
using UnifiMcp.Contracts;

namespace UnifiMcp.Writes;

public sealed class ConfirmationStore
{
    private readonly ConcurrentDictionary<string, PendingChange> _changes = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _timeToLive;

    public ConfirmationStore(TimeProvider? timeProvider = null, TimeSpan? timeToLive = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _timeToLive = timeToLive ?? TimeSpan.FromMinutes(5);
    }

    public PendingChange Add(
        ValidatedRequest mutation,
        ValidatedRequest? stateRead,
        string? beforeHash,
        System.Text.Json.Nodes.JsonNode? before,
        IReadOnlyList<string> warnings,
        ValidatedRequest? safetyRead = null,
        string? safetyHash = null)
    {
        RemoveExpired();
        if (_changes.Count >= 100)
        {
            throw new InvalidOperationException("Too many pending UniFi changes. Wait for old confirmations to expire.");
        }

        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        var change = new PendingChange(
            token,
            _timeProvider.GetUtcNow().Add(_timeToLive),
            mutation,
            stateRead,
            beforeHash,
            before?.DeepClone(),
            warnings,
            safetyRead,
            safetyHash);
        if (!_changes.TryAdd(token, change))
        {
            throw new InvalidOperationException("Could not allocate a unique confirmation token.");
        }

        return change;
    }

    public PendingChange Consume(string token)
    {
        if (string.IsNullOrWhiteSpace(token) || !_changes.TryRemove(token, out var change))
        {
            throw new ConfirmationException("Confirmation token is invalid or has already been used.");
        }

        if (change.ExpiresAt <= _timeProvider.GetUtcNow())
        {
            throw new ConfirmationException("Confirmation token has expired. Preview the change again.");
        }

        return change;
    }

    private void RemoveExpired()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var item in _changes.Where(item => item.Value.ExpiresAt <= now))
        {
            _changes.TryRemove(item.Key, out _);
        }
    }
}

public sealed class ConfirmationException : Exception
{
    public ConfirmationException(string message)
        : base(message)
    {
    }
}
