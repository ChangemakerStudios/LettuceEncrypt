// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

internal class InMemoryHttpChallengeResponseStore : IHttpChallengeResponseStore, IDisposable
{
    private readonly ConcurrentDictionary<string, ChallengeEntry> _values = new();
    private readonly ILogger<InMemoryHttpChallengeResponseStore> _logger;
    private readonly Timer _cleanupTimer;
    private readonly TimeSpan _challengeTtl = TimeSpan.FromHours(1);
    private bool _disposed;

    private class ChallengeEntry
    {
        public string Response { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; }
    }

    public InMemoryHttpChallengeResponseStore(ILogger<InMemoryHttpChallengeResponseStore> logger)
    {
        _logger = logger;
        // Run cleanup every 15 minutes
        _cleanupTimer = new Timer(CleanupExpiredChallenges, null, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15));
    }

    public void AddChallengeResponse(string token, string response)
    {
        var entry = new ChallengeEntry
        {
            Response = response,
            CreatedAt = DateTimeOffset.UtcNow
        };

        _values.AddOrUpdate(token, entry, (_, _) => entry);
        _logger.LogDebug("Added HTTP challenge response for token {Token} (first 10 chars: {TokenPrefix}...)",
            token, token.Length > 10 ? token.Substring(0, 10) : token);
    }

    public bool TryGetResponse(string token, out string? value)
    {
        if (_values.TryGetValue(token, out var entry))
        {
            value = entry.Response;
            _logger.LogTrace("Retrieved HTTP challenge response for token {Token}", token);
            return true;
        }

        value = null;
        _logger.LogTrace("No HTTP challenge response found for token {Token}", token);
        return false;
    }

    public void RemoveChallenge(string token)
    {
        if (_values.TryRemove(token, out _))
        {
            _logger.LogDebug("Removed HTTP challenge response for token {Token}", token);
        }
    }

    private void CleanupExpiredChallenges(object? state)
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            var now = DateTimeOffset.UtcNow;
            var expiredTokens = _values
                .Where(kvp => now - kvp.Value.CreatedAt > _challengeTtl)
                .Select(kvp => kvp.Key)
                .ToList();

            if (expiredTokens.Any())
            {
                _logger.LogInformation("Cleaning up {Count} expired HTTP challenge(s) older than {TTL}",
                    expiredTokens.Count, _challengeTtl);

                foreach (var token in expiredTokens)
                {
                    _values.TryRemove(token, out _);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during HTTP challenge cleanup");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cleanupTimer?.Dispose();
    }
}
