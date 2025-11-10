// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

/// <summary>
/// Tracks certificate renewal failures and implements exponential backoff strategy.
/// </summary>
internal class RenewalFailureTracker
{
    private readonly ConcurrentDictionary<string, FailureInfo> _failures = new();
    private readonly ILogger<RenewalFailureTracker> _logger;

    private class FailureInfo
    {
        public int ConsecutiveFailures { get; set; }
        public DateTimeOffset LastFailureTime { get; set; }
        public DateTimeOffset? NextRetryTime { get; set; }
        public Exception? LastException { get; set; }
    }

    public RenewalFailureTracker(ILogger<RenewalFailureTracker> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Records a renewal failure for the specified domain.
    /// </summary>
    public void RecordFailure(string domainName, Exception exception)
    {
        var now = DateTimeOffset.UtcNow;

        var failure = _failures.AddOrUpdate(
            domainName,
            _ => new FailureInfo
            {
                ConsecutiveFailures = 1,
                LastFailureTime = now,
                NextRetryTime = now + CalculateBackoff(1),
                LastException = exception
            },
            (_, existing) =>
            {
                existing.ConsecutiveFailures++;
                existing.LastFailureTime = now;
                existing.NextRetryTime = now + CalculateBackoff(existing.ConsecutiveFailures);
                existing.LastException = exception;
                return existing;
            });

        var backoffPeriod = failure.NextRetryTime!.Value - now;
        _logger.LogWarning(
            exception,
            "Certificate renewal failed for domain '{DomainName}'. " +
            "Consecutive failures: {FailureCount}. " +
            "Next retry in {BackoffPeriod:F1}s at {NextRetryTime}. " +
            "Error: {ErrorMessage}",
            domainName,
            failure.ConsecutiveFailures,
            backoffPeriod.TotalSeconds,
            failure.NextRetryTime.Value,
            exception.Message);
    }

    /// <summary>
    /// Records a successful renewal, resetting the failure count for the domain.
    /// </summary>
    public void RecordSuccess(string domainName)
    {
        if (_failures.TryRemove(domainName, out var failure))
        {
            _logger.LogInformation(
                "Certificate renewal succeeded for domain '{DomainName}' after {FailureCount} previous failure(s). Backoff reset.",
                domainName,
                failure.ConsecutiveFailures);
        }
    }

    /// <summary>
    /// Determines if renewal should be attempted for the domain based on backoff strategy.
    /// </summary>
    public bool ShouldAttemptRenewal(string domainName, DateTimeOffset certificateExpiration)
    {
        if (!_failures.TryGetValue(domainName, out var failure))
        {
            // No failures recorded, proceed with renewal
            return true;
        }

        var now = DateTimeOffset.UtcNow;

        // If certificate expires in less than 7 days, override backoff and retry aggressively
        var daysUntilExpiry = (certificateExpiration - now).TotalDays;
        if (daysUntilExpiry < 7)
        {
            _logger.LogWarning(
                "Certificate for '{DomainName}' expires in {Days:F1} days. Overriding backoff policy to attempt renewal.",
                domainName,
                daysUntilExpiry);
            return true;
        }

        // Check if enough time has passed based on backoff
        if (failure.NextRetryTime.HasValue && now < failure.NextRetryTime.Value)
        {
            var timeUntilRetry = failure.NextRetryTime.Value - now;
            _logger.LogDebug(
                "Skipping renewal attempt for '{DomainName}' due to backoff policy. " +
                "Next retry in {TimeUntilRetry:F1}s. Consecutive failures: {FailureCount}",
                domainName,
                timeUntilRetry.TotalSeconds,
                failure.ConsecutiveFailures);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Calculates exponential backoff period based on failure count.
    /// Backoff: 1h, 2h, 4h, 8h, then caps at 24h
    /// </summary>
    private TimeSpan CalculateBackoff(int consecutiveFailures)
    {
        // Exponential backoff: 1 hour * 2^(failures - 1), capped at 24 hours
        var hours = Math.Min(Math.Pow(2, consecutiveFailures - 1), 24);
        return TimeSpan.FromHours(hours);
    }

    /// <summary>
    /// Gets failure information for diagnostics.
    /// </summary>
    public string GetFailureInfo(string domainName)
    {
        if (!_failures.TryGetValue(domainName, out var failure))
        {
            return "No failures recorded";
        }

        var now = DateTimeOffset.UtcNow;
        var nextRetry = failure.NextRetryTime.HasValue
            ? $"next retry in {(failure.NextRetryTime.Value - now).TotalSeconds:F0}s"
            : "no retry scheduled";

        return $"{failure.ConsecutiveFailures} consecutive failures, {nextRetry}, last error: {failure.LastException?.Message}";
    }
}
