// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

internal abstract class DomainOwnershipValidator
{
    protected readonly AcmeClient _client;
    protected readonly ILogger _logger;
    protected readonly string _domainName;
    protected readonly TaskCompletionSource<object?> _appStarted = new();
    protected readonly TimeSpan _validationTimeout;
    protected readonly TimeSpan _validationPollInterval;

    protected DomainOwnershipValidator(
        IHostApplicationLifetime appLifetime,
        AcmeClient client,
        ILogger logger,
        string domainName,
        TimeSpan validationTimeout,
        TimeSpan validationPollInterval)
    {
        _client = client;
        _logger = logger;
        _domainName = domainName;
        _validationTimeout = validationTimeout;
        _validationPollInterval = validationPollInterval;

        appLifetime.ApplicationStarted.Register(() => _appStarted.TrySetResult(null));
        if (appLifetime.ApplicationStarted.IsCancellationRequested)
        {
            _appStarted.TrySetResult(null);
        }
    }

    public abstract Task ValidateOwnershipAsync(IAuthorizationContext authzContext, CancellationToken cancellationToken);

    protected async Task WaitForChallengeResultAsync(IAuthorizationContext authorizationContext, CancellationToken cancellationToken)
    {
        var startTime = DateTimeOffset.UtcNow;
        var attempt = 0;

        while (true)
        {
            attempt++;
            var elapsed = DateTimeOffset.UtcNow - startTime;

            if (elapsed >= _validationTimeout)
            {
                throw new TimeoutException(
                    $"Timed out after {elapsed.TotalSeconds:F1} seconds waiting for domain ownership validation of '{_domainName}'. " +
                    $"Made {attempt} attempts. Consider increasing ValidationTimeout in LettuceEncryptOptions.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            var authorization = await _client.GetAuthorizationAsync(authorizationContext);

            _logger.LogAcmeAction("GetAuthorization");
            _logger.LogTrace("Validation attempt {Attempt} for domain '{DomainName}': status = {Status}, elapsed = {Elapsed:F1}s",
                attempt, _domainName, authorization.Status, elapsed.TotalSeconds);

            switch (authorization.Status)
            {
                case AuthorizationStatus.Valid:
                    _logger.LogInformation("Domain '{DomainName}' validated successfully after {Attempts} attempts in {Elapsed:F1}s",
                        _domainName, attempt, elapsed.TotalSeconds);
                    return;
                case AuthorizationStatus.Pending:
                    await Task.Delay(_validationPollInterval, cancellationToken);
                    continue;
                case AuthorizationStatus.Invalid:
                    throw InvalidAuthorizationError(authorization);
                case AuthorizationStatus.Revoked:
                    throw new InvalidOperationException(
                        $"The authorization to verify domainName '{_domainName}' has been revoked.");
                case AuthorizationStatus.Expired:
                    throw new InvalidOperationException(
                        $"The authorization to verify domainName '{_domainName}' has expired.");
                case AuthorizationStatus.Deactivated:
                default:
                    throw new ArgumentOutOfRangeException("authorization",
                        "Unexpected response from server while validating domain ownership.");
            }
        }
    }

    private Exception InvalidAuthorizationError(Authorization authorization)
    {
        var reason = "unknown";
        var domainName = authorization.Identifier.Value;
        try
        {
            var errors = authorization.Challenges.Where(a => a.Error != null).Select(a => a.Error)
                .Select(error => $"{error.Type}: {error.Detail}, Code = {error.Status}");
            reason = string.Join("; ", errors);
        }
        catch
        {
            _logger.LogTrace("Could not determine reason why validation failed. Response: {resp}", authorization);
        }

        _logger.LogError("Failed to validate ownership of domainName '{domainName}'. Reason: {reason}", domainName,
            reason);

        return new InvalidOperationException($"Failed to validate ownership of domainName '{domainName}'");
    }
}
