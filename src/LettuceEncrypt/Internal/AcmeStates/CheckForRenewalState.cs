// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.IO;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates;

internal class CheckForRenewalState : AcmeState
{
    private readonly ILogger<CheckForRenewalState> _logger;
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly CertificateSelector _selector;
    private readonly IClock _clock;
    private readonly RenewalFailureTracker _failureTracker;

    public CheckForRenewalState(
        AcmeStateMachineContext context,
        ILogger<CheckForRenewalState> logger,
        IOptions<LettuceEncryptOptions> options,
        CertificateSelector selector,
        IClock clock,
        RenewalFailureTracker failureTracker) : base(context)
    {
        _logger = logger;
        _options = options;
        _selector = selector;
        _clock = clock;
        _failureTracker = failureTracker;
    }

    public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var checkPeriod = _options.Value.RenewalCheckPeriod;
            var daysInAdvance = _options.Value.RenewDaysInAdvance;
            if (!checkPeriod.HasValue || !daysInAdvance.HasValue)
            {
                _logger.LogInformation("Automatic certificate renewal is not configured. Stopping {service}",
                    nameof(AcmeCertificateLoader));
                return MoveTo<TerminalState>();
            }

            var domainNames = _options.Value.DomainNames;
            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Checking certificates' renewals for {hostname}",
                    string.Join(", ", domainNames));
            }

            foreach (var domainName in domainNames)
            {
                if (!_selector.TryGet(domainName, out var cert)
                    || cert == null
                    || cert.NotAfter <= _clock.Now.DateTime + daysInAdvance.Value)
                {
                    var certExpiration = cert?.NotAfter ?? _clock.Now.DateTime;

                    // Check backoff policy before attempting renewal
                    if (!_failureTracker.ShouldAttemptRenewal(domainName, certExpiration))
                    {
                        _logger.LogDebug(
                            "Skipping renewal for '{DomainName}' due to backoff policy. {FailureInfo}",
                            domainName,
                            _failureTracker.GetFailureInfo(domainName));
                        continue;
                    }

                    _logger.LogInformation(
                        "Certificate renewal needed for '{DomainName}'. Expiration: {Expiration}, Days until expiry: {DaysUntilExpiry:F1}",
                        domainName,
                        certExpiration,
                        (certExpiration - _clock.Now.DateTime).TotalDays);

                    return MoveTo<BeginCertificateCreationState>();
                }
            }

            await Task.Delay(checkPeriod.Value, cancellationToken);
        }

        return MoveTo<TerminalState>();
    }
}
