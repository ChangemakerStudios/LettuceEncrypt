// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates;

internal class BeginCertificateCreationState : AcmeState
{
    private readonly ILogger<ServerStartupState> _logger;
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly AcmeCertificateFactory _acmeCertificateFactory;
    private readonly CertificateSelector _selector;
    private readonly IEnumerable<ICertificateRepository> _certificateRepositories;
    private readonly RenewalFailureTracker _failureTracker;
    private readonly ICertificateOrderLock _orderLock;

    public BeginCertificateCreationState(
        AcmeStateMachineContext context,
        ILogger<ServerStartupState> logger,
        IOptions<LettuceEncryptOptions> options,
        AcmeCertificateFactory acmeCertificateFactory,
        CertificateSelector selector,
        IEnumerable<ICertificateRepository> certificateRepositories,
        RenewalFailureTracker failureTracker,
        ICertificateOrderLock orderLock)
        : base(context)
    {
        _logger = logger;
        _options = options;
        _acmeCertificateFactory = acmeCertificateFactory;
        _selector = selector;
        _certificateRepositories = certificateRepositories;
        _failureTracker = failureTracker;
        _orderLock = orderLock;
    }

    public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
    {
        var domainNames = _options.Value.DomainNames;

        // When several instances share storage they all reach this state at once. Ordering from
        // each of them wastes the certificate authority's duplicate-certificate allowance, so only
        // one instance orders. The rest pick the certificate up from the shared repository on their
        // next renewal check.
        using var orderLock = _orderLock.TryAcquire();

        if (orderLock == null)
        {
            return MoveTo<CheckForRenewalState>();
        }

        try
        {
            var account = await _acmeCertificateFactory.GetOrCreateAccountAsync(cancellationToken);
            _logger.LogInformation("Using account {accountId}", account.Id);

            _logger.LogInformation("Creating certificate for {hostname}",
                string.Join(",", domainNames));

            var cert = await _acmeCertificateFactory.CreateCertificateAsync(cancellationToken);

            _logger.LogInformation("Created certificate {subjectName} ({thumbprint})",
                cert.Subject,
                cert.Thumbprint);

            await SaveCertificateAsync(cert, cancellationToken);

            // Record success for all domains
            foreach (var domain in domainNames)
            {
                _failureTracker.RecordSuccess(domain);
            }
        }
        catch (Exception ex)
        {
            // Rethrow cancellation exceptions immediately to preserve cooperative cancellation semantics
            if (ex is OperationCanceledException || ex is TaskCanceledException)
            {
                throw;
            }

            // Record failure for all domains
            foreach (var domain in domainNames)
            {
                _failureTracker.RecordFailure(domain, ex);
            }

            _logger.LogError(0, ex, "Failed to automatically create a certificate for {hostname}", domainNames);

            // Don't throw - return to CheckForRenewalState to implement backoff
            // The exception has been logged and tracked
        }

        return MoveTo<CheckForRenewalState>();
    }

    /// <summary>
    /// How long the repositories collectively have to store a new certificate.
    /// </summary>
    private static readonly TimeSpan s_saveTimeout = TimeSpan.FromMinutes(5);

    private Task SaveCertificateAsync(X509Certificate2 cert, CancellationToken cancellationToken)
    {
        _selector.Add(cert);

        return SaveToRepositoriesAsync(_certificateRepositories, cert, s_saveTimeout, cancellationToken);
    }

    /// <summary>
    /// Stores a certificate in every repository, allowing them <paramref name="timeout"/> in total.
    /// </summary>
    internal static async Task SaveToRepositoriesAsync(
        IEnumerable<ICertificateRepository> repositories,
        X509Certificate2 cert,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        // This bound used to be expressed as a Task.Delay inside the awaited set, which made every
        // save take five minutes rather than allowing it up to five minutes, and delayed the report
        // of a failed save by the same amount. Cancelling the repositories bounds it properly.
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        var saveTasks = new List<Task>();
        var errors = new List<Exception>();

        foreach (var repo in repositories)
        {
            try
            {
                saveTasks.Add(repo.SaveAsync(cert, timeoutSource.Token));
            }
            catch (Exception ex)
            {
                // synchronous saves may fail immediately
                errors.Add(ex);
            }
        }

        try
        {
            await Task.WhenAll(saveTasks);
        }
        catch (Exception)
        {
            // Awaiting Task.WhenAll rethrows only the first exception. Every repository's failure
            // matters here, because a certificate saved to none of them is lost on restart.
            foreach (var task in saveTasks)
            {
                if (task.IsFaulted && task.Exception != null)
                {
                    errors.AddRange(task.Exception.InnerExceptions);
                }
            }

            // A caller-requested shutdown is not a save failure.
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            if (timeoutSource.IsCancellationRequested)
            {
                errors.Add(new TimeoutException(
                    $"Timed out after {timeout.TotalMinutes:F0} minutes saving the certificate to " +
                    $"one or more repositories."));
            }
        }

        if (errors.Count > 0)
        {
            throw new AggregateException("Failed to save cert to repositories", errors);
        }
    }
}
