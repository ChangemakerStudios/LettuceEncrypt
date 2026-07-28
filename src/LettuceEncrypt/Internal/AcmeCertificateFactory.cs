// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal.PfxBuilder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

internal class AcmeCertificateFactory
{
    private readonly AcmeClientFactory _acmeClientFactory;
    private readonly TermsOfServiceChecker _tosChecker;
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly IHttpChallengeResponseStore _challengeStore;
    private readonly IAccountStore _accountRepository;
    private readonly ILogger _logger;
    private readonly IHostApplicationLifetime _appLifetime;
    private readonly TlsAlpnChallengeResponder _tlsAlpnChallengeResponder;
    private readonly IDnsChallengeProvider _dnsChallengeProvider;
    private readonly ICertificateAuthorityConfiguration _certificateAuthority;
    private readonly IPfxBuilderFactory _pfxBuilderFactory;
    private readonly IServer _server;
    private readonly TaskCompletionSource<object?> _appStarted = new();
    private AcmeClient? _client;
    private IKey? _acmeAccountKey;

    public AcmeCertificateFactory(
        AcmeClientFactory acmeClientFactory,
        TermsOfServiceChecker tosChecker,
        IOptions<LettuceEncryptOptions> options,
        IHttpChallengeResponseStore challengeStore,
        ILogger<AcmeCertificateFactory> logger,
        IHostApplicationLifetime appLifetime,
        TlsAlpnChallengeResponder tlsAlpnChallengeResponder,
        ICertificateAuthorityConfiguration certificateAuthority,
        IDnsChallengeProvider dnsChallengeProvider,
        IPfxBuilderFactory pfxBuilderFactory,
        IServer server,
        IAccountStore? accountRepository = null)
    {
        _acmeClientFactory = acmeClientFactory;
        _tosChecker = tosChecker;
        _options = options;
        _challengeStore = challengeStore;
        _logger = logger;
        _appLifetime = appLifetime;
        _tlsAlpnChallengeResponder = tlsAlpnChallengeResponder;
        _dnsChallengeProvider = dnsChallengeProvider;
        _certificateAuthority = certificateAuthority;
        _pfxBuilderFactory = pfxBuilderFactory;
        _server = server;

        appLifetime.ApplicationStarted.Register(() => _appStarted.TrySetResult(null));
        if (appLifetime.ApplicationStarted.IsCancellationRequested)
        {
            _appStarted.TrySetResult(null);
        }

        _accountRepository = accountRepository ?? new FileSystemAccountStore(logger, certificateAuthority);
    }

    public async Task<AccountModel> GetOrCreateAccountAsync(CancellationToken cancellationToken)
    {
        var account = await _accountRepository.GetAccountAsync(cancellationToken);

        _acmeAccountKey = account != null
            ? KeyFactory.FromDer(account.PrivateKey)
            : KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);

        _client = _acmeClientFactory.Create(_acmeAccountKey);

        if (account != null && await ExistingAccountIsValidAsync())
        {
            return account;
        }

        return await CreateAccount(cancellationToken);
    }

    private async Task<AccountModel> CreateAccount(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client == null || _acmeAccountKey == null)
        {
            throw new InvalidOperationException();
        }

        var tosUri = await _client.GetTermsOfServiceAsync();

        _tosChecker.EnsureTermsAreAccepted(tosUri);

        var options = _options.Value;
        _logger.LogInformation("Creating new account for {email}", options.EmailAddress);
        var accountId = await _client.CreateAccountAsync(options.EmailAddress);

        var accountModel = new AccountModel
        {
            Id = accountId,
            EmailAddresses = new[] { options.EmailAddress },
            PrivateKey = _acmeAccountKey.ToDer(),
        };

        await _accountRepository.SaveAccountAsync(accountModel, cancellationToken);

        return accountModel;
    }

    private async Task<bool> ExistingAccountIsValidAsync()
    {
        if (_client == null)
        {
            throw new InvalidOperationException();
        }

        // double checks the account is still valid
        Account existingAccount;
        try
        {
            existingAccount = await _client.GetAccountAsync();
        }
        catch (AcmeRequestException exception)
        {
            _logger.LogWarning(
                "An account key was found, but could not be matched to a valid account. Validation error: {acmeError}",
                exception.Error);
            return false;
        }

        if (existingAccount.Status != AccountStatus.Valid)
        {
            _logger.LogWarning(
                "An account key was found, but the account is no longer valid. Account status: {status}." +
                "A new account will be registered.",
                existingAccount.Status);
            return false;
        }

        _logger.LogInformation("Using existing account {@ExistingAccount} for renewal", existingAccount);

        if (existingAccount.TermsOfServiceAgreed != true)
        {
            var tosUri = await _client.GetTermsOfServiceAsync();
            _tosChecker.EnsureTermsAreAccepted(tosUri);
            await _client.AgreeToTermsOfServiceAsync();
        }

        return true;
    }

    public async Task<X509Certificate2> CreateCertificateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client == null)
        {
            throw new InvalidOperationException();
        }

        IOrderContext? orderContext = null;
        var orders = await _client.GetOrdersAsync();
        if (orders.Any())
        {
            var expectedDomains = new HashSet<string>(_options.Value.DomainNames);
            foreach (var order in orders)
            {
                var orderDetails = await _client.GetOrderDetailsAsync(order);
                if (orderDetails.Status != OrderStatus.Pending)
                {
                    continue;
                }

                var orderDomains = orderDetails
                    .Identifiers
                    .Where(i => i.Type == IdentifierType.Dns)
                    .Select(s => s.Value);

                if (expectedDomains.SetEquals(orderDomains))
                {
                    _logger.LogDebug("Found an existing order for a certificate");
                    orderContext = order;
                    break;
                }
            }
        }

        if (orderContext == null)
        {
            _logger.LogDebug("Creating new order for a certificate");
            orderContext = await _client.CreateOrderAsync(_options.Value.DomainNames);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var authorizations = await _client.GetOrderAuthorizations(orderContext);

        cancellationToken.ThrowIfCancellationRequested();
        await Task.WhenAll(BeginValidateAllAuthorizations(authorizations, cancellationToken));

        cancellationToken.ThrowIfCancellationRequested();
        return await CompleteCertificateRequestAsync(orderContext, cancellationToken);
    }

    private IEnumerable<Task> BeginValidateAllAuthorizations(IEnumerable<IAuthorizationContext> authorizations,
        CancellationToken cancellationToken)
    {
        foreach (var authorization in authorizations)
        {
            yield return ValidateDomainOwnershipAsync(authorization, cancellationToken);
        }
    }

    private async Task ValidateDomainOwnershipAsync(IAuthorizationContext authorizationContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client == null)
        {
            throw new InvalidOperationException();
        }

        var authorization = await _client.GetAuthorizationAsync(authorizationContext);
        var domainName = authorization.Identifier.Value;

        if (authorization.Status == AuthorizationStatus.Valid)
        {
            // Short circuit if authorization is already complete
            return;
        }

        _logger.LogDebug("Requesting authorization to create certificate for {domainName}", domainName);

        cancellationToken.ThrowIfCancellationRequested();

        var validators = new List<DomainOwnershipValidator>();
        var validationTimeout = _options.Value.ValidationTimeout;
        var validationPollInterval = _options.Value.ValidationPollInterval;
        var enableSelfTest = _options.Value.EnableChallengeSelfTest;
        var selfTestBaseUrl = _options.Value.ChallengeSelfTestBaseUrl;

        if (_tlsAlpnChallengeResponder.IsEnabled)
        {
            validators.Add(new TlsAlpn01DomainValidator(
                _tlsAlpnChallengeResponder, _appLifetime, _client, _logger, domainName, validationTimeout, validationPollInterval));
        }

        if (_options.Value.AllowedChallengeTypes.HasFlag(ChallengeType.Http01))
        {
            validators.Add(new Http01DomainValidator(
                _challengeStore, _appLifetime, _client, _logger, domainName, validationTimeout, validationPollInterval, enableSelfTest, selfTestBaseUrl, _server));
        }

        if (_options.Value.AllowedChallengeTypes.HasFlag(ChallengeType.Dns01))
        {
            // The no-op provider reports success without publishing a TXT record, so validation
            // would wait for the full timeout and then fail. Skipping it keeps the failure fast
            // and the reason obvious.
            if (_dnsChallengeProvider is NoOpDnsChallengeProvider)
            {
                _logger.LogDebug(
                    "Skipping Dns01 validation for '{DomainName}'. No {ProviderType} is configured, " +
                    "so no TXT record can be published.",
                    domainName, nameof(IDnsChallengeProvider));
            }
            else
            {
                validators.Add(new Dns01DomainValidator(
                    _dnsChallengeProvider, _appLifetime, _client, _logger, domainName, validationTimeout, validationPollInterval));
            }
        }

        if (validators.Count == 0)
        {
            var challengeTypes = string.Join(", ", Enum.GetNames(typeof(ChallengeType)));
            throw new InvalidOperationException(
                "Could not find a method for validating domain ownership. " +
                "Ensure at least one kind of these challenge types is configured: " + challengeTypes);
        }

        _logger.LogInformation(
            "Attempting domain validation for '{DomainName}' using {ValidatorCount} challenge method(s): {Validators}",
            domainName,
            validators.Count,
            string.Join(", ", validators.Select(v => v.GetType().Name.Replace("DomainValidator", ""))));

        var failures = new List<Exception>();
        var attempted = new List<string>();
        var authorizationInvalidated = false;

        foreach (var validator in validators)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var validatorName = validator.GetType().Name.Replace("DomainValidator", "");
            attempted.Add(validatorName);

            try
            {
                _logger.LogDebug("Trying {ValidatorName} validation for domain '{DomainName}'",
                    validatorName, domainName);

                await validator.ValidateOwnershipAsync(authorizationContext, cancellationToken);

                // The method above raises if validation fails. If no exception occurs, we assume validation completed successfully.
                _logger.LogInformation(
                    "Domain validation succeeded using {ValidatorName} for '{DomainName}'",
                    validatorName, domainName);
                return;
            }
            catch (Exception ex)
            {
                // Rethrow cancellation exceptions immediately to preserve cooperative cancellation semantics
                if (ex is OperationCanceledException || ex is TaskCanceledException)
                {
                    throw;
                }

                failures.Add(ex);
                _logger.LogWarning(ex,
                    "Validation with {ValidatorName} failed for domain '{DomainName}'. Error: {ErrorMessage}",
                    validatorName,
                    domainName,
                    ex.Message);
            }

            // A failed challenge moves the whole authorization to 'invalid' (RFC 8555 section 7.1.6).
            // No other challenge type can succeed against it, so the remaining validators would only
            // produce misleading errors about missing challenge information.
            authorizationInvalidated = await IsAuthorizationInvalidAsync(authorizationContext);

            if (authorizationInvalidated)
            {
                var remaining = validators.Count - attempted.Count;

                if (remaining > 0)
                {
                    _logger.LogError(
                        "The authorization for '{DomainName}' was invalidated by the failed {ValidatorName} challenge, " +
                        "so the remaining {RemainingValidators} challenge method(s) cannot be attempted against it. " +
                        "A certificate authority marks the entire authorization invalid once any challenge fails, " +
                        "so challenge types are not interchangeable fallbacks. Set AllowedChallengeTypes to the one " +
                        "challenge type this deployment can actually serve.",
                        domainName, validatorName, remaining);
                }

                break;
            }
        }

        var failureDetails = string.Join("; ", failures.Select((ex, i) => $"{attempted[i]}: {ex.Message}"));

        _logger.LogError(
            "Domain validation failed for '{DomainName}' after attempting {AttemptedCount} of {ValidatorCount} " +
            "challenge method(s). Failures: {FailureDetails}",
            domainName,
            attempted.Count,
            validators.Count,
            failureDetails);

        var summary = authorizationInvalidated
            ? $"Failed to validate ownership of domainName '{domainName}'. The authorization was invalidated by the " +
              $"failed {attempted[attempted.Count - 1]} challenge, so no further challenge type could be attempted. " +
              $"Attempted: {string.Join(", ", attempted)}. See inner exceptions for details."
            : $"Failed to validate ownership of domainName '{domainName}' using any available challenge method. " +
              $"Attempted: {string.Join(", ", attempted)}. See inner exceptions for details.";

        throw new AggregateException(summary, failures);
    }

    /// <summary>
    /// Checks whether the certificate authority has moved the authorization to a terminal invalid
    /// state, which makes every remaining challenge type unusable.
    /// </summary>
    private async Task<bool> IsAuthorizationInvalidAsync(IAuthorizationContext authorizationContext)
    {
        try
        {
            var authorization = await _client!.GetAuthorizationAsync(authorizationContext);
            return authorization.Status == AuthorizationStatus.Invalid;
        }
        catch (Exception ex)
        {
            // If the status cannot be read, fall through to the next validator rather than giving
            // up on a certificate that might still be obtainable.
            _logger.LogDebug(ex, "Could not read authorization status after a failed challenge");
            return false;
        }
    }

    private async Task<X509Certificate2> CompleteCertificateRequestAsync(IOrderContext order,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client == null)
        {
            throw new InvalidOperationException();
        }

        var commonName = _options.Value.DomainNames[0];
        _logger.LogDebug("Creating cert for {commonName}", commonName);

        var csrInfo = new CsrInfo
        {
            CommonName = commonName,
        };
        var privateKeyAlgorithm = (Certes.KeyAlgorithm)_options.Value.KeyAlgorithm;
        var privateKey = KeyFactory.NewKey(privateKeyAlgorithm, _options.Value.KeySize);
        var acmeCert = await _client.GetCertificateAsync(csrInfo, privateKey, order);

        _logger.LogAcmeAction("NewCertificate");

        var pfxBuilder = CreatePfxBuilder(acmeCert, privateKey);
        var pfx = pfxBuilder.Build("HTTPS Cert - " + _options.Value.DomainNames, string.Empty);
        return new X509Certificate2(pfx, string.Empty, X509KeyStorageFlags.Exportable);
    }

    internal IPfxBuilder CreatePfxBuilder(CertificateChain certificateChain, IKey certKey)
    {
        var pfxBuilder = _pfxBuilderFactory.FromChain(certificateChain, certKey);

        _logger.LogDebug(
            "Adding {IssuerCount} additional issuers to certes before building pfx certificate file",
            _options.Value.AdditionalIssuers.Length + _certificateAuthority.IssuerCertificates.Length);

        foreach (var issuer in _options.Value.AdditionalIssuers.Concat(_certificateAuthority.IssuerCertificates))
        {
            pfxBuilder.AddIssuer(Encoding.UTF8.GetBytes(issuer));
        }

        return pfxBuilder;
    }
}
