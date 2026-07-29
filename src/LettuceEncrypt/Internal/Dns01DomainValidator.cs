// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

internal class Dns01DomainValidator : DomainOwnershipValidator
{
    private readonly IDnsChallengeProvider _dnsChallengeProvider;

    public Dns01DomainValidator(
        IDnsChallengeProvider dnsChallengeProvider,
        IHostApplicationLifetime appLifetime,
        AcmeClient client,
        ILogger logger,
        string domainName,
        TimeSpan validationTimeout,
        TimeSpan validationPollInterval
    ) : base(appLifetime, client, logger, domainName, validationTimeout, validationPollInterval)
    {
        _dnsChallengeProvider = dnsChallengeProvider;
    }

    public override async Task ValidateOwnershipAsync(
        IAuthorizationContext authzContext,
        CancellationToken cancellationToken
    )
    {
        DnsTxtRecordContext? context = null;
        try
        {
            context = await PrepareDns01ChallengeResponseAsync(authzContext, _domainName, cancellationToken);
            await WaitForChallengeResultAsync(authzContext, cancellationToken);
        }
        finally
        {
            // Only clean up a record that was actually added. Preparation can fail before the
            // provider is called, and asking it to remove a record it never created may delete
            // an unrelated TXT value.
            if (context != null)
            {
                await _dnsChallengeProvider.RemoveTxtRecordAsync(context, cancellationToken);
            }
        }
    }

    private async Task<DnsTxtRecordContext> PrepareDns01ChallengeResponseAsync(
        IAuthorizationContext authorizationContext,
        string domainName,
        CancellationToken cancellationToken
    )
    {
        cancellationToken.ThrowIfCancellationRequested();

        var account = _client.GetAccountKey();
        var dnsChallenge = await _client.CreateChallengeAsync(authorizationContext, ChallengeTypes.Dns01);

        if (dnsChallenge == null)
        {
            // The authorization does not offer this challenge type. This normally means the
            // authorization has already been invalidated by an earlier, failed challenge.
            throw new InvalidOperationException(
                $"Did not receive challenge information for challenge type {ChallengeTypes.Dns01}");
        }

        var dnsTxt = account.DnsTxt(dnsChallenge.Token);

        var acmeDomain = GetAcmeDnsDomain(domainName);

        var context = await _dnsChallengeProvider.AddTxtRecordAsync(acmeDomain, dnsTxt, cancellationToken);

        _logger.LogTrace("Requesting server to validate DNS challenge");
        await _client.ValidateChallengeAsync(dnsChallenge);

        return context;
    }

    private const string DnsAcmePrefix = "_acme-challenge";

    private string GetAcmeDnsDomain(string domainName) =>
        $"{DnsAcmePrefix}.{domainName.TrimStart('*')}";
}
