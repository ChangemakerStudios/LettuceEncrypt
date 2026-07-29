// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Security.KeyVault.Secrets;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Azure.Internal;

/// <summary>
/// Stores HTTP-01 challenge responses as Key Vault secrets so that every application instance can
/// answer a validation request, regardless of which instance began the ACME order.
/// </summary>
/// <remarks>
/// <para>
/// Challenges are short lived but the vault is shared, so this trades a little latency for not
/// needing shared storage of its own.
/// </para>
/// <para>
/// Lookups happen while serving a request on a publicly reachable path that scanners probe
/// constantly. Three things keep that from turning into a stream of calls to the vault: tokens that
/// are not valid base64url are rejected outright, challenges written by this instance are answered
/// from memory without any call at all, and tokens already found to be absent are remembered
/// briefly so a repeated probe does not repeat the lookup.
/// </para>
/// </remarks>
internal class AzureKeyVaultHttpChallengeStore : IHttpChallengeResponseStore
{
    /// <summary>
    /// Key Vault secret names are limited to alphanumerics and dashes, but ACME tokens are
    /// base64url and may contain underscores. Hashing sidesteps the mismatch without any chance of
    /// two tokens colliding on one name.
    /// </summary>
    private const string SecretNamePrefix = "le-challenge-";

    private static readonly TimeSpan s_challengeLifetime = TimeSpan.FromHours(1);
    private static readonly TimeSpan s_negativeCacheDuration = TimeSpan.FromSeconds(30);
    private const int MaxNegativeCacheEntries = 1024;

    private readonly ISecretClientFactory _secretClientFactory;
    private readonly ILogger<AzureKeyVaultHttpChallengeStore> _logger;

    // Challenges this instance created. The instance that orders is also the one most likely to be
    // asked first, so this answers the common case without touching the network.
    private readonly ConcurrentDictionary<string, string> _local = new(StringComparer.Ordinal);

    // Tokens recently confirmed absent from the vault.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _knownAbsent = new(StringComparer.Ordinal);

    public AzureKeyVaultHttpChallengeStore(
        ISecretClientFactory secretClientFactory,
        ILogger<AzureKeyVaultHttpChallengeStore> logger)
    {
        _secretClientFactory = secretClientFactory ?? throw new ArgumentNullException(nameof(secretClientFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task AddChallengeResponseAsync(string token, string response, CancellationToken cancellationToken = default)
    {
        if (!AcmeChallengeToken.IsValid(token))
        {
            throw new ArgumentException("Challenge token contains characters that are not valid base64url.", nameof(token));
        }

        _local[token] = response;
        _knownAbsent.TryRemove(token, out _);

        var secretName = GetSecretName(token);

        var secret = new KeyVaultSecret(secretName, response);

        // An expiry means an abandoned challenge stops being served even if cleanup never runs.
        secret.Properties.ExpiresOn = DateTimeOffset.UtcNow.Add(s_challengeLifetime);
        secret.Properties.ContentType = "text/plain";

        try
        {
            var client = _secretClientFactory.Create();
            await client.SetSecretAsync(secret, cancellationToken);

            _logger.LogDebug(
                "Stored HTTP challenge response for token {Token} in Azure KeyVault as {SecretName}",
                token, secretName);
        }
        catch (RequestFailedException ex)
        {
            // Without the challenge in the vault, only this instance can answer, and the
            // certificate authority is unlikely to reach it. Failing here is clearer than letting
            // validation time out for reasons that look unrelated.
            _logger.LogError(ex,
                "Failed to store HTTP challenge response for token {Token} in Azure KeyVault. " +
                "Other application instances will not be able to answer the validation request.",
                token);
            throw;
        }
    }

    public async Task<string?> GetResponseAsync(string token, CancellationToken cancellationToken = default)
    {
        // The token comes from the request path, so it is untrusted. Screening it here keeps
        // scanner traffic from reaching the vault at all.
        if (!AcmeChallengeToken.IsValid(token))
        {
            _logger.LogTrace("Ignoring HTTP challenge request for malformed token");
            return null;
        }

        if (_local.TryGetValue(token, out var local))
        {
            _logger.LogTrace("Answered HTTP challenge for token {Token} from local memory", token);
            return local;
        }

        if (IsKnownAbsent(token))
        {
            _logger.LogTrace("Token {Token} was recently confirmed absent. Not querying Azure KeyVault", token);
            return null;
        }

        try
        {
            var client = _secretClientFactory.Create();
            var secret = await client.GetSecretAsync(GetSecretName(token), cancellationToken: cancellationToken);

            var value = secret?.Value?.Value;

            if (string.IsNullOrEmpty(value))
            {
                RecordAbsent(token);
                return null;
            }

            _logger.LogDebug("Retrieved HTTP challenge response for token {Token} from Azure KeyVault", token);
            return value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            RecordAbsent(token);
            _logger.LogTrace("No HTTP challenge response found for token {Token} in Azure KeyVault", token);
            return null;
        }
        catch (RequestFailedException ex)
        {
            // Report the challenge as unknown rather than failing the request. The certificate
            // authority retries, and a vault problem should not surface as a 500 on a public path.
            _logger.LogWarning(ex,
                "Could not read HTTP challenge response for token {Token} from Azure KeyVault", token);
            return null;
        }
    }

    public async Task RemoveChallengeAsync(string token, CancellationToken cancellationToken = default)
    {
        if (!AcmeChallengeToken.IsValid(token))
        {
            return;
        }

        _local.TryRemove(token, out _);

        var secretName = GetSecretName(token);

        try
        {
            var client = _secretClientFactory.Create();
            var operation = await client.StartDeleteSecretAsync(secretName, cancellationToken);

            _logger.LogDebug("Deleted HTTP challenge secret {SecretName} from Azure KeyVault", secretName);

            // On a vault with soft delete but without purge protection, purging keeps spent
            // challenges from piling up. Where purge is not permitted the entries simply age out
            // over the vault's retention period.
            try
            {
                await operation.WaitForCompletionAsync(cancellationToken);
                await client.PurgeDeletedSecretAsync(secretName, cancellationToken);
            }
            catch (RequestFailedException ex)
            {
                _logger.LogDebug(ex,
                    "Could not purge deleted challenge secret {SecretName}. It will remain recoverable " +
                    "until the vault's retention period elapses.", secretName);
            }
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            // Already gone.
        }
        catch (RequestFailedException ex)
        {
            // The secret expires on its own, so a failed cleanup is not worth failing the order for.
            _logger.LogWarning(ex,
                "Could not delete HTTP challenge secret {SecretName} from Azure KeyVault. " +
                "It will stop being served when it expires.", secretName);
        }
    }

    private bool IsKnownAbsent(string token)
    {
        if (!_knownAbsent.TryGetValue(token, out var recordedAt))
        {
            return false;
        }

        if (DateTimeOffset.UtcNow - recordedAt <= s_negativeCacheDuration)
        {
            return true;
        }

        _knownAbsent.TryRemove(token, out _);
        return false;
    }

    private void RecordAbsent(string token)
    {
        // Bounded so that a flood of distinct tokens cannot grow this without limit.
        if (_knownAbsent.Count >= MaxNegativeCacheEntries)
        {
            var cutoff = DateTimeOffset.UtcNow - s_negativeCacheDuration;

            foreach (var entry in _knownAbsent)
            {
                if (entry.Value < cutoff)
                {
                    _knownAbsent.TryRemove(entry.Key, out _);
                }
            }

            if (_knownAbsent.Count >= MaxNegativeCacheEntries)
            {
                return;
            }
        }

        _knownAbsent[token] = DateTimeOffset.UtcNow;
    }

    internal static string GetSecretName(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));

#if NET5_0_OR_GREATER
        return SecretNamePrefix + Convert.ToHexString(hash).ToLowerInvariant();
#else
        return SecretNamePrefix + BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
#endif
    }
}
