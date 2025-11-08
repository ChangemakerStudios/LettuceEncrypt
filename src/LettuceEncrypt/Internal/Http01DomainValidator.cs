// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

internal class Http01DomainValidator : DomainOwnershipValidator
{
    private readonly IHttpChallengeResponseStore _challengeStore;
    private readonly bool _enableSelfTest;
    private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

    public Http01DomainValidator(
        IHttpChallengeResponseStore challengeStore,
        IHostApplicationLifetime appLifetime,
        AcmeClient client,
        ILogger logger,
        string domainName,
        TimeSpan validationTimeout,
        TimeSpan validationPollInterval,
        bool enableSelfTest)
        : base(appLifetime, client, logger, domainName, validationTimeout, validationPollInterval)
    {
        _challengeStore = challengeStore;
        _enableSelfTest = enableSelfTest;
    }

    public override async Task ValidateOwnershipAsync(IAuthorizationContext authzContext, CancellationToken cancellationToken)
    {
        string? challengeToken = null;
        try
        {
            challengeToken = await PrepareHttpChallengeResponseAsync(authzContext, cancellationToken);
            await WaitForChallengeResultAsync(authzContext, cancellationToken);
        }
        finally
        {
            // Always cleanup challenge response, even if validation fails
            if (challengeToken != null)
            {
                _challengeStore.RemoveChallenge(challengeToken);
            }
        }
    }

    private async Task<string> PrepareHttpChallengeResponseAsync(
        IAuthorizationContext authorizationContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client == null)
        {
            throw new InvalidOperationException();
        }

        var httpChallenge = await _client.CreateChallengeAsync(authorizationContext, ChallengeTypes.Http01);
        if (httpChallenge == null)
        {
            throw new InvalidOperationException(
                $"Did not receive challenge information for challenge type {ChallengeTypes.Http01}");
        }

        var token = httpChallenge.Token;
        var keyAuth = httpChallenge.KeyAuthz;

        try
        {
            _challengeStore.AddChallengeResponse(token, keyAuth);

            _logger.LogTrace("Waiting for server to start accepting HTTP requests");
            await _appStarted.Task;

            // Perform self-test if enabled
            if (_enableSelfTest)
            {
                await SelfTestChallengeEndpointAsync(token, keyAuth, cancellationToken);
            }

            _logger.LogTrace("Requesting server to validate HTTP challenge");
            await _client.ValidateChallengeAsync(httpChallenge);

            return token;
        }
        catch
        {
            // If anything fails after adding to store, remove it before rethrowing
            _challengeStore.RemoveChallenge(token);
            throw;
        }
    }

    private async Task SelfTestChallengeEndpointAsync(string token, string expectedResponse, CancellationToken cancellationToken)
    {
        var challengeUrl = $"http://localhost/.well-known/acme-challenge/{token}";

        try
        {
            _logger.LogDebug("Performing self-test of HTTP challenge endpoint: {ChallengeUrl}", challengeUrl);

            var startTime = DateTimeOffset.UtcNow;
            var response = await _httpClient.GetAsync(challengeUrl, cancellationToken);
            var elapsed = DateTimeOffset.UtcNow - startTime;

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"Self-test failed: HTTP challenge endpoint returned {response.StatusCode}. " +
                    $"URL: {challengeUrl}. " +
                    $"Ensure the HTTP server is properly configured and the challenge middleware is registered.");
            }

            var actualResponse = await response.Content.ReadAsStringAsync();

            if (actualResponse != expectedResponse)
            {
                throw new InvalidOperationException(
                    $"Self-test failed: HTTP challenge endpoint returned incorrect response. " +
                    $"Expected: {expectedResponse.Substring(0, Math.Min(20, expectedResponse.Length))}..., " +
                    $"Actual: {actualResponse.Substring(0, Math.Min(20, actualResponse.Length))}... " +
                    $"URL: {challengeUrl}");
            }

            _logger.LogInformation(
                "HTTP challenge endpoint self-test passed for domain '{DomainName}' in {Elapsed:F0}ms. Ready for Let's Encrypt validation.",
                _domainName, elapsed.TotalMilliseconds);
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Self-test failed: Unable to reach HTTP challenge endpoint at {challengeUrl}. " +
                $"Error: {ex.Message}. " +
                $"Ensure the HTTP server is listening and accessible locally.", ex);
        }
        catch (TaskCanceledException ex)
        {
            throw new InvalidOperationException(
                $"Self-test failed: Timeout reaching HTTP challenge endpoint at {challengeUrl}. " +
                $"The server may be overloaded or not responding.", ex);
        }
    }
}
