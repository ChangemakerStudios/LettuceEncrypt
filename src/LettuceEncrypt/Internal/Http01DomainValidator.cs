// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

internal class Http01DomainValidator : DomainOwnershipValidator
{
    private readonly IHttpChallengeResponseStore _challengeStore;
    private readonly bool _enableSelfTest;
    private readonly string? _selfTestBaseUrl;
    private readonly IServer _server;
    private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

    public Http01DomainValidator(
        IHttpChallengeResponseStore challengeStore,
        IHostApplicationLifetime appLifetime,
        AcmeClient client,
        ILogger logger,
        string domainName,
        TimeSpan validationTimeout,
        TimeSpan validationPollInterval,
        bool enableSelfTest,
        string? selfTestBaseUrl,
        IServer server)
        : base(appLifetime, client, logger, domainName, validationTimeout, validationPollInterval)
    {
        _challengeStore = challengeStore;
        _enableSelfTest = enableSelfTest;
        _selfTestBaseUrl = selfTestBaseUrl;
        _server = server;
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
        var baseUrl = ResolveChallengeSelfTestBaseUrl();
        var challengeUrl = $"{baseUrl.TrimEnd('/')}/.well-known/acme-challenge/{token}";

        try
        {
            _logger.LogDebug("Performing self-test of HTTP challenge endpoint: {ChallengeUrl} (base: {BaseUrl})",
                challengeUrl, baseUrl);

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
                "HTTP challenge endpoint self-test passed for domain '{DomainName}' at {ChallengeUrl} in {Elapsed:F0}ms. Ready for Let's Encrypt validation.",
                _domainName, challengeUrl, elapsed.TotalMilliseconds);
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Self-test failed: Unable to reach HTTP challenge endpoint at {challengeUrl}. " +
                $"Error: {ex.Message}. " +
                $"Ensure the HTTP server is listening and accessible locally. " +
                $"For containerized apps, set ChallengeSelfTestBaseUrl in LettuceEncryptOptions.", ex);
        }
        catch (TaskCanceledException ex)
        {
            throw new InvalidOperationException(
                $"Self-test failed: Timeout reaching HTTP challenge endpoint at {challengeUrl}. " +
                $"The server may be overloaded or not responding.", ex);
        }
    }

    private string ResolveChallengeSelfTestBaseUrl()
    {
        // 1. Prefer explicitly configured base URL
        if (!string.IsNullOrWhiteSpace(_selfTestBaseUrl))
        {
            _logger.LogTrace("Using configured ChallengeSelfTestBaseUrl: {BaseUrl}", _selfTestBaseUrl);
            return _selfTestBaseUrl;
        }

        // 2. Try to detect from server bindings
        var serverAddresses = _server.Features.Get<IServerAddressesFeature>();
        if (serverAddresses?.Addresses != null && serverAddresses.Addresses.Any())
        {
            // Prefer HTTP addresses (not HTTPS) since ACME HTTP-01 challenge must use HTTP
            var httpAddresses = serverAddresses.Addresses
                .Where(a => a.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (httpAddresses.Any())
            {
                // Try to find an address that matches the domain name
                var matchingAddress = httpAddresses.FirstOrDefault(a =>
                    a.Contains(_domainName, StringComparison.OrdinalIgnoreCase));

                var selectedAddress = matchingAddress ?? httpAddresses.First();

                // Convert binding addresses to localhost-based URLs for self-test
                // e.g., "http://0.0.0.0:5000" -> "http://localhost:5000"
                //       "http://+:5000" -> "http://localhost:5000"
                //       "http://*:5000" -> "http://localhost:5000"
                var uri = new Uri(selectedAddress);
                var baseUrl = uri.Host switch
                {
                    "0.0.0.0" or "+" or "*" => $"http://localhost:{uri.Port}",
                    _ => selectedAddress.TrimEnd('/')
                };

                _logger.LogTrace("Detected server binding: {ServerAddress}, using self-test URL: {BaseUrl}",
                    selectedAddress, baseUrl);
                return baseUrl;
            }

            // If only HTTPS addresses exist, warn and use the first one converted to HTTP
            if (serverAddresses.Addresses.Any())
            {
                var firstAddress = serverAddresses.Addresses.First();
                var uri = new Uri(firstAddress);
                var baseUrl = $"http://{(uri.Host == "0.0.0.0" || uri.Host == "+" || uri.Host == "*" ? "localhost" : uri.Host)}:{uri.Port}";

                _logger.LogWarning(
                    "No HTTP bindings found, only HTTPS. Attempting self-test with HTTP on same port: {BaseUrl}. " +
                    "This may fail if HTTP is not enabled. Consider setting ChallengeSelfTestBaseUrl explicitly.",
                    baseUrl);
                return baseUrl;
            }
        }

        // 3. Fall back to localhost (default port 80 implied)
        _logger.LogWarning(
            "Could not detect server binding addresses. Falling back to http://localhost for self-test. " +
            "For containerized apps or non-standard ports, set ChallengeSelfTestBaseUrl in LettuceEncryptOptions.");
        return "http://localhost";
    }
}
