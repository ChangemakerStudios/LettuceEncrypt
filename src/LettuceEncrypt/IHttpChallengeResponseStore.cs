// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt;

/// <summary>
/// Stores the key authorization values used to answer ACME HTTP-01 challenges.
/// </summary>
/// <remarks>
/// The default implementation keeps challenges in the memory of a single process. That is only
/// correct when exactly one instance of the application can receive the certificate authority's
/// validation request. When an application runs multiple instances behind a load balancer, the
/// instance that begins the ACME order is usually not the instance that receives the validation
/// request, so the challenge must be kept somewhere all instances can read. Implement this
/// interface to back challenges with shared storage, or use
/// <see cref="FileSystemStorageExtensions.PersistHttpChallengesToDirectory"/> when all instances
/// share a directory.
/// </remarks>
public interface IHttpChallengeResponseStore
{
    /// <summary>
    /// Records the response to send when the certificate authority requests <paramref name="token"/>.
    /// </summary>
    /// <param name="token">The challenge token issued by the certificate authority.</param>
    /// <param name="response">The key authorization value to return for the token.</param>
    void AddChallengeResponse(string token, string response);

    /// <summary>
    /// Looks up the response for a challenge token.
    /// </summary>
    /// <param name="token">The challenge token from the request path.</param>
    /// <param name="value">The key authorization value, or null when the token is unknown.</param>
    /// <returns>True when a response was found for the token.</returns>
    bool TryGetResponse(string token, out string? value);

    /// <summary>
    /// Discards a challenge once validation has finished.
    /// </summary>
    /// <param name="token">The challenge token to discard.</param>
    void RemoveChallenge(string token);
}
