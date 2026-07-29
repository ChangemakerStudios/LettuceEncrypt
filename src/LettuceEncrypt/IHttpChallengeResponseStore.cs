// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt;

/// <summary>
/// Stores the key authorization values used to answer ACME HTTP-01 challenges.
/// </summary>
/// <remarks>
/// <para>
/// The default implementation keeps challenges in the memory of a single process. That is only
/// correct when exactly one instance of the application can receive the certificate authority's
/// validation request. When an application runs multiple instances behind a load balancer, the
/// instance that begins the ACME order is usually not the instance that receives the validation
/// request, so the challenge must be kept somewhere all instances can read.
/// </para>
/// <para>
/// The methods are asynchronous because an implementation may be backed by remote storage, and
/// <see cref="GetResponseAsync"/> is called while serving a request.
/// </para>
/// </remarks>
public interface IHttpChallengeResponseStore
{
    /// <summary>
    /// Records the response to send when the certificate authority requests <paramref name="token"/>.
    /// </summary>
    /// <param name="token">The challenge token issued by the certificate authority.</param>
    /// <param name="response">The key authorization value to return for the token.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task AddChallengeResponseAsync(string token, string response, CancellationToken cancellationToken = default);

    /// <summary>
    /// Looks up the response for a challenge token.
    /// </summary>
    /// <remarks>
    /// This is called for every request to the ACME challenge path, including requests from
    /// scanners probing for unknown tokens. An implementation backed by remote storage should
    /// avoid a round trip for tokens that cannot be valid.
    /// </remarks>
    /// <param name="token">The challenge token from the request path. This value is untrusted.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The key authorization value, or null when the token is unknown.</returns>
    Task<string?> GetResponseAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Discards a challenge once validation has finished.
    /// </summary>
    /// <param name="token">The challenge token to discard.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task RemoveChallengeAsync(string token, CancellationToken cancellationToken = default);
}
