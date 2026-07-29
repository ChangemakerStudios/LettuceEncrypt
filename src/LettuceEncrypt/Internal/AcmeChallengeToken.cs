// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal;

/// <summary>
/// Validation for ACME challenge tokens.
/// </summary>
/// <remarks>
/// Tokens reach <see cref="IHttpChallengeResponseStore.GetResponseAsync"/> straight from the
/// request path, so they are attacker controlled. Every store must screen them before the value is
/// used to address storage: a file-backed store would otherwise be open to path traversal, and a
/// remotely backed store would make a network call for every scanner probe.
/// </remarks>
internal static class AcmeChallengeToken
{
    /// <summary>
    /// Real tokens are 43 characters, but the specification does not fix a length. This bound only
    /// needs to reject values that are obviously not tokens.
    /// </summary>
    private const int MaxLength = 256;

    /// <summary>
    /// Returns true when the value is a plain base64url string, as required by RFC 8555 section 8.3.
    /// </summary>
    public static bool IsValid(string? token)
    {
        if (string.IsNullOrEmpty(token) || token!.Length > MaxLength)
        {
            return false;
        }

        foreach (var c in token)
        {
            var isBase64Url = c is (>= 'a' and <= 'z')
                or (>= 'A' and <= 'Z')
                or (>= '0' and <= '9')
                or '-'
                or '_';

            if (!isBase64Url)
            {
                return false;
            }
        }

        return true;
    }
}
