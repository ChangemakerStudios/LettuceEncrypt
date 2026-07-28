// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Text;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

/// <summary>
/// Stores HTTP-01 challenge responses as files so that every application instance sharing the
/// directory can answer a validation request, regardless of which instance began the ACME order.
/// </summary>
internal class FileSystemHttpChallengeStore : IHttpChallengeResponseStore
{
    // Challenge tokens are base64url values per RFC 8555 section 8.3. Anything else is either a
    // probe or an attempt at path traversal, and must never reach the file system.
    private const int MaxTokenLength = 256;

    private static readonly TimeSpan s_challengeTtl = TimeSpan.FromHours(1);
    private static readonly UTF8Encoding s_utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private readonly DirectoryInfo _challengeDir;
    private readonly ILogger<FileSystemHttpChallengeStore> _logger;

    public FileSystemHttpChallengeStore(DirectoryInfo directory, ILogger<FileSystemHttpChallengeStore> logger)
    {
        if (directory is null)
        {
            throw new ArgumentNullException(nameof(directory));
        }

        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _challengeDir = directory.CreateSubdirectory("challenges");
    }

    public void AddChallengeResponse(string token, string response)
    {
        if (!IsValidToken(token))
        {
            throw new ArgumentException("Challenge token contains characters that are not valid base64url.", nameof(token));
        }

        _challengeDir.Create();

        // Write to a temporary file and move it into place. File.Move is atomic on most file
        // systems, so a concurrent reader never observes a partially written challenge.
        var tmpFile = Path.Combine(_challengeDir.FullName, Path.GetRandomFileName());

        try
        {
            File.WriteAllText(tmpFile, response, s_utf8NoBom);
            File.Move(tmpFile, GetChallengePath(token), overwrite: true);
        }
        catch (Exception)
        {
            TryDelete(tmpFile);
            throw;
        }

        _logger.LogDebug("Wrote HTTP challenge response for token {Token} to shared storage", token);

        RemoveExpiredChallenges();
    }

    public bool TryGetResponse(string token, out string? value)
    {
        value = null;

        // The token arrives from the request path, so it is untrusted. Reject anything that is not
        // a plain base64url value before it is used to build a file path.
        if (!IsValidToken(token))
        {
            _logger.LogTrace("Ignoring HTTP challenge request for malformed token");
            return false;
        }

        try
        {
            var path = GetChallengePath(token);

            if (!File.Exists(path))
            {
                _logger.LogTrace("No HTTP challenge response found for token {Token}", token);
                return false;
            }

            value = File.ReadAllText(path, s_utf8NoBom);
            _logger.LogTrace("Retrieved HTTP challenge response for token {Token} from shared storage", token);
            return true;
        }
        catch (IOException ex)
        {
            // A read failure must not fail the request. Report the challenge as unknown and let the
            // certificate authority retry.
            _logger.LogWarning(ex, "Could not read HTTP challenge response for token {Token}", token);
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Access denied reading HTTP challenge response for token {Token}", token);
            return false;
        }
    }

    public void RemoveChallenge(string token)
    {
        if (!IsValidToken(token))
        {
            return;
        }

        if (TryDelete(GetChallengePath(token)))
        {
            _logger.LogDebug("Removed HTTP challenge response for token {Token} from shared storage", token);
        }
    }

    private string GetChallengePath(string token) => Path.Combine(_challengeDir.FullName, token);

    /// <summary>
    /// Deletes challenges left behind by an instance that stopped before it could clean up.
    /// </summary>
    private void RemoveExpiredChallenges()
    {
        try
        {
            var cutoff = DateTimeOffset.UtcNow - s_challengeTtl;
            var expired = _challengeDir
                .GetFiles()
                .Where(f => f.LastWriteTimeUtc < cutoff)
                .ToList();

            if (expired.Count == 0)
            {
                return;
            }

            _logger.LogInformation(
                "Cleaning up {Count} expired HTTP challenge(s) older than {TTL} from shared storage",
                expired.Count, s_challengeTtl);

            foreach (var file in expired)
            {
                TryDelete(file.FullName);
            }
        }
        catch (Exception ex)
        {
            // Cleanup is opportunistic. Never let it interrupt an in-flight certificate order.
            _logger.LogWarning(ex, "Error during HTTP challenge cleanup");
        }
    }

    private static bool TryDelete(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            File.Delete(path);
            return true;
        }
        catch (IOException)
        {
            // Another instance may have removed the file, or it may be briefly locked. Either way
            // the expiry sweep will retry later.
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsValidToken(string? token)
    {
        if (string.IsNullOrEmpty(token) || token!.Length > MaxTokenLength)
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
