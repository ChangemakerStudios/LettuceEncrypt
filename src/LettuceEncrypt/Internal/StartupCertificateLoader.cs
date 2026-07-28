// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

internal class StartupCertificateLoader(
    IEnumerable<ICertificateSource> certSources,
    CertificateSelector selector,
    ILogger<StartupCertificateLoader> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        logger.LogDebug("Loading existing certificates from {SourceCount} certificate source(s)", certSources.Count());

        var allCerts = new List<X509Certificate2>();
        foreach (var certSource in certSources)
        {
            var certs = await certSource.GetCertificatesAsync(cancellationToken);
            allCerts.AddRange(certs);
        }

        logger.LogInformation("Found {CertificateCount} existing certificate(s) to validate and load", allCerts.Count);

        var validCerts = 0;
        var invalidCerts = 0;
        var expiredCerts = 0;
        var expiringSoonCerts = 0;

        // Add newer certificates first. This avoid potentially unnecessary cert validations on older certificates
        foreach (var cert in allCerts.OrderByDescending(c => c.NotAfter))
        {
            var validationResult = ValidateCertificate(cert);
            if (validationResult == CertificateValidationResult.Valid)
            {
                selector.Add(cert);
                validCerts++;
            }
            else if (validationResult == CertificateValidationResult.Expired)
            {
                expiredCerts++;
            }
            else if (validationResult == CertificateValidationResult.ExpiringSoon)
            {
                selector.Add(cert);
                expiringSoonCerts++;
            }
            else
            {
                invalidCerts++;
            }
        }

        if (validCerts > 0)
        {
            logger.LogInformation("Loaded {ValidCount} valid certificate(s)", validCerts);
        }

        if (expiringSoonCerts > 0)
        {
            logger.LogWarning("Loaded {ExpiringSoonCount} certificate(s) that expire within 30 days and need renewal", expiringSoonCerts);
        }

        if (expiredCerts > 0)
        {
            logger.LogWarning("Skipped {ExpiredCount} expired certificate(s)", expiredCerts);
        }

        if (invalidCerts > 0)
        {
            logger.LogWarning("Skipped {InvalidCount} invalid or corrupted certificate(s)", invalidCerts);
        }
    }

    private enum CertificateValidationResult
    {
        Valid,
        Expired,
        ExpiringSoon,
        Invalid
    }

    private CertificateValidationResult ValidateCertificate(X509Certificate2 cert)
    {
        try
        {
            var now = DateTime.UtcNow;

            // X509Certificate2.NotBefore and NotAfter are expressed in local time. They must be
            // converted before being compared against a UTC timestamp, or the comparison is wrong
            // by the machine's UTC offset: certificates appear to expire early west of UTC, and
            // freshly issued certificates appear to be not yet valid east of it.
            var notBefore = cert.NotBefore.ToUniversalTime();
            var notAfter = cert.NotAfter.ToUniversalTime();

            // Check if certificate has a private key
            if (!cert.HasPrivateKey)
            {
                logger.LogWarning(
                    "Certificate '{Subject}' (thumbprint: {Thumbprint}) does not have a private key. Skipping.",
                    cert.Subject,
                    cert.Thumbprint);
                return CertificateValidationResult.Invalid;
            }

            // Check if certificate is expired
            if (notAfter <= now)
            {
                logger.LogWarning(
                    "Certificate '{Subject}' (thumbprint: {Thumbprint}) expired on {ExpiryDate}. Skipping.",
                    cert.Subject,
                    cert.Thumbprint,
                    cert.NotAfter);
                return CertificateValidationResult.Expired;
            }

            // Check if certificate is not yet valid
            if (notBefore > now)
            {
                logger.LogWarning(
                    "Certificate '{Subject}' (thumbprint: {Thumbprint}) is not yet valid (starts: {StartDate}). Skipping.",
                    cert.Subject,
                    cert.Thumbprint,
                    cert.NotBefore);
                return CertificateValidationResult.Invalid;
            }

            // Warn if certificate expires soon (within 30 days)
            var daysUntilExpiry = (notAfter - now).TotalDays;
            if (daysUntilExpiry <= 30)
            {
                logger.LogWarning(
                    "Certificate '{Subject}' (thumbprint: {Thumbprint}) expires in {Days:F1} days on {ExpiryDate}. Renewal needed.",
                    cert.Subject,
                    cert.Thumbprint,
                    daysUntilExpiry,
                    cert.NotAfter);
                return CertificateValidationResult.ExpiringSoon;
            }

            logger.LogDebug(
                "Certificate '{Subject}' (thumbprint: {Thumbprint}) is valid. Expires in {Days:F1} days on {ExpiryDate}.",
                cert.Subject,
                cert.Thumbprint,
                daysUntilExpiry,
                cert.NotAfter);

            return CertificateValidationResult.Valid;
        }
        catch (Exception ex)
        {
            logger.LogError(ex,
                "Failed to validate certificate '{Subject}' (thumbprint: {Thumbprint}). Error: {ErrorMessage}. Skipping.",
                cert.Subject,
                cert.Thumbprint,
                ex.Message);
            return CertificateValidationResult.Invalid;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
        => Task.CompletedTask;
}
