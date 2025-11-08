// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Azure.Internal;

internal class AzureKeyVaultCertificateRepository : ICertificateRepository, ICertificateSource
{
    private readonly IOptions<LettuceEncryptOptions> _encryptOptions;
    private readonly ILogger<AzureKeyVaultCertificateRepository> _logger;
    private readonly ICertificateClientFactory _certificateClientFactory;
    private readonly ISecretClientFactory _secretClientFactory;

    public AzureKeyVaultCertificateRepository(
        ICertificateClientFactory certificateClientFactory,
        ISecretClientFactory secretClientFactory,
        IOptions<LettuceEncryptOptions> encryptOptions,
        ILogger<AzureKeyVaultCertificateRepository> logger)
    {
        _certificateClientFactory = certificateClientFactory ??
                                    throw new ArgumentNullException(nameof(_certificateClientFactory));
        _secretClientFactory = secretClientFactory ?? throw new ArgumentNullException(nameof(secretClientFactory));
        _encryptOptions = encryptOptions ?? throw new ArgumentNullException(nameof(encryptOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
    {
        var certs = new List<X509Certificate2>();

        foreach (var domain in _encryptOptions.Value.DomainNames)
        {
            var cert = await GetCertificateWithPrivateKeyAsync(domain, cancellationToken);

            if (cert != null && IsCertificateValid(cert, domain))
            {
                certs.Add(cert);
            }
            else if (cert != null)
            {
                // Certificate was retrieved but is invalid, dispose it
                cert.Dispose();
            }
        }

        return certs;
    }

    private async Task<X509Certificate2?> GetCertificateAsync(string domainName, CancellationToken token)
    {
        _logger.LogDebug("Searching for certificate metadata in KeyVault for {domainName}", domainName);

        try
        {
            var normalizedName = NormalizeHostName(domainName);
            var certificateClient = _certificateClientFactory.Create();

            var certificate = await certificateClient.GetCertificateAsync(normalizedName, token);

            if (certificate?.Value?.Cer == null)
            {
                _logger.LogWarning("Certificate response for {domainName} was null or empty", domainName);
                return null;
            }

            return new X509Certificate2(certificate.Value.Cer);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogDebug("Could not find certificate for {domainName} in Azure KeyVault", domainName);
            return null;
        }
        catch (CredentialUnavailableException ex)
        {
            _logger.LogError(ex, "Could not retrieve credentials for Azure Key Vault");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Unexpected error attempting to retrieve certificate for {domainName} from Azure KeyVault. Verify settings and try again.",
                domainName);
            throw;
        }
    }

    private async Task<X509Certificate2?> GetCertificateWithPrivateKeyAsync(string domainName, CancellationToken token)
    {
        _logger.LogDebug("Searching for certificate with private key in KeyVault for {domainName}", domainName);

        try
        {
            var normalizedName = NormalizeHostName(domainName);
            var secretClient = _secretClientFactory.Create();

            var certificate = await secretClient.GetSecretAsync(normalizedName, null, token);

            if (certificate?.Value?.Value == null)
            {
                _logger.LogWarning("Certificate secret for {domainName} was null or empty", domainName);
                return null;
            }

            var certBytes = Convert.FromBase64String(certificate.Value.Value);
            var cert = new X509Certificate2(certBytes, (string?)null, X509KeyStorageFlags.Exportable);

            _logger.LogInformation(
                "Found certificate for {domainName} from Azure Key Vault with thumbprint {thumbprint}",
                domainName, cert.Thumbprint);

            return cert;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogDebug("Could not find certificate for {domainName} in Azure KeyVault", domainName);
            return null;
        }
        catch (CredentialUnavailableException ex)
        {
            _logger.LogError(ex, "Could not retrieve credentials for Azure Key Vault");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Unexpected error attempting to retrieve certificate for {domainName} from Azure KeyVault. Verify settings and try again.",
                domainName);
            throw;
        }
    }

    public async Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        var domainName = certificate.GetNameInfo(X509NameType.DnsName, false);

        _logger.LogInformation("Saving certificate for {domainName} in Azure KeyVault.", domainName);

        if (!await ShouldImportVersionAsync(domainName, certificate, cancellationToken))
        {
            _logger.LogInformation(
                "Certificate for {domainName} is already up-to-date in Azure KeyVault. Skipping import.",
                domainName);
            return;
        }

        byte[] exported;
        try
        {
            // Export with empty password for compatibility with Azure Key Vault
            // Azure Key Vault will manage the certificate security
            exported = certificate.Export(X509ContentType.Pfx, string.Empty);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to export certificate for {domainName}. Cannot save to Azure KeyVault.", domainName);
            throw new InvalidOperationException($"Failed to export certificate for {domainName}", ex);
        }

        var options = new ImportCertificateOptions(NormalizeHostName(domainName), exported)
        {
            Enabled = true
        };

        try
        {
            var certificateClient = _certificateClientFactory.Create();

            await certificateClient.ImportCertificateAsync(options, cancellationToken);

            _logger.LogInformation("Successfully imported certificate into Azure KeyVault for {domainName}", domainName);
        }
        catch (RequestFailedException ex)
        {
            _logger.LogError(ex, "Failed to save certificate for {domainName} to Azure KeyVault", domainName);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error saving certificate for {domainName} to Azure KeyVault", domainName);
            throw;
        }
    }

    private async ValueTask<bool> ShouldImportVersionAsync(string domainName, X509Certificate2 certificate,
        CancellationToken token)
    {
        using var other = await GetCertificateAsync(domainName, token);

        if (other is null)
        {
            return true;
        }

        return !string.Equals(certificate.Thumbprint, other.Thumbprint, StringComparison.Ordinal);
    }

    private bool IsCertificateValid(X509Certificate2 certificate, string domainName)
    {
        // Check if certificate has expired
        if (certificate.NotAfter < DateTime.UtcNow)
        {
            _logger.LogWarning(
                "Certificate for {domainName} has expired (NotAfter: {NotAfter}). It will not be used.",
                domainName, certificate.NotAfter);
            return false;
        }

        // Check if certificate is not yet valid
        if (certificate.NotBefore > DateTime.UtcNow)
        {
            _logger.LogWarning(
                "Certificate for {domainName} is not yet valid (NotBefore: {NotBefore}). It will not be used.",
                domainName, certificate.NotBefore);
            return false;
        }

        // Check if certificate has a private key
        if (!certificate.HasPrivateKey)
        {
            _logger.LogWarning(
                "Certificate for {domainName} does not have a private key. It will not be used.",
                domainName);
            return false;
        }

        _logger.LogDebug(
            "Certificate for {domainName} is valid (NotBefore: {NotBefore}, NotAfter: {NotAfter})",
            domainName, certificate.NotBefore, certificate.NotAfter);

        return true;
    }

    /// <summary>
    /// Names must follow the regular expression <c>/^[0-9a-zA-Z-]+$/</c>
    /// See https://docs.microsoft.com/en-us/rest/api/keyvault/ImportCertificate/ImportCertificate.
    /// </summary>
    internal static string NormalizeHostName(string hostName) =>
        hostName.Replace(".", "-")
            .Replace("*", "-");
}
