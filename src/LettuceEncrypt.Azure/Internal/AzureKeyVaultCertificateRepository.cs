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
    private readonly IOptions<AzureKeyVaultLettuceEncryptOptions> _keyVaultOptions;
    private readonly ILogger<AzureKeyVaultCertificateRepository> _logger;
    private readonly ICertificateClientFactory _certificateClientFactory;
    private readonly ISecretClientFactory _secretClientFactory;

    public AzureKeyVaultCertificateRepository(
        ICertificateClientFactory certificateClientFactory,
        ISecretClientFactory secretClientFactory,
        IOptions<LettuceEncryptOptions> encryptOptions,
        IOptions<AzureKeyVaultLettuceEncryptOptions> keyVaultOptions,
        ILogger<AzureKeyVaultCertificateRepository> logger)
    {
        _certificateClientFactory = certificateClientFactory ??
                                    throw new ArgumentNullException(nameof(_certificateClientFactory));
        _secretClientFactory = secretClientFactory ?? throw new ArgumentNullException(nameof(secretClientFactory));
        _encryptOptions = encryptOptions ?? throw new ArgumentNullException(nameof(encryptOptions));
        _keyVaultOptions = keyVaultOptions ?? throw new ArgumentNullException(nameof(keyVaultOptions));
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

        var certificateName = NormalizeHostName(domainName);

        try
        {
            var certificateClient = _certificateClientFactory.Create();

            try
            {
                await certificateClient.ImportCertificateAsync(options, cancellationToken);
            }
            catch (RequestFailedException ex) when (IsDeletedButRecoverable(ex))
            {
                await RecoverAndRetryImportAsync(
                    certificateClient, certificateName, domainName, options, cancellationToken);
            }

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

    /// <summary>
    /// A soft-deleted certificate keeps its name reserved, and a read of it returns 404 rather than
    /// anything that reveals the deleted state. The conflict on import is the first sign of it.
    /// </summary>
    private static bool IsDeletedButRecoverable(RequestFailedException ex)
        => ex.Status == 409
           && ex.Message.Contains("ObjectIsDeletedButRecoverable", StringComparison.OrdinalIgnoreCase);

    private async Task RecoverAndRetryImportAsync(
        CertificateClient certificateClient,
        string certificateName,
        string domainName,
        ImportCertificateOptions options,
        CancellationToken cancellationToken)
    {
        if (!_keyVaultOptions.Value.RecoverDeletedCertificates)
        {
            throw new InvalidOperationException(
                $"The certificate '{certificateName}' is soft-deleted in Azure KeyVault, which reserves " +
                $"its name and prevents a new certificate for {domainName} from being saved. The certificate " +
                $"was issued successfully but cannot be persisted, so it will be lost when this process stops. " +
                $"Recover it with 'az keyvault certificate recover --vault-name <vault> --name {certificateName}', " +
                $"or set RecoverDeletedCertificates to true in AzureKeyVaultLettuceEncryptOptions to have this " +
                $"happen automatically. Purging is the alternative, but it is irreversible and is refused " +
                $"outright on a vault with purge protection enabled.");
        }

        _logger.LogWarning(
            "The certificate '{CertificateName}' is soft-deleted in Azure KeyVault, which reserves its name. " +
            "Recovering it so the certificate for {domainName} can be saved.",
            certificateName, domainName);

        var operation = await certificateClient.StartRecoverDeletedCertificateAsync(certificateName, cancellationToken);
        await operation.WaitForCompletionAsync(cancellationToken);

        _logger.LogInformation(
            "Recovered the soft-deleted certificate '{CertificateName}'. Retrying the import.", certificateName);

        await certificateClient.ImportCertificateAsync(options, cancellationToken);
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
        // X509Certificate2.NotBefore and NotAfter are expressed in local time, so they must be
        // converted before being compared against a UTC timestamp. Otherwise the comparison is
        // wrong by the machine's UTC offset.
        // Check if certificate has expired
        if (certificate.NotAfter.ToUniversalTime() < DateTime.UtcNow)
        {
            _logger.LogWarning(
                "Certificate for {domainName} has expired (NotAfter: {NotAfter}). It will not be used.",
                domainName, certificate.NotAfter);
            return false;
        }

        // Check if certificate is not yet valid
        if (certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow)
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
