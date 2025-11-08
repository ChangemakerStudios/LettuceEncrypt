// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Text.Json;
using Azure;
using Azure.Identity;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Azure.Internal;

internal class AzureKeyVaultAccountStore : IAccountStore
{
    private readonly ILogger<AzureKeyVaultAccountStore> _logger;
    private readonly IOptions<AzureKeyVaultLettuceEncryptOptions> _options;
    private readonly ICertificateAuthorityConfiguration _certificateAuthority;
    private readonly ISecretClientFactory _secretClientFactory;

    public AzureKeyVaultAccountStore(
        ILogger<AzureKeyVaultAccountStore> logger,
        IOptions<AzureKeyVaultLettuceEncryptOptions> options,
        ISecretClientFactory secretClientFactory,
        ICertificateAuthorityConfiguration certificateAuthority)
    {
        _logger = logger;
        _options = options;
        _secretClientFactory = secretClientFactory;
        _certificateAuthority = certificateAuthority;
    }

    public async Task SaveAccountAsync(AccountModel account, CancellationToken cancellationToken)
    {
        if (account == null)
        {
            throw new ArgumentNullException(nameof(account));
        }

        var secretName = GetSecretName();
        _logger.LogDebug("Saving account information to Azure Key Vault as {secretName}", secretName);

        string secretValue;
        try
        {
            secretValue = JsonSerializer.Serialize(account);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to serialize account information");
            throw new InvalidOperationException("Failed to serialize account information", ex);
        }

        try
        {
            var secretClient = _secretClientFactory.Create();
            await secretClient.SetSecretAsync(secretName, secretValue, cancellationToken);
            _logger.LogInformation("Successfully saved account information to Azure Key Vault as {secretName}", secretName);
        }
        catch (CredentialUnavailableException ex)
        {
            _logger.LogError(ex, "Could not retrieve credentials for Azure Key Vault");
            throw;
        }
        catch (RequestFailedException ex)
        {
            _logger.LogError(ex, "Azure Key Vault request failed while saving account information to {secretName}", secretName);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error saving account information to Azure Key Vault as {secretName}", secretName);
            throw;
        }
    }

    public async Task<AccountModel?> GetAccountAsync(CancellationToken cancellationToken)
    {
        var secretName = GetSecretName();
        _logger.LogDebug("Retrieving account information from Azure Key Vault secret {secretName}", secretName);

        try
        {
            var secretClient = _secretClientFactory.Create();
            var secret = await secretClient.GetSecretAsync(secretName, version: null, cancellationToken);

            _logger.LogInformation("Found account key in {secretName}, version {version}",
                secret.Value.Name,
                secret.Value.Properties.Version);

            var account = JsonSerializer.Deserialize<AccountModel>(secret.Value.Value);

            if (account == null)
            {
                _logger.LogWarning("Account information in secret '{secretName}' was null or could not be deserialized", secretName);
                return null;
            }

            return account;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogDebug("Could not find account information in secret '{secretName}' in Azure Key Vault", secretName);
            return null;
        }
        catch (CredentialUnavailableException ex)
        {
            _logger.LogError(ex, "Could not retrieve credentials for Azure Key Vault");
            throw;
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Failed to deserialize account information from secret '{secretName}'", secretName);
            throw new InvalidOperationException($"Failed to deserialize account information from secret '{secretName}'", ex);
        }
        catch (RequestFailedException ex)
        {
            _logger.LogError(ex, "Azure Key Vault request failed while fetching secret '{secretName}'", secretName);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error fetching secret '{secretName}' from Azure Key Vault", secretName);
            throw;
        }
    }

    private string GetSecretName()
    {
        const int MaxLength = 127;

        var options = _options.Value;
        var name = !string.IsNullOrEmpty(options.AccountKeySecretName)
            ? options.AccountKeySecretName!
            : _certificateAuthority.AcmeDirectoryUri.Host;

        name = "le-account-" + name.Replace(".", "-");
        return name.Length > MaxLength ? name[..MaxLength] : name;
    }
}
