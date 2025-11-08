// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Azure.Internal;

internal interface ISecretClientFactory
{
    SecretClient Create();
}

internal class SecretClientFactory : ISecretClientFactory
{
    private readonly IOptions<AzureKeyVaultLettuceEncryptOptions> _options;
    private readonly Lazy<SecretClient> _client;

    public SecretClientFactory(IOptions<AzureKeyVaultLettuceEncryptOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _client = new Lazy<SecretClient>(CreateClient);
    }

    public SecretClient Create() => _client.Value;

    private SecretClient CreateClient()
    {
        var value = _options.Value;

        if (string.IsNullOrEmpty(value.AzureKeyVaultEndpoint))
        {
            throw new ArgumentException("Missing required option: AzureKeyVaultEndpoint");
        }

        var vaultUri = new Uri(value.AzureKeyVaultEndpoint);
        var credentials = value.Credentials ?? new DefaultAzureCredential();

        var clientOptions = new SecretClientOptions
        {
            Retry =
            {
                Mode = RetryMode.Exponential,
                MaxRetries = 3,
                Delay = TimeSpan.FromSeconds(1),
                MaxDelay = TimeSpan.FromSeconds(16),
                NetworkTimeout = TimeSpan.FromSeconds(100)
            }
        };

        return new SecretClient(vaultUri, credentials, clientOptions);
    }
}
