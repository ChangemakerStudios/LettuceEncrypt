// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Azure.Internal;

internal interface ICertificateClientFactory
{
    CertificateClient Create();
}

internal class CertificateClientFactory : ICertificateClientFactory
{
    private readonly IOptions<AzureKeyVaultLettuceEncryptOptions> _options;
    private readonly Lazy<CertificateClient> _client;

    public CertificateClientFactory(IOptions<AzureKeyVaultLettuceEncryptOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _client = new Lazy<CertificateClient>(CreateClient);
    }

    public CertificateClient Create() => _client.Value;

    private CertificateClient CreateClient()
    {
        var value = _options.Value;

        if (string.IsNullOrEmpty(value.AzureKeyVaultEndpoint))
        {
            throw new ArgumentException("Missing required option: AzureKeyVaultEndpoint");
        }

        var vaultUri = new Uri(value.AzureKeyVaultEndpoint);
        var credentials = value.Credentials ?? new DefaultAzureCredential();

        var clientOptions = new CertificateClientOptions
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

        return new CertificateClient(vaultUri, credentials, clientOptions);
    }
}
