// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;

namespace LettuceEncrypt.Internal;

internal class StartupCertificateLoader(IEnumerable<ICertificateSource> certSources, CertificateSelector selector) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var allCerts = new List<X509Certificate2>();
        foreach (var certSource in certSources)
        {
            var certs = await certSource.GetCertificatesAsync(cancellationToken);
            allCerts.AddRange(certs);
        }

        // Add newer certificates first. This avoid potentially unnecessary cert validations on older certificates
        foreach (var cert in allCerts.OrderByDescending(c => c.NotAfter))
        {
            selector.Add(cert);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
        => Task.CompletedTask;
}
