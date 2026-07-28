// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using LettuceEncrypt.Azure.Internal;
using LettuceEncrypt.UnitTests;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.Azure.UnitTests;

public class AzureKeyVaultTests
{
    private static void DefaultConfigure(AzureKeyVaultLettuceEncryptOptions options)
    {
        options.AzureKeyVaultEndpoint = "http://something";
    }

    [Fact]
    public void SourceAndRepositorySameInstance()
    {
        var provider = new ServiceCollection()
            .AddSingleton<IHostEnvironment, HostingEnvironment>()
            .AddLogging()
            .AddLettuceEncrypt()
            .PersistCertificatesToAzureKeyVault(DefaultConfigure)
            .Services
            .BuildServiceProvider(validateScopes: true);


        var repository = provider.GetServices<ICertificateRepository>().OfType<AzureKeyVaultCertificateRepository>()
            .First();
        var source = provider.GetServices<ICertificateSource>().OfType<AzureKeyVaultCertificateRepository>()
            .First();

        Assert.Same(source, repository);
    }

    [Fact]
    public void MultipleCallsToPersistCertificatesToAzureKeyVaultDoesNotDuplicateServices()
    {
        var provider = new ServiceCollection()
            .AddSingleton<IHostEnvironment, HostingEnvironment>()
            .AddLogging()
            .AddLettuceEncrypt()
            .PersistCertificatesToAzureKeyVault(DefaultConfigure)
            .PersistCertificatesToAzureKeyVault(DefaultConfigure)
            .PersistCertificatesToAzureKeyVault(DefaultConfigure)
            .Services
            .BuildServiceProvider(validateScopes: true);


        Assert.Single(provider.GetServices<ICertificateRepository>().OfType<AzureKeyVaultCertificateRepository>());
        Assert.Single(provider.GetServices<ICertificateSource>().OfType<AzureKeyVaultCertificateRepository>());
    }

    [Fact]
    public async Task ImportCertificateChecksDuplicate()
    {
        const string Domain1 = "github.com";
        const string Domain2 = "azure.com";

        var certClient = new Mock<CertificateClient>();
        var certClientFactory = new Mock<ICertificateClientFactory>();
        certClientFactory.Setup(c => c.Create()).Returns(certClient.Object);
        var options = Options.Create(new LettuceEncryptOptions());

        options.Value.DomainNames = new[] { Domain1, Domain2 };

        var repository = new AzureKeyVaultCertificateRepository(
            certClientFactory.Object,
            Mock.Of<ISecretClientFactory>(),
            options,
            Options.Create(new AzureKeyVaultLettuceEncryptOptions()),
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);
        foreach (var domain in options.Value.DomainNames)
        {
            var certificateToSave = TestUtils.CreateTestCert(domain);
            await repository.SaveAsync(certificateToSave, CancellationToken.None);
        }

        certClient.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1),
            CancellationToken.None));
        certClient.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2),
            CancellationToken.None));
    }

    [Fact]
    public async Task GetCertificateLooksForDomainsAsync()
    {
        const string Domain1 = "github.com";
        const string Domain2 = "azure.com";

        var secretClient = new Mock<SecretClient>();
        var secretClientFactory = new Mock<ISecretClientFactory>();
        secretClientFactory.Setup(c => c.Create()).Returns(secretClient.Object);
        var options = Options.Create(new LettuceEncryptOptions());

        options.Value.DomainNames = new[] { Domain1, Domain2 };

        var repository = new AzureKeyVaultCertificateRepository(
            Mock.Of<ICertificateClientFactory>(),
            secretClientFactory.Object, options,
            Options.Create(new AzureKeyVaultLettuceEncryptOptions()),
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);

        var certificates = await repository.GetCertificatesAsync(CancellationToken.None);

        Assert.Empty(certificates);

        secretClient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1),
            null, CancellationToken.None));
        secretClient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2),
            null, CancellationToken.None));
    }

    [Fact]
    public async Task ASoftDeletedCertificateExplainsHowToRecoverIt()
    {
        var (certClient, certClientFactory) = CreateMockCertClient();
        var options = Options.Create(new LettuceEncryptOptions());

        certClient
            .Setup(c => c.ImportCertificateAsync(It.IsAny<ImportCertificateOptions>(), It.IsAny<CancellationToken>()))
            .Throws(SoftDeleteConflict());

        var repository = new AzureKeyVaultCertificateRepository(
            certClientFactory,
            Mock.Of<ISecretClientFactory>(),
            options,
            Options.Create(new AzureKeyVaultLettuceEncryptOptions()),
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);

        var cert = TestUtils.CreateTestCert("github.com");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => repository.SaveAsync(cert, CancellationToken.None));

        // The raw Azure error does not say what to do about it.
        Assert.Contains("az keyvault certificate recover", ex.Message, StringComparison.Ordinal);
        Assert.Contains("github-com", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASoftDeletedCertificateIsRecoveredWhenTheOptionIsSet()
    {
        var (certClient, certClientFactory) = CreateMockCertClient();
        var options = Options.Create(new LettuceEncryptOptions());

        var imported = 0;
        certClient
            .Setup(c => c.ImportCertificateAsync(It.IsAny<ImportCertificateOptions>(), It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                imported++;
                if (imported == 1)
                {
                    throw SoftDeleteConflict();
                }

                return Task.FromResult(Response.FromValue(default(KeyVaultCertificateWithPolicy)!, null!));
            });

        var recoverOperation = new Mock<RecoverDeletedCertificateOperation>();
        certClient
            .Setup(c => c.StartRecoverDeletedCertificateAsync("github-com", It.IsAny<CancellationToken>()))
            .Returns(Task.FromResult(recoverOperation.Object));

        var repository = new AzureKeyVaultCertificateRepository(
            certClientFactory,
            Mock.Of<ISecretClientFactory>(),
            options,
            Options.Create(new AzureKeyVaultLettuceEncryptOptions { RecoverDeletedCertificates = true }),
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);

        await repository.SaveAsync(TestUtils.CreateTestCert("github.com"), CancellationToken.None);

        certClient.Verify(
            c => c.StartRecoverDeletedCertificateAsync("github-com", It.IsAny<CancellationToken>()),
            Times.Once);
        Assert.Equal(2, imported);
    }

    [Fact]
    public async Task AnUnrelatedConflictIsNotTreatedAsASoftDelete()
    {
        var (certClient, certClientFactory) = CreateMockCertClient();
        var options = Options.Create(new LettuceEncryptOptions());

        certClient
            .Setup(c => c.ImportCertificateAsync(It.IsAny<ImportCertificateOptions>(), It.IsAny<CancellationToken>()))
            .Throws(new RequestFailedException(409, "Some other conflict"));

        var repository = new AzureKeyVaultCertificateRepository(
            certClientFactory,
            Mock.Of<ISecretClientFactory>(),
            options,
            Options.Create(new AzureKeyVaultLettuceEncryptOptions { RecoverDeletedCertificates = true }),
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);

        await Assert.ThrowsAsync<RequestFailedException>(
            () => repository.SaveAsync(TestUtils.CreateTestCert("github.com"), CancellationToken.None));

        certClient.Verify(
            c => c.StartRecoverDeletedCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    private static RequestFailedException SoftDeleteConflict()
        => new(409,
            "Certificate github-com is currently in a deleted but recoverable state, and its name cannot be " +
            "reused; in this state, the certificate can only be recovered or purged. " +
            "innererror: ObjectIsDeletedButRecoverable",
            "Conflict",
            null);

    private static (Mock<CertificateClient>, ICertificateClientFactory) CreateMockCertClient()
    {
        var certClient = new Mock<CertificateClient>();
        var factory = new Mock<ICertificateClientFactory>();
        factory.Setup(c => c.Create()).Returns(certClient.Object);
        return (certClient, factory.Object);
    }
}
