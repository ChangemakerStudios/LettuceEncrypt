// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Azure;
using Azure.Security.KeyVault.Secrets;
using LettuceEncrypt.Azure.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace LettuceEncrypt.Azure.UnitTests;

public class AzureKeyVaultHttpChallengeStoreTests
{
    private const string Token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    private const string KeyAuth = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypzEt62jcerQ";

    [Fact]
    public async Task ItStoresTheChallengeAsASecret()
    {
        var (secretClient, factory) = CreateMockClient();
        var store = CreateStore(factory);

        await store.AddChallengeResponseAsync(Token, KeyAuth);

        secretClient.Verify(c => c.SetSecretAsync(
            It.Is<KeyVaultSecret>(s => s.Value == KeyAuth),
            It.IsAny<CancellationToken>()));
    }

    /// <summary>
    /// Key Vault secret names allow only alphanumerics and dashes, but ACME tokens are base64url
    /// and may contain underscores.
    /// </summary>
    [Fact]
    public void TheSecretNameIsAlwaysAValidKeyVaultName()
    {
        foreach (var token in new[] { Token, "with_underscore", "a-b_c-D_9", "z" })
        {
            var name = AzureKeyVaultHttpChallengeStore.GetSecretName(token);

            Assert.Matches("^[0-9a-zA-Z-]+$", name);
            Assert.True(name.Length <= 127);
        }
    }

    [Fact]
    public void DifferentTokensGetDifferentSecretNames()
    {
        var a = AzureKeyVaultHttpChallengeStore.GetSecretName("with_underscore");
        var b = AzureKeyVaultHttpChallengeStore.GetSecretName("with-underscore");

        // Naive character replacement would collide these two.
        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task ItReadsAChallengeWrittenByAnotherInstance()
    {
        var (secretClient, factory) = CreateMockClient();
        var name = AzureKeyVaultHttpChallengeStore.GetSecretName(Token);

        secretClient
            .Setup(c => c.GetSecretAsync(name, null, It.IsAny<CancellationToken>()))
            .Returns(Task.FromResult(Response.FromValue(new KeyVaultSecret(name, KeyAuth), null!)));

        // A store that never called Add stands in for a different application instance.
        var store = CreateStore(factory);

        Assert.Equal(KeyAuth, await store.GetResponseAsync(Token));
    }

    [Fact]
    public async Task ItReturnsNullWhenTheSecretIsAbsent()
    {
        var (secretClient, factory) = CreateMockClient();

        secretClient
            .Setup(c => c.GetSecretAsync(It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .Throws(new RequestFailedException(404, "Not found"));

        var store = CreateStore(factory);

        Assert.Null(await store.GetResponseAsync(Token));
    }

    [Fact]
    public async Task AVaultFailureIsReportedAsAnUnknownTokenRatherThanThrowing()
    {
        var (secretClient, factory) = CreateMockClient();

        secretClient
            .Setup(c => c.GetSecretAsync(It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .Throws(new RequestFailedException(429, "Throttled"));

        var store = CreateStore(factory);

        // A vault problem must not surface as a 500 on a publicly reachable path.
        Assert.Null(await store.GetResponseAsync(Token));
    }

    [Fact]
    public async Task TheWritingInstanceAnswersWithoutCallingTheVault()
    {
        var (secretClient, factory) = CreateMockClient();
        var store = CreateStore(factory);

        await store.AddChallengeResponseAsync(Token, KeyAuth);

        Assert.Equal(KeyAuth, await store.GetResponseAsync(Token));

        secretClient.Verify(
            c => c.GetSecretAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Theory]
    // Tokens arrive from the request path, so scanners control them. These must never reach Azure.
    [InlineData("../../../etc/passwd")]
    [InlineData("has space")]
    [InlineData("has.dot")]
    [InlineData("")]
    public async Task MalformedTokensNeverReachTheVault(string token)
    {
        var (secretClient, factory) = CreateMockClient();
        var store = CreateStore(factory);

        Assert.Null(await store.GetResponseAsync(token));

        secretClient.Verify(
            c => c.GetSecretAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task ARepeatedProbeForTheSameUnknownTokenOnlyQueriesTheVaultOnce()
    {
        var (secretClient, factory) = CreateMockClient();

        secretClient
            .Setup(c => c.GetSecretAsync(It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .Throws(new RequestFailedException(404, "Not found"));

        var store = CreateStore(factory);

        for (var i = 0; i < 25; i++)
        {
            Assert.Null(await store.GetResponseAsync(Token));
        }

        // Without the negative cache, a scanner hammering one valid-looking token would turn into
        // 25 calls to the vault and risk throttling.
        secretClient.Verify(
            c => c.GetSecretAsync(It.IsAny<string>(), null, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task AddingClearsAPreviousNegativeCacheEntry()
    {
        var (secretClient, factory) = CreateMockClient();

        secretClient
            .Setup(c => c.GetSecretAsync(It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .Throws(new RequestFailedException(404, "Not found"));

        var store = CreateStore(factory);

        Assert.Null(await store.GetResponseAsync(Token));

        await store.AddChallengeResponseAsync(Token, KeyAuth);

        Assert.Equal(KeyAuth, await store.GetResponseAsync(Token));
    }

    [Fact]
    public async Task ItRejectsAddingAMalformedToken()
    {
        var (_, factory) = CreateMockClient();
        var store = CreateStore(factory);

        await Assert.ThrowsAsync<ArgumentException>(
            () => store.AddChallengeResponseAsync("has space", KeyAuth));
    }

    [Fact]
    public async Task AFailureToStoreIsSurfaced()
    {
        var (secretClient, factory) = CreateMockClient();

        secretClient
            .Setup(c => c.SetSecretAsync(It.IsAny<KeyVaultSecret>(), It.IsAny<CancellationToken>()))
            .Throws(new RequestFailedException(403, "Forbidden"));

        var store = CreateStore(factory);

        // If the challenge is not in the vault, other instances cannot answer. Failing here is
        // clearer than a validation timeout that looks unrelated.
        await Assert.ThrowsAsync<RequestFailedException>(
            () => store.AddChallengeResponseAsync(Token, KeyAuth));
    }

    [Fact]
    public async Task RemovingDropsTheLocalCopyEvenIfTheVaultCallFails()
    {
        var (secretClient, factory) = CreateMockClient();
        var store = CreateStore(factory);

        await store.AddChallengeResponseAsync(Token, KeyAuth);

        secretClient
            .Setup(c => c.StartDeleteSecretAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Throws(new RequestFailedException(403, "Forbidden"));
        secretClient
            .Setup(c => c.GetSecretAsync(It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .Throws(new RequestFailedException(404, "Not found"));

        await store.RemoveChallengeAsync(Token);

        Assert.Null(await store.GetResponseAsync(Token));
    }

    private static AzureKeyVaultHttpChallengeStore CreateStore(ISecretClientFactory factory)
        => new(factory, NullLogger<AzureKeyVaultHttpChallengeStore>.Instance);

    private static (Mock<SecretClient>, ISecretClientFactory) CreateMockClient()
    {
        var secretClient = new Mock<SecretClient>();
        var secretClientFactory = new Mock<ISecretClientFactory>();
        secretClientFactory.Setup(c => c.Create()).Returns(secretClient.Object);
        return (secretClient, secretClientFactory.Object);
    }
}
