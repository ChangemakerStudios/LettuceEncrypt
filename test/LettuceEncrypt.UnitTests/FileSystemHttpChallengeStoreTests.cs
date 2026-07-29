// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class FileSystemHttpChallengeStoreTests : IDisposable
{
    private readonly DirectoryInfo _testDir;

    public FileSystemHttpChallengeStoreTests()
    {
        _testDir = new DirectoryInfo(
            Path.Combine(Path.GetTempPath(), "LettuceEncrypt.Tests", Guid.NewGuid().ToString("N")));
        _testDir.Create();
    }

    private FileSystemHttpChallengeStore CreateStore()
        => CreateStore(_testDir);

    private static FileSystemHttpChallengeStore CreateStore(DirectoryInfo directory)
        => new(directory, NullLogger<FileSystemHttpChallengeStore>.Instance);

    [Fact]
    public async Task ItRoundTripsAChallengeResponse()
    {
        var store = CreateStore();

        await store.AddChallengeResponseAsync("token-abc", "key-authorization-value");

        Assert.Equal("key-authorization-value", await store.GetResponseAsync("token-abc"));
    }

    [Fact]
    public async Task ItReturnsNullForUnknownToken()
    {
        var store = CreateStore();

        Assert.Null(await store.GetResponseAsync("never-added"));
    }

    [Fact]
    public async Task ItRemovesAChallenge()
    {
        var store = CreateStore();
        await store.AddChallengeResponseAsync("token-abc", "value");

        await store.RemoveChallengeAsync("token-abc");

        Assert.Null(await store.GetResponseAsync("token-abc"));
    }

    [Fact]
    public async Task RemovingAnUnknownChallengeDoesNotThrow()
    {
        var store = CreateStore();

        await store.RemoveChallengeAsync("never-added");
    }

    [Fact]
    public async Task ItOverwritesAnExistingToken()
    {
        var store = CreateStore();

        await store.AddChallengeResponseAsync("token-abc", "first");
        await store.AddChallengeResponseAsync("token-abc", "second");

        Assert.Equal("second", await store.GetResponseAsync("token-abc"));
    }

    /// <summary>
    /// A second store over the same directory stands in for a second application instance sharing
    /// a volume. This is the whole point of the file-backed store.
    /// </summary>
    [Fact]
    public async Task AnotherInstanceSharingTheDirectoryCanAnswerTheChallenge()
    {
        var writer = CreateStore();
        var reader = CreateStore(new DirectoryInfo(_testDir.FullName));

        await writer.AddChallengeResponseAsync("token-abc", "key-authorization-value");

        Assert.Equal("key-authorization-value", await reader.GetResponseAsync("token-abc"));
    }

    [Theory]
    // The token is taken from the request path, so it is attacker controlled.
    [InlineData("../../../etc/passwd")]
    [InlineData("..\\..\\..\\windows\\win.ini")]
    [InlineData("../secrets")]
    [InlineData("sub/dir")]
    [InlineData("has space")]
    [InlineData("has.dot")]
    [InlineData("")]
    public async Task ItRejectsTokensThatAreNotBase64Url(string token)
    {
        var store = CreateStore();

        Assert.Null(await store.GetResponseAsync(token));
    }

    [Fact]
    public async Task ItDoesNotReadFilesOutsideTheChallengeDirectory()
    {
        var secretPath = Path.Combine(_testDir.FullName, "secret.txt");
        File.WriteAllText(secretPath, "sensitive");

        var store = CreateStore();

        Assert.Null(await store.GetResponseAsync("../secret.txt"));
        Assert.True(File.Exists(secretPath));
    }

    [Fact]
    public async Task ItRejectsAddingAMalformedToken()
    {
        var store = CreateStore();

        await Assert.ThrowsAsync<ArgumentException>(
            () => store.AddChallengeResponseAsync("../escape", "value"));
    }

    [Fact]
    public async Task ItDoesNotDeleteFilesOutsideTheChallengeDirectory()
    {
        var secretPath = Path.Combine(_testDir.FullName, "secret.txt");
        File.WriteAllText(secretPath, "sensitive");

        var store = CreateStore();
        await store.RemoveChallengeAsync("../secret.txt");

        Assert.True(File.Exists(secretPath));
    }

    [Fact]
    public async Task ItAcceptsARealisticAcmeToken()
    {
        var store = CreateStore();

        // Shape of a real RFC 8555 token: base64url, no padding.
        const string Token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
        const string KeyAuth = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypzEt62jcerQ";

        await store.AddChallengeResponseAsync(Token, KeyAuth);

        Assert.Equal(KeyAuth, await store.GetResponseAsync(Token));
    }

    [Fact]
    public async Task ItWritesWithoutAByteOrderMark()
    {
        var store = CreateStore();
        await store.AddChallengeResponseAsync("token-abc", "value");

        var file = Path.Combine(_testDir.FullName, "challenges", "token-abc");
        var bytes = File.ReadAllBytes(file);

        // A BOM would be sent to the certificate authority and fail the key authorization compare.
        Assert.Equal("value", System.Text.Encoding.UTF8.GetString(bytes));
        Assert.NotEqual(0xEF, bytes[0]);
    }

    [Fact]
    public async Task ItLeavesNoTemporaryFilesBehind()
    {
        var store = CreateStore();
        await store.AddChallengeResponseAsync("token-abc", "value");

        var challengeDir = new DirectoryInfo(Path.Combine(_testDir.FullName, "challenges"));

        Assert.Single(challengeDir.GetFiles());
    }

    public void Dispose()
    {
        try
        {
            _testDir.Delete(recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
