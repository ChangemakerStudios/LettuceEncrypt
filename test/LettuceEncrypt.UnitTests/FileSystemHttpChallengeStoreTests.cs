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
    public void ItRoundTripsAChallengeResponse()
    {
        var store = CreateStore();

        store.AddChallengeResponse("token-abc", "key-authorization-value");

        Assert.True(store.TryGetResponse("token-abc", out var value));
        Assert.Equal("key-authorization-value", value);
    }

    [Fact]
    public void ItReturnsFalseForUnknownToken()
    {
        var store = CreateStore();

        Assert.False(store.TryGetResponse("never-added", out var value));
        Assert.Null(value);
    }

    [Fact]
    public void ItRemovesAChallenge()
    {
        var store = CreateStore();
        store.AddChallengeResponse("token-abc", "value");

        store.RemoveChallenge("token-abc");

        Assert.False(store.TryGetResponse("token-abc", out _));
    }

    [Fact]
    public void RemovingAnUnknownChallengeDoesNotThrow()
    {
        var store = CreateStore();

        store.RemoveChallenge("never-added");
    }

    [Fact]
    public void ItOverwritesAnExistingToken()
    {
        var store = CreateStore();

        store.AddChallengeResponse("token-abc", "first");
        store.AddChallengeResponse("token-abc", "second");

        Assert.True(store.TryGetResponse("token-abc", out var value));
        Assert.Equal("second", value);
    }

    /// <summary>
    /// A second store over the same directory stands in for a second application instance sharing
    /// a volume. This is the whole point of the file-backed store.
    /// </summary>
    [Fact]
    public void AnotherInstanceSharingTheDirectoryCanAnswerTheChallenge()
    {
        var writer = CreateStore();
        var reader = CreateStore(new DirectoryInfo(_testDir.FullName));

        writer.AddChallengeResponse("token-abc", "key-authorization-value");

        Assert.True(reader.TryGetResponse("token-abc", out var value));
        Assert.Equal("key-authorization-value", value);
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
    public void ItRejectsTokensThatAreNotBase64Url(string token)
    {
        var store = CreateStore();

        Assert.False(store.TryGetResponse(token, out var value));
        Assert.Null(value);
    }

    [Fact]
    public void ItDoesNotReadFilesOutsideTheChallengeDirectory()
    {
        var secretPath = Path.Combine(_testDir.FullName, "secret.txt");
        File.WriteAllText(secretPath, "sensitive");

        var store = CreateStore();

        Assert.False(store.TryGetResponse("../secret.txt", out var value));
        Assert.Null(value);
        Assert.True(File.Exists(secretPath));
    }

    [Fact]
    public void ItRejectsAddingAMalformedToken()
    {
        var store = CreateStore();

        Assert.Throws<ArgumentException>(() => store.AddChallengeResponse("../escape", "value"));
    }

    [Fact]
    public void ItDoesNotDeleteFilesOutsideTheChallengeDirectory()
    {
        var secretPath = Path.Combine(_testDir.FullName, "secret.txt");
        File.WriteAllText(secretPath, "sensitive");

        var store = CreateStore();
        store.RemoveChallenge("../secret.txt");

        Assert.True(File.Exists(secretPath));
    }

    [Fact]
    public void ItAcceptsARealisticAcmeToken()
    {
        var store = CreateStore();

        // Shape of a real RFC 8555 token: base64url, no padding.
        const string Token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
        const string KeyAuth = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypzEt62jcerQ";

        store.AddChallengeResponse(Token, KeyAuth);

        Assert.True(store.TryGetResponse(Token, out var value));
        Assert.Equal(KeyAuth, value);
    }

    [Fact]
    public void ItWritesWithoutAByteOrderMark()
    {
        var store = CreateStore();
        store.AddChallengeResponse("token-abc", "value");

        var file = Path.Combine(_testDir.FullName, "challenges", "token-abc");
        var bytes = File.ReadAllBytes(file);

        // A BOM would be sent to the certificate authority and fail the key authorization compare.
        Assert.Equal("value", System.Text.Encoding.UTF8.GetString(bytes));
        Assert.NotEqual(0xEF, bytes[0]);
    }

    [Fact]
    public void ItLeavesNoTemporaryFilesBehind()
    {
        var store = CreateStore();
        store.AddChallengeResponse("token-abc", "value");

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
