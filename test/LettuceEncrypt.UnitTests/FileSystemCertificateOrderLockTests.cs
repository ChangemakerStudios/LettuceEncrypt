// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class FileSystemCertificateOrderLockTests : IDisposable
{
    private readonly DirectoryInfo _testDir;

    public FileSystemCertificateOrderLockTests()
    {
        _testDir = new DirectoryInfo(
            Path.Combine(Path.GetTempPath(), "LettuceEncrypt.Tests", Guid.NewGuid().ToString("N")));
        _testDir.Create();
    }

    private FileSystemCertificateOrderLock CreateLock()
        => new(new DirectoryInfo(_testDir.FullName), NullLogger<FileSystemCertificateOrderLock>.Instance);

    [Fact]
    public void ItAcquiresWhenUncontended()
    {
        using var handle = CreateLock().TryAcquire();

        Assert.NotNull(handle);
    }

    /// <summary>
    /// A second lock over the same directory stands in for a second application instance. Only one
    /// may hold it, otherwise both instances order a certificate and spend the certificate
    /// authority's duplicate-certificate allowance.
    /// </summary>
    [Fact]
    public void ASecondInstanceCannotAcquireWhileHeld()
    {
        using var first = CreateLock().TryAcquire();
        Assert.NotNull(first);

        var second = CreateLock().TryAcquire();

        Assert.Null(second);
    }

    [Fact]
    public void ItIsReacquirableAfterRelease()
    {
        var first = CreateLock().TryAcquire();
        Assert.NotNull(first);
        first!.Dispose();

        using var second = CreateLock().TryAcquire();

        Assert.NotNull(second);
    }

    [Fact]
    public void ItCreatesTheDirectoryIfMissing()
    {
        var missing = new DirectoryInfo(Path.Combine(_testDir.FullName, "not-yet-there"));
        var orderLock = new FileSystemCertificateOrderLock(
            missing, NullLogger<FileSystemCertificateOrderLock>.Instance);

        using var handle = orderLock.TryAcquire();

        Assert.NotNull(handle);
        Assert.True(Directory.Exists(missing.FullName));
    }

    [Fact]
    public void ItRecordsTheHolderForDiagnostics()
    {
        using (var handle = CreateLock().TryAcquire())
        {
            Assert.NotNull(handle);
        }

        var lockFile = Path.Combine(_testDir.FullName, ".certificate-order.lock");
        Assert.True(File.Exists(lockFile));
        Assert.Contains("pid", File.ReadAllText(lockFile), StringComparison.Ordinal);
    }

    [Fact]
    public void ReleasingIsIdempotent()
    {
        var handle = CreateLock().TryAcquire();
        Assert.NotNull(handle);

        handle!.Dispose();
        handle.Dispose();

        using var reacquired = CreateLock().TryAcquire();
        Assert.NotNull(reacquired);
    }

    [Fact]
    public void TheNoOpLockAlwaysAcquires()
    {
        var orderLock = new NoOpCertificateOrderLock();

        using var first = orderLock.TryAcquire();
        using var second = orderLock.TryAcquire();

        Assert.NotNull(first);
        Assert.NotNull(second);
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
