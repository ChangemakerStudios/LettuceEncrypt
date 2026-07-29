// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using LettuceEncrypt.Internal.AcmeStates;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class CertificateSaveTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The timeout was previously a Task.Delay inside the awaited set, which made every save wait
    /// for the whole timeout instead of at most the timeout.
    /// </summary>
    [Fact]
    public async Task SavingDoesNotWaitForTheFullTimeout()
    {
        var repo = new FakeRepository();
        var stopwatch = Stopwatch.StartNew();

        await BeginCertificateCreationState.SaveToRepositoriesAsync(
            new[] { repo }, CreateCert(), Timeout, CancellationToken.None);

        stopwatch.Stop();

        Assert.True(repo.Saved);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1),
            $"Saving took {stopwatch.Elapsed}, which suggests it waited on the timeout.");
    }

    [Fact]
    public async Task ItSavesToEveryRepository()
    {
        var first = new FakeRepository();
        var second = new FakeRepository();

        await BeginCertificateCreationState.SaveToRepositoriesAsync(
            new[] { first, second }, CreateCert(), Timeout, CancellationToken.None);

        Assert.True(first.Saved);
        Assert.True(second.Saved);
    }

    [Fact]
    public async Task AFailingRepositoryIsReportedWithoutWaitingForTheTimeout()
    {
        var repo = new FakeRepository { Failure = new InvalidOperationException("nope") };
        var stopwatch = Stopwatch.StartNew();

        var ex = await Assert.ThrowsAsync<AggregateException>(
            () => BeginCertificateCreationState.SaveToRepositoriesAsync(
                new[] { repo }, CreateCert(), Timeout, CancellationToken.None));

        stopwatch.Stop();

        Assert.Contains(ex.InnerExceptions, e => e.Message == "nope");
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1),
            $"Reporting the failure took {stopwatch.Elapsed}.");
    }

    /// <summary>
    /// A certificate stored in none of the repositories is lost on restart, so every repository's
    /// failure needs to reach the log, not just the first.
    /// </summary>
    [Fact]
    public async Task EveryRepositoryFailureIsReported()
    {
        var first = new FakeRepository { Failure = new InvalidOperationException("first failed") };
        var second = new FakeRepository { Failure = new InvalidOperationException("second failed") };

        var ex = await Assert.ThrowsAsync<AggregateException>(
            () => BeginCertificateCreationState.SaveToRepositoriesAsync(
                new[] { first, second }, CreateCert(), Timeout, CancellationToken.None));

        Assert.Contains(ex.InnerExceptions, e => e.Message == "first failed");
        Assert.Contains(ex.InnerExceptions, e => e.Message == "second failed");
    }

    [Fact]
    public async Task ASlowRepositoryIsBoundedByTheTimeout()
    {
        var repo = new FakeRepository { Delay = TimeSpan.FromMinutes(10) };

        var ex = await Assert.ThrowsAsync<AggregateException>(
            () => BeginCertificateCreationState.SaveToRepositoriesAsync(
                new[] { repo }, CreateCert(), TimeSpan.FromMilliseconds(200), CancellationToken.None));

        Assert.Contains(ex.InnerExceptions, e => e is TimeoutException);
    }

    [Fact]
    public async Task AWorkingRepositoryStillSavesWhenAnotherFails()
    {
        var failing = new FakeRepository { Failure = new InvalidOperationException("nope") };
        var working = new FakeRepository();

        await Assert.ThrowsAsync<AggregateException>(
            () => BeginCertificateCreationState.SaveToRepositoriesAsync(
                new[] { failing, working }, CreateCert(), Timeout, CancellationToken.None));

        Assert.True(working.Saved);
    }

    /// <summary>
    /// A shutdown is not a save failure, and must stay distinguishable from one.
    /// </summary>
    [Fact]
    public async Task CallerCancellationSurfacesAsCancellation()
    {
        var repo = new FakeRepository { Delay = TimeSpan.FromMinutes(10) };
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => BeginCertificateCreationState.SaveToRepositoriesAsync(
                new[] { repo }, CreateCert(), Timeout, cts.Token));
    }

    [Fact]
    public async Task ARepositoryThatThrowsSynchronouslyIsReported()
    {
        var repo = new ThrowsSynchronouslyRepository();

        var ex = await Assert.ThrowsAsync<AggregateException>(
            () => BeginCertificateCreationState.SaveToRepositoriesAsync(
                new[] { repo }, CreateCert(), Timeout, CancellationToken.None));

        Assert.Contains(ex.InnerExceptions, e => e.Message == "immediate");
    }

    private static X509Certificate2 CreateCert() => TestUtils.CreateTestCert("test.natemcmaster.com");

    private class FakeRepository : ICertificateRepository
    {
        public bool Saved { get; private set; }
        public Exception Failure { get; set; }
        public TimeSpan Delay { get; set; }

        public async Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
        {
            if (Delay > TimeSpan.Zero)
            {
                await Task.Delay(Delay, cancellationToken);
            }

            if (Failure != null)
            {
                throw Failure;
            }

            Saved = true;
        }
    }

    private class ThrowsSynchronouslyRepository : ICertificateRepository
    {
        public Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
            => throw new InvalidOperationException("immediate");
    }
}
