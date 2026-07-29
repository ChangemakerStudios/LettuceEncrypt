// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Text;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

/// <summary>
/// Coordinates certificate ordering across application instances using an exclusively opened file
/// in a shared directory.
/// </summary>
/// <remarks>
/// The lock is the open file handle itself rather than the existence of the file, so it is released
/// by the operating system if an instance stops without cleaning up. That avoids a stale lock file
/// blocking renewal indefinitely.
/// </remarks>
internal class FileSystemCertificateOrderLock : ICertificateOrderLock
{
    private const string LockFileName = ".certificate-order.lock";

    private readonly DirectoryInfo _directory;
    private readonly ILogger<FileSystemCertificateOrderLock> _logger;

    public FileSystemCertificateOrderLock(DirectoryInfo directory, ILogger<FileSystemCertificateOrderLock> logger)
    {
        _directory = directory ?? throw new ArgumentNullException(nameof(directory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public IDisposable? TryAcquire()
    {
        var path = Path.Combine(_directory.FullName, LockFileName);

        FileStream stream;

        try
        {
            _directory.Create();

            stream = new FileStream(
                path,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None);
        }
        catch (IOException)
        {
            // The file is held open by another instance, which is the expected contended case.
            _logger.LogInformation(
                "Another application instance is ordering a certificate. Skipping this attempt to " +
                "avoid duplicate orders against the certificate authority.");
            return null;
        }
        catch (UnauthorizedAccessException ex)
        {
            // Without the ability to coordinate, proceeding risks duplicate orders. Ordering anyway
            // is the lesser problem, since failing here would prevent renewal entirely.
            _logger.LogWarning(ex,
                "Could not open the certificate order lock at {LockPath}. Proceeding without " +
                "coordination between instances.", path);
            return new Handle(null, _logger);
        }

        try
        {
            // Record who holds the lock. Purely diagnostic; the handle is what enforces exclusion.
            var holder = Encoding.UTF8.GetBytes(
                $"{System.Net.Dns.GetHostName()} pid {System.Environment.ProcessId} at {DateTimeOffset.UtcNow:O}");
            stream.SetLength(0);
            stream.Write(holder, 0, holder.Length);
            stream.Flush();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not record the holder of the certificate order lock");
        }

        _logger.LogDebug("Acquired the certificate order lock at {LockPath}", path);

        return new Handle(stream, _logger);
    }

    private sealed class Handle : IDisposable
    {
        private readonly FileStream? _stream;
        private readonly ILogger _logger;

        public Handle(FileStream? stream, ILogger logger)
        {
            _stream = stream;
            _logger = logger;
        }

        public void Dispose()
        {
            if (_stream == null)
            {
                return;
            }

            try
            {
                _stream.Dispose();
                _logger.LogDebug("Released the certificate order lock");
            }
            catch (IOException ex)
            {
                _logger.LogDebug(ex, "Error releasing the certificate order lock");
            }
        }
    }
}
