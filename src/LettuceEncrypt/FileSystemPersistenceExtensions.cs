// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt;

/// <summary>
/// Extensions for configuring certificate persistence
/// </summary>
public static class FileSystemStorageExtensions
{
    /// <summary>
    /// Save certificates and account data to a directory.
    /// Certificates are stored in the .pfx (PKCS #12) format in a subdirectory of <paramref name="directory"/>.
    /// Account key information is stored in a JSON format in a different subdirectory of <paramref name="directory"/>.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="directory">The root directory for storing information. Information may be stored in subdirectories.</param>
    /// <param name="pfxPassword">Set to null or empty for password-less .pfx files.</param>
    /// <returns></returns>
    public static ILettuceEncryptServiceBuilder PersistDataToDirectory(
        this ILettuceEncryptServiceBuilder builder,
        DirectoryInfo directory,
        string? pfxPassword)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (directory is null)
        {
            throw new ArgumentNullException(nameof(directory));
        }

        var otherFileSystemRepoServices = builder
            .Services
            .Where(d => d.ServiceType == typeof(ICertificateRepository)
            && d.ImplementationInstance != null
            && d.ImplementationInstance.GetType() == typeof(FileSystemCertificateRepository));

        foreach (var serviceDescriptor in otherFileSystemRepoServices)
        {
            var otherRepo = (FileSystemCertificateRepository)serviceDescriptor.ImplementationInstance!;
            if (otherRepo.RootDir.Equals(directory))
            {
                if (otherRepo.PfxPassword != pfxPassword)
                {
                    throw new ArgumentException($"Another file system repo has been configured for {directory}, but with a different password.");
                }
                return builder;
            }
        }

        var implementationInstance = new FileSystemCertificateRepository(directory, pfxPassword);
        builder.Services
            .AddSingleton<ICertificateRepository>(implementationInstance)
            .AddSingleton<ICertificateSource>(implementationInstance);

        builder.Services.TryAddSingleton<IAccountStore>(services => new FileSystemAccountStore(directory,
                services.GetRequiredService<ILogger<FileSystemAccountStore>>(),
                services.GetRequiredService<ICertificateAuthorityConfiguration>()));

        return builder;
    }

    /// <summary>
    /// Store HTTP-01 challenge responses in a directory instead of in the memory of a single process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Use this when the application runs more than one instance behind a load balancer and those
    /// instances share a directory. By default challenges are held in memory, so only the instance
    /// that began the ACME order can answer the certificate authority's validation request. When the
    /// load balancer sends that request to any other instance, validation fails. Writing challenges
    /// to shared storage lets every instance answer.
    /// </para>
    /// <para>
    /// The directory must be genuinely shared between instances, such as a clustered volume. A
    /// per-host volume of the same name on each machine does not work.
    /// </para>
    /// <para>
    /// Set <see cref="LettuceEncryptOptions.AllowedChallengeTypes"/> to
    /// <see cref="Acme.ChallengeType.Http01"/> when using this. Otherwise TLS-ALPN-01 is attempted
    /// first, and it has the same single-instance limitation with no equivalent workaround.
    /// </para>
    /// </remarks>
    /// <param name="builder"></param>
    /// <param name="directory">The root directory for storing challenges. A "challenges" subdirectory is created.</param>
    /// <returns></returns>
    public static ILettuceEncryptServiceBuilder PersistHttpChallengesToDirectory(
        this ILettuceEncryptServiceBuilder builder,
        DirectoryInfo directory)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (directory is null)
        {
            throw new ArgumentNullException(nameof(directory));
        }

        // Replace rather than add. The in-memory store is registered unconditionally by
        // AddLettuceEncrypt, and leaving both registered would depend on registration order.
        builder.Services.Replace(
            ServiceDescriptor.Singleton<IHttpChallengeResponseStore>(services =>
                new FileSystemHttpChallengeStore(
                    directory,
                    services.GetRequiredService<ILogger<FileSystemHttpChallengeStore>>())));

        // A shared directory also lets instances agree on which one places an order, so they do not
        // each spend part of the certificate authority's duplicate-certificate allowance.
        builder.Services.Replace(
            ServiceDescriptor.Singleton<ICertificateOrderLock>(services =>
                new FileSystemCertificateOrderLock(
                    directory,
                    services.GetRequiredService<ILogger<FileSystemCertificateOrderLock>>())));

        return builder;
    }
}
