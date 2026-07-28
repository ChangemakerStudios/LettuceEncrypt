// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Azure;
using LettuceEncrypt.Azure.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions to integrate Azure with LettuceEncrypt.
/// </summary>
public static class AzureLettuceEncryptExtensions
{
    /// <summary>
    /// Persists certificates to configured key vault.
    /// </summary>
    /// <param name="builder">A LettuceEncrypt service builder.</param>
    /// <returns>The original LettuceEncrypt service builder.</returns>
    public static ILettuceEncryptServiceBuilder PersistCertificatesToAzureKeyVault(
        this ILettuceEncryptServiceBuilder builder)
        => builder.PersistCertificatesToAzureKeyVault(_ => { });

    /// <summary>
    /// Persists certificates to configured key vault.
    /// </summary>
    /// <param name="builder">A LettuceEncrypt service builder.</param>
    /// <param name="configure">Configuration for KeyVault connections.</param>
    /// <returns>The original LettuceEncrypt service builder.</returns>
    public static ILettuceEncryptServiceBuilder PersistCertificatesToAzureKeyVault(
        this ILettuceEncryptServiceBuilder builder,
        Action<AzureKeyVaultLettuceEncryptOptions> configure)
    {
        var services = builder.Services;
        services.TryAddSingleton<ICertificateClientFactory, CertificateClientFactory>();
        services.TryAddSingleton<ISecretClientFactory, SecretClientFactory>();

        services.TryAddSingleton<AzureKeyVaultCertificateRepository>();
        services.TryAddSingleton<IAccountStore, AzureKeyVaultAccountStore>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<ICertificateRepository, AzureKeyVaultCertificateRepository>(x =>
                x.GetRequiredService<AzureKeyVaultCertificateRepository>()));
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<ICertificateSource, AzureKeyVaultCertificateRepository>(x =>
                x.GetRequiredService<AzureKeyVaultCertificateRepository>()));

        AddKeyVaultOptions(services, configure);

        return builder;
    }

    private static void AddKeyVaultOptions(
        IServiceCollection services,
        Action<AzureKeyVaultLettuceEncryptOptions> configure)
    {
        services.AddSingleton<IConfigureOptions<AzureKeyVaultLettuceEncryptOptions>>(s =>
        {
            var config = s.GetService<IConfiguration?>();
            return new ConfigureOptions<AzureKeyVaultLettuceEncryptOptions>(o =>
                config?.Bind("LettuceEncrypt:AzureKeyVault", o));
        });

        services
            .AddOptions<AzureKeyVaultLettuceEncryptOptions>()
            .Configure(configure)
            .ValidateDataAnnotations();
    }

    /// <summary>
    /// Stores HTTP-01 challenge responses in the configured key vault instead of in the memory of a
    /// single process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Use this when the application runs more than one instance behind a load balancer. By default
    /// challenges are held in memory, so only the instance that began the ACME order can answer the
    /// certificate authority's validation request. When the load balancer sends that request to any
    /// other instance, validation fails. Storing challenges in the vault lets every instance answer.
    /// </para>
    /// <para>
    /// Set <see cref="LettuceEncryptOptions.AllowedChallengeTypes"/> to
    /// <see cref="LettuceEncrypt.Acme.ChallengeType.Http01"/> when using this. Otherwise TLS-ALPN-01
    /// is attempted first, and it has the same single-instance limitation with no equivalent
    /// workaround.
    /// </para>
    /// <para>
    /// The application's vault identity needs secret set, get and delete permissions. Delete
    /// permission is only used to clean up spent challenges; without it they remain until they
    /// expire an hour after they are created.
    /// </para>
    /// </remarks>
    /// <param name="builder">A LettuceEncrypt service builder.</param>
    /// <returns>The original LettuceEncrypt service builder.</returns>
    public static ILettuceEncryptServiceBuilder PersistHttpChallengesToAzureKeyVault(
        this ILettuceEncryptServiceBuilder builder)
        => builder.PersistHttpChallengesToAzureKeyVault(_ => { });

    /// <summary>
    /// Stores HTTP-01 challenge responses in the configured key vault instead of in the memory of a
    /// single process.
    /// </summary>
    /// <remarks>
    /// See <see cref="PersistHttpChallengesToAzureKeyVault(ILettuceEncryptServiceBuilder)"/>.
    /// </remarks>
    /// <param name="builder">A LettuceEncrypt service builder.</param>
    /// <param name="configure">Configuration for KeyVault connections.</param>
    /// <returns>The original LettuceEncrypt service builder.</returns>
    public static ILettuceEncryptServiceBuilder PersistHttpChallengesToAzureKeyVault(
        this ILettuceEncryptServiceBuilder builder,
        Action<AzureKeyVaultLettuceEncryptOptions> configure)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        var services = builder.Services;

        services.TryAddSingleton<ISecretClientFactory, SecretClientFactory>();

        // Replace rather than add. The in-memory store is registered unconditionally by
        // AddLettuceEncrypt, and leaving both registered would depend on registration order.
        services.Replace(
            ServiceDescriptor.Singleton<IHttpChallengeResponseStore, AzureKeyVaultHttpChallengeStore>());

        // Configured here as well so this can be used without also persisting certificates to the
        // vault. Both paths bind the same options, so calling both is harmless.
        AddKeyVaultOptions(services, configure);

        return builder;
    }
}
