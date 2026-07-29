// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.ComponentModel.DataAnnotations;
using Azure.Core;
using Azure.Identity;
using LettuceEncrypt.Accounts;

namespace LettuceEncrypt.Azure;

/// <summary>
/// Options to connect to an Azure KeyVault
/// </summary>
public class AzureKeyVaultLettuceEncryptOptions
{
    /// <summary>
    /// Gets or sets the Url for the KeyVault instance.
    /// </summary>
    [Url]
    [Required]
    public string AzureKeyVaultEndpoint { get; set; } = null!;

    /// <summary>
    /// Gets or sets the credentials used for connecting to the key vault. If null, will use <see cref="DefaultAzureCredential" />.
    /// </summary>
    public TokenCredential? Credentials { get; set; }

    /// <summary>
    /// Gets or sets the name the secret used to store the account information for accessing the certificate authority.
    /// This is a JSON string which encodes the information in <see cref="AccountModel"/>.
    /// If not set, the name defaults to the name of the "le-account-${ACME server hostname}".
    /// </summary>
    [MaxLength(127)]
    public string? AccountKeySecretName { get; set; }

    /// <summary>
    /// Gets or sets whether to recover a soft-deleted certificate automatically so that its name
    /// can be reused. Defaults to false.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A vault with soft delete enabled reserves the name of a deleted certificate until it is
    /// recovered or purged. Until then a new certificate cannot be saved under that name, and
    /// importing one fails with HTTP 409.
    /// </para>
    /// <para>
    /// This defaults to false because recovering undoes a deletion someone performed deliberately.
    /// When it is false, a save that hits this state fails with an explanation of how to recover
    /// the certificate by hand.
    /// </para>
    /// </remarks>
    public bool RecoverDeletedCertificates { get; set; }
}
