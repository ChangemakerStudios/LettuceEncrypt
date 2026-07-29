// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal;

/// <summary>
/// Coordinates certificate ordering between application instances so that only one instance places
/// an order at a time.
/// </summary>
internal interface ICertificateOrderLock
{
    /// <summary>
    /// Attempts to take the lock without waiting.
    /// </summary>
    /// <returns>
    /// A handle that releases the lock when disposed, or null when another instance holds it.
    /// </returns>
    IDisposable? TryAcquire();
}
