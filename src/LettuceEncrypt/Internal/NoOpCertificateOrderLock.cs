// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal;

/// <summary>
/// The default lock for applications running a single instance, where there is nothing to
/// coordinate with. It always succeeds.
/// </summary>
internal class NoOpCertificateOrderLock : ICertificateOrderLock
{
    private static readonly IDisposable s_handle = new Handle();

    public IDisposable? TryAcquire() => s_handle;

    private sealed class Handle : IDisposable
    {
        public void Dispose()
        {
        }
    }
}
