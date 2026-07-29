<h1>
<img src="./src/icon.png" width="42" height="42"/>
LettuceEncrypt for ASP.NET Core
</h1>

> **Note:** This is a fork of the [original LettuceEncrypt project](https://github.com/natemcmaster/LettuceEncrypt) which has been archived and is no longer actively maintained. This fork aims to continue development and maintenance of the library.

[ACME]: https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment
[Let's Encrypt]: https://letsencrypt.org/

LettuceEncrypt provides API for ASP.NET Core projects to integrate with a certificate authority (CA), such as
[Let's Encrypt], for free, automatic HTTPS (SSL/TLS) certificates using the [ACME] protocol.

When enabled, your web server will **automatically** generate an HTTPS certificate during start up.
It then configures Kestrel to use this certificate for all HTTPS traffic.
See [usage instructions below](#usage) to get started.

This project is **not an official offering** from Let's Encrypt® or ISRG™.

## Will this work for me?

That depends on [which kind of web server you are using](#web-server-scenarios). This library only works with
[Kestrel](https://docs.microsoft.com/aspnet/core/fundamentals/servers/kestrel), which is the default server
configuration for ASP.NET Core projects. Other servers, such as IIS and HTTP.sys, are not supported.
Furthermore, this only works when Kestrel is the edge server.

Not sure? [Read "Web Server Scenarios" below for more details.](#web-server-scenarios)

Using :cloud: Azure App Services (aka WebApps)? This library isn't for you, but you can still get free HTTPS certificates.
See ["Securing An Azure App Service with Let's Encrypt"](https://www.hanselman.com/blog/SecuringAnAzureAppServiceWebsiteUnderSSLInMinutesWithLetsEncrypt.aspx) by Scott Hanselman for more details.

## Usage

The primary API usage is to call `IServiceCollection.AddLettuceEncrypt` in the `Startup` class `ConfigureServices` method.

```csharp
using Microsoft.Extensions.DependencyInjection;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddLettuceEncrypt();
    }
}
```

A few required options should be set, typically via the appsettings.json file.

```jsonc
// appsettings.json
{
    "LettuceEncrypt": {
        // Set this to automatically accept the terms of service of your certificate authority.
        // If you don't set this in config, you will need to press "y" whenever the application starts
        "AcceptTermsOfService": true,

        // You must specify at least one domain name
        "DomainNames": [ "example.com", "www.example.com" ],

        // You must specify an email address to register with the certificate authority
        "EmailAddress": "it-admin@example.com"
    }
}
```

## Additional options

### Kestrel configuration

If your code is using the `.UseKestrel()` method to configure IP addresses, ports, or HTTPS settings,
you will also need to call `UseLettuceEncrypt`. This is required to make Lettuce Encrypt work.

#### Example: ConfigureHttpsDefaults

If calling `ConfigureHttpsDefaults`, use `UseLettuceEncrypt` like this:

```c#
webBuilder.UseKestrel(k =>
{
    var appServices = k.ApplicationServices;
    k.ConfigureHttpsDefaults(h =>
    {
        h.UseLettuceEncrypt(appServices);
    });
});
```

> :warning: **`ConfigureHttpsDefaults` replaces rather than accumulates.** Each call discards the
> delegate from the previous one, and LettuceEncrypt registers its own call internally. Whichever
> runs last wins, and the order depends on where `AddLettuceEncrypt` sits relative to your Kestrel
> configuration.
>
> In practice this means any *other* HTTPS setting you put in this block, such as
> `ClientCertificateMode`, may be silently discarded — or may silently start taking effect later if
> registration order ever changes. Put only `UseLettuceEncrypt` here, and configure other HTTPS
> options through `Listen` + `UseHttps` on a specific endpoint instead.

#### Example: Listen + UseHttps
If using `Listen` + `UseHttps` to manually configure Kestrel's address binding, use `UseLettuceEncrypt` like this:

```c#
webBuilder.UseKestrel(k =>
{
    var appServices = k.ApplicationServices;
    k.Listen(
        IPAddress.Any, 443,
        o => o.UseHttps(h =>
        {
            h.UseLettuceEncrypt(appServices);
        }));
});
```

### Customizing storage

Certificates are stored to the machine's X.509 store by default. Certificates can be stored in additional
locations by using extension methods after calling `AddLettuceEncrypt()` in the `Startup` class.

Multiple storage locations can be configured.

### Save generated certificates and account information to a directory

This will save and load certificate files (PFX format) using the specified directory.
It will also save your certificate authority account key into the same directory.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddLettuceEncrypt()
        .PersistDataToDirectory(new DirectoryInfo("C:/data/LettuceEncrypt/"), "Password123");
}
```

### Save generated certificates to Azure Key Vault

Install [LettuceEncrypt.Azure](https://nuget.org/packages/LettuceEncrypt.Azure).
This will save and load certificate files using an Azure Key Vault.
It will also save your certificate authority account key as a secret in the same vault.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddLettuceEncrypt()
        .PersistCertificatesToAzureKeyVault();
}
```

```jsonc
// appsettings.json
{
    "LettuceEncrypt": {
        "AzureKeyVault": {
            // Required - specify the name of your key vault
            "AzureKeyVaultEndpoint": "https://myaccount.vault.azure.net/",

            // Optional - specify the secret name used to store your account info (used for cert rewewals)
            // If not specified, name defaults to "le-encrypt-${ACME server URL}"
            "AccountKeySecretName": "my-lets-encrypt-account",

            // Optional - recover a soft-deleted certificate automatically so its name can be reused.
            // Defaults to false. See "Soft-deleted certificates" below.
            "RecoverDeletedCertificates": false
        }
    }
}
```

#### Soft-deleted certificates

A key vault with soft delete enabled reserves the name of a deleted certificate until it is
recovered or purged. Until then a new certificate cannot be saved under that name. Reading the
certificate returns "not found" rather than anything revealing the deleted state, so the first sign
of it is a failure to save a certificate that was otherwise issued successfully — meaning the
certificate is lost when the process stops.

By default this fails with the command needed to fix it:

```
az keyvault certificate recover --vault-name <vault> --name <certificate>
```

Set `RecoverDeletedCertificates` to `true` to have the certificate recovered automatically instead.
It defaults to `false` because recovering undoes a deletion that someone performed deliberately.

### Customizing how the certs are saved and loaded

Create a class that implements `ICertificateRepository` to customize how to save your certificates.

Create a class that implements `ICertificateSource` to customize where pre-existing certificates are
found when the server starts.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services.AddLettuceEncrypt();
    services.AddSingleton<ICertificateRepository, MyCertRepo>();
    services.AddSingleton<ICertificateSource, MyCertSource>();
}

class MyCertRepo : ICertificateRepository
{
    public async Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        byte[] certData = certificate.Export(X509ContentType.Pfx, "optionallySetPfxPassword");
        // save this data somehow
    }
}

class MyCertSource : ICertificateSource
{
    public async Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken);
    {
        // find and return certificate objects. Return an empty enumerable if none are found
    }
}
```

### Customizing saving your account key

Your interactions with the certificate authority are encrypted with a private
key which is generated automatically on first-use. To ensure you can renew certificates
later using the same account, this account key is saved to disk by default.
You can customize where this account information is shared by adding your own implementation
of `IAccountStore`.

```c#
using LettuceEncrypt;
using LettuceEncrypt.Accounts;


public void ConfigureServices(IServiceCollection services)
{
    services.AddLettuceEncrypt();
    services.AddSingleton<IAccountStore, MyAccountStore>();
}


class MyAccountStore: IAccountStore
{
    public Task SaveAccountAsync(AccountModel account, CancellationToken cancellationToken)
    {
        // save the account object somewhere
    }

    // add #nullable enable if using c#, or remove the question mark for older versions of C#
    public Task<AccountModel?> GetAccountAsync(CancellationToken cancellationToken)
    {
        // return null if there is no account and one will be created for you
    }
}
```


### Changing which challenge types are used

The ACME protocol supports multiple methods for proving you own a DNS name called "challenge types".
If you wish to manually select which challenge types are used, set the "AllowedChallengeTypes" method.

Current supported values:
* `Http01` - The HTTP-01 challenge, which uses a well-known URL on the server and a HTTP request/response. Requires port 80 to be reachable from the internet; the certificate authority will not use another port.
* `TlsAlpn01` - The TLS-ALPN-01 challenge, which uses an auto-generated, ephemeral certificate in the TLS handshake. Requires port 443, and only works with a single instance.
* `Dns01` - The DNS-01 challenge, which uses TXT record under that domain name. Requires an `IDnsChallengeProvider`. Needs no inbound ports and is unaffected by how many instances you run.
* `Any` - _(default)_ - try each configured challenge type in turn.

Tip: if you wish to set multiple method types and are use the "appsettings.json" approach, provide a comma-seperated list.


```json
{
    "LettuceEncrypt": {
        "AllowedChallengeTypes": "Http01, TlsAlpn01, Dns01"
    }
}
```

### Challenge types are not fallbacks

`Any` reads as "try everything until one works", but a certificate authority does not allow that.
Under [RFC 8555 section 7.1.6](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6), a failed
challenge moves the **whole authorization** to an invalid state. No other challenge type can succeed
against it, so the challenge types after the first failure never get a real attempt.

The order attempted is TLS-ALPN-01, then HTTP-01, then DNS-01. So if TLS-ALPN-01 cannot work in your
deployment, leaving the default of `Any` means HTTP-01 and DNS-01 are never usefully tried, no matter
how well they are configured.

**Set `AllowedChallengeTypes` to the one challenge type your deployment can actually serve.** When
the authorization is invalidated this way, the error message says so explicitly rather than
reporting a confusing "did not receive challenge information" for the later types.

### When using DNS-01

When using the DNS-01 challenge an `IDnsChallengeProvider` must be registered to replace the
`NoOpDnsChallengeProvider`. The default provider reports success without publishing anything, so
DNS-01 is skipped entirely unless you supply a real one.

`AddTxtRecordAsync` returns a `DnsTxtRecordContext`, which is handed back to `RemoveTxtRecordAsync`
for cleanup. If several instances may order at once, add and remove the individual TXT *value*
rather than replacing or deleting the whole record set — a certificate authority accepts the record
if any value at that name matches, so instances can coexist, but only if one does not delete
another's pending value.

```c#
using LettuceEncrypt.Acme;

public class MyDnsChallengeProvider : IDnsChallengeProvider
{
    private readonly ISomeExternalDnsClient _client;

    public MyDnsChallengeProvider(ISomeExternalDnsClient client) => _client = client;

    public async Task<DnsTxtRecordContext> AddTxtRecordAsync(
        string domainName, string txt, CancellationToken ct = default)
    {
        await _client.AddDnsTxtRecord(domainName, txt, ct);
        return new DnsTxtRecordContext(domainName, txt);
    }

    public Task RemoveTxtRecordAsync(DnsTxtRecordContext context, CancellationToken ct = default)
    {
        return _client.RemoveDnsTxtRecord(context.DomainName, context.Txt, ct);
    }
}
```

```c#
services.AddLettuceEncrypt();
services.Replace(ServiceDescriptor.Singleton<IDnsChallengeProvider, MyDnsChallengeProvider>());
```

## Running more than one instance

Challenge responses are held in the memory of a single process by default. That is correct when
exactly one instance of your application can receive the certificate authority's validation request.

**When you run multiple instances behind a load balancer, the default does not work.** The instance
that begins the ACME order is usually not the instance the load balancer sends the validation
request to, so validation fails — often intermittently, with a different error each time, because
which instance answers is effectively random.

Symptoms of this include `remote error: tls: no application protocol` from a healthy server, and
errors mentioning "during secondary validation" (the certificate authority checks from several
network locations, and each one is a fresh roll of the dice).

The fix is to put challenge state somewhere every instance can read.

### Share challenges through a directory

Use this when all instances share a directory, such as a clustered volume. A per-host volume of the
same name on each machine does not work — the directory must be genuinely shared.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddLettuceEncrypt()
        .PersistDataToDirectory(new DirectoryInfo("/srv/shared/lettuceencrypt/"), "Password123")
        .PersistHttpChallengesToDirectory(new DirectoryInfo("/srv/shared/lettuceencrypt/"));
}
```

This also coordinates ordering between instances, so they do not each place an order and spend the
certificate authority's duplicate-certificate allowance several times over.

### Share challenges through Azure Key Vault

Use this when instances do not share storage but do share a key vault.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddLettuceEncrypt()
        .PersistCertificatesToAzureKeyVault()
        .PersistHttpChallengesToAzureKeyVault();
}
```

The application's vault identity needs secret **set**, **get** and **delete** permissions. Delete is
only used to clean up spent challenges; without it they remain until they expire an hour after they
are created.

### You must also restrict the challenge type

```jsonc
// appsettings.json
{
    "LettuceEncrypt": {
        "AllowedChallengeTypes": "Http01"
    }
}
```

This is not optional. Left at the default of `Any`, the TLS-ALPN-01 challenge is attempted first,
and it has the same single-instance limitation with no equivalent workaround — the challenge
certificate has to be held by the process completing the TLS handshake. Its failure then invalidates
the whole authorization, so HTTP-01 never gets a turn. See
["Challenge types are not fallbacks"](#challenge-types-are-not-fallbacks).

### Customizing where challenges are stored

Implement `IHttpChallengeResponseStore` to back challenges with any shared store you like.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services.AddLettuceEncrypt();
    services.Replace(ServiceDescriptor.Singleton<IHttpChallengeResponseStore, MyChallengeStore>());
}

class MyChallengeStore : IHttpChallengeResponseStore
{
    public Task AddChallengeResponseAsync(string token, string response, CancellationToken ct = default)
    {
        // store the response so that every instance can read it
    }

    public Task<string?> GetResponseAsync(string token, CancellationToken ct = default)
    {
        // return the response, or null if the token is unknown
    }

    public Task RemoveChallengeAsync(string token, CancellationToken ct = default)
    {
        // discard the challenge
    }
}
```

Use `Replace` rather than `AddSingleton`. The in-memory store is registered unconditionally by
`AddLettuceEncrypt`, and leaving both registered makes the result depend on registration order.

> :warning: `GetResponseAsync` receives the token straight from the request path, so it is
> **attacker controlled**, and it is called for every request to a publicly reachable path that
> scanners probe constantly. Validate the token before using it to address storage — the built-in
> stores reject anything that is not plain base64url. A store that builds a file path from the token
> is otherwise open to path traversal, and one backed by a remote service will make a call per probe.

## Testing in development

See the [developer docs](./test/Integration/) for details on how to test in a non-production environment.

Point at the certificate authority's staging server while you are working things out. Failed
validations count against a strict rate limit on the production server — five per account, per
hostname, per hour — and issued certificates count against a separate weekly limit that takes a full
week to roll off.

```jsonc
// appsettings.Development.json
{
    "LettuceEncrypt": {
        "UseStagingServer": true
    }
}
```

## Building and releasing

```bash
./build.ps1          # format check, build, pack, test
dotnet test LettuceEncrypt.sln
```

Versions come from [GitVersion](https://gitversion.net/) rather than being hard-coded, so install it
before building anything you intend to publish:

```bash
dotnet tool install --global GitVersion.Tool
```

Without it the build falls back to the version in `Directory.Build.props` and suffixes packages
`-local`. `push.ps1` refuses to publish those, since they are not real versions.

The branch decides the version shape, using GitVersion's default branch configuration:

| Branch    | Produces        | Notes                                  |
| --------- | --------------- | -------------------------------------- |
| `main`    | `1.3.5`         | Stable. Patch increment.               |
| `develop` | `1.4.0-alpha.N` | Minor increment, `alpha` label.        |
| other     | inherited       | Derived from the branch it forked from |

`next-version` in [GitVersion.yml](./GitVersion.yml) sets the starting point, because the repository
has no version tags yet and GitVersion would otherwise begin at 0.1.0. Once a tag exists that line
can be removed and versions come from tags alone. Keep `VersionPrefix` in `Directory.Build.props` in
step with it.

### Publishing

[deploy.yml](./.github/workflows/deploy.yml) computes the version, builds, tests, packs, and
attaches the packages to the workflow run. It does **not** publish — the feed
(`proget.captiveaire.com`) is on a private network and is unreachable from GitHub-hosted runners.

Publish from a machine on that network:

```powershell
./build.ps1 -ci
./push.ps1 -ApiKey <key>
```

To publish from CI instead, add a self-hosted runner with network access and restore a push step to
the workflow, or point at a feed reachable from GitHub. Note that the `LettuceEncrypt`,
`LettuceEncrypt.Azure` and `McMaster.AspNetCore.Kestrel.Certificates` package IDs on nuget.org belong
to the original author, so publishing this fork there needs ownership of those IDs or a rename.

## Web Server Scenarios

I recommend also reading [Microsoft's official documentation on hosting and deploying ASP.NET Core](https://docs.microsoft.com/aspnet/core/host-and-deploy/).

### ASP.NET Core with Kestrel

:white_check_mark: supported

![Diagram of Kestrel on the edge with Kestrel](https://i.imgur.com/vhQTgUe.png)

In this scenario, ASP.NET Core is hosted by the Kestrel server (the default, in-process HTTP server) and that web server exposes its ports directly to the internet. This library will configure Kestrel with an auto-generated certificate.

### ASP.NET Core with IIS

:x: NOT supported

![Diagram of Kestrel on the edge with IIS](https://i.imgur.com/PmrcLkN.png)

In this scenario, ASP.NET Core is hosted by IIS and that web server exposes its ports directly to the internet. IIS does not support dynamically configuring HTTPS certificates, so this library cannot support this scenario, but you can still configure cert automation using a different tool. See ["Using Let's Encrypt with IIS On Windows"](https://weblog.west-wind.com/posts/2016/feb/22/using-lets-encrypt-with-iis-on-windows) for details.

Azure App Service uses this for ASP.NET Core 2.2 and newer, which is why this library cannot support that scenario.. Older versions of ASP.NET Core on Azure App Service run with IIS as the reverse proxy (see below), which is also an unsupported scenario.


### ASP.NET Core with Kestrel Behind a TCP Load Balancer (aka SSL pass-thru)

:white_check_mark: supported

![Diagram of TCP Load Balancer](https://i.imgur.com/txqLTv5.png)

In this scenario, ASP.NET Core is hosted by the Kestrel server (the default, in-process HTTP server) and that web server exposes its ports directly to a local network. A TCP load balancer such as nginx forwards traffic without decrypting it to the host running Kestrel. This library will configure Kestrel with an auto-generated certificate.

### ASP.NET Core with Kestrel Behind a Reverse Proxy

:x: NOT supported

![Diagram of reverse proxy](https://i.imgur.com/LA4jms7.png)

In this scenario, HTTPS traffic is decrypted by a different web server that is beyond the control of ASP.NET Core. This library cannot support this scenario because HTTPS certificates must be configured by the reverse proxy server.

This is commonly done by web hosting providers. For example, :cloud: Azure App Services (aka WebApps) often runs older versions of ASP.NET Core in a reverse proxy.

If you are running the reverse proxy, you can still get free HTTPS certificates, but you'll need to use a different method. [Try Googling this](https://www.google.com/search?q=let%27s%20encrypt%20nginx).
