// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.AcmeStates;

using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

/// <summary>
/// This starts the ACME state machine, which handles certificate generation and renewal
/// </summary>
internal class AcmeCertificateLoader(
    IHostApplicationLifetime appLifetime,
    IServiceScopeFactory serviceScopeFactory,
    IOptions<LettuceEncryptOptions> options,
    ILogger<AcmeCertificateLoader> logger,
    IServer server,
    IConfiguration config) : BackgroundService
{
    private readonly ILogger _logger = logger;

    public TimeSpan RunDelay => options.Value.StartupRunDelay;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Run(
            async () =>
            {
                appLifetime.ApplicationStarted.WaitHandle.WaitOne();

                _logger.LogInformation("App Started -- Running Acme Certificate Loader in {DelaySeconds} Seconds", this.RunDelay.TotalSeconds);

                await Task.Delay(this.RunDelay, stoppingToken);

                await this.RunStartup(stoppingToken);
            },
            stoppingToken);
    }

    private async Task RunStartup(CancellationToken stoppingToken)
    {
        if (!server.GetType().Name.StartsWith(nameof(KestrelServer)))
        {
            var serverType = server.GetType().FullName;
            this._logger.LogWarning(
                "LettuceEncrypt can only be used with Kestrel and is not supported on {serverType} servers. Skipping certificate provisioning.",
                serverType);
            return;
        }

        if (config.GetValue<bool>("UseIISIntegration"))
        {
            this._logger.LogWarning(
                "LettuceEncrypt does not work with apps hosting in IIS. IIS does not allow for dynamic HTTPS certificate binding. Skipping certificate provisioning.");
            return;
        }

        // load certificates in the background
        if (!this.LettuceEncryptDomainNamesWereConfigured())
        {
            this._logger.LogInformation("No domain names were configured");
            return;
        }

        using var acmeStateMachineScope = serviceScopeFactory.CreateScope();

        try
        {
            IAcmeState state = acmeStateMachineScope.ServiceProvider.GetRequiredService<ServerStartupState>();

            while (!stoppingToken.IsCancellationRequested)
            {
                this._logger.LogTrace("ACME state transition: moving to {stateName}", state.GetType().Name);
                state = await state.MoveNextAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            this._logger.LogDebug("State machine cancellation requested. Exiting...");
        }
        catch (AggregateException ex) when (ex.InnerException != null)
        {
            this._logger.LogError(0, ex.InnerException, "ACME state machine encountered unhandled error");
        }
        catch (Exception ex)
        {
            this._logger.LogError(0, ex, "ACME state machine encountered unhandled error");
        }
    }

    private bool LettuceEncryptDomainNamesWereConfigured() =>
        options.Value.DomainNames.Any(w => !string.Equals("localhost", w, StringComparison.OrdinalIgnoreCase));
}
