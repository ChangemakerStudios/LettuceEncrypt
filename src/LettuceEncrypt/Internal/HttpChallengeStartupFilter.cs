// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

internal class HttpChallengeStartupFilter : IStartupFilter
{
    private readonly ILogger<HttpChallengeStartupFilter> _logger;

    public HttpChallengeStartupFilter(ILogger<HttpChallengeStartupFilter> logger)
    {
        _logger = logger;
    }

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        _logger.LogDebug("Configuring HttpChallengeStartupFilter middleware into the pipeline.");

        return app =>
        {
            app.UseHttpChallengeResponseMiddleware();

            next(app);
        };
    }
}
