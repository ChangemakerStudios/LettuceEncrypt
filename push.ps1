param(
    [Parameter(Mandatory=$true)]
    [string]$ApiKey
)

$ErrorActionPreference = "Stop"

$artifactsDir = Join-Path $PSScriptRoot "artifacts"

if (-not (Test-Path $artifactsDir)) {
    Write-Error "Artifacts directory not found at: $artifactsDir"
    exit 1
}

$packages = Get-ChildItem -Path $artifactsDir -Filter "*.nupkg" -Recurse

if ($packages.Count -eq 0) {
    Write-Warning "No NuGet packages found in $artifactsDir"
    exit 0
}

Write-Host "Found $($packages.Count) package(s) to push:" -ForegroundColor Green
$packages | ForEach-Object { Write-Host "  - $($_.Name)" }
Write-Host ""

foreach ($package in $packages) {
    Write-Host "Pushing $($package.Name)..." -ForegroundColor Cyan

    dotnet nuget push $package.FullName `
        --api-key $ApiKey `
        --source https://proget.captiveaire.com/nuget/CaptiveAire

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to push $($package.Name)"
        exit $LASTEXITCODE
    }

    Write-Host "Successfully pushed $($package.Name)" -ForegroundColor Green
    Write-Host ""
}

Write-Host "All packages pushed successfully!" -ForegroundColor Green
