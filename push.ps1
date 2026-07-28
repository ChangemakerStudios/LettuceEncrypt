param(
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

    # Push packages built without GitVersion. These carry the "-local" suffix from
    # Directory.Build.props and are not real versions, so pushing them is almost always a mistake.
    [switch]$AllowLocalVersions
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

$localPackages = $packages | Where-Object { $_.Name -match '-local(\.\d+)?\.nupkg$' }

if ($localPackages -and -not $AllowLocalVersions) {
    Write-Host "Refusing to push packages built without GitVersion:" -ForegroundColor Red
    $localPackages | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Red }
    Write-Host ""
    Write-Host "Install GitVersion and rebuild so packages get a real version:" -ForegroundColor Yellow
    Write-Host "  dotnet tool install --global GitVersion.Tool" -ForegroundColor Yellow
    Write-Host "  ./build.ps1 -ci" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Pass -AllowLocalVersions to push them anyway." -ForegroundColor Yellow
    exit 1
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
