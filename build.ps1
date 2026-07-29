#!/usr/bin/env pwsh
[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('Debug', 'Release')]
    $Configuration = $null,
    [switch]
    $ci,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$MSBuildArgs
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

Import-Module -Force -Scope Local "$PSScriptRoot/src/common.psm1"

#
# Main
#

if ($env:CI -eq 'true') {
    $ci = $true
}

if (!$Configuration) {
    $Configuration = if ($ci) { 'Release' } else { 'Debug' }
}

if ($ci) {
    $MSBuildArgs += '-p:CI=true'

    & dotnet --info
}

if (-not (Test-Path variable:\IsCoreCLR)) {
    $IsWindows = $true
}

$artifacts = "$PSScriptRoot/artifacts/"

Remove-Item -Recurse $artifacts -ErrorAction Ignore

# Versions come from GitVersion, matching what the Package workflow computes. Without the tool the
# build falls back to the version in Directory.Build.props, which is suffixed "-local" so those
# packages are never mistaken for a release. Install with:
#
#   dotnet tool install --global GitVersion.Tool
#
[string[]] $versionArgs = @()
if (Get-Command dotnet-gitversion -ErrorAction SilentlyContinue) {
    $gitVersion = & dotnet-gitversion /output json | ConvertFrom-Json
    $versionArgs += "-p:Version=$($gitVersion.FullSemVer)"
    $versionArgs += "-p:PackageVersion=$($gitVersion.FullSemVer)"
    $versionArgs += "-p:AssemblyVersion=$($gitVersion.AssemblySemVer)"
    $versionArgs += "-p:FileVersion=$($gitVersion.AssemblySemFileVer)"
    $versionArgs += "-p:InformationalVersion=$($gitVersion.InformationalVersion)"
    write-host -f cyan "GitVersion: $($gitVersion.FullSemVer)"
}
else {
    write-host -f yellow 'GitVersion not found. Building with the fallback version from Directory.Build.props.'
    write-host -f yellow 'These packages are suffixed "-local" and cannot be published.'
}

[string[]] $formatArgs=@()
if ($ci) {
    $formatArgs += '--verify-no-changes'
}

exec dotnet format -v detailed @formatArgs
exec dotnet build --configuration $Configuration '-warnaserror:CS1591' @versionArgs @MSBuildArgs
exec dotnet pack --no-restore --no-build --configuration $Configuration -o $artifacts @versionArgs @MSBuildArgs

[string[]] $testArgs=@()
if ($env:TF_BUILD) {
    $testArgs += '--logger', 'trx'
}

exec dotnet test --no-restore --no-build --configuration $Configuration '-clp:Summary' `
    --collect:"XPlat Code Coverage" `
    @testArgs `
    @MSBuildArgs

write-host -f green 'BUILD SUCCEEDED'
