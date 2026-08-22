[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "Visual Studio Installer discovery tool was not found."
}

$installationPath = & $vswhere `
    -latest `
    -products * `
    -requires Microsoft.VisualStudio.Workload.NativeDesktop `
    -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
    throw "Visual Studio 2022 with the Desktop C++ workload was not found."
}

$testRunner = Join-Path $installationPath `
    "Common7\IDE\CommonExtensions\Microsoft\TestWindow\vstest.console.exe"
if (-not (Test-Path -LiteralPath $testRunner)) {
    throw "The Visual Studio test runner was not found."
}

$testAssembly = Join-Path $PSScriptRoot "..\$Platform\$Configuration\EspReader.Tests.dll"
if (-not (Test-Path -LiteralPath $testAssembly)) {
    throw "The EspReader test assembly was not found: $testAssembly"
}

& $testRunner $testAssembly "/Platform:$Platform" "/Logger:Console;Verbosity=normal"
if ($LASTEXITCODE -ne 0) {
    throw "EspReader parser tests failed with exit code $LASTEXITCODE."
}
