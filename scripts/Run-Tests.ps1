[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64",

    [string]$PlatformToolset,

    [switch]$EnableAddressSanitizer,

    [string]$ResultsDirectory
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
    throw "Visual Studio with the Desktop C++ workload was not found."
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

$arguments = @(
    $testAssembly
    "/Platform:$Platform"
    "/Logger:Console;Verbosity=normal"
)

$resolvedResultsDirectory = $null
if (-not [string]::IsNullOrWhiteSpace($ResultsDirectory)) {
    $repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    $resolvedResultsDirectory = if ([IO.Path]::IsPathRooted($ResultsDirectory)) {
        [IO.Path]::GetFullPath($ResultsDirectory)
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $repositoryRoot $ResultsDirectory))
    }

    New-Item -ItemType Directory -Path $resolvedResultsDirectory -Force | Out-Null
    $arguments += "/ResultsDirectory:$resolvedResultsDirectory"
    $arguments += "/Logger:trx;LogFileName=EspReader.Tests.trx"
}

$originalPath = $env:PATH
try {
    if ($EnableAddressSanitizer) {
        $versionFileName = if ([string]::IsNullOrWhiteSpace($PlatformToolset)) {
            "Microsoft.VCToolsVersion.default.txt"
        }
        else {
            "Microsoft.VCToolsVersion.$PlatformToolset.default.txt"
        }
        $versionFile = Join-Path $installationPath "VC\Auxiliary\Build\$versionFileName"
        if (-not (Test-Path -LiteralPath $versionFile)) {
            throw "The selected MSVC toolset version file was not found."
        }

        $toolsVersion = (Get-Content -Raw -LiteralPath $versionFile).Trim()
        $runtimeDirectory = Join-Path $installationPath "VC\Tools\MSVC\$toolsVersion\bin\Hostx64\x64"
        $addressSanitizerRuntime = Join-Path $runtimeDirectory "clang_rt.asan_dynamic-x86_64.dll"
        if (-not (Test-Path -LiteralPath $addressSanitizerRuntime)) {
            throw "The AddressSanitizer runtime was not found for the selected MSVC toolset."
        }

        $env:PATH = "$runtimeDirectory;$originalPath"
    }

    & $testRunner @arguments
    $testExitCode = $LASTEXITCODE
}
finally {
    $env:PATH = $originalPath
}

if ($resolvedResultsDirectory) {
    $privateRoots = @(
        [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
        $installationPath
        $env:GITHUB_WORKSPACE
        $env:RUNNER_TEMP
        $env:RUNNER_TOOL_CACHE
        $env:USERPROFILE
        $env:TEMP
        $env:ProgramFiles
        ${env:ProgramFiles(x86)}
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    Get-ChildItem -LiteralPath $resolvedResultsDirectory -Filter "*.trx" | ForEach-Object {
        $content = Get-Content -Raw -LiteralPath $_.FullName
        foreach ($privateRoot in $privateRoots) {
            $content = [Regex]::Replace(
                $content,
                [Regex]::Escape([IO.Path]::GetFullPath($privateRoot)),
                "<private-path>",
                [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
        $content = [Regex]::Replace(
            $content,
            "\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
            "<secret>",
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        Set-Content -LiteralPath $_.FullName -Value $content -Encoding utf8
    }
}

if ($testExitCode -ne 0) {
    throw "EspReader parser tests failed with exit code $testExitCode."
}
