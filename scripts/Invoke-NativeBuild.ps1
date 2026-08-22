[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64",

    [string]$PlatformToolset,

    [switch]$Analyze,

    [switch]$EnableAddressSanitizer,

    [string]$ArtifactDirectory
)

$ErrorActionPreference = "Stop"

$msbuildCommand = Get-Command "msbuild.exe" -ErrorAction SilentlyContinue
if ($msbuildCommand) {
    $msbuild = $msbuildCommand.Source
}
else {
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

    $msbuild = Join-Path $installationPath "MSBuild\Current\Bin\MSBuild.exe"
    if (-not (Test-Path -LiteralPath $msbuild)) {
        throw "MSBuild was not found in the selected Visual Studio installation."
    }
}
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$solution = Join-Path $repositoryRoot "EspReader.sln"
$arguments = @(
    $solution
    "/t:Rebuild"
    "/m"
    "/p:Configuration=$Configuration"
    "/p:Platform=$Platform"
    "/nologo"
    "/verbosity:minimal"
)

if ($Analyze) {
    $arguments += "/p:RunCodeAnalysis=true"
}

if (-not [string]::IsNullOrWhiteSpace($PlatformToolset)) {
    $arguments += "/p:PlatformToolset=$PlatformToolset"
}

if ($EnableAddressSanitizer) {
    $arguments += "/p:EnableASAN=true"
}

$output = @(& $msbuild @arguments 2>&1)
$buildExitCode = $LASTEXITCODE
$output | ForEach-Object { Write-Host $_ }

if (-not [string]::IsNullOrWhiteSpace($ArtifactDirectory)) {
    $resolvedArtifactDirectory = if ([IO.Path]::IsPathRooted($ArtifactDirectory)) {
        [IO.Path]::GetFullPath($ArtifactDirectory)
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $repositoryRoot $ArtifactDirectory))
    }

    New-Item -ItemType Directory -Path $resolvedArtifactDirectory -Force | Out-Null
    $sanitizedLog = $output -join [Environment]::NewLine
    $privateRoots = @(
        $repositoryRoot
        ($msbuild -split "\\MSBuild\\", 2)[0]
        $env:GITHUB_WORKSPACE
        $env:RUNNER_TEMP
        $env:RUNNER_TOOL_CACHE
        $env:USERPROFILE
        $env:TEMP
        $env:ProgramFiles
        ${env:ProgramFiles(x86)}
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($privateRoot in $privateRoots) {
        $sanitizedLog = [Regex]::Replace(
            $sanitizedLog,
            [Regex]::Escape([IO.Path]::GetFullPath($privateRoot)),
            "<private-path>",
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $sanitizedLog = [Regex]::Replace(
        $sanitizedLog,
        "\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
        "<secret>",
        [Text.RegularExpressions.RegexOptions]::IgnoreCase)

    $logName = if ($Analyze) { "native-analysis.log" } elseif ($EnableAddressSanitizer) {
        "sanitizer-build.log"
    } else {
        "native-build.log"
    }
    Set-Content -LiteralPath (Join-Path $resolvedArtifactDirectory $logName) `
        -Value $sanitizedLog `
        -Encoding utf8
}

if ($buildExitCode -ne 0) {
    throw "EspReader native build failed with exit code $buildExitCode."
}

$warningLines = @($output | Where-Object { $_ -match "\bwarning [A-Z]+[0-9]+\b" })
if ($warningLines.Count -ne 0) {
    throw "EspReader native build emitted $($warningLines.Count) warning line(s)."
}
