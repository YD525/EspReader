$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$version = "3.1.2"
$expectedHash = "F0446D863F9C19926AD9483C523FDC42E42B8D4A6A431D27E09D49C79A140D9A"
$archiveUri = "https://github.com/richgel999/miniz/releases/download/$version/miniz-$version.zip"
$projectDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\EspReader"))
$temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$temporaryDirectory = Join-Path $temporaryRoot ("EspReader-miniz-" + [System.Guid]::NewGuid().ToString("N"))

if (-not $temporaryDirectory.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The temporary directory is outside the system temporary directory."
}

New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

try {
    $archivePath = Join-Path $temporaryDirectory "miniz.zip"
    Invoke-WebRequest -Uri $archiveUri -OutFile $archivePath

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if (-not $actualHash.Equals($expectedHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The miniz archive checksum does not match the pinned checksum."
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $temporaryDirectory
    Copy-Item -LiteralPath (Join-Path $temporaryDirectory "miniz.c") -Destination $projectDirectory
    Copy-Item -LiteralPath (Join-Path $temporaryDirectory "miniz.h") -Destination $projectDirectory
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
