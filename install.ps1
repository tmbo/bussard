<#
.SYNOPSIS
    Installs the bussard CLI on Windows.

.DESCRIPTION
    Downloads the release binary for this machine, verifies the published
    SHA-256 checksum, and puts bussard.exe on your disk. Nothing is compiled
    and nothing outside the install directory is touched.

    Run it with:

        irm https://raw.githubusercontent.com/tmbo/bussard/main/install.ps1 | iex

.PARAMETER Version
    Version to install, for example 0.1.0. Defaults to the latest release.
    Can also be set through the BUSSARD_VERSION environment variable.

.PARAMETER InstallDir
    Where to put bussard.exe. Defaults to %LOCALAPPDATA%\Programs\bussard.
    Can also be set through the BUSSARD_INSTALL_DIR environment variable.

.NOTES
    Written for Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param(
    [string] $Version = $env:BUSSARD_VERSION,
    [string] $InstallDir = $env:BUSSARD_INSTALL_DIR
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Repo = 'tmbo/bussard'
$ReleasesUrl = "https://github.com/$Repo/releases"
$ApiUrl = "https://api.github.com/repos/$Repo/releases"

# Windows PowerShell 5.1 still defaults to TLS 1.0, which github.com refuses.
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Get-BussardAsset {
    # Only an x64 binary is published. Windows on arm64 runs it under emulation,
    # so warn rather than refuse.
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq 'ARM64') {
        Write-Warning 'No native arm64 Windows build yet; installing the x64 binary, which Windows runs under emulation.'
    }
    elseif ($arch -ne 'AMD64') {
        throw "Unsupported CPU architecture '$arch'. bussard publishes an x64 Windows binary; see $ReleasesUrl."
    }
    return 'bussard-windows-x64.exe'
}

function Resolve-BussardVersion {
    if ($Version) { return $Version }

    try {
        # The API reports the newest non-draft, non-prerelease release.
        $release = Invoke-RestMethod -Uri "$ApiUrl/latest" -UseBasicParsing `
            -Headers @{ 'User-Agent' = 'bussard-installer' }
    }
    catch {
        throw ("Could not determine the latest bussard release ($($_.Exception.Message)). " +
            "GitHub may be rate-limiting this machine. Pick a version from $ReleasesUrl " +
            'and retry with: $env:BUSSARD_VERSION = "x.y.z"')
    }
    # Guard the property access: Set-StrictMode throws on a missing property.
    if (-not $release.PSObject.Properties['tag_name'] -or -not $release.tag_name) {
        throw "Could not determine the latest bussard release; see $ReleasesUrl."
    }
    return $release.tag_name
}

function Save-Url {
    param([string] $Url, [string] $Path)
    Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing `
        -Headers @{ 'User-Agent' = 'bussard-installer' }
}

$asset = Get-BussardAsset
$requested = Resolve-BussardVersion
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("bussard-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    # Release tags are pushed either as `0.1.0` or `v0.1.0`. Try both, using the
    # small checksum file as the probe, and remember which one exists.
    $bare = $requested -replace '^v', ''
    $tag = $null
    $sumPath = Join-Path $tmp "$asset.sha256"
    foreach ($candidate in @($bare, "v$bare")) {
        try {
            Save-Url -Url "$ReleasesUrl/download/$candidate/$asset.sha256" -Path $sumPath
            $tag = $candidate
            break
        }
        catch {
            continue
        }
    }
    if (-not $tag) {
        throw ("No download found for $asset in release '$requested'. " +
            "Check $ReleasesUrl for the versions and platforms that are published.")
    }

    Write-Host "Downloading bussard $tag ($asset)"
    $exePath = Join-Path $tmp $asset
    Save-Url -Url "$ReleasesUrl/download/$tag/$asset" -Path $exePath

    # The checksum file is "<hash>  <filename>", as written by sha256sum.
    $expected = ((Get-Content -Path $sumPath -TotalCount 1) -split '\s+')[0]
    if (-not $expected) {
        throw "The published checksum file for $asset is empty."
    }
    $actual = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash
    if ($expected.ToLowerInvariant() -ne $actual.ToLowerInvariant()) {
        throw ("Checksum mismatch for ${asset}: expected $expected, got $actual. " +
            'The download was corrupted or tampered with; nothing was installed.')
    }
    Write-Host 'Checksum verified'

    if (-not $InstallDir) {
        $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\bussard'
    }
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $target = Join-Path $InstallDir 'bussard.exe'
    Move-Item -LiteralPath $exePath -Destination $target -Force

    Write-Host "Installed $target"
    Write-Host ''
    & $target --version

    # Put the install directory on the user PATH. The current session keeps its
    # inherited PATH, so tell the user to open a new terminal.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $onPath = @($userPath -split ';' | Where-Object { $_ -eq $InstallDir }).Count -gt 0
    if (-not $onPath) {
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        $env:Path = "$env:Path;$InstallDir"
        Write-Host ''
        Write-Host "Added $InstallDir to your PATH. Open a new terminal, then run: bussard --help"
    }
    else {
        Write-Host ''
        Write-Host 'Next: bussard --help'
    }
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
