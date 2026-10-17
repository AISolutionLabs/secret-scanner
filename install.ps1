# SPDX-License-Identifier: Apache-2.0
#
# Install a secretscan release binary on Windows (also works in PowerShell on
# Linux and macOS) after verifying its SHA-256 checksum.
#
#   irm https://raw.githubusercontent.com/AISolutionLabs/secret-scanner/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm .../install.ps1))) -Version v1.0.0 -InstallDir C:\tools
#
# Nothing is installed if the download or the checksum check fails. The
# checksum file is signed by the release workflow with Sigstore (keyless); if
# cosign is on PATH the signature is verified too. -RequireSignature (or
# SECRETSCAN_REQUIRE_SIGNATURE=1) makes that check mandatory.
param(
    [string]$Version = $(if ($env:SECRETSCAN_VERSION) { $env:SECRETSCAN_VERSION } else { 'latest' }),
    [string]$InstallDir = $(if ($env:BINDIR) { $env:BINDIR } elseif ($IsWindows -or $env:OS -eq 'Windows_NT') {
            Join-Path $env:LOCALAPPDATA 'Programs\secretscan' } else { Join-Path $HOME '.local/bin' }),
    [switch]$RequireSignature = ($env:SECRETSCAN_REQUIRE_SIGNATURE -eq '1'),
    # Alternative download location with the same layout as a GitHub release
    # (a mirror, or a local directory in tests). The checksum still applies.
    [string]$BaseUrl = $env:SECRETSCAN_BASE_URL
)
$ErrorActionPreference = 'Stop'
$Repo = 'AISolutionLabs/secret-scanner'

function Say($m) { [Console]::Error.WriteLine("secretscan-install: $m") }
function Fail($m) { Say "error: $m"; exit 1 }

$windows = $IsWindows -or $env:OS -eq 'Windows_NT'
$os = if ($windows) { 'windows' } elseif ($IsMacOS) { 'darwin' } else { 'linux' }
$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { 'amd64' } 'Arm64' { 'arm64' } default { Fail "unsupported architecture $_" }
}
$asset = "secretscan-$os-$arch" + $(if ($windows) { '.exe' } else { '' })

if (-not $BaseUrl) {
    if ($Version -eq 'latest') { $BaseUrl = "https://github.com/$Repo/releases/latest/download" }
    else {
        if (-not $Version.StartsWith('v')) { $Version = "v$Version" }
        $BaseUrl = "https://github.com/$Repo/releases/download/$Version"
    }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("secretscan-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    function Fetch($name) {
        $dest = Join-Path $tmp $name
        $src = "$BaseUrl/$name"
        try {
            if ($src -match '^[a-z]+://') { Invoke-WebRequest -UseBasicParsing -Uri $src -OutFile $dest }
            else { Copy-Item -LiteralPath $src -Destination $dest }
        } catch { Fail "download failed: $src" }
        return $dest
    }
    Say "downloading $asset ($Version)"
    $bin = Fetch $asset
    $sums = Fetch 'SHA256SUMS'

    $want = $null
    foreach ($line in Get-Content -LiteralPath $sums) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $asset) { $want = $parts[0].ToLower() }
    }
    if (-not $want) { Fail "$asset is not listed in SHA256SUMS" }
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $bin).Hash.ToLower()
    if ($got -ne $want) { Fail "checksum mismatch for $asset (want $want, got $got)" }
    Say 'checksum verified'

    if (Get-Command cosign -ErrorAction SilentlyContinue) {
        $bundle = Fetch 'SHA256SUMS.sigstore.json'
        & cosign verify-blob $sums --bundle $bundle `
            --certificate-identity-regexp "^https://github.com/$Repo/\.github/workflows/release\.yml@refs/tags/v" `
            --certificate-oidc-issuer https://token.actions.githubusercontent.com *> $null
        if ($LASTEXITCODE -ne 0) { Fail 'signature verification of SHA256SUMS failed' }
        Say "signature verified (release workflow of $Repo)"
    } elseif ($RequireSignature) {
        Fail 'signature required (-RequireSignature) but cosign is not installed'
    } else {
        Say "note: install cosign to also verify the publisher's signature (see README)"
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $target = Join-Path $InstallDir $(if ($windows) { 'secretscan.exe' } else { 'secretscan' })
    Move-Item -Force -LiteralPath $bin -Destination $target
    if (-not $windows) { & chmod 0755 $target }
    Say "installed $(& $target version) to $target"
    $sep = [System.IO.Path]::PathSeparator
    if (-not (($env:PATH -split [regex]::Escape($sep)) -contains $InstallDir)) {
        Say "note: $InstallDir is not on your PATH"
    }
} finally {
    Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}
