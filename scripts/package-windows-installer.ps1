param(
    [string]$Version,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not $Version) {
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $repoRoot "Cargo.toml")
    $match = [regex]::Match($manifest, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $match.Success) {
        throw "could not read package version from Cargo.toml"
    }
    $Version = $match.Groups[1].Value
}

if (-not $SkipBuild) {
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        throw "release build failed with exit code $LASTEXITCODE"
    }
}

$binary = Join-Path $repoRoot "target\release\ciphermesh.exe"
if (-not (Test-Path -LiteralPath $binary)) {
    throw "release binary not found: $binary"
}

$compilerCandidates = @(
    (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

$compiler = $compilerCandidates | Select-Object -First 1
if (-not $compiler) {
    throw "Inno Setup 6 is required. Install it with: winget install --id JRSoftware.InnoSetup -e"
}

New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot "dist") | Out-Null
& $compiler "/DAppVersion=$Version" (Join-Path $repoRoot "packaging\windows\ciphermesh.iss")
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed with exit code $LASTEXITCODE"
}

$installer = Join-Path $repoRoot "dist\CipherMesh-$Version-windows-x64-setup.exe"
if (-not (Test-Path -LiteralPath $installer)) {
    throw "installer was not created: $installer"
}
Write-Host "Packaged: $installer"
