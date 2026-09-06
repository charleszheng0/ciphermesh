param(
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$targetDir = Join-Path $repoRoot $OutDir
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

Write-Host ">>> cargo build --release"
cargo build --release
if ($LASTEXITCODE -ne 0) {
    throw "release build failed with exit code $LASTEXITCODE"
}

$binaryName = if ($IsWindows -or $env:OS -eq "Windows_NT") { "ciphermesh.exe" } else { "ciphermesh" }
$source = Join-Path $repoRoot "target\release\$binaryName"
if (-not (Test-Path -LiteralPath $source)) {
    throw "release binary not found: $source"
}

$osName = if ($IsWindows -or $env:OS -eq "Windows_NT") { "windows" } elseif ($IsMacOS) { "macos" } else { "linux" }
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq "Arm64") { "arm64" } else { "x64" }
$dest = Join-Path $targetDir "ciphermesh-$osName-$arch-$binaryName"

Copy-Item -LiteralPath $source -Destination $dest -Force
Write-Host "Packaged: $dest"
