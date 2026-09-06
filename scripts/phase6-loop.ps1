param(
    [int]$Iterations = 1,
    [int]$DelaySeconds = 5,
    [switch]$Full,
    [switch]$NoClippy
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$phase6Filters = @(
    "hardening_tests",
    "storage::tests::outbox",
    "storage::tests::sync",
    "storage::tests::own_device",
    "storage::tests::device_revocation",
    "storage::tests::duplicate",
    "crdt::tests",
    "discovery_tests"
)

function Invoke-Phase6Command {
    param([string[]]$Command)

    Write-Host ""
    Write-Host ">>> $($Command -join ' ')"
    & $Command[0] $Command[1..($Command.Length - 1)]
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

$count = 0
while ($Iterations -eq 0 -or $count -lt $Iterations) {
    $count += 1
    Write-Host ""
    Write-Host "=== Phase 6 validation pass $count ==="
    Write-Host "Started: $(Get-Date -Format o)"

    Invoke-Phase6Command @("cargo", "fmt", "--check")

    foreach ($filter in $phase6Filters) {
        Invoke-Phase6Command @("cargo", "test", $filter)
    }

    if ($Full) {
        Invoke-Phase6Command @("cargo", "test")
    }

    Invoke-Phase6Command @("cargo", "run", "--", "phase6-lan-smoke")
    Invoke-Phase6Command @("cargo", "run", "--", "phase6-invite-discovery-smoke")
    Invoke-Phase6Command @("cargo", "run", "--", "phase6-mailbox-smoke")

    if (-not $NoClippy) {
        Invoke-Phase6Command @("cargo", "clippy", "--all-targets", "--all-features", "--", "-D", "warnings")
    }

    Write-Host "Finished: $(Get-Date -Format o)"

    if ($Iterations -eq 0 -or $count -lt $Iterations) {
        Start-Sleep -Seconds $DelaySeconds
    }
}
