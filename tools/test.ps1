# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

param(
    [ValidateSet('windows')]
    [string]$Workflow = 'windows',
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$buildDirectories = @{ windows = 'windows-msvc' }

if (-not $env:VCPKG_ROOT) {
    Write-Error 'Set VCPKG_ROOT to a vcpkg checkout first, for example: $env:VCPKG_ROOT = "C:\dev\vcpkg"'
}

$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root (Join-Path 'build' $buildDirectories[$Workflow])
$results = Join-Path $build 'test-results.xml'
$report = Join-Path $build 'test-report.html'

Push-Location $root
try {
    if (Test-Path $results) { Remove-Item $results }
    cmake --workflow --preset $Workflow
    $status = $LASTEXITCODE
    if (-not (Test-Path $results)) {
        Write-Host 'No test results: the configure or build step failed. See the output above.'
        exit $(if ($status -ne 0) { $status } else { 1 })
    }
    python (Join-Path $root 'tools\test_report.py') $results $report
    if (-not $NoBrowser) { Start-Process $report }
    exit $status
}
finally {
    Pop-Location
}
