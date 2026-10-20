<#
.SYNOPSIS
    Removes everything Lumen created during a sandboxed test run.

.DESCRIPTION
    Deletes the .sandbox folder: the sandboxed data directory (settings, history,
    quarantine vault, logs, remediation journal), the isolated build output and any
    screenshots. Nothing outside this project folder is touched.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()

$root = Split-Path -Parent $PSScriptRoot
$sandbox = Join-Path $root '.sandbox'

if (-not (Test-Path $sandbox)) {
    Write-Host "Nothing to clean: $sandbox does not exist." -ForegroundColor DarkGray
    return
}

$size = (Get-ChildItem -Path $sandbox -Recurse -File -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum).Sum
$sizeMb = [math]::Round(($size / 1MB), 1)

if ($PSCmdlet.ShouldProcess($sandbox, "Delete $sizeMb MB of sandbox data and build output")) {
    Remove-Item -Path $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Cleaned $sandbox ($sizeMb MB)." -ForegroundColor Green
}
