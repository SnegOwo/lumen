<#
.SYNOPSIS
    Builds the distributable ZIP that can be copied to a machine with nothing
    installed on it.

.DESCRIPTION
    Publishes Lumen self-contained, so the ZIP carries its own copy of the .NET
    runtime and needs no installation. The result is a single Lumen.exe plus the
    data-driven detection rules, two launchers and a README.

    The first publish downloads the Windows runtime packs into the local NuGet
    cache. That is a build-time download; the application itself never makes a
    network call.

.EXAMPLE
    .\scripts\package.ps1
#>
[CmdletBinding()]
param(
    [string]$Version = '2.0.0',
    [string]$Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $env:USERPROFILE '.dotnet\dotnet.exe'
if (-not (Test-Path $dotnet)) { $dotnet = 'dotnet' }

$project = Join-Path $root 'src\Lumen.App\Lumen.App.csproj'
$dist = Join-Path $root 'dist\Lumen'
$stage = Join-Path $env:TEMP 'lumen-package-stage'
$zip = Join-Path $root "Lumen-$Version-$Runtime.zip"

Write-Host "Publishing self-contained ($Runtime)..." -ForegroundColor Cyan
& $dotnet publish $project -c Release -r $Runtime --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -o $dist
if ($LASTEXITCODE -ne 0) { throw "The publish failed." }

Write-Host "Staging..." -ForegroundColor Cyan
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$stage\Lumen" | Out-Null

Copy-Item "$dist\Lumen.exe" "$stage\Lumen\" -Force
Copy-Item "$dist\Signatures" "$stage\Lumen\" -Recurse -Force

# The launchers and the README live in the repository so they are versioned, and
# they are copied into the package here.
Copy-Item "$root\packaging\README.txt" "$stage\Lumen\" -Force
Copy-Item "$root\packaging\Start Lumen.cmd" "$stage\Lumen\" -Force
Copy-Item "$root\packaging\Start Lumen (isolated).cmd" "$stage\Lumen\" -Force

Write-Host "Zipping..." -ForegroundColor Cyan
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path "$stage\Lumen" -DestinationPath $zip -CompressionLevel Optimal

$size = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host "`n$zip  ($size MB)" -ForegroundColor Green
Write-Host "Extract it anywhere and double-click 'Start Lumen.cmd'." -ForegroundColor DarkGray
