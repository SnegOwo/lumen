<#
.SYNOPSIS
    Runs Lumen in a sandbox: all data inside this project folder, real-time
    protection disabled, nothing outside the folder touched.

.DESCRIPTION
    Sets LUMEN_DATA_DIR to .sandbox\data inside the project and
    LUMEN_DISABLE_REALTIME=1 so the on-access watcher never looks at the real
    Desktop, Documents or Downloads. Running the app then leaves no trace
    outside this folder.

    Delete the .sandbox folder to remove every trace of a test run.

.PARAMETER Build
    Build the solution before running.

.PARAMETER Screenshot
    Also capture a screenshot of the window into .sandbox\shots.

.PARAMETER Demo
    Start in demonstration mode: Lumen raises the detection alert on a harmless
    sample file a moment after the window opens.

.EXAMPLE
    .\scripts\run-sandbox.ps1 -Build -Screenshot
.EXAMPLE
    .\scripts\run-sandbox.ps1 -Build -Demo -Screenshot
#>
[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$Screenshot,
    [switch]$Demo,
    [int]$ScreenshotDelaySeconds = 4
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$sandbox = Join-Path $root '.sandbox'
$data = Join-Path $sandbox 'data'
$shots = Join-Path $sandbox 'shots'

$dotnet = Join-Path $env:USERPROFILE '.dotnet\dotnet.exe'
if (-not (Test-Path $dotnet)) { $dotnet = 'dotnet' }

$artifacts = Join-Path $sandbox 'artifacts'
$appProject = Join-Path $root 'src\Lumen.App\Lumen.App.csproj'

New-Item -ItemType Directory -Force -Path $data, $shots | Out-Null

if ($Build) {
    Write-Host "Building Lumen..." -ForegroundColor Cyan
    & $dotnet restore $appProject --artifacts-path $artifacts | Out-Host
    & $dotnet build $appProject --artifacts-path $artifacts --no-restore -c Debug | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The build failed." }
}

$exe = Join-Path $artifacts 'bin\Lumen\debug\Lumen.exe'
if (-not (Test-Path $exe)) {
    $found = Get-ChildItem -Path $artifacts -Filter 'Lumen.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $found) { throw "Lumen.exe was not found under $artifacts. Run with -Build first." }
    $exe = $found.FullName
}

$env:LUMEN_DATA_DIR = $data
$env:LUMEN_DISABLE_REALTIME = '1'

Write-Host "Sandbox data: $data" -ForegroundColor Green
Write-Host "Real-time protection: disabled" -ForegroundColor Green
Write-Host "Starting $exe" -ForegroundColor Cyan

$arguments = @()
if ($Demo) { $arguments = @('--demo') }

$process = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru

if ($Screenshot) {
    Start-Sleep -Seconds $ScreenshotDelaySeconds
    $path = Join-Path $shots ("lumen-{0}.png" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    Write-Host "Screenshot saved: $path" -ForegroundColor Green
}

Write-Host "Running. Close the window, or press Ctrl+C to stop waiting." -ForegroundColor DarkGray
$process.WaitForExit()
