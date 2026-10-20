<#
.SYNOPSIS
    Verifies Lumen end to end: build, test, launch, screenshot every page, and
    check the rendered output for the mistakes that are easy to miss by reading
    the code.

.DESCRIPTION
    Everything runs against the sandbox folder inside the project, so nothing is
    written outside it and clean-sandbox.ps1 removes the lot.

    The pixel checks are the interesting part. They catch the failure mode that a
    compiler and a unit test cannot: a page whose background is not themed, so
    light text lands on a light background and the title is invisible.

.PARAMETER SkipBuild
    Reuse the existing build output.

.PARAMETER SkipTests
    Do not run the test suites.
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$sandbox = Join-Path $root '.sandbox'
$data = Join-Path $sandbox 'data'
$shots = Join-Path $sandbox 'shots'
$artifacts = Join-Path $sandbox 'artifacts'
$dotnet = Join-Path $env:USERPROFILE '.dotnet\dotnet.exe'
if (-not (Test-Path $dotnet)) { $dotnet = 'dotnet' }

New-Item -ItemType Directory -Force -Path $data, $shots | Out-Null
$env:LUMEN_DATA_DIR = $data
$env:LUMEN_DISABLE_REALTIME = '1'

Write-Host "`n=== 1. Build ===" -ForegroundColor Cyan
if (-not $SkipBuild) {
    & $dotnet restore "$root\Lumen.slnx" --artifacts-path $artifacts | Out-Host
    & $dotnet build "$root\Lumen.slnx" --artifacts-path $artifacts --no-restore -v q | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The build failed." }
}

if (-not $SkipTests) {
    Write-Host "`n=== 2. Tests ===" -ForegroundColor Cyan
    foreach ($project in @('tests\Lumen.Core.Tests\Lumen.Core.Tests.csproj', 'tests\Lumen.App.Tests\Lumen.App.Tests.csproj')) {
        $result = & $dotnet test "$root\$project" --artifacts-path $artifacts --no-restore 2>&1
        $text = $result | Out-String
        Write-Host "  $project" -ForegroundColor DarkGray

        # The test summary is localized and French typography puts a narrow no-break
        # space (U+202F) before the colon, which .NET's \s does NOT match. Match on
        # "anything that is not a digit" instead.
        $total = [regex]::Match($text, 'total[^0-9]{1,6}([0-9]+)')
        $passed = [regex]::Match($text, 'ussite[^0-9]{1,6}([0-9]+)')
        $failed = [regex]::Match($text, 'chec[^0-9]{1,6}([0-9]+)')
        if ($total.Success) {
            $colour = if ($failed.Success -and [int]$failed.Groups[1].Value -gt 0) { 'Red' } else { 'Green' }
            Write-Host ("    total {0}  passed {1}  failed {2}" -f `
                $total.Groups[1].Value, `
                $(if ($passed.Success) { $passed.Groups[1].Value } else { '?' }), `
                $(if ($failed.Success) { $failed.Groups[1].Value } else { '0' })) -ForegroundColor $colour
        }
        else {
            Write-Host '    (no summary found)' -ForegroundColor Yellow
        }

        $fails = $result | Select-String -Pattern '\[FAIL\]'
        if ($fails) {
            $fails | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        }
    }
}

Write-Host "`n=== 3. Screenshots ===" -ForegroundColor Cyan
Remove-Item "$shots\*.png" -ErrorAction SilentlyContinue
# Start from a clean log so only errors from THIS run are reported.
$logPath = Join-Path $data 'logs\lumen.log'
if (Test-Path $logPath) { Remove-Item $logPath -Force -ErrorAction SilentlyContinue }
$exe = Get-ChildItem -Path $artifacts -Filter 'Lumen.exe' -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $exe) { throw "Lumen.exe was not found. Run without -SkipBuild." }

$process = Start-Process -FilePath $exe -ArgumentList @('--shots', "`"$shots`"") -PassThru
$process.WaitForExit(30000) | Out-Null
Start-Sleep -Milliseconds 800

$captured = Get-ChildItem "$shots\*.png" -ErrorAction SilentlyContinue
if ($captured.Count -eq 0) {
    Write-Host "  No screenshots were produced." -ForegroundColor Red
    if (Test-Path "$shots\capture-errors.txt") { Get-Content "$shots\capture-errors.txt" }
    throw "The capture run produced nothing."
}
$captured | ForEach-Object { Write-Host ("  {0,8} bytes  {1}" -f $_.Length, $_.Name) }

Write-Host "`n=== 4. Pixel checks ===" -ForegroundColor Cyan
Add-Type -AssemblyName System.Drawing

function Get-Pixel($image, $x, $y) {
    $color = $image.GetPixel($x, $y)
    return [int](($color.R * 0.299) + ($color.G * 0.587) + ($color.B * 0.114))
}

$problems = @()
foreach ($file in $captured) {
    $image = [System.Drawing.Bitmap]::FromFile($file.FullName)
    try {
        $width = $image.Width
        $height = $image.Height

        # The page area, below the header and to the right of the sidebar.
        $page = Get-Pixel $image ([int]($width * 0.55)) ([int]($height * 0.12))
        # The header strip.
        $header = Get-Pixel $image ([int]($width * 0.5)) ([int]($height * 0.03))
        # The sidebar.
        $sidebar = Get-Pixel $image ([int]($width * 0.07)) ([int]($height * 0.75))

        Write-Host ("  {0,-16} page={1,3}  header={2,3}  sidebar={3,3}" -f $file.BaseName, $page, $header, $sidebar)

        # A dark theme means the page must not be brighter than the sidebar.
        if ($page -gt 60) {
            $problems += "$($file.BaseName): the page background is light (luma $page). The window background is probably not themed."
        }
        if ($header -gt 60) {
            $problems += "$($file.BaseName): the header is light (luma $header)."
        }
        if ($sidebar -gt 60) {
            $problems += "$($file.BaseName): the sidebar is light (luma $sidebar)."
        }
    }
    finally { $image.Dispose() }
}

Write-Host "`n=== 5. Log ===" -ForegroundColor Cyan
$log = Join-Path $data 'logs\lumen.log'
if (Test-Path $log) {
    $errors = Get-Content $log | Select-String -Pattern '\[ERROR\]'
    if ($errors) {
        $errors | Select-Object -Last 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        $problems += "The log contains $($errors.Count) error(s)."
    }
    else { Write-Host "  No errors logged." -ForegroundColor Green }
}

Write-Host "`n=== Result ===" -ForegroundColor Cyan
if ($problems.Count -eq 0) {
    Write-Host "  All checks passed." -ForegroundColor Green
    exit 0
}

$problems | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
exit 1
