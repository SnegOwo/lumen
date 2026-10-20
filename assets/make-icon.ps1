# make-icon.ps1
# Generates assets/lumen.ico : a multi-size, PNG-compressed Windows icon used for the
# application executable, the main window and the tray icon.
#
# Run:  powershell -ExecutionPolicy Bypass -File .\assets\make-icon.ps1
#
# The icon is generated (not downloaded) so the repository contains no binary blob that
# could not be reviewed. Design: rounded gradient tile + white shield + check mark.

Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'
$outDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$icoPath = Join-Path $outDir 'lumen.ico'

function New-RoundedPath([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

function New-ShieldPath([single]$size) {
    # Normalised shield outline scaled to $size.
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $s = $size
    $pts = @(
        [System.Drawing.PointF]::new(0.500*$s, 0.075*$s),
        [System.Drawing.PointF]::new(0.925*$s, 0.245*$s),
        [System.Drawing.PointF]::new(0.925*$s, 0.520*$s),
        [System.Drawing.PointF]::new(0.870*$s, 0.760*$s),
        [System.Drawing.PointF]::new(0.700*$s, 0.905*$s),
        [System.Drawing.PointF]::new(0.500*$s, 0.975*$s),
        [System.Drawing.PointF]::new(0.300*$s, 0.905*$s),
        [System.Drawing.PointF]::new(0.130*$s, 0.760*$s),
        [System.Drawing.PointF]::new(0.075*$s, 0.520*$s),
        [System.Drawing.PointF]::new(0.075*$s, 0.245*$s)
    )
    $p.AddPolygon($pts)
    $p.CloseFigure()
    return $p
}

function New-IconBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap -ArgumentList @($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode   = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    $pad = [single]($size * 0.045)
    $tile = New-RoundedPath $pad $pad ($size - 2*$pad) ($size - 2*$pad) ([single]($size * 0.215))
    $rect = New-Object System.Drawing.RectangleF -ArgumentList @($pad, $pad, ($size - 2*$pad), ($size - 2*$pad))
    $top = [System.Drawing.Color]::FromArgb(255, 20, 184, 166)
    $bottom = [System.Drawing.Color]::FromArgb(255, 13, 108, 138)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush -ArgumentList @($rect, $top, $bottom, [single]90)
    $g.FillPath($grad, $tile)

    # Soft inner highlight so the tile does not look flat at large sizes.
    if ($size -ge 48) {
        $hl = New-RoundedPath $pad $pad ($size - 2*$pad) (($size - 2*$pad) * 0.5) ([single]($size * 0.19))
        $hlTop = [System.Drawing.Color]::FromArgb(48, 255, 255, 255)
        $hlBottom = [System.Drawing.Color]::FromArgb(0, 255, 255, 255)
        $hlBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush -ArgumentList @($rect, $hlTop, $hlBottom, [single]90)
        $g.FillPath($hlBrush, $hl)
        $hlBrush.Dispose(); $hl.Dispose()
    }

    $shieldSize = [single]($size * 0.60)
    $ox = [single](($size - $shieldSize) / 2.0)
    $oy = [single](($size - $shieldSize) / 2.0 + $size * 0.015)
    $state = $g.Save()
    $g.TranslateTransform($ox, $oy)
    $shield = New-ShieldPath $shieldSize
    $white = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 255, 255, 255))
    $g.FillPath($white, $shield)
    $g.Restore($state)

    if ($size -ge 24) {
        $state2 = $g.Save()
        $g.TranslateTransform($ox, $oy)
        $penW = [single]($shieldSize * 0.115)
        $pen = New-Object System.Drawing.Pen -ArgumentList @([System.Drawing.Color]::FromArgb(255, 13, 108, 138), $penW)
        $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $g.DrawLines($pen, @(
            [System.Drawing.PointF]::new(0.310*$shieldSize, 0.520*$shieldSize),
            [System.Drawing.PointF]::new(0.445*$shieldSize, 0.660*$shieldSize),
            [System.Drawing.PointF]::new(0.710*$shieldSize, 0.360*$shieldSize)
        ))
        $pen.Dispose()
        $g.Restore($state2)
    }

    $white.Dispose(); $shield.Dispose(); $grad.Dispose(); $tile.Dispose(); $g.Dispose()
    return $bmp
}

# ---- Write a PNG-compressed .ico container --------------------------------------------
$sizes = @(256, 128, 64, 48, 32, 24, 16)
$pngs = @()
foreach ($s in $sizes) {
    $bmp = New-IconBitmap $s
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs += ,@{ Size = $s; Bytes = $ms.ToArray() }
    $ms.Dispose(); $bmp.Dispose()
}

$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0)               # reserved
$bw.Write([uint16]1)               # type: icon
$bw.Write([uint16]$pngs.Count)     # image count
$offset = 6 + 16 * $pngs.Count
foreach ($img in $pngs) {
    $dim = $img.Size
    if ($dim -ge 256) { $dim = 0 }  # 0 means 256 in the ICO header
    $bw.Write([byte]$dim)
    $bw.Write([byte]$dim)
    $bw.Write([byte]0)              # palette
    $bw.Write([byte]0)              # reserved
    $bw.Write([uint16]1)            # colour planes
    $bw.Write([uint16]32)           # bits per pixel
    $bw.Write([uint32]$img.Bytes.Length)
    $bw.Write([uint32]$offset)
    $offset += $img.Bytes.Length
}
foreach ($img in $pngs) { $bw.Write($img.Bytes) }
$bw.Flush(); $bw.Dispose(); $fs.Dispose()

Write-Host ("Wrote {0} ({1} bytes, sizes: {2})" -f $icoPath, (Get-Item $icoPath).Length, ($sizes -join ', '))

