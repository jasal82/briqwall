<#
.SYNOPSIS
  Erzeugt die Branding-Bilder des Installers (NSIS/MUI2):
    sidebar.bmp  164x314  Willkommens- und Abschlussseite
    header.bmp   150x57   Kopfbereich der übrigen Seiten
  Ausgabe: crates\briqwall-ui\installer\
#>
Add-Type -AssemblyName System.Drawing
$out = Join-Path $PSScriptRoot "..\crates\briqwall-ui\installer"
New-Item -ItemType Directory -Force $out | Out-Null

$green1 = [System.Drawing.Color]::FromArgb(52, 201, 123)
$green2 = [System.Drawing.Color]::FromArgb(20, 129, 75)

function New-ShieldPath([single]$x, [single]$y, [single]$size) {
    # Shield from design/icon.svg (viewBox 1024), scaled into a box of $size.
    $s = $size / 1024.0
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $pt = { param($a, $b) New-Object System.Drawing.PointF(($x + ($a - 128) * $s), ($y + ($b - 128) * $s)) }
    $p.AddLine((& $pt 512 196), (& $pt 260 296))
    $p.AddLine((& $pt 260 296), (& $pt 260 468))
    $p.AddBezier((& $pt 260 468), (& $pt 260 636), (& $pt 366 764), (& $pt 512 820))
    $p.AddBezier((& $pt 512 820), (& $pt 658 764), (& $pt 764 636), (& $pt 764 468))
    $p.AddLine((& $pt 764 468), (& $pt 764 296))
    $p.CloseFigure()
    return $p
}

function Draw-Mark($g, [single]$x, [single]$y, [single]$size, $color) {
    $s = $size / 1024.0
    $w = [single](60 * $s); if ($w -lt 1.6) { $w = 1.6 }
    $pen = New-Object System.Drawing.Pen($color, $w)
    $pen.LineJoin = 'Round'
    $g.DrawPath($pen, (New-ShieldPath $x $y $size))
    $pen.Width = [single](64 * $s); if ($pen.Width -lt 1.8) { $pen.Width = 1.8 }
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $pts = @(
        (New-Object System.Drawing.PointF(($x + (396 - 128) * $s), ($y + (504 - 128) * $s))),
        (New-Object System.Drawing.PointF(($x + (480 - 128) * $s), ($y + (588 - 128) * $s))),
        (New-Object System.Drawing.PointF(($x + (636 - 128) * $s), ($y + (424 - 128) * $s)))
    )
    $g.DrawLines($pen, $pts)
}

function Save-Bmp($bmp, $name) {
    # MUI2 expects a plain 24-bit bitmap.
    $rgb = New-Object System.Drawing.Bitmap($bmp.Width, $bmp.Height, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $g = [System.Drawing.Graphics]::FromImage($rgb); $g.DrawImage($bmp, 0, 0, $bmp.Width, $bmp.Height); $g.Dispose()
    $rgb.Save((Join-Path $out $name), [System.Drawing.Imaging.ImageFormat]::Bmp)
    $rgb.Dispose()
}

# ---- sidebar 164x314 --------------------------------------------------------
$bmp = New-Object System.Drawing.Bitmap(164, 314)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'
$rect = New-Object System.Drawing.Rectangle(0, 0, 164, 314)
$grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $green1, $green2, 70)
$g.FillRectangle($grad, $rect)
# subtle large shield watermark
Draw-Mark $g -40 150 260 ([System.Drawing.Color]::FromArgb(28, 255, 255, 255))
Draw-Mark $g 46 40 72 ([System.Drawing.Color]::White)
$white = [System.Drawing.Brushes]::White
$fTitle = New-Object System.Drawing.Font("Segoe UI Semibold", 17)
$fmt = New-Object System.Drawing.StringFormat; $fmt.Alignment = 'Center'
# Language-neutral: the installer shows English or German depending on Windows.
$g.DrawString("Briqwall", $fTitle, $white, (New-Object System.Drawing.RectangleF(0, 128, 164, 34)), $fmt)
$g.Dispose(); Save-Bmp $bmp "sidebar.bmp"; $bmp.Dispose()

# ---- header 150x57 ------------------------------------------------------------
$bmp = New-Object System.Drawing.Bitmap(150, 57)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.Clear([System.Drawing.Color]::White)
$tile = New-Object System.Drawing.Rectangle(104, 10, 37, 37)
$gp = New-Object System.Drawing.Drawing2D.GraphicsPath
$r = 9
$gp.AddArc($tile.X, $tile.Y, $r * 2, $r * 2, 180, 90)
$gp.AddArc($tile.Right - $r * 2, $tile.Y, $r * 2, $r * 2, 270, 90)
$gp.AddArc($tile.Right - $r * 2, $tile.Bottom - $r * 2, $r * 2, $r * 2, 0, 90)
$gp.AddArc($tile.X, $tile.Bottom - $r * 2, $r * 2, $r * 2, 90, 90)
$gp.CloseFigure()
$g.FillPath((New-Object System.Drawing.Drawing2D.LinearGradientBrush($tile, $green1, $green2, 45)), $gp)
Draw-Mark $g 109.5 15.5 26 ([System.Drawing.Color]::White)
$g.Dispose(); Save-Bmp $bmp "header.bmp"; $bmp.Dispose()

Write-Host "Bilder geschrieben nach $out"
