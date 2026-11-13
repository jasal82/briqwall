<#
.SYNOPSIS
  Installiert Briqwall nach "C:\Program Files\Briqwall" und richtet den Dienst ein.

.DESCRIPTION
  Muss als Administrator ausgeführt werden. Erwartet die Release-Binaries in
  target\release (cargo build --release) oder im Ordner, der per -Source
  angegeben wird.

  Der Installationsort ist sicherheitsrelevant: Nur in einem Ordner, in den
  ausschließlich Administratoren schreiben dürfen, kann kein anderes Programm
  den Dienst austauschen.
#>
param(
    [string]$Source = (Join-Path $PSScriptRoot "..\target\release"),
    [string]$Target = (Join-Path $env:ProgramFiles "Briqwall")
)
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Bitte PowerShell als Administrator starten."
}

foreach ($f in "briqwall-service.exe", "briqwall.exe") {
    if (-not (Test-Path (Join-Path $Source $f))) { throw "$f fehlt in $Source - zuerst 'cargo build --release' ausführen." }
}

# Laufende Instanzen beenden (Filter bleiben aktiv, der Schutz läuft weiter).
Get-Process briqwall-ui -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service briqwall -ErrorAction SilentlyContinue) { Stop-Service briqwall -Force }

New-Item -ItemType Directory -Force $Target | Out-Null
Copy-Item (Join-Path $Source "briqwall-service.exe") $Target -Force
Copy-Item (Join-Path $Source "briqwall.exe") $Target -Force

& (Join-Path $Target "briqwall-service.exe") install
if ($LASTEXITCODE -ne 0) { throw "Dienstinstallation fehlgeschlagen." }

# Startmenü-Verknüpfung (für alle Benutzer)
$lnk = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Briqwall.lnk"
$sh = New-Object -ComObject WScript.Shell
$s = $sh.CreateShortcut($lnk)
$s.TargetPath = Join-Path $Target "briqwall.exe"
$s.Description = "Briqwall Firewall"
$s.Save()

# Oberfläche ohne Administratorrechte im Kontext des angemeldeten Benutzers starten.
Start-Process explorer.exe -ArgumentList "`"$(Join-Path $Target 'briqwall.exe')`""

Write-Host ""
Write-Host "Briqwall ist installiert und aktiv." -ForegroundColor Green
Write-Host "Notfall - alle Filter sofort entfernen:  `"$Target\briqwall-service.exe`" reset"
