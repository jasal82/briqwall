<#
.SYNOPSIS
  Entfernt Briqwall vollständig: Dienst, alle WFP-Filter, Verknüpfungen.
  Mit -Purge werden auch Regeln und Protokolle in C:\ProgramData\Briqwall gelöscht.
#>
param(
    [string]$Target = (Join-Path $env:ProgramFiles "Briqwall"),
    [switch]$Purge
)
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Bitte PowerShell als Administrator starten."
}

Get-Process briqwall-ui -ErrorAction SilentlyContinue | Stop-Process -Force

$exe = Join-Path $Target "briqwall-service.exe"
if (Test-Path $exe) {
    if ($Purge) { & $exe uninstall --purge } else { & $exe uninstall }
}

Remove-Item (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Briqwall.lnk") -ErrorAction SilentlyContinue
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Briqwall -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Classes\briqwall" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Classes\AppUserModelId\Briqwall.Firewall" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Briqwall" -Recurse -ErrorAction SilentlyContinue
Remove-Item $Target -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Briqwall wurde entfernt." -ForegroundColor Green
