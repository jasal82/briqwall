<#
.SYNOPSIS
  Baut Briqwall komplett inklusive Installer.

.DESCRIPTION
  1. Typprüfung der Oberfläche (ui/)
  2. Tests (überspringbar mit -SkipTests)
  3. Firewall-Dienst (Release) als Beilage für den Installer
  4. Oberfläche + NSIS-Installer über die Tauri-CLI

  Ergebnis:
    target\release\briqwall.exe
    target\release\briqwall-service.exe
    target\release\bundle\nsis\Briqwall_<version>_x64-setup.exe
#>
param([switch]$SkipTests)
# Native tools write progress to stderr; Windows PowerShell 5.1 would treat
# that as an error under "Stop". Exit codes are checked explicitly instead.
$ErrorActionPreference = "Continue"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what fehlgeschlagen (Exit-Code $LASTEXITCODE)" } }

Push-Location $root
try {
    Step "Frontend-Abhängigkeiten"
    if (-not (Test-Path "ui\node_modules")) { npm --prefix ui ci; Check "npm ci" }

    Step "Typprüfung und Build der Oberfläche"
    npm --prefix ui run check; Check "Typprüfung"
    npm --prefix ui run build; Check "Frontend-Build"

    # The UI crate embeds ui/dist and the service binary (Tauri checks both at
    # compile time), so the service is built first.
    Step "Firewall-Dienst"
    cargo build --release --locked -p briqwall-service; Check "Dienst-Build"
    $triple = (rustc -vV | Select-String "^host: (.+)$").Matches[0].Groups[1].Value
    $sidecar = "crates\briqwall-ui\binaries\briqwall-service-$triple.exe"
    New-Item -ItemType Directory -Force (Split-Path $sidecar) | Out-Null
    Copy-Item "target\release\briqwall-service.exe" $sidecar -Force

    if (-not $SkipTests) {
        Step "Tests"
        cargo test --release --locked --workspace; Check "cargo test"
    }

    Step "Oberfläche und Installer"
    Push-Location "crates\briqwall-ui"
    try { & "$root\ui\node_modules\.bin\tauri.cmd" build; Check "Tauri-Build" } finally { Pop-Location }

    $setup = Get-ChildItem "target\release\bundle\nsis\*-setup.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Host "`nFertig:" -ForegroundColor Green
    Write-Host "  Installer: $($setup.FullName)"
} finally { Pop-Location }
