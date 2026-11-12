# KittyPass : installe le serveur sur Windows (10, 11, Server 2019+), sans
# Docker. Le serveur tourne en tâche planifiée au démarrage, sous le compte
# restreint « Service local », et redémarre s'il s'arrête.
#
# Utilisation : clic droit sur « Installer.cmd » → Exécuter en tant
# qu'administrateur. Ou, dans PowerShell administrateur :
#   powershell -ExecutionPolicy Bypass -File install.ps1 [-Port 8080] [-ProxyIp 192.168.1.10] [-Require2fa]
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Update
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall   (garde les données)
param(
  [int]$Port = 8080,
  [string]$ProxyIp = "",
  [switch]$Require2fa,
  [switch]$Update,
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$Task = "KittyPass Server"
$Dir  = Join-Path $env:ProgramFiles "KittyPass Server"
$Data = Join-Path $env:ProgramData "KittyPass Server"
$Exe  = Join-Path $Dir "kittypass-server.exe"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Ok($m)  { Write-Host "OK  $m" -ForegroundColor Green }
function Die($m) { Write-Host "ERREUR  $m" -ForegroundColor Red; exit 1 }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Die "à lancer en administrateur" }

function Stop-Server {
  if (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue }
  Get-Process kittypass-server -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 1
}

if ($Uninstall) {
  Stop-Server
  Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetFirewallRule -DisplayName $Task -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force $Dir -ErrorAction SilentlyContinue
  Ok "serveur retiré. Données gardées dans $Data."
  exit 0
}

# Vérification du binaire fourni à côté du script.
$src = Join-Path $Here "kittypass-server.exe"
if (-not (Test-Path $src)) { Die "kittypass-server.exe introuvable à côté du script" }
$want = (Get-Content (Join-Path $Here "kittypass-server.exe.sha256")).Split(" ")[0].Trim().ToLower()
$got  = (Get-FileHash $src -Algorithm SHA256).Hash.ToLower()
if ($want -ne $got) { Die "binaire corrompu (empreinte)" }
Ok "binaire vérifié"

if ($Update) {
  if (-not (Test-Path $Exe)) { Die "KittyPass Server n'est pas installé ici" }
  Stop-Server
  Copy-Item $src $Exe -Force
  Start-ScheduledTask -TaskName $Task
  Ok "serveur mis à jour et redémarré"
  exit 0
}
if (Test-Path $Exe) { Die "déjà installé : utilise -Update pour mettre à jour" }

# Fichiers : programme en lecture seule, données réservées au service.
New-Item -ItemType Directory -Force $Dir, $Data | Out-Null
Copy-Item $src $Exe -Force
icacls $Data /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-19:(OI)(CI)M" | Out-Null

$bind = "0.0.0.0:$Port"
$twofa = if ($Require2fa) { "true" } else { "false" }
$runner = Join-Path $Dir "run.cmd"
@"
@echo off
set KITTYPASS_DATA=$Data
set KITTYPASS_BIND=$bind
set KITTYPASS_TRUSTED_PROXIES=$ProxyIp
set KITTYPASS_REQUIRE_2FA=$twofa
"$Exe" serve
"@ | Set-Content -Encoding ASCII $runner

# Tâche planifiée : au démarrage, compte Service local, relance en cas d'arrêt.
$action    = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$runner`""
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LOCALSERVICE" -LogonType ServiceAccount
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $Task

# Pare-feu : port ouvert sur le réseau privé (ou seulement au proxy).
$fw = @{ DisplayName = $Task; Direction = "Inbound"; Protocol = "TCP"; LocalPort = $Port; Action = "Allow"; Profile = "Private,Domain" }
if ($ProxyIp) { $fw.RemoteAddress = $ProxyIp }
New-NetFirewallRule @fw | Out-Null

$up = $false
for ($i = 0; $i -lt 20; $i++) {
  try { if ((Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$Port/health" -TimeoutSec 2).Content -match "ok") { $up = $true; break } } catch {}
  Start-Sleep -Seconds 1
}
if (-not $up) { Die "le serveur ne répond pas (voir l'Observateur d'événements, tâche « $Task »)" }
Ok "serveur actif sur le port $Port"

$env:KITTYPASS_DATA = $Data
$invite = & $Exe invite --admin 72 2>$null
# Le fichier de la base, créé par l'administrateur, doit rester accessible au service.
icacls $Data /grant:r "*S-1-5-19:(OI)(CI)M" /T | Out-Null

Write-Host ""
Ok "KittyPass Server est installé."
Write-Host "  Le serveur parle HTTP : place un reverse proxy HTTPS devant (Caddy, IIS, Nginx Proxy Manager…)."
Write-Host "  Invitation ADMIN (72 h, une seule fois) : $invite"
Write-Host "  Sauvegarde : $Data (kittypass.db, et secret.key A GARDER A PART)."
Write-Host "  Mise à jour : nouveau dossier, puis install.ps1 -Update"
