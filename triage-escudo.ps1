#Requires -Version 5.1
<#
  triage-escudo.ps1  -  recolector de evidencia para respuesta a incidentes (Windows)

  Cuando SOSPECHAS que un equipo esta comprometido, toma una "foto" del estado del
  sistema para analizarla con calma. SOLO LEE: no borra ni cambia nada, no usa
  internet. Respeta el orden de volatilidad y calcula el SHA-256 de cada archivo
  de evidencia (cadena de custodia).

  Usalo SOLO en equipos propios o con autorizacion escrita.

  Uso (en PowerShell, idealmente como Administrador):
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\triage-escudo.ps1                 # evidencia en .\EVIDENCE_<host>_<fecha>
    .\triage-escudo.ps1 -Salida D:\     # guarda en otro destino (USB)
#>
[CmdletBinding()]
param(
    [string]$Salida = ".",
    [switch]$Version
)

$VER = "1.0.0"
if ($Version) { Write-Output "triage-escudo v$VER"; exit 0 }

$ErrorActionPreference = "Continue"
$host_ = $env:COMPUTERNAME
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$OUT = Join-Path $Salida ("EVIDENCE_{0}_{1}" -f $host_, $stamp)
New-Item -ItemType Directory -Path $OUT -Force | Out-Null

$LOG = Join-Path $OUT "collection.log"
$ALERTS = Join-Path $OUT "ALERTS.txt"
"" | Set-Content $LOG; "" | Set-Content $ALERTS

$esAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

function Log($m) { "[{0}] {1}" -f (Get-Date -Format "HH:mm:ssZ"), $m | Add-Content $LOG }
function Alerta($sev, $msg) { "[$sev] $msg" | Add-Content $ALERTS }

function Cap($sub, $name, $desc, [scriptblock]$block) {
    $dir = Join-Path $OUT $sub
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $f = Join-Path $dir $name
    Log "$sub/$name :: $desc"
    try {
        $out = & $block 2>$null | Out-String
        "# $desc`r`n# hora UTC: $((Get-Date).ToUniversalTime())`r`n`r`n$out" |
            Set-Content -Path $f -Encoding UTF8
    } catch {
        "# $desc`r`n# error: $($_.Exception.Message)" | Set-Content -Path $f -Encoding UTF8
    }
}

Write-Output "triage-escudo v$VER  -  host=$host_  -  inicio=$stamp (UTC)"
if (-not $esAdmin) { Write-Output "AVISO: sin Administrador, algunos artefactos quedaran incompletos." }

# ------------------------------------------------- 00 info del sistema
Cap "00_sistema" "system_info.txt" "Informacion del sistema" {
    "host: $host_"; "operador: $env:USERNAME"; "inicio UTC: $stamp"
    "hora local: $(Get-Date)"; "zona: $([TimeZoneInfo]::Local.Id)"
    $os = Get-CimInstance Win32_OperatingSystem
    "SO: $($os.Caption) $($os.Version) (build $($os.BuildNumber))"
    "ultimo arranque: $($os.LastBootUpTime)"
    "== hosts =="; Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
}

# ------------------------------------------------- 01 procesos
Cap "01_procesos" "procesos.txt" "Procesos (con ruta, padre y linea de comando)" {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath |
        Format-Table -AutoSize
}
Cap "01_procesos" "binarios_hash.txt" "SHA-256 de los ejecutables en ejecucion" {
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } |
        Select-Object -ExpandProperty ExecutablePath -Unique | ForEach-Object {
            $h = try { (Get-FileHash -Algorithm SHA256 $_ -ErrorAction Stop).Hash } catch { "NA" }
            "$h  $_"
        }
}

# ------------------------------------------------- 02 red
Cap "02_red" "conexiones.txt" "Conexiones TCP (con proceso)" {
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
        Sort-Object State | Format-Table -AutoSize
}
Cap "02_red" "escucha_udp.txt" "Puertos UDP en escucha" {
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
}
Cap "02_red" "ipconfig.txt" "Configuracion de red" { ipconfig /all }
Cap "02_red" "arp.txt" "Tabla ARP" { arp -a }
Cap "02_red" "dns_cache.txt" "Cache DNS" { ipconfig /displaydns }

# ------------------------------------------------- 03 sesiones y cuentas
Cap "03_sesiones_cuentas" "sesiones.txt" "Sesiones activas" { query user 2>$null; query session 2>$null }
Cap "03_sesiones_cuentas" "usuarios_locales.txt" "Usuarios locales" {
    Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, LastLogon, PasswordLastSet | Format-Table -AutoSize
}
Cap "03_sesiones_cuentas" "admins.txt" "Miembros de Administradores" {
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue 2>$null
    Get-LocalGroupMember -Group "Administradores" -ErrorAction SilentlyContinue 2>$null
}

# ------------------------------------------------- 04 persistencia
Cap "04_persistencia" "tareas.txt" "Tareas programadas" {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Select-Object TaskName, TaskPath, State, Author, Date | Format-Table -AutoSize
}
Cap "04_persistencia" "servicios.txt" "Servicios" {
    Get-CimInstance Win32_Service |
        Select-Object Name, State, StartMode, StartName, PathName | Format-Table -AutoSize
}
Cap "04_persistencia" "run_keys.txt" "Claves de arranque (Run/RunOnce)" {
    $keys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run")
    foreach ($k in $keys) {
        "== $k =="
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue |
            Select-Object * -ExcludeProperty PS* | Format-List
    }
}
Cap "04_persistencia" "wmi_subscriptions.txt" "Suscripciones WMI (persistencia sigilosa)" {
    "== __EventFilter =="
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    "== CommandLineEventConsumer =="
    Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
}

# ------------------------------------------------- 05 historial
$histDir = Join-Path $OUT "05_historial"
New-Item -ItemType Directory -Path $histDir -Force | Out-Null
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $h = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    if (Test-Path $h) {
        Copy-Item $h (Join-Path $histDir ("{0}_ps_history.txt" -f $_.Name)) -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------- 06 archivos recientes
Cap "06_archivos" "temporales.txt" "Ejecutables recientes en rutas temporales" {
    $rutas = @($env:TEMP, "$env:windir\Temp", "$env:USERPROFILE\Downloads")
    foreach ($r in $rutas) {
        if (Test-Path $r) {
            "== $r =="
            Get-ChildItem $r -Recurse -ErrorAction SilentlyContinue -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.scr |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
                Select-Object LastWriteTime, Length, FullName | Format-Table -AutoSize
        }
    }
}

# ------------------------------------------------- 07 logs
$logDir = Join-Path $OUT "07_logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
foreach ($canal in @("Security", "System")) {
    try {
        Get-WinEvent -LogName $canal -MaxEvents 2000 -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, Message |
            Export-Csv (Join-Path $logDir "$canal.csv") -NoTypeInformation -Encoding UTF8
    } catch { Log "no se pudo exportar el log $canal : $($_.Exception.Message)" }
}

# ================================================= HEURISTICAS
try {
    Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and ($_.ExecutablePath -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\")
    } | ForEach-Object { Alerta "CRITICO" "Proceso desde ruta temporal: $($_.Name) -> $($_.ExecutablePath)" }

    Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -and ($_.CommandLine -match "-enc |-EncodedCommand|FromBase64String|IEX |Invoke-Expression|DownloadString")
    } | ForEach-Object { Alerta "ALTO" "PowerShell/comando sospechoso: $($_.CommandLine.Substring(0,[Math]::Min(160,$_.CommandLine.Length)))" }

    $wmi = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    if ($wmi) { Alerta "ALTO" "Existe CommandLineEventConsumer (WMI): persistencia poco comun, revisar." }

    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Date -and ([datetime]$_.Date -gt (Get-Date).AddDays(-3))
    } | ForEach-Object { Alerta "ALTO" "Tarea programada creada en <=3 dias: $($_.TaskPath)$($_.TaskName)" }

    Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -and $_.PasswordLastSet -and ($_.PasswordLastSet -gt (Get-Date).AddDays(-3))
    } | ForEach-Object { Alerta "MEDIO" "Usuario local con contrasena cambiada en <=3 dias: $($_.Name)" }
} catch { Log "error en heuristicas: $($_.Exception.Message)" }

if ((Get-Content $ALERTS -ErrorAction SilentlyContinue).Count -le 1) {
    "(sin senales automaticas; revisa la evidencia manualmente)" | Add-Content $ALERTS
}

# ================================================= MANIFEST + hashes
$MAN = Join-Path $OUT "MANIFEST.txt"
"# MANIFEST - triage-escudo v$VER" | Set-Content $MAN
"# host: $host_  inicio UTC: $stamp  fin UTC: $((Get-Date).ToUniversalTime())" | Add-Content $MAN
"# SHA256  tamano(bytes)  ruta" | Add-Content $MAN
Get-ChildItem $OUT -Recurse -File | Where-Object { $_.Name -ne "MANIFEST.txt" } |
    Sort-Object FullName | ForEach-Object {
        $h = try { (Get-FileHash -Algorithm SHA256 $_.FullName).Hash } catch { "NA" }
        $rel = $_.FullName.Substring($OUT.Length).TrimStart("\")
        "$h  $($_.Length)  $rel" | Add-Content $MAN
    }
(Get-FileHash -Algorithm SHA256 $MAN).Hash | Set-Content (Join-Path $OUT "MANIFEST.sha256")

$nal = (Get-Content $ALERTS -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Output "Listo. Evidencia en: $OUT"
Write-Output ("  Senales automaticas: ver ALERTS.txt ({0} linea[s])" -f $nal)
Write-Output "  Integridad: MANIFEST.txt (hash en MANIFEST.sha256)"
exit 0
