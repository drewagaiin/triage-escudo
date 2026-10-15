#!/usr/bin/env bash
# =============================================================================
# triage-escudo.sh  —  recolector de evidencia para respuesta a incidentes (Linux)
#
# Cuando SOSPECHAS que un equipo está comprometido, este script toma una "foto"
# del estado del sistema para analizarla con calma. SOLO LEE: no borra, no cambia
# nada, no se conecta a internet. Respeta el orden de volatilidad (RFC 3227) y
# calcula el hash SHA-256 de cada archivo de evidencia (cadena de custodia).
#
# Úsalo SOLO en equipos propios o con autorización escrita.
#
# Uso:
#   sudo ./triage-escudo.sh                 # recolecta en ./EVIDENCE_<host>_<fecha>
#   sudo ./triage-escudo.sh -o /mnt/usb     # guarda la evidencia en otro destino
#   ./triage-escudo.sh                      # sin sudo: recoge lo que se pueda
#
# Idea: corre esto desde un USB hacia un destino SEPARADO del disco investigado.
# =============================================================================
set -u

VERSION="1.0.0"
DEST="."
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--salida) DEST="${2:-.}"; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    --version) echo "triage-escudo v$VERSION"; exit 0 ;;
    *) echo "Opción desconocida: $1 (usa -h)"; exit 2 ;;
  esac
done

HOST="$(hostname 2>/dev/null || echo desconocido)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$DEST/EVIDENCE_${HOST}_${STAMP}"
mkdir -p "$OUT" || { echo "No pude crear $OUT"; exit 2; }

LOG="$OUT/collection.log"
MAN="$OUT/MANIFEST.txt"
ALERTS="$OUT/ALERTS.txt"
: > "$LOG"; : > "$ALERTS"
echo "triage-escudo v$VERSION  ·  host=$HOST  ·  inicio=$STAMP (UTC)" | tee -a "$LOG"
[ "$(id -u)" -ne 0 ] && echo "AVISO: sin root, algunos artefactos quedarán incompletos." | tee -a "$LOG"

# cap: guarda la salida de un comando en un archivo del bundle, registrando todo.
cap() {
  # cap <carpeta> <nombre> <descripcion> -- <comando...>
  local sub="$1" name="$2" desc="$3"; shift 3; [ "$1" = "--" ] && shift
  local dir="$OUT/$sub"; mkdir -p "$dir"
  local f="$dir/$name"
  echo "[$(date -u +%H:%M:%SZ)] $sub/$name :: $* " >> "$LOG"
  if command -v "$1" >/dev/null 2>&1; then
    { echo "# $desc"; echo "# comando: $*"; echo "# hora UTC: $(date -u)"; echo; \
      "$@" ; } > "$f" 2>>"$LOG" || echo "   (el comando devolvió error, ver collection.log)" >> "$LOG"
  else
    echo "# $desc" > "$f"; echo "# (comando no disponible: $1)" >> "$f"
  fi
}

copia() {
  # copia <carpeta> <ruta_origen> : copia un archivo tal cual (si existe y es legible)
  local sub="$1" src="$2"; local dir="$OUT/$sub"; mkdir -p "$dir"
  if [ -r "$src" ] && [ -f "$src" ]; then
    cp -p --no-dereference "$src" "$dir/" 2>>"$LOG" && \
      echo "[$(date -u +%H:%M:%SZ)] copia $src" >> "$LOG"
  fi
}

alerta() { echo "[$1] $2" >> "$ALERTS"; }

# ------------------------------------------------------------------ 01 procesos
cap 01_procesos ps_aux.txt         "Procesos en ejecución" -- ps auxww
cap 01_procesos arbol.txt          "Árbol de procesos (padre-hijo)" -- ps axjf
if [ -d /proc ]; then
  { echo "# PID -> ejecutable -> SHA256 (binarios en ejecución)"; \
    for p in /proc/[0-9]*; do
      exe="$(readlink -f "$p/exe" 2>/dev/null)"; [ -n "$exe" ] || continue
      h="$(sha256sum "$exe" 2>/dev/null | awk '{print $1}')"
      printf '%s\t%s\t%s\n' "${p#/proc/}" "${h:-NA}" "$exe"
    done ; } > "$OUT/01_procesos/binarios_hash.txt" 2>>"$LOG"
fi

# ------------------------------------------------------------------- 02 red
cap 02_red conexiones.txt   "Conexiones y puertos (con proceso dueño)" -- ss -tulpnae
command -v ss >/dev/null 2>&1 || cap 02_red conexiones.txt "Conexiones (netstat)" -- netstat -tulpnae
cap 02_red interfaces.txt   "Interfaces de red" -- ip a
cap 02_red rutas.txt        "Tabla de rutas" -- ip route
cap 02_red arp.txt          "Tabla ARP / vecinos" -- ip neigh
copia 02_red /etc/resolv.conf
copia 02_red /etc/hosts

# ------------------------------------------------------ 03 sesiones y cuentas
cap 03_sesiones_cuentas logueados.txt  "Usuarios conectados ahora" -- w
cap 03_sesiones_cuentas who.txt        "Sesiones (who)" -- who
cap 03_sesiones_cuentas ultimos.txt    "Últimos accesos" -- last -50
[ "$(id -u)" -eq 0 ] && cap 03_sesiones_cuentas fallidos.txt "Accesos fallidos" -- lastb -50
copia 03_sesiones_cuentas /etc/passwd
copia 03_sesiones_cuentas /etc/group
copia 03_sesiones_cuentas /etc/sudoers
# claves SSH autorizadas de cada home
{ echo "# authorized_keys por usuario"; \
  while IFS=: read -r u _ uid _ _ home _; do
    [ "$uid" -ge 1000 ] 2>/dev/null || [ "$u" = root ] || continue
    ak="$home/.ssh/authorized_keys"
    [ -r "$ak" ] && { echo "== $u ($ak) =="; cat "$ak"; echo; }
  done < /etc/passwd ; } > "$OUT/03_sesiones_cuentas/authorized_keys.txt" 2>>"$LOG"

# ------------------------------------------------------------- 04 persistencia
mkdir -p "$OUT/04_persistencia"
cap 04_persistencia servicios.txt   "Servicios/units (systemd)" -- systemctl list-units --type=service --all --no-pager
cap 04_persistencia timers.txt      "Timers de systemd" -- systemctl list-timers --all --no-pager
{ echo "# crontabs por usuario + /etc/cron*"; \
  while IFS=: read -r u _ uid _ _ _ _; do
    [ "$uid" -ge 1000 ] 2>/dev/null || [ "$u" = root ] || continue
    out="$(crontab -l -u "$u" 2>/dev/null)"; [ -n "$out" ] && { echo "== crontab de $u =="; echo "$out"; echo; }
  done < /etc/passwd
  for d in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [ -e "$d" ] && { echo "== $d =="; ls -la "$d" 2>/dev/null; }
  done ; } > "$OUT/04_persistencia/cron.txt" 2>>"$LOG"
copia 04_persistencia /etc/rc.local
copia 04_persistencia /etc/ld.so.preload
cap 04_persistencia modulos_kernel.txt "Módulos del kernel cargados" -- lsmod
{ echo "# perfiles de shell y autostart"; \
  for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
    [ -r "$f" ] && { echo "== $f =="; ls -la "$f"; }
  done ; } > "$OUT/04_persistencia/perfiles_shell.txt" 2>>"$LOG"

# ------------------------------------------------------------------ 05 historial
mkdir -p "$OUT/05_historial"
while IFS=: read -r u _ uid _ _ home _; do
  [ "$uid" -ge 1000 ] 2>/dev/null || [ "$u" = root ] || continue
  for hf in .bash_history .zsh_history .sh_history; do
    [ -r "$home/$hf" ] && cp -p "$home/$hf" "$OUT/05_historial/${u}_${hf}" 2>>"$LOG"
  done
done < /etc/passwd

# ------------------------------------------------------------------- 06 archivos
mkdir -p "$OUT/06_archivos"
{ echo "# archivos en rutas temporales (posible staging de herramientas)"; \
  for d in /tmp /var/tmp /dev/shm; do
    # SC2012: el listado tipo 'ls -laR' es intencional (formato forense legible).
    # shellcheck disable=SC2012
    [ -d "$d" ] && { echo "== $d =="; ls -laR "$d" 2>/dev/null | head -500; }
  done ; } > "$OUT/06_archivos/temporales.txt" 2>>"$LOG"
cap 06_archivos recientes.txt "Ejecutables modificados en 7 días (rutas clave)" -- \
  find /tmp /var/tmp /dev/shm /home /root -type f -mtime -7 -perm -u+x -printf '%TY-%Tm-%Td %Tu %p\n'

# --------------------------------------------------------------------- 07 logs
mkdir -p "$OUT/07_logs"
for lg in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/audit/audit.log; do
  copia 07_logs "$lg"
done
command -v journalctl >/dev/null 2>&1 && \
  journalctl --since "-7 days" --no-pager > "$OUT/07_logs/journal_7dias.txt" 2>>"$LOG"

# ---------------------------------------------------------- 00 info del sistema
mkdir -p "$OUT/00_sistema"
{ echo "# triage-escudo v$VERSION"; echo "host: $HOST"; echo "inicio UTC: $STAMP";
  echo "operador: $(id -un) (uid $(id -u))"; echo "uname: $(uname -a)";
  echo "uptime: $(uptime 2>/dev/null)"; echo "hora local: $(date)"; echo "zona: $(date +%Z)";
  echo; echo "== /etc/os-release =="; cat /etc/os-release 2>/dev/null;
  echo; echo "== montajes =="; mount 2>/dev/null; } > "$OUT/00_sistema/system_info.txt" 2>>"$LOG"

# ---------------------------------------------------------------- HEURÍSTICAS
# Procesos desde rutas temporales
grep -E '/tmp/|/dev/shm/|/var/tmp/' "$OUT/01_procesos/ps_aux.txt" 2>/dev/null | \
  grep -vE 'grep|triage-escudo' | while read -r l; do
    alerta CRITICO "Proceso ejecutándose desde ruta temporal: $l"
  done
# ld.so.preload presente y no vacío
if [ -s /etc/ld.so.preload ]; then
  alerta CRITICO "/etc/ld.so.preload NO está vacío (persistencia sigilosa): $(cat /etc/ld.so.preload 2>/dev/null)"
fi
# usuarios con UID 0 además de root
awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null | while read -r u; do
  [ -n "$u" ] && alerta CRITICO "Usuario con UID 0 además de root: $u"
done
# cron modificado en las últimas 72h
find /etc/cron* /var/spool/cron -type f -mtime -3 2>/dev/null | while read -r f; do
  alerta ALTO "Tarea cron modificada en los últimos 3 días: $f"
done
# /etc/hosts modificado recientemente
if [ -f /etc/hosts ] && [ -n "$(find /etc/hosts -mtime -7 2>/dev/null)" ]; then
  alerta MEDIO "/etc/hosts modificado en los últimos 7 días (revisar entradas)"
fi
# puertos escuchando en todas las interfaces (dirección LOCAL = campo 5 de ss),
# excluyendo loopback (127.0.0.1 / [::1]).
awk '/LISTEN/ {
       la=$5
       if ((la ~ /^0\.0\.0\.0:/ || la ~ /^\[::\]:/ || la ~ /^\*:/) &&
            la !~ /^127\.0\.0\.1:/ && la !~ /^\[::1\]:/)
         print $5, $7
     }' "$OUT/02_red/conexiones.txt" 2>/dev/null | sort -u | while read -r addr proc; do
  alerta MEDIO "Puerto en escucha en todas las interfaces: $addr $proc"
done

[ -s "$ALERTS" ] || echo "(sin señales automáticas; revisa la evidencia manualmente)" >> "$ALERTS"

# ------------------------------------------------------------ MANIFEST + hashes
{ echo "# MANIFEST — triage-escudo v$VERSION"; echo "# host: $HOST  inicio UTC: $STAMP";
  echo "# fin UTC: $(date -u)"; echo "# SHA256  tamaño(bytes)  ruta"; echo; } > "$MAN"
( cd "$OUT" && find . -type f ! -name MANIFEST.txt -print0 | sort -z | \
  while IFS= read -r -d '' f; do
    h="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
    sz="$(stat -c %s "$f" 2>/dev/null || echo 0)"
    printf '%s  %s  %s\n' "${h:-NA}" "$sz" "$f"
  done ) >> "$MAN"
sha256sum "$MAN" 2>/dev/null | awk '{print $1}' > "$OUT/MANIFEST.sha256"

NAL="$(grep -c . "$ALERTS" 2>/dev/null || echo 0)"
echo "Listo. Evidencia en: $OUT" | tee -a "$LOG"
echo "  Señales automáticas: ver ALERTS.txt ($NAL línea[s])" | tee -a "$LOG"
echo "  Integridad: MANIFEST.txt (hash en MANIFEST.sha256)" | tee -a "$LOG"
exit 0
