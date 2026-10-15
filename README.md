# triage-escudo

Cuando sospechas que un equipo está comprometido, los primeros minutos importan: hay evidencia que vive en la memoria y desaparece al apagar o reiniciar. **triage-escudo** toma una "foto" ordenada del estado del sistema para analizarla con calma, respetando los principios forenses.

**Solo lee. No borra, no cambia nada, no usa internet.** Recolecta por **orden de volatilidad** (RFC 3227) y calcula el **SHA-256** de cada archivo de evidencia (cadena de custodia).

Dos versiones:
- **`triage-escudo.sh`** — Linux (Bash).
- **`triage-escudo.ps1`** — Windows (PowerShell 5.1+).

> Úsalo **solo en equipos propios o con autorización escrita**. Es una herramienta de defensa (Blue Team), no de ataque.

## Cómo se usa

**Linux:**
```bash
sudo ./triage-escudo.sh                # evidencia en ./EVIDENCE_<host>_<fecha>
sudo ./triage-escudo.sh -o /mnt/usb    # guarda en un destino separado (USB)
```

**Windows** (PowerShell como Administrador):
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\triage-escudo.ps1
.\triage-escudo.ps1 -Salida D:\
```

**Consejo forense:** corre la herramienta hacia un **destino separado** del disco investigado (un USB o un recurso de red), para no sobrescribir evidencia.

## Qué recolecta (por orden de volatilidad)

1. **Procesos** — ruta, padre, línea de comando y **hash SHA-256** de cada binario en ejecución.
2. **Red** — conexiones y puertos con su proceso dueño, ARP, caché DNS, interfaces.
3. **Sesiones y cuentas** — quién está conectado, usuarios locales, administradores, claves SSH.
4. **Persistencia** — tareas programadas / cron / systemd timers, servicios, claves Run, suscripciones WMI, `ld.so.preload`, perfiles de shell.
5. **Historial** — de comandos (bash/zsh/PowerShell).
6. **Archivos recientes** — ejecutables en rutas temporales y Descargas (staging típico de malware).
7. **Logs** — de autenticación y del sistema.

## Qué entrega

```
EVIDENCE_<host>_<fecha>/
├── MANIFEST.txt        # SHA-256 y tamaño de cada archivo (integridad)
├── MANIFEST.sha256     # hash del propio manifiesto (sello)
├── collection.log      # todo lo que se ejecutó (tu propia huella)
├── ALERTS.txt          # señales automáticas para revisar primero
└── 00..07_*/           # los artefactos, por carpeta
```

**Señales que marca solo** (heurísticas, para revisar — no veredictos): proceso ejecutándose desde una ruta temporal, `ld.so.preload` no vacío, usuario con UID 0 además de root, tarea/cron creada en los últimos días, `CommandLineEventConsumer` de WMI, PowerShell con comando codificado, puertos abiertos a todas las interfaces.

## Marcos

Alimenta la función **Responder (RS.AN)** de **NIST CSF 2.0** y la fase de **Identificación** del ciclo de respuesta a incidentes (NIST SP 800-61 / SANS). Ayuda a cazar técnicas de **persistencia y descubrimiento** de **MITRE ATT&CK** (T1547, T1053, T1543, T1546, T1136, T1098...).

## Qué necesita

Linux: Bash y utilidades estándar (`ps`, `ss`, `sha256sum`...). Windows: PowerShell 5.1+.

Licencia [MIT](LICENSE). Hecho por Andrés Clark en Panamá.
