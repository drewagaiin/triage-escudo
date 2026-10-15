# Cambios

## [1.0.0] - 2026-10-12

Primera versión.

- Recolector de evidencia para respuesta a incidentes (triage en vivo), read-only.
- Dos versiones: triage-escudo.sh (Linux) y triage-escudo.ps1 (Windows / PowerShell 5.1+).
- Recolecta por orden de volatilidad (RFC 3227): procesos (con hash SHA-256), red (conexiones/puertos/ARP/DNS), sesiones y cuentas, persistencia (cron/systemd/Run keys/servicios/WMI), historial, archivos recientes y logs.
- Cadena de custodia: MANIFEST.txt con SHA-256 de cada archivo + collection.log de lo ejecutado.
- ALERTS.txt con señales automáticas (proceso en ruta temporal, ld.so.preload, UID 0 extra, tarea reciente, WMI consumer, PowerShell codificado...).
- Mapea a MITRE ATT&CK (persistencia/descubrimiento) y NIST CSF 2.0 (RS.AN).
- 6 pruebas bats + ShellCheck + validación de sintaxis PowerShell en CI.
