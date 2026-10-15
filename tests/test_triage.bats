#!/usr/bin/env bats
# Pruebas de triage-escudo.sh  ·  bats tests/test_triage.bats

SCRIPT="${BATS_TEST_DIRNAME}/../triage-escudo.sh"

setup() {
  TMP="$(mktemp -d)"
}
teardown() {
  rm -rf "$TMP"
}

@test "muestra la versión" {
  run "$SCRIPT" --version
  [ "$status" -eq 0 ]
  [[ "$output" == *"triage-escudo v"* ]]
}

@test "la ayuda funciona" {
  run "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"recolector de evidencia"* ]]
}

@test "rechaza opción desconocida" {
  run "$SCRIPT" --noexiste
  [ "$status" -eq 2 ]
}

@test "crea un bundle de evidencia con estructura" {
  run "$SCRIPT" -o "$TMP"
  [ "$status" -eq 0 ]
  d="$(find "$TMP" -maxdepth 1 -type d -name 'EVIDENCE_*' | head -1)"
  [ -n "$d" ]
  [ -d "$d/01_procesos" ]
  [ -d "$d/02_red" ]
  [ -d "$d/04_persistencia" ]
  [ -f "$d/MANIFEST.txt" ]
  [ -f "$d/ALERTS.txt" ]
  [ -f "$d/collection.log" ]
}

@test "el MANIFEST trae hashes SHA-256" {
  "$SCRIPT" -o "$TMP" >/dev/null
  d="$(find "$TMP" -maxdepth 1 -type d -name 'EVIDENCE_*' | head -1)"
  # Una línea de dato: 64 hex + espacios + número + ruta
  run grep -Ec '^[0-9a-f]{64}  [0-9]+  \./' "$d/MANIFEST.txt"
  [ "$status" -eq 0 ]
  [ "$output" -gt 0 ]
}

@test "no modifica el sistema (solo crea su carpeta de salida)" {
  # El script no debe escribir fuera de su carpeta de evidencia.
  before="$(find "$TMP" -type f | wc -l)"
  "$SCRIPT" -o "$TMP" >/dev/null
  d="$(find "$TMP" -maxdepth 1 -type d -name 'EVIDENCE_*' | head -1)"
  # Todo lo nuevo debe estar bajo el bundle.
  run bash -c "find '$TMP' -type f ! -path '$d/*' | wc -l"
  [ "$output" -eq "$before" ]
}
