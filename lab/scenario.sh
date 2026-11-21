#!/usr/bin/env bash
# Scenariusz zmian w laboratorium między przebiegami skanu.
#   step2 – wyłącza FTP i Redis, uruchamia nowy host (Kibana), aktualizuje OpenSSH,
#           zmienia staging (tytuł, nagłówek debug, nowy certyfikat), wyłącza czujnik
#   step3 – czujnik wraca (niestabilny), FTP nadal wyłączony (→ nieaktywny po K przebiegach)
#   flap  – czujnik miga co N sekund (Ctrl+C kończy)
#   reset – stan początkowy
set -euo pipefail
cd "$(dirname "$0")/.."
DC=${DC:-"docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml"}

case "${1:-}" in
  step2)
    $DC stop ftp redis
    $DC --profile step2 up -d newhost
    SSH_ALPINE=3.20 $DC up -d --build sshd
    STAGING_VARIANT=-v2 $DC up -d --force-recreate staging
    $DC stop flapper
    echo "step2: FTP i Redis wyłączone, nowy host 10.77.7.10, OpenSSH zaktualizowany, staging zmieniony, czujnik wyłączony"
    ;;
  step3)
    $DC start flapper
    echo "step3: czujnik 10.77.6.10 znów odpowiada; FTP nadal wyłączony"
    ;;
  flap)
    while true; do
      $DC stop flapper >/dev/null; sleep "${2:-40}"
      $DC start flapper >/dev/null; sleep "${2:-40}"
    done
    ;;
  reset)
    $DC --profile step2 stop newhost || true
    SSH_ALPINE=3.18 $DC up -d --build sshd
    $DC up -d --force-recreate staging
    $DC start ftp redis flapper
    echo "reset: stan początkowy"
    ;;
  *)
    echo "użycie: $0 step2 | step3 | flap [sekundy] | reset"
    exit 2
    ;;
esac
