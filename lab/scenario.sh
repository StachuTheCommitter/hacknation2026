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

# Wyłącza usługi. Gdy Docker nie może zatrzymać kontenera (np. AppArmor: "permission denied"),
# odłącza go od sieci – dla skanera efekt jest ten sam: host przestaje odpowiadać.
off() {
  $DC stop "$@" 2>/dev/null && return 0
  echo "uwaga: docker stop nieudany – odłączam kontenery od sieci ($*)" >&2
  for s in "$@"; do
    id=$($DC ps -q "$s"); [ -n "$id" ] || continue
    for n in $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$id"); do
      docker network disconnect -f "$n" "$id"
    done
  done
}
# Włącza usługi; kontenery odłączone przez off() są tworzone na nowo.
on() {
  for s in "$@"; do
    id=$($DC ps -aq "$s")
    if [ -n "$id" ] && [ "$(docker inspect -f '{{.State.Running}} {{len .NetworkSettings.Networks}}' "$id")" = "true 0" ]; then
      docker rm -f "$id" >/dev/null 2>&1 || true
    fi
  done
  $DC up -d "$@"
}

case "${1:-}" in
  step2)
    off ftp redis
    $DC --profile step2 up -d newhost
    SSH_ALPINE=3.20 $DC up -d --build sshd
    STAGING_VARIANT=-v2 $DC up -d --force-recreate staging
    off flapper
    echo "step2: FTP i Redis wyłączone, nowy host 10.77.7.10, OpenSSH zaktualizowany, staging zmieniony, czujnik wyłączony"
    ;;
  step3)
    on flapper
    echo "step3: czujnik 10.77.6.10 znów odpowiada; FTP nadal wyłączony"
    ;;
  flap)
    while true; do
      off flapper >/dev/null; sleep "${2:-40}"
      on flapper >/dev/null; sleep "${2:-40}"
    done
    ;;
  reset)
    $DC --profile step2 stop newhost || true
    SSH_ALPINE=3.18 $DC up -d --build sshd
    $DC up -d --force-recreate staging
    on ftp redis flapper
    echo "reset: stan początkowy"
    ;;
  *)
    echo "użycie: $0 step2 | step3 | flap [sekundy] | reset"
    exit 2
    ;;
esac
