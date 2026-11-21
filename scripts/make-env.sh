#!/usr/bin/env bash
# Tworzy .env z losowymi sekretami; uzupełnia brakujące klucze w istniejącym .env.
set -euo pipefail
cd "$(dirname "$0")/.."
rnd() { head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
[ -f .env ] || cp .env.example .env
setk() { # ustawia klucz, jeśli jest pusty lub go brak
  if grep -q "^$1=." .env; then return; fi
  if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi
}
setk ASI_MASTER_KEY "$(head -c 32 /dev/urandom | base64)"
setk ASI_WORKER_TOKEN "asi_wk_$(rnd 32)"
setk ASI_BOOTSTRAP_ADMIN_PASSWORD "$(rnd 20)"
setk DD_ADMIN_PASSWORD "$(rnd 20)"
setk DD_SECRET_KEY "$(rnd 50)"
setk DD_CREDENTIAL_AES_256_KEY "$(rnd 32)"
echo "Plik .env gotowy."
echo "  ASI        http://localhost:$(grep -E '^ASI_PORT=' .env | cut -d= -f2 || echo 8800)  admin@asi.local / $(grep ADMIN_PASSWORD= .env | head -1 | cut -d= -f2)"
echo "  DefectDojo http://localhost:8880  admin / $(grep '^DD_ADMIN_PASSWORD=' .env | cut -d= -f2)  (po make dojo)"
