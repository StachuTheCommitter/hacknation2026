#!/usr/bin/env bash
# Tworzy .env z losowymi sekretami.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] && { echo ".env już istnieje"; exit 0; }
rnd() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
cp .env.example .env
sed -i "s|^ASI_MASTER_KEY=.*|ASI_MASTER_KEY=$(head -c 32 /dev/urandom | base64)|" .env
sed -i "s|^ASI_WORKER_TOKEN=.*|ASI_WORKER_TOKEN=asi_wk_$(rnd 32)|" .env
sed -i "s|^ASI_BOOTSTRAP_ADMIN_PASSWORD=.*|ASI_BOOTSTRAP_ADMIN_PASSWORD=$(rnd 20)|" .env
echo "Utworzono .env – hasło administratora (admin@asi.local): $(grep ADMIN_PASSWORD .env | cut -d= -f2)"
