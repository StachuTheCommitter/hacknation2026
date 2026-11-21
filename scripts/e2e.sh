#!/usr/bin/env bash
# Test end-to-end w laboratorium: skan bazowy → zmiany (scenario.sh step2) → skan szybki → asercje.
# Wymaga działającego stosu: make lab. Zmienne: ASI_URL (domyślnie http://localhost:8800), DC (polecenie compose).
set -euo pipefail
cd "$(dirname "$0")/.."
URL=${ASI_URL:-http://localhost:${ASI_PORT:-8800}}
B=$URL/api/v1
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT
export DC=${DC:-"docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml"}

j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
CSRF=$(curl -sf -c "$JAR" -X POST "$B/auth/login" -H 'Content-Type: application/json' -d '{"email":"admin@lab","password":"demo-password-admin"}' | j 'd["csrf"]')
get()  { curl -sf -b "$JAR" "$B$1"; }
post() { curl -sf -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X POST "$B$1" -d "${2:-{\}}"; }

fail=0
check() { if [ "$2" = "1" ]; then echo "  ✓ $1"; else echo "  ✗ $1"; fail=1; fi; }

GROUP=$(get /target-groups | j '[g["id"] for g in d if g["name"]=="Lab – usługi"][0]')
run_and_wait() {
  local id
  id=$(post /runs "{\"group_id\":\"$GROUP\",\"mode\":\"$1\"}" | j 'd["id"]')
  echo "przebieg $1: $id" >&2
  for _ in $(seq 1 240); do
    st=$(get "/runs/$id" | j 'd["status"]+" "+d["phase"]+" "+str(d["done_addresses"])+"/"+str(d["total_addresses"])')
    case "$st" in COMPLETED*) echo "  zakończony: $st" >&2; echo "$id"; return 0;; FAILED*|CANCELLED*) echo "  błąd: $st" >&2; exit 1;; esac
    sleep 5
  done
  echo "przekroczono czas oczekiwania" >&2; exit 1
}

echo "== Skan 1 (baseline)"
R1=$(run_and_wait baseline)
hosts=$(get "/hosts?limit=500" | j 'd["total"]')
echo "  aktywne hosty: $hosts"
check "wykryto ≥ 25 hostów" "$([ "$hosts" -ge 25 ] && echo 1 || echo 0)"
has() { get "/hosts?limit=500&q=$1" | j '1 if d["total"]>0 else 0'; }
check "WordPress (CMS)" "$(has tech:wordpress)"
check "panel administracyjny" "$(has cat:admin_panel)"
check "środowisko staging" "$(has cat:staging)"
check "urządzenia IoT" "$(has cat:iot)"
check "oprogramowanie bez wsparcia (EOL)" "$(has cat:eol_software)"
check "logowanie przez HTTP" "$(has cat:cleartext_login)"
check "problem TLS (wygasły certyfikat)" "$(has cat:tls_issue)"
check "host bez otwartych portów wykryty (10.77.6.20)" "$(get '/hosts?q=ip:10.77.6.20' | j '1 if d["total"]>0 else 0')"
check "SPA bez fałszywego /admin (soft-404)" "$(get '/web?q=ip:10.77.3.30' | j '0 if any(m["sig_id"]=="panel-admin-path" for w in d["items"] for m in (w["matches"] or [])) else 1')"
check "grupa podobnych drukarek z odstającą" "$(get /clusters | j '1 if any(c["count"]>=5 for c in d) else 0')"

echo "== Zmiany w laboratorium (step2)"
./lab/scenario.sh step2 >/dev/null 2>&1 || ./lab/scenario.sh step2
sleep 5

echo "== Skan 2 (differential)"
R2=$(run_and_wait differential)
ch() { get "/changes?run_id=$R2&limit=500&type=$1" | j 'len(d)'; }
echo "  zmiany: nowe=$(ch HOST_NEW,SERVICE_NEW) zmienione=$(ch SERVICE_CHANGED,HTTP_CHANGED,TLS_CHANGED)"
check "nowy host 10.77.7.10 (HOST_NEW)" "$(get "/changes?run_id=$R2&type=HOST_NEW&limit=100" | j '1 if any(c["host_ip"]=="10.77.7.10" for c in d) else 0')"
check "zmiana stagingu (HTTP_CHANGED/TLS_CHANGED)" "$(get "/changes?run_id=$R2&limit=500" | j '1 if any(c["host_ip"]=="10.77.3.10" and c["type"] in ("HTTP_CHANGED","TLS_CHANGED") for c in d) else 0')"
check "zmiana wersji OpenSSH (SERVICE_CHANGED)" "$(get "/changes?run_id=$R2&limit=500" | j '1 if any(c["host_ip"]=="10.77.5.10" and c["type"]=="SERVICE_CHANGED" for c in d) else 0')"
diff=$(get "/runs/$R1/diff/$R2")
check "diff: FTP usunięty (REMOVED)" "$(echo "$diff" | j '1 if any(i["kind"]=="REMOVED" and i["key"].startswith("10.77.5.20/tcp/21") for i in d["items"]) else 0')"
check "diff: nowy host dodany (ADDED)" "$(echo "$diff" | j '1 if any(i["kind"]=="ADDED" and i["ip"]=="10.77.7.10" for i in d["items"]) else 0')"
echo "  diff: $(echo "$diff" | j 'd["counts"]')"

echo "== RBAC"
VJ=$(mktemp)
VC=$(curl -sf -c "$VJ" -X POST "$B/auth/login" -H 'Content-Type: application/json' -d '{"email":"viewer@lab","password":"demo-password-viewer"}' | j 'd["csrf"]')
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$VJ" -H "X-CSRF-Token: $VC" -H 'Content-Type: application/json' -X POST "$B/runs" -d "{\"group_id\":\"$GROUP\"}")
check "viewer nie może uruchomić skanu (403)" "$([ "$code" = 403 ] && echo 1 || echo 0)"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$VJ" "$B/raw?entity_type=http&key=10.77.3.40/tcp/80/http/-")
check "viewer nie widzi danych wrażliwych (403)" "$([ "$code" = 403 ] && echo 1 || echo 0)"
rm -f "$VJ"

echo
[ $fail = 0 ] && echo "E2E: wszystkie asercje spełnione" || { echo "E2E: są niespełnione asercje"; exit 1; }
