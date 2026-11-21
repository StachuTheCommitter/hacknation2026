# ASI · Attack Surface Intelligence

System do cyklicznego, bezpiecznego skanowania rozległych sieci (>10 000 adresów IP). Wykrywa aktywne hosty, usługi, technologie WWW, CMS-y, panele administracyjne, środowiska testowe, urządzenia IoT, ciekawe nagłówki i ciasteczka, rejestruje zmiany w czasie i współpracuje z **DefectDojo** jako silnikiem deduplikacji znalezisk.

Projekt na zadanie konkursowe Centrum Bezpieczeństwa Informacji AGH. Pełna specyfikacja: [`docs/DOKUMENTACJA.md`](docs/DOKUMENTACJA.md).

```
DefectDojo (API v2)  ⇄  ASI control plane (Go + PostgreSQL + UI)  ⇄  workery: nmap · naabu · prober HTTP (wappalyzergo)
```

## Szybki start

```bash
make lab
```

To polecenie:
1. tworzy `.env` z losowymi sekretami (klucz szyfrowania, token workera, hasło administratora);
2. buduje obrazy;
3. uruchamia system razem z laboratorium: 37 kontenerów w sieci `10.77.0.0/16`, tryb demo i konta demonstracyjne.

Interfejs: **http://localhost:8080**. Konta demonstracyjne (tylko w trybie laboratorium):

| Konto | Hasło | Rola |
|---|---|---|
| `admin@lab` | `demo-password-admin` | Administracja |
| `editor@lab` | `demo-password-editor` | Dodawanie, usuwanie, modyfikacja |
| `modifier@lab` | `demo-password-modifier` | Modyfikacja i odczyt |
| `viewer@lab` | `demo-password-viewer` | Odczyt |

System bez laboratorium uruchamia `make up`. Administratora (`admin@asi.local`) i jego hasło znajdziesz w `.env`.

### Scenariusz demo

```bash
make lab                    # system + laboratorium
make seed                   # 14 dni syntetycznej historii: hosty niestabilne i okresowe
```

```bash
./lab/scenario.sh step2     # między skanami: znika FTP, pojawia się nowy host, zmiana OpenSSH i stagingu
```

```bash
make e2e                    # automatyczny test: skan → zmiany → skan → asercje
```

Kolejne kroki demo:
1. W UI: **Skany → Uruchom skan → „Lab – usługi”** (2048 adresów) albo **„Lab – cała sieć /16”** (65 536 adresów, pokazuje skalę).
2. Uruchom `./lab/scenario.sh step2`, a potem drugi skan w trybie *differential*.
3. **Zmiany → Porównanie skanów**. Dla trzech workerów dzielących wspólny budżet ruchu: `make scale`.

## Co robi pipeline

| Etap | Narzędzie | Wynik |
|---|---|---|
| 0. DNS | resolver Go | domeny → IP (tylko w scope) |
| 1. Discovery | `nmap -sn` (ICMP, SYN, ACK, ARP; RST = żywy) | aktywne hosty, także bez otwartych portów |
| 2. Porty | `naabu` SYN (zapasowo `nmap`) | otwarte porty TCP / UDP z profilu |
| 3. Usługi | `nmap -sV` + skrypty `banner`, `ssl-cert`, `ssh-hostkey` | produkt, wersja, CPE, pewność (`method`, `conf`) |
| 4. HTTP | natywny prober Go + **wappalyzergo** (silnik `httpx -td`), równolegle z etapem 3 | tytuł, kod, nagłówki, cookies, TLS, przekierowania, favicona MMH3, technologie, ścieżki z kontrolą soft-404, vhosty |
| 5. Analiza | serwer | sygnatury, kategorie, pewność (noisy-OR), ocena „ciekawości”, klastry, zmiany, automat stanowy, DefectDojo |

## Najważniejsze cechy

- **Bezpieczeństwo skanera:**
  - lista dozwolonych zakresów i wykluczeń, sprawdzana trzykrotnie (przy dodawaniu, w dispatcherze, w workerze);
  - wspólny budżet pakietów grupy niezależny od liczby workerów i globalny sufit;
  - allowlista skryptów nmap, sygnatury aktywne tylko `GET`/`HEAD`, bez logowania i payloadów;
  - identyfikujący User-Agent, wyłącznik awaryjny i pełny audyt.
- **Duże sieci:**
  - adaptacyjny podział na zadania (rozmiar liczony z mierzonej prędkości);
  - estymacja czasu, także kalendarzowa z uwzględnieniem okien;
  - okna czasowe per grupa (również przez północ i z niskim tempem w dzień);
  - twarde zatrzymanie na końcu okna i wznowienie od kursora w kolejnym oknie;
  - harmonogram CRON z polityką nakładania się przebiegów.
- **Zmiany w czasie:**
  - porównanie dwóch przebiegów tylko na **wspólnym pokryciu**, więc przerwany skan nie daje fałszywych „zniknięć”;
  - stabilne odciski pól, bez szumu z dat i tokenów;
  - automat stanowy ACTIVE → SUSPECT → INACTIVE z powtórnymi pomiarami;
  - flapping, okresowość (pora dnia × dni robocze/weekend) i wykrywanie podmiany urządzenia (klucz SSH).
- **Fingerprinting:**
  - około 60 wbudowanych sygnatur: CMS, frameworki, serwery, panele, IoT, staging, ekspozycje, TLS, EOL;
  - własne sygnatury YAML z edytorem, testem na encji i „retro-huntingiem” bez ponownego skanu;
  - import szablonów nuclei.
- **Dane:**
  - formularz, import CSV, JSON, JSONL, nmap XML, naabu i httpx przez ten sam pipeline co skaner;
  - eksport z wartościami efektywnymi;
  - ocena trafności (precision i recall) względem wyników referencyjnych.
- **Nadpisania analityka:** przechowywane osobno od danych skanera, więc przetrwają kolejne skany. Konflikt ze skanerem jest sygnalizowany.
- **RBAC:**
  - role jako zbiory uprawnień (4 domyślne i dowolne własne);
  - uprawnienia egzekwowane w API, a macierz tras jest testowana ([`docs/RBAC.md`](docs/RBAC.md)).
- **Szyfrowanie:**
  - AES-256-GCM dla danych wrażliwych (pełne nagłówki, cookies, treści, banery, notatki, token DefectDojo) w schemacie envelope z AAD i rotacją kluczy;
  - HMAC dla odcisków;
  - argon2id dla haseł i tokenów.
- **DefectDojo:**
  - znaleziska informacyjne przez `import-scan` i `reimport-scan`, z deterministycznym opisem (podstawa `hash_code`);
  - statusy FP i risk accepted pobierane z DefectDojo i synchronizowane z UI.

## Struktura

```
cmd/asi            binarka: server | worker | migrate | keygen | rotate-keys | seed-history | eval
internal/core      logika control plane (cele, przebiegi, dispatcher, ingest, analiza, zmiany, findings)
internal/api       REST API + API workerów + SSE + serwowanie UI
internal/worker    worker skanujący; internal/prober – fingerprinting HTTP
internal/sigs      silnik sygnatur (+ adapter nuclei); signatures/builtin – pakiet wbudowany
internal/{netx,obs,crypto,auth,rbac,dd,nmapxml,model,config,db}
web/               interfejs (React + TypeScript, ręcznie pisany CSS, bez bibliotek UI)
lab/               laboratorium: labweb (emulator usług), profile, obrazy, scenario.sh
deploy/Dockerfile  obrazy server / worker / labweb
docs/              dokumentacja techniczna, macierz RBAC
```

## Rozwój

```bash
go test ./...                       # testy jednostkowe (sygnatury, zakresy, szyfrowanie, okna, RBAC)
```

```bash
cd web && npm ci && npm run dev     # UI z proxy do :8080
```

```bash
make dev                            # serwer lokalnie (PostgreSQL + zmienne z .env)
```

Worker poza Dockerem wymaga `nmap` (oraz opcjonalnie `naabu`) i uprawnień `CAP_NET_RAW`. Bez nich przechodzi w tryb TCP connect i zgłasza ostrzeżenie w UI.

```bash
ASI_SERVER_URL=http://localhost:8080 ASI_WORKER_TOKEN=... asi worker
```
