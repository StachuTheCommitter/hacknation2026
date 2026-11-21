# Attack Surface Intelligence (ASI) – Dokumentacja techniczna v2

> System klasy ASM (Attack Surface Management) do cyklicznego, bezpiecznego skanowania rozległych sieci (>10 000 adresów IP), zbudowany dla Centrum Bezpieczeństwa Informacji AGH.
>
> Ten dokument jest **specyfikacją implementacyjną**. Na jego podstawie powstaje kod (`/home/user/asi`), środowisko laboratoryjne do testów i demo oraz prezentacja. Tam, gdzie treść zadania jest niejednoznaczna, dokument podejmuje decyzję i ją uzasadnia.

**Wersja:** 2.0 (z poprawkami po przeglądzie koncepcji v1)
**Język kodu:** Go 1.23 (backend, orkiestrator, worker), TypeScript + React (UI)
**Baza:** PostgreSQL 16

---

## Spis treści

0. [Słownik i konwencje](#0-słownik-i-konwencje)
1. [Wizja i architektura](#1-wizja-i-architektura)
2. [Bezpieczeństwo działania skanera](#2-bezpieczeństwo-działania-skanera)
3. [Cele skanowania: wejście, walidacja, grupy](#3-cele-skanowania-wejście-walidacja-grupy)
4. [Pipeline skanowania](#4-pipeline-skanowania)
5. [Planowanie: przebiegi, zadania, estymacja, budżet ruchu, okna czasowe](#5-planowanie-przebiegi-zadania-estymacja-budżet-ruchu-okna-czasowe)
6. [Porównywanie przebiegów i raportowanie zmian](#6-porównywanie-przebiegów-i-raportowanie-zmian)
7. [Dostępność, niestabilność (flapping), okresowość, nieaktywność](#7-dostępność-niestabilność-flapping-okresowość-nieaktywność)
8. [Fingerprinting, klasyfikacja i pewność identyfikacji](#8-fingerprinting-klasyfikacja-i-pewność-identyfikacji)
9. [Silnik sygnatur](#9-silnik-sygnatur)
10. [Ocena „ciekawości”, grupowanie podobnych usług](#10-ocena-ciekawości-grupowanie-podobnych-usług)
11. [Model danych](#11-model-danych)
12. [Warstwa nadpisań (overlay)](#12-warstwa-nadpisań-overlay)
13. [Import, eksport, formularz ręczny, ocena trafności](#13-import-eksport-formularz-ręczny-ocena-trafności)
14. [Integracja z DefectDojo](#14-integracja-z-defectdojo)
15. [RBAC, uwierzytelnianie, audyt](#15-rbac-uwierzytelnianie-audyt)
16. [Szyfrowanie danych w spoczynku](#16-szyfrowanie-danych-w-spoczynku)
17. [API REST](#17-api-rest)
18. [Interfejs użytkownika](#18-interfejs-użytkownika)
19. [Konfiguracja](#19-konfiguracja)
20. [Uruchomienie i wdrożenie](#20-uruchomienie-i-wdrożenie)
21. [Struktura repozytorium](#21-struktura-repozytorium)
22. [Strategia testów](#22-strategia-testów)
23. [Środowisko laboratoryjne i demo](#23-środowisko-laboratoryjne-i-demo)
24. [Odpowiedzi na pytania z treści zadania](#24-odpowiedzi-na-pytania-z-treści-zadania)
25. [Macierz zgodności z wymaganiami](#25-macierz-zgodności-z-wymaganiami)
26. [Ryzyka i kwestie otwarte](#26-ryzyka-i-kwestie-otwarte)
27. [Plan implementacji](#27-plan-implementacji)

---

## 0. Słownik i konwencje

| Termin | Znaczenie |
|---|---|
| **Grupa celów** (`TargetGroup`) | Zbiór celów (IP, CIDR, zakresy, domeny) z własnym profilem, budżetem ruchu, oknami czasowymi i harmonogramem, np. `Instytut_A`. |
| **Profil skanu** (`ScanProfile`) | Parametry techniczne: porty TCP/UDP, sondy discovery, intensywność nmapa, włączone etapy, timeouty, retry. |
| **Przebieg** (`ScanRun`) | Jedno wykonanie skanu dla grupy celów. Może trwać przez kilka okien czasowych. |
| **Zadanie** (`Task`) | Atomowa jednostka pracy dla workera: `sweep` (zakres IP), `probe` (lista hostów), `retry`, `dns`. |
| **Pokrycie** (`Coverage`) | Zbiór (adresy × porty), które przebieg **faktycznie** przeskanował. Podstawa porównań. |
| **Obserwacja** (`Observation`) | Pojedynczy pomiar encji (host, usługa, endpoint HTTP) w danym przebiegu, z dowolnego źródła. |
| **Encja** | Host (`ip`), usługa (`ip/proto/port`), endpoint HTTP (`ip/port/scheme/vhost`). Identyfikowana **kluczem naturalnym**. |
| **Stabilny odcisk** (`stable_fp`) | Hash ze stabilnych pól encji (bez dat, tokenów, wartości sesji). Służy do wykrywania zmian. |
| **Nadpisanie** (`Override`) | Ręczna edycja pola przez analityka, przechowywana osobno od danych ze skanera. |
| **Znalezisko** (`Finding`) | Wyselekcjonowana obserwacja do przekazania do DefectDojo (typ informacyjny). |
| **Worker** | Proces wykonujący narzędzia skanujące. Komunikuje się z serwerem wyłącznie przez API. |
| **Control plane** | Serwer ASI: API, UI, scheduler, dispatcher, analiza. Jedyny komponent z dostępem do bazy i klucza. |

Konwencje: czas w bazie w UTC (`timestamptz`), okna czasowe w strefie grupy (domyślnie `Europe/Warsaw`). Identyfikatory w API: UUID v7. Wszystkie progi liczbowe w tym dokumencie są **domyślne i konfigurowalne**. `ASI_DEMO_MODE=true` skraca je do wartości demonstracyjnych (sekcja 19).

---

## 1. Wizja i architektura

### 1.1. Rola systemu

Zgodnie z wytycznymi mentorów system **nie reimplementuje skanerów**. Jest warstwą pośrednią (control plane) między skanerami open source a DefectDojo:

```text
+-----------------------------------------------------------------------------------+
|                               DEFECTDOJO (API v2)                                 |
|        deduplikacja znalezisk, statusy False Positive / Risk Accepted             |
+--------------------------------------^--------------------------------------------+
                  reimport-scan (push) |  GET findings (pull statusów)
+--------------------------------------v--------------------------------------------+
|                          ASI CONTROL PLANE (Go, 1 binarka)                         |
|                                                                                   |
|  +-------------+  +----------------+  +--------------+  +-----------------------+ |
|  | Web UI +    |  | Scheduler      |  | Dispatcher   |  | Analiza (offline):    | |
|  | REST API    |  | (cron, okna,   |  | (leasing     |  | normalizacja, stan,   | |
|  | RBAC, audyt |  |  pauza/wznów.) |  |  zadań,      |  | diff, sygnatury,      | |
|  | import/exp. |  |  estymacja     |  |  budżet pps) |  | pewność, scoring,     | |
|  +------+------+  +-------+--------+  +------+-------+  | klastry, findings     | |
|         |                 |                  |          +-----------+-----------+ |
|  +------v-----------------v------------------v----------------------v-----------+ |
|  |   PostgreSQL 16: źródło prawdy, kolejka zadań (SKIP LOCKED), szyfrowanie     | |
|  |   pól AES-256-GCM w warstwie aplikacji, overlay, historia obserwacji         | |
|  +-------------------------------------------------------------------------------+ |
+--------------------------------------^--------------------------------------------+
                Worker API (HTTPS + token): lease / heartbeat / complete
+--------------------------------------v--------------------------------------------+
|                  PULA WORKERÓW (skalowalna: `--scale worker=N`)                    |
|  nmap -sn (discovery) -> naabu (porty) -> nmap -sV (usługi) -> httpx + prober      |
|  (HTTP, sygnatury aktywne) [-> nuclei: tylko detekcja, opcjonalnie] ; dnsx (DNS)  |
+-----------------------------------------------------------------------------------+
```

### 1.2. Podział odpowiedzialności

| Komponent | Odpowiada za | Nie robi |
|---|---|---|
| **PostgreSQL (przez control plane)** | Inwentarz, historia obserwacji, pokrycie przebiegów, zmiany, stan dostępności, sygnatury, nadpisania, RBAC, audyt, kolejka zadań. | – |
| **Control plane** | Logika biznesowa, szyfrowanie, analiza offline, decyzje o tempie i oknach, integracja z DefectDojo. | Nie wysyła ruchu skanującego. |
| **Worker** | Uruchamia narzędzia w granicach otrzymanego budżetu, parsuje ich wyjście do formatu kanonicznego, odsyła wyniki. Sam sprawdza, czy cel mieści się w dozwolonym zakresie (obrona w głąb). | Nie ma dostępu do bazy ani klucza szyfrującego. Nie analizuje. |
| **DefectDojo** | Deduplikacja znalezisk, workflow analityka (FP, risk accepted, mitigated). | Nie przechowuje całego inwentarza (tylko znaleziska). |

### 1.3. Dlaczego workery przez API, a nie przez bazę

1. Worker na osobnej maszynie (inna podsieć, inny punkt widzenia) nie powinien znać hasła do bazy ani klucza szyfrowania. Kompromitacja workera nie ujawnia zgromadzonych danych.
2. Serwer szyfruje dane przed zapisem, więc klucz jest w jednym miejscu.
3. Serwer kontroluje tempo: przydziela każdemu zadaniu limit `pps` i może je anulować przez odpowiedź na heartbeat.

### 1.4. Przepływ danych (jeden przebieg)

1. Scheduler tworzy `ScanRun` (z crona lub „uruchom teraz”) z migawką profilu.
2. Planner rozwija cele i tworzy zadania `dns` (dla domen), a dispatcher **leniwie** wycina z kursora kolejne zadania `sweep` (rozmiar dobierany adaptacyjnie, sekcja 5.3).
3. Worker leasinguje `sweep`: discovery (Etap 1), skanowanie portów żywych hostów (Etap 2), odsyła wynik.
4. Serwer zapisuje pokrycie i obserwacje, tworzy zadania `probe` dla hostów z otwartymi portami.
5. Worker leasinguje `probe`: nmap `-sV` (Etap 3), httpx + prober HTTP + sygnatury aktywne (Etap 4), odsyła wynik.
6. Serwer uruchamia analizę offline (Etap 5): normalizacja → stan → sygnatury pasywne → klasyfikacja → pewność → scoring → znaleziska.
7. Po przeskanowaniu całego zakresu: zadania `retry` dla znanych usług, które nie odpowiedziały (sekcja 7.2).
8. Zakończenie przebiegu: diff względem poprzedniego przebiegu na wspólnym pokryciu, aktualizacja automatu stanowego, flapping i okresowość, reimport do DefectDojo.

---

## 2. Bezpieczeństwo działania skanera

Ostrożność skanera jest osobnym kryterium oceny. Poniższe zasady są **twardymi ograniczeniami w kodzie**, a nie zaleceniami.

### 2.1. Zakres (scope)

- **Lista dozwolonych zakresów** (`scope_allow`): tylko ADMIN może ją edytować. Każdy cel spoza niej jest odrzucany przy dodawaniu i ponownie sprawdzany przez dispatcher i przez workera. Chroni przed literówką typu `10.0.0.0/8` zamiast `/24` i przed skanowaniem internetu.
- **Lista wykluczeń** (`exclusions`): adresy, zakresy i nazwy, których nie wolno dotykać (np. sterowniki przemysłowe, urządzenia medyczne, kontroler domeny). Przekazywana narzędziom (`--excludefile`, `-exclude-file`) i dodatkowo filtrowana w kodzie.
- **Limit rozmiaru**: pojedynczy cel nie może być większy niż `/16` (konfigurowalne). Większe zakresy wymagają potwierdzenia przez ADMIN.
- Adresy sieci i broadcastu w zakresach `/24` i mniejszych są pomijane domyślnie.
- Zakresy nierutowalne i specjalne (`127.0.0.0/8`, `169.254.0.0/16`, multicast) są odrzucane, chyba że znajdują się wprost na liście dozwolonych.

### 2.2. Kontrola intensywności

- **Budżet ruchu grupy** (`rate_pps`, `http_rps`) jest **globalny** dla grupy, a nie per worker. Dispatcher dzieli go między zadania wykonywane równolegle (sekcja 5.4).
- **Globalny sufit** `ASI_GLOBAL_MAX_PPS`: suma budżetów wszystkich aktywnych zadań nie może go przekroczyć.
- **Limit równoległości na host**: w Etapach 3–4 maks. 2 równoległe połączenia na jeden adres IP (delikatne urządzenia IoT i drukarki).
- **Timeouty**: każdy proces narzędzia ma twardy limit czasu (`--host-timeout` w nmapie, kontekst z deadline w Go). Po jego przekroczeniu worker zabija całą grupę procesów.
- **Retry ograniczone** do wartości z profilu (domyślnie 2), a ich koszt uwzględnia estymacja.

### 2.3. Zakaz eksploatacji

- Brak payloadów, brute-force'u, prób logowania i domyślnych haseł.
- Sygnatury aktywne mogą wysyłać wyłącznie `GET`/`HEAD`, bez treści żądania, bez nagłówków uwierzytelniających i cookies, maks. 3 żądania na sygnaturę na endpoint (sekcja 9.4).
- **Skrypty nmapa z allowlisty**: `banner`, `ssl-cert`, `ssh-hostkey`, `http-title` (awaryjnie). Bez kategorii `intrusive`, `brute`, `dos`, `exploit`, `vuln`, `auth`. Zakaz skryptu `vulners`: wysyła inwentarz do zewnętrznego API.
- **Bez `--allports`**: nmap domyślnie pomija w detekcji wersji porty 9100–9107 (drukarki drukują wtedy śmieci). To zachowanie musi zostać.
- **SNMP**: brak zgadywania community. Sondowanie UDP/161 przez `nmap -sV` wysyła zapytanie z community `public`, co można uznać za użycie domyślnego poświadczenia, dlatego port 161 jest **domyślnie wyłączony** w profilach i wymaga świadomego włączenia przez ADMIN.
- **Nuclei** (opcjonalny): wyłącznie szablony `http/technologies` i `http/exposed-panels`, z wykluczeniem tagów `intrusive,dos,fuzz,bruteforce,default-login`. Domyślnie wyłączony.
- Prober HTTP nie zapisuje treści ścieżek wrażliwych (np. `/.env`, `/.git/HEAD`): tylko status, długość i dopasowanie wzorca. Treść jest odrzucana.

### 2.4. Identyfikowalność i nadzór

- Stały **User-Agent** wszystkich żądań HTTP: `ASI-Scanner/1.0 (AGH CBI; +<kontakt z konfiguracji>)`. Administratorzy usług wiedzą, kto ich skanuje.
- **Audit log** każdej akcji: kto uruchomił, zatrzymał lub zmienił skan, scope, sygnaturę, rolę. Każde zadanie zapisuje worker, czas startu i końca, zakres i tempo. SOC może odpowiedzieć na pytanie „czy to był nasz skan?”.
- **Wyłącznik awaryjny** (kill switch): przycisk w UI i endpoint API. Dispatcher przestaje wydawać zadania, a najbliższy heartbeat (≤ 5 s) każe workerom zabić procesy. Działanie jest audytowane, a wznowienie wymaga ręcznego wyłączenia.
- Rejestr workerów z ostatnim heartbeatem, wersją narzędzi i bieżącym tempem.

---

## 3. Cele skanowania: wejście, walidacja, grupy

### 3.1. Rodzaje celów

| Rodzaj | Przykład | Obsługa |
|---|---|---|
| `ip` | `10.77.1.10` | IPv4 lub IPv6 (IPv6 tylko pojedyncze adresy). |
| `cidr` | `10.77.0.0/16` | Tylko IPv4. Rozwijany leniwie przez kursor (bez materializacji listy). |
| `range` | `10.77.1.1-10.77.1.200` | Normalizowany do listy CIDR. |
| `domain` | `portal.lab.local` | Zadanie `dns`: rozwiązanie A/AAAA/CNAME (dnsx). Uzyskane IP muszą być w scope, inaczej odnotowanie „domena poza zakresem” bez skanowania. |

### 3.2. Źródła celów

Wszystkie źródła przechodzą tę samą walidację (składnia, scope, wykluczenia, deduplikacja) i trafiają do tej samej tabeli `targets` z polem `source`:
- formularz w UI (pojedynczy cel lub pole tekstowe z wieloma liniami),
- plik CSV (`value,group,tags,note`), plik JSON (`{"targets":[{"value":..,"group":..,"tags":[..]}]}`), plik TXT (jeden cel na linię),
- API.

Odpowiedzią importu jest raport: ile przyjęto, ile odrzucono i dlaczego (np. „poza scope”, „wykluczony”, „duplikat”).

### 3.3. Nazwy hostów i vhosty

- Relacja **nazwa ↔ IP jest wiele-do-wielu** (`hostnames`, `host_hostnames`). Źródła nazw: `dns` (z celu), `ptr` (reverse DNS dla żywych hostów, opcjonalnie), `tls_san` (z certyfikatów), `http_redirect` (z przekierowań w tym samym scope), `manual`.
- Nazwy odkryte w SAN i przekierowaniach są **kandydatami**. Są sondowane jako vhosty tylko wtedy, gdy rozwiązują się do IP w scope albo wskazują na ten sam IP (sondowanie z nagłówkiem `Host` i SNI).
- Endpoint HTTP jest identyfikowany przez `ip/port/scheme/vhost`, gdzie `vhost` może być pusty (żądanie na sam IP).

---

## 4. Pipeline skanowania

### 4.1. Przegląd etapów

| Etap | Gdzie | Narzędzie | Wejście → wyjście |
|---|---|---|---|
| 0. DNS | worker (`dns`) | `dnsx` | domeny → IP, CNAME |
| 1. Discovery | worker (`sweep`) | `nmap -sn` (domyślnie) / `naabu -sn` | zakres IP → żywe hosty |
| 2. Porty | worker (`sweep`) | `naabu` (TCP SYN), `nmap -sU` (UDP, opcjonalnie) | żywe hosty → otwarte porty |
| 3. Usługi | worker (`probe`) | `nmap -sV` + skrypty z allowlisty | otwarte porty → usługa, produkt, wersja, CPE, banery, certyfikat |
| 4. HTTP | worker (`probe`) | `httpx` + własny prober Go (+ `nuclei` opcjonalnie) | wszystkie otwarte porty TCP → metadane HTTP/TLS, technologie, ścieżki |
| 5. Analiza | serwer | Go | obserwacje → stan, sygnatury pasywne, klasyfikacja, pewność, scoring, diff, findings |

Wszystkie narzędzia są uruchamiane jako podprocesy z wyjściem strukturalnym (XML/JSONL), w osobnej grupie procesów, z kontekstem z deadline'em. Parsery mają testy jednostkowe na zapisanych próbkach wyjścia (`internal/tools/*/testdata`).

### 4.2. Etap 0 – DNS

```bash
dnsx -l domains.txt -a -aaaa -cname -resp -json -silent -rl <dns_rps> -retry 2
```

Wynik: rekordy dla każdej domeny. Serwer odrzuca IP spoza scope i dodaje pozostałe do zakresu przebiegu. Opcjonalnie po Etapie 1: `dnsx -ptr` dla żywych hostów (nazwy PTR często mówią dużo o roli maszyny, np. `lab-sw-01`).

### 4.3. Etap 1 – Discovery (wykrywanie żywych hostów)

**Poprawka względem v1:** host żywy ≠ host z otwartym portem z listy dozwolonych. Host, który odpowiada RST na każdy port, żyje. Dlatego discovery jest osobnym etapem z wieloma typami sond:

```bash
nmap -sn -n -PE -PP -PS21,22,23,25,80,135,443,445,3389,8080 -PA80,443 \
     --max-rate <pps_zadania> --max-retries 1 --min-hostgroup 256 \
     --excludefile exclusions.txt -iL chunk.txt -oX -
```

- W tym samym segmencie L2 nmap (z uprawnieniami root) używa automatycznie ARP, co jest najpewniejszą metodą (ważne w labie na Dockerze).
- Każda odpowiedź (echo reply, timestamp reply, SYN-ACK, **RST**) oznacza host żywy. Zapisujemy również **powód** (`reason` z XML nmapa, np. `arp-response`, `reset`, `echo-reply`), który wchodzi do pewności.
- Alternatywny silnik: `naabu -sn -pe -pp -ps <porty> -pa <porty> -arp` (wybór w profilu: `discovery_engine: nmap|naabu`).
- Profil ma opcję `portscan_scope: alive | all`. `all` (odpowiednik `-Pn`) skanuje porty na wszystkich adresach. Używać w przebiegach baseline, gdy podejrzewamy hosty ignorujące wszystkie sondy discovery.

**Zysk wydajności (przykład do prezentacji):** 10 000 IP × 1000 portów = 10 mln pakietów, czyli ok. 2,8 h przy 1000 pps. Discovery to ok. 13 sond na IP = 130 tys. pakietów ≈ 2 min. Przy 25% żywych hostów skan portów to 2,5 mln pakietów ≈ 42 min.

### 4.4. Etap 2 – Skanowanie portów

TCP:

```bash
naabu -list alive.txt -p <tcp_ports_spec> -scan-type s -rate <pps_zadania> -c 25 \
      -retries <retries> -timeout 1000 -Pn -exclude-file exclusions.txt -json -silent
```

- `-Pn`, bo discovery już się odbyło. `-scan-type s` (SYN) wymaga `NET_RAW`/`NET_ADMIN`. Worker przy starcie **sprawdza uprawnienia** i jeśli działa w trybie connect, zgłasza to w rejestrze workerów i w UI jako ostrzeżenie (inna charakterystyka ruchu, wolniej).
- `tcp_ports_spec` pochodzi z profilu: lista organizatorów, `top-100`, `top-1000`, zakresy. Zawsze przecięta z listą dozwolonych portów z ustawień globalnych.

UDP (opcjonalnie, tylko porty z listy profilu, domyślnie `53,123,500,1900,5353`; 161 tylko po świadomym włączeniu):

```bash
nmap -sU -sV --version-intensity 2 -n -Pn -p U:<udp_ports> --max-rate <pps_udp> \
     --max-retries 1 --host-timeout 3m -oX - -iL alive.txt
```

### 4.5. Etap 3 – Identyfikacja usług (nmap)

**Poprawki względem v1:**
- nmap nie przyjmuje par `(IP, port)`, bo `-p` dotyczy wszystkich celów. Worker **grupuje hosty o identycznym zbiorze portów** w jedno wywołanie, a pozostałe uruchamia osobno, z limitem równoległych procesów nmap na workera (`max_nmap_procs`, domyślnie 4).
- Domyślna intensywność detekcji (`7`), a nie `--version-light`: po odsianiu portów koszt jest mały, a trafność identyfikacji usług to największe kryterium oceny. Intensywność można zmienić w profilu.

```bash
nmap -sV --version-intensity <7> -Pn -n -p <porty_hosta> \
     --script "banner,ssl-cert,ssh-hostkey" --script-timeout 15s \
     --max-rate <pps_zadania> --max-retries 2 --host-timeout 5m \
     -oX - <host1> <host2> ...
```

Z XML wyciągamy: `service@name`, `product`, `version`, `extrainfo`, `ostype`, `devicetype`, `tunnel` (ssl), `cpe`, **`method` (`probed`/`table`) i `conf` (0–10)**, wyniki skryptów (`banner`, certyfikat z `ssl-cert` także dla usług innych niż HTTP, `ssh-hostkey` jako odcisk tożsamości urządzenia).

`method="table"` oznacza nazwę usługi zgadniętą tylko z numeru portu, co daje niską pewność (sekcja 8.3).

### 4.6. Etap 4 – Fingerprinting HTTP/HTTPS

**Poprawka względem v1:** httpx działa na **wszystkich** otwartych portach TCP (a nie tylko na „portach webowych”), bo panele na 8081, 9443 czy 10000 to najciekawsze znaleziska. Usługi inne niż HTTP odpadają szybko na timeoucie. Dodatkowo każdy port jest sondowany dla każdej nazwy hosta powiązanej z IP (vhost).

```bash
httpx -l targets.txt -json -silent \
      -sc -title -server -td -favicon -hash sha256 -tls-grab -ip -cname \
      -irh -fr -max-redirects 5 -include-chain -location \
      -rl <http_rps_zadania> -t <threads> -timeout 10 -retries 1 \
      -H "User-Agent: ASI-Scanner/1.0 (AGH CBI; +kontakt)"
```

`targets.txt` zawiera wpisy `ip:port` oraz `vhost:port` (z `-sni`, a rozwiązanie nazwy wymuszone na konkretne IP). Zbierane pola: kod HTTP, tytuł, nagłówki odpowiedzi, `Set-Cookie` (nazwy, flagi, wartości), łańcuch przekierowań, końcowy URL, certyfikat TLS (subject CN, SAN, issuer, not_before, not_after, self-signed, wersja TLS, szyfr), favicon MMH3, technologie (wappalyzergo, `-td`), hash treści.

**Prober HTTP (własny, Go)**, uruchamiany po httpx na endpointach HTTP:
1. **Kontrola soft-404**: `GET /asi-nx-<losowe 12 znaków>`. Zapamiętuje status, długość, tytuł i hash znormalizowanej treści (bez liczb i tokenów). Ścieżka sondowana później uznawana jest za istniejącą tylko wtedy, gdy jej odpowiedź **różni się istotnie** od tej wartości bazowej (inny status lub podobieństwo treści < 0,9).
2. **Ścieżki wbudowane** (konfigurowalne): `/robots.txt`, `/.well-known/security.txt`, `/admin`, `/administrator/`, `/login`, `/user/login`, `/wp-login.php`, `/phpmyadmin/`, `/manager/html`, `/server-status`, `/version`, `/api`, `/swagger-ui/`, `/actuator/health`, `/_profiler`, `/.git/HEAD` (tylko status i wzorzec, bez zapisu treści), `/.env` (jw.).
3. **Ścieżki z sygnatur aktywnych** (sekcja 9.4): deduplikowane, każda ścieżka wysyłana raz na endpoint, a odpowiedź udostępniana wszystkim sygnaturom.
4. Ograniczenia: `GET`/`HEAD`, bez cookies i uwierzytelnienia, `http_rps` z budżetu, maks. 2 równoległe połączenia na host, treść obcinana do 256 KB (zapis do 64 KB, szyfrowany).

**Nuclei (opcjonalnie)**:

```bash
nuclei -l urls.txt -t http/technologies -t http/exposed-panels \
       -etags intrusive,dos,fuzz,bruteforce,default-login \
       -rl <http_rps> -c 5 -bs 10 -jsonl -silent -disable-update-check -no-interactsh
```

Wyniki nuclei to dodatkowe dowody technologii i paneli (z własną wagą pewności), a nie osobne znaleziska.

### 4.7. Etap 5 – Analiza offline (serwer)

Dla każdej przyjętej porcji wyników (i każdego importu, sekcja 13):

1. **Walidacja i normalizacja** do schematu kanonicznego (sekcja 13.2), wspólnego dla skanera, formularza i importu.
2. **Zapis obserwacji** z `run_id` i źródłem, aktualizacja encji (`hosts`, `services`, `http_endpoints`) i pokrycia przebiegu.
3. **Stabilny odcisk** każdej encji (sekcja 6.3).
4. **Sygnatury pasywne** na obserwacji (sekcja 9).
5. **Klasyfikacja** (CMS, framework, serwer aplikacyjny, IoT, staging, panel admina itd.) i **pewność** (sekcja 8).
6. **Scoring „ciekawości”** (sekcja 10).
7. **Wybór znalezisk** dla DefectDojo według reguł (sekcja 14.2).

Po zakończeniu przebiegu (lub jego wstrzymaniu) dochodzą: diff, automat stanowy, flapping i okresowość, reimport do DefectDojo (sekcja 14.3, z regułą dla przebiegów częściowych).

### 4.8. Tryby przebiegu

| Tryb | Etapy | Zastosowanie |
|---|---|---|
| `baseline` | 0–5 w pełni, `portscan_scope` z profilu | Cykliczne pełne odświeżenie (np. raz w tygodniu). |
| `differential` (szybki) | 0–2 pełne. Etap 3 tylko dla **nowych** par `(IP, port)`. Etap 4 skrócony dla znanych endpointów. | Częste przebiegi (np. codziennie). |
| `liveness` (dzienny, niskie tempo) | Etap 1 dla całego zakresu + Etap 2 tylko dla znanych portów. Etapy 3–4 tylko dla hostów **nowych lub niewidzianych w ostatnim przebiegu nocnym**. | Okna dzienne z niskim budżetem. Wykrywa hosty działające tylko w dzień. |
| `retry` | Ponowny pomiar wybranych encji | Automatycznie po przebiegu (sekcja 7.2) lub ręcznie z widoku hosta. |

**Wykrywanie podmiany usługi w trybie szybkim (poprawka v1):** dla znanych endpointów HTTP wykonujemy lekkie żądanie (`GET /` z httpx bez `-td` i bez favicony) i porównujemy **stabilny odcisk** (status, tytuł, `Server`, zbiór nazw nagłówków, odcisk certyfikatu), a nie hash całej treści, który zmienia się przy każdym żądaniu na dynamicznych stronach. Zmiana odcisku uruchamia pełny Etap 4 dla tego endpointu. Dla usług innych niż HTTP porównujemy banner z `nmap --version-intensity 0` (tani). Zmiana banera uruchamia pełny `-sV`.

---

## 5. Planowanie: przebiegi, zadania, estymacja, budżet ruchu, okna czasowe

### 5.1. Model wykonania

- `ScanRun` ma **kursor** (pozycja w znormalizowanej, posortowanej liście zakresów grupy) i migawkę profilu. Przebieg nie zmienia się, jeśli w trakcie ktoś edytuje profil.
- Zadania `sweep` są wycinane **leniwie** przez dispatcher w momencie leasingu, z aktualnym rozmiarem (sekcja 5.3). Dzięki temu rozmiar zmienia się w trakcie przebiegu, a wznowienie to po prostu kontynuacja od kursora.
- Zadania `probe` powstają z wyników `sweep`. Paczka to `probe_batch_hosts` hostów (domyślnie 16) lub mniej, gdy hosty mają dużo portów (limit 200 par).
- W obrębie zadania `sweep` adresy są przekazywane narzędziu w kolejności losowej (naabu i nmap i tak randomizują). Rozkłada to ruch w podsieci.
- Kolejka: tabela `tasks` + `SELECT ... FOR UPDATE SKIP LOCKED`. Bez Redisa.

### 5.2. Leasing, heartbeat, idempotencja

- Worker wywołuje `POST /worker/v1/lease` z listą zdolności (`syn`, `udp`, `nuclei`). Dostaje zadanie z `lease_expires_at` (60 s), przydzielonym `rate_pps` / `http_rps` i aktualną listą scope i wykluczeń.
- Co 5 s `POST /worker/v1/heartbeat` przedłuża lease i zwraca polecenie: `continue | cancel | throttle(new_rate)`.
- Lease wygasł (worker padł): zadanie wraca do `pending`, `attempt++`. Po 3 nieudanych próbach przechodzi w `failed` z widocznym błędem w UI.
- **Zadania są idempotentne**: wynik zapisujemy z kluczem `(task_id, attempt)`, a ponowne wykonanie nadpisuje częściowe dane tego zadania. Nie zapisujemy wewnętrznego stanu narzędzi.

### 5.3. Adaptacyjny podział na podgrupy (poprawka v1)

Treść wymaga podziału „w zależności od szybkości skanowania”. Rozmiar zadania `sweep`:

$$
N_{\text{chunk}} = \operatorname{clamp}\left(\hat{v}_{\text{IP/s}} \cdot T_{\text{target}},\; N_{\min},\; N_{\max}\right)
$$

- $T_{\text{target}}$ – docelowy czas zadania (domyślnie 60 s, demo 15 s). Krótkie zadania pozwalają szybko reagować na koniec okna i kill switch.
- $\hat{v}_{\text{IP/s}}$ – przepustowość w adresach na sekundę dla tej grupy: średnia krocząca EWMA (α = 0,3) z ukończonych zadań. Na start wartość teoretyczna: $\frac{R_{\text{task}}}{p_{\text{disc}} + \rho_{\text{alive}} \cdot N_{\text{ports}} \cdot (1 + r)}$, gdzie $p_{\text{disc}}$ to liczba sond discovery na IP, $\rho_{\text{alive}}$ to historyczny odsetek żywych (start 0,3), a $r$ to średnia liczba retry.
- $N_{\min} = 16$, $N_{\max} = 4096$.
- Dodatkowo zadanie nie może być dłuższe niż pozostały czas okna (sekcja 5.6).

Każde zadanie zapisuje faktyczny czas trwania, liczbę adresów, pakietów (szacunkowo) i wyników. Na tej podstawie UI pokazuje rzeczywistą przepustowość i czas trwania przebiegu oraz każdego zadania.

### 5.4. Budżet ruchu (poprawka v1)

Limit `pps` jest **wspólny dla grupy**, a nie per worker:
- Grupa ma `rate_pps` i `max_parallel_sweeps` (domyślnie 2). Dispatcher wydaje zadanie `sweep` tylko wtedy, gdy liczba aktywnych zadań grupy jest mniejsza od `max_parallel_sweeps`, i przydziela mu `rate_pps / max_parallel_sweeps`. Suma nigdy nie przekracza budżetu grupy, niezależnie od liczby workerów.
- Analogicznie `http_rps` dla zadań `probe` z `max_parallel_probes` (domyślnie 4).
- Globalny sufit `ASI_GLOBAL_MAX_PPS`: dispatcher nie wyda zadania, jeśli suma przydzielonych `pps` aktywnych zadań przekroczyłaby sufit.
- Zmiana budżetu w trakcie: heartbeat zwraca `throttle(new_rate)`. Worker nie zmieni tempa działającego procesu, więc zastosuje je od następnego wywołania narzędzia w ramach zadania. Przy dużej obniżce zadanie jest anulowane i wycinane ponownie.

**Gdzie więcej workerów naprawdę pomaga:** Etap 1–2 jest ograniczony budżetem pakietów, więc dodatkowe workery go nie przyspieszą. Etapy 3–4 są ograniczone opóźnieniami i timeoutami (`-sV` czeka na odpowiedzi sond), więc równoległe zadania `probe` skalują się niemal liniowo.

### 5.5. Estymacja czasu trwania

Przed startem (i przy zapisie harmonogramu):

$$
T_{\text{est}} = \underbrace{\frac{N_{\text{IP}} \cdot p_{\text{disc}}}{R}}_{\text{discovery}}
+ \underbrace{\frac{\hat{N}_{\text{alive}} \cdot N_{\text{ports}} \cdot (1+r)}{R}}_{\text{porty}}
+ \underbrace{\frac{\hat{N}_{\text{open}} \cdot \bar{t}_{\text{probe}}}{P_{\text{probe}}}}_{\text{usługi + HTTP}}
$$

gdzie $R = \min(\text{rate\_pps}_{\text{grupy}}, \text{ASI\_GLOBAL\_MAX\_PPS})$, $\hat{N}_{\text{alive}}$ i $\hat{N}_{\text{open}}$ pochodzą z poprzedniego przebiegu (lub z domyślnych proporcji), $\bar{t}_{\text{probe}}$ to historyczny średni czas sondowania jednego portu, a $P_{\text{probe}}$ to `max_parallel_probes`.

- **ETA w trakcie przebiegu**: ta sama formuła dla pozostałej części kursora i pozostałych zadań `probe`, z prędkościami EWMA z bieżącego przebiegu.
- **ETA kalendarzowe**: rozkładamy $T_{\text{est}}$ na najbliższe okna czasowe grupy, np. „zakończy się w 2. oknie, ok. czwartek 03:40”.
- **Walidacja harmonogramu**: przy zapisie, jeśli $T_{\text{est}}$ > długość okna, UI pokazuje ostrzeżenie „skan zajmie ok. 3 okna – rozważ większy budżet, szersze okno albo tryb `differential`”.

### 5.6. Okna czasowe

- Okno należy do grupy: `days_mask` (pn–nd), `start`, `end`, strefa czasowa grupy. `end < start` oznacza przejście przez północ (np. 22:00–06:00). Obliczenia w strefie lokalnej z obsługą zmiany czasu (DST).
- Okno ma `kind`: `full` (profil grupy) albo `low_impact` (nadpisanie profilu, np. tryb `liveness` i 10% budżetu).
- Brak zdefiniowanych okien = skanowanie dozwolone zawsze (tylko jeśli ADMIN to zatwierdził w ustawieniach grupy).

**Zachowanie na granicach okna (poprawka v1 – twarde zatrzymanie):**
1. Dispatcher **nie wydaje zadania**, jeśli jego szacowany czas (rozmiar × prędkość + margines 20%) przekracza czas pozostały do końca okna. Może wtedy wyciąć mniejsze zadanie, aż do $N_{\min}$.
2. O końcu okna heartbeat zwraca `cancel`. Worker zabija grupę procesów (SIGTERM, po 3 s SIGKILL) i zgłasza `aborted`. Zadanie wraca do `pending` bez zwiększania licznika prób. Wyniki częściowe są odrzucane: zadanie wykona się w całości ponownie.
3. Status przebiegu: `PAUSED_WINDOW`. Kursor i ukończone zadania zostają.
4. Przy otwarciu kolejnego okna scheduler zmienia status na `RUNNING`, a dispatcher kontynuuje od kursora i zadań `pending`.

### 5.7. Statusy przebiegu

`PENDING → RUNNING ⇄ PAUSED_WINDOW | PAUSED_MANUAL → COMPLETED`, oraz `CANCELLED`, `SUPERSEDED` (zastąpiony nowym), `FAILED` (zbyt wiele nieudanych zadań, próg 10%).

### 5.8. Harmonogram i polityka nakładania się

- Harmonogram: wyrażenie CRON (strefa grupy), tryb (`baseline` / `differential` / `liveness`), profil, `overlap_policy`.
- `overlap_policy` (gdy cron odpala, a poprzedni przebieg wciąż trwa lub jest wstrzymany):
  - `skip` (domyślnie): nie twórz nowego, odnotuj w logu harmonogramu;
  - `supersede`: poprzedni → `SUPERSEDED` (jego pokrycie zostaje i jest używane w diffach), nowy startuje od początku;
  - `queue`: nowy czeka na zakończenie poprzedniego (maks. 1 w kolejce).
- Przebieg może też być uruchomiony ręcznie („Uruchom teraz”), także w trybie `retry` dla wybranych hostów.

---

## 6. Porównywanie przebiegów i raportowanie zmian

### 6.1. Dwa poziomy raportowania

1. **Diff przebiegów (surowy)**: dowolna para `Run A` vs `Run B` w widoku porównania. Pokazuje, co było widać w A, a czego nie w B, i na odwrót, **tylko na wspólnym pokryciu**.
2. **Strumień zmian (przefiltrowany)**: zdarzenia generowane po każdym przebiegu względem stanu referencyjnego encji, z uwzględnieniem automatu stanowego (sekcja 7). Usługa niewidziana raz nie „znika” od razu, tylko przechodzi w `SUSPECT`, a zdarzenie `SERVICE_GONE` pojawia się dopiero przy `INACTIVE`. Ten strumień zasila dashboard i alerty.

### 6.2. Pokrycie i przebiegi częściowe (poprawka v1)

- Każde ukończone zadanie zapisuje pokrycie: `(run_id, zakres IP, specyfikacja portów TCP/UDP, etapy)`.
- Diff A vs B liczony jest wyłącznie na $S = \text{cov}(A) \cap \text{cov}(B)$ (przecięcie adresów i portów).
- Przebieg wstrzymany w połowie nie generuje `HOST_GONE` dla nieprzeskanowanej połowy. Przebieg z mniejszym zestawem portów nie generuje `SERVICE_GONE` dla portów, których nie sprawdzał.
- Przebiegi ze źródła `manual` lub `import` mają pokrycie ograniczone do encji, które zawierają. Nigdy nie oznaczają innych encji jako zniknięte.

### 6.3. Stabilny odcisk i pola porównywane (poprawka v1)

Porównujemy **listę stabilnych pól**, nie surowe odpowiedzi. Pola zmienne (nagłówki `Date`, `Expires`, `Age`, `ETag`, `Last-Modified`, `X-Request-Id`, `CF-Ray`, **wartości** cookies, tokeny CSRF, treść strony) **nie** są porównywane.

| Encja | Pola stabilne (wchodzą do `stable_fp` i diffu) |
|---|---|
| Host | stan (up/down), zbiór otwartych portów, odcisk `ssh-hostkey`, nazwy (PTR, DNS) |
| Usługa | `service`, `product`, `version`, `extrainfo`, `tunnel`, CPE, odcisk banera (po usunięciu liczb i dat), odcisk certyfikatu (SHA-256) |
| Endpoint HTTP | status, tytuł (znormalizowany), `Server`, `X-Powered-By`, zbiór **nazw** nagłówków, zbiór **nazw** cookies + flagi (Secure, HttpOnly, SameSite), końcowy URL przekierowań (bez query), favicon MMH3, technologie z wersjami, certyfikat: CN, SAN, issuer, not_after, odcisk; dopasowania sygnatur |

`stable_fp = HMAC-SHA256(klucz_fp, kanoniczny JSON pól stabilnych)`. Używamy HMAC zamiast zwykłego hasha, żeby odcisk nie pozwalał na słownikowe odgadnięcie wartości.

### 6.4. Typy zdarzeń zmian

| Typ | Kiedy |
|---|---|
| `HOST_NEW` | host pierwszy raz widziany |
| `HOST_GONE` | host przeszedł w `INACTIVE` (strumień) / niewidziany w B przy widoczności w A (diff) |
| `HOST_RETURNED` | host z `INACTIVE` znowu widziany |
| `SERVICE_NEW` / `SERVICE_GONE` / `SERVICE_RETURNED` | analogicznie dla `ip/proto/port` |
| `SERVICE_CHANGED` | zmiana pola stabilnego usługi; zdarzenie zawiera listę `{pole, stara, nowa}` |
| `HTTP_CHANGED` | zmiana pól stabilnych endpointu (tytuł, technologie, cookies, nagłówki) |
| `TLS_CHANGED` | zmiana certyfikatu (rotacja, nowy issuer, zbliżające się wygaśnięcie < 14 dni) |
| `TECH_ADDED` / `TECH_REMOVED` / `TECH_VERSION_CHANGED` | zmiany wykrytych technologii |
| `SIGNATURE_MATCH_NEW` / `SIGNATURE_MATCH_GONE` | nowe lub ustałe dopasowanie sygnatury |
| `IDENTITY_CHANGED` | pod tym samym IP najpewniej jest inne urządzenie (DHCP): zmiana `ssh-hostkey` lub >70% zbioru usług i technologii naraz |
| `STATE_FLAPPING` / `STATE_PERIODIC` | nadanie etykiety niestabilności lub okresowości |

Każde zdarzenie ma priorytet (sekcja 10), a dashboard sortuje po nim. Zdarzenia dla encji z etykietą `FLAPPING` mają obniżony priorytet (×0,5) i są grupowane („host X zmienił stan 4 razy w ostatnich 10 przebiegach”), zamiast generować osobny alert za każdym razem.

---

## 7. Dostępność, niestabilność (flapping), okresowość, nieaktywność

### 7.1. Automat stanowy (osobno dla hosta i dla usługi)

```text
            widziany                      niewidziany i misses < K_eff
  (nowy) ----------> ACTIVE ------------------------------------------> SUSPECT
                       ^  ^                                               |
                       |  +--------------- widziany ----------------------+
                       |                                                  | misses >= K_eff
                       |                                                  | i reguła 7.5
                       +------------------ widziany ------------------ INACTIVE
                                           (HOST_RETURNED)
```

- `consecutive_misses` rośnie tylko wtedy, gdy encja **była w pokryciu** przebiegu i nie odpowiedziała (także po retry z sekcji 7.2).
- `total_seen` to liczba przebiegów, w których encję widziano.
- $K$ = 3 (demo: 2). $K_{\text{ephemeral}}$ = 1 dla encji z `total_seen ≤ 2`. Host widziany tylko raz lub dwa razy (np. laptop gościa) szybciej przestaje zaśmiecać widoki aktywnych zasobów.
- Usługa nie może być `ACTIVE`, gdy jej host jest `INACTIVE`. Host `SUSPECT` z odpowiadającą usługą jest `ACTIVE` (spójność).

### 7.2. Powtarzanie pomiarów (retry) w obrębie przebiegu

Po zakończeniu skanu całego zakresu dispatcher tworzy zadania `retry` dla encji, które **były `ACTIVE` lub `SUSPECT`, a w tym przebiegu nie odpowiedziały**:
- opóźnienia: 2 min i 10 min (demo: 20 s i 60 s), tzn. maks. 2 dodatkowe pomiary;
- zakres pomiaru minimalny: discovery hosta i SYN na jego znane porty (bez `-sV`, chyba że port odpowie);
- odpowiedź w retry → encja widziana w tym przebiegu (pakiet zgubił się jednorazowo), z adnotacją `recovered_on_retry` (wpływa na pewność i jest sygnałem niestabilności);
- retry respektuje okna i budżet.

To jest wariant pomysłu „ponów za 10 minut, potem podwajaj”. Krótkie ponowienia w obrębie przebiegu eliminują jednorazowe straty pakietów, a decyzje długoterminowe zapadają w automacie stanowym między przebiegami.

### 7.3. Wskaźnik niestabilności (flap rate)

Dla ostatnich $M$ obserwacji encji w przebiegach, które ją pokrywały ($M$ = 10, demo 5), z $s_i \in \{\text{UP}, \text{DOWN}\}$:

$$
F = \frac{\sum_{i=2}^{M} \mathbb{I}(s_i \neq s_{i-1})}{M - 1}
$$

Etykieta `FLAPPING`, gdy $F \ge 0{,}4$ i liczba obserwacji ≥ 4 (demo: 3). Etykieta znika, gdy $F < 0{,}2$ przez kolejne $M$ obserwacji (histereza, bez migotania etykiety). Przypadki `recovered_on_retry` liczone są dodatkowo jako „półprzejście” (+0,5 do licznika). Host, który odpowiada dopiero za drugim razem, jest niestabilny, nawet jeśli wynik końcowy to UP.

**Hosty zmieniające odpowiedź** (nie tylko dostępność): jeśli `stable_fp` endpointu zmienia się w ≥ 3 z ostatnich 5 przebiegów, endpoint dostaje etykietę `UNSTABLE_RESPONSE` (np. load balancer z różnymi backendami). Jego zdarzenia `HTTP_CHANGED` są grupowane, a nie zgłaszane osobno.

### 7.4. Okresowość (pora dnia, dzień tygodnia)

- Historia dostępności `availability_history(entity, run_id, at, up, bucket)` zawiera tylko pomiary z pokrycia.
- Kubełki pory dnia: `NIGHT 00–06`, `MORNING 06–12`, `AFTERNOON 12–18`, `EVENING 18–24` (strefa grupy). Dodatkowo podział `WEEKDAY` / `WEEKEND`.
- Dla każdego kubełka $b$ z $n_b \ge 3$ pomiarami: $p_b = \frac{\text{UP}_b}{n_b}$.
- Etykieta `PERIODIC(<kubełki aktywne>)`, gdy istnieje kubełek z $p_b \ge 0{,}85$ i kubełek z $p_b \le 0{,}10$, a pomiary obejmują ≥ 2 kubełki. Przykład: `PERIODIC(MORNING,AFTERNOON; WEEKDAY)` dla komputera w laboratorium.
- Host `PERIODIC` **nie dostaje** etykiety `FLAPPING`: zmiany stanu są wyjaśnione porą dnia.
- Widok hosta pokazuje mapę cieplną 7 dni × 24 godziny (odsetek UP).

### 7.5. Reguła nieaktywności (odpowiedź na pytanie z treści zadania)

Encja przechodzi w `INACTIVE`, gdy **wszystkie** warunki są spełnione:
1. `consecutive_misses ≥ K_eff` (K = 3, efemeryczne 1);
2. od `last_seen` minęło ≥ $T_{\min}$ (domyślnie 72 h, efemeryczne 24 h, demo 0);
3. braki **obejmują kubełek, w którym encja była dotąd aktywna**. Dla encji `PERIODIC` liczą się tylko pomiary z jej aktywnych kubełków. Host działający w dzień nie zostanie uznany za martwy przez skany nocne. Dla encji bez etykiety braki muszą obejmować ≥ 2 różne kubełki, o ile grupa ma okna w więcej niż jednym kubełku.

Gdy encja bywa pomijana w pokryciu (np. tryb `liveness` nie skanuje jej portu), licznik nie rośnie. Brak pomiaru to nie brak odpowiedzi.

---

## 8. Fingerprinting, klasyfikacja i pewność identyfikacji

### 8.1. Zbierane informacje

| Obszar | Dane |
|---|---|
| Usługa | nazwa, produkt, wersja, extrainfo, typ urządzenia, OS (z `-sV`), CPE, baner, `method`, `conf` |
| HTTP | status, tytuł, nagłówki, cookies (nazwa, wartość, flagi, domena, ścieżka), przekierowania, końcowy URL, favicon MMH3, hash treści, technologie, wyniki ścieżek probera |
| TLS | wersja, szyfr, subject CN, SAN, issuer, daty, self-signed, zgodność nazwy z vhostem, długość klucza |
| Host | nazwy (DNS, PTR, SAN), odcisk SSH, typ urządzenia z nmapa |

**Minimalizacja danych (cookies):** nazwy i flagi są przechowywane jawnie (potrzebne do wyszukiwania i sygnatur). **Wartości** są szyfrowane i domyślnie maskowane w UI oraz eksporcie (`sensitive:read` pozwala je odsłonić, sekcja 15). Opcja `store_cookie_values=false` w ustawieniach wyłącza ich zapis całkowicie (zostaje tylko HMAC wartości do porównań).

### 8.2. Kategorie klasyfikacji

Encja może mieć wiele kategorii, każdą z pewnością:

| Kategoria | Przykładowe dowody |
|---|---|
| `cms` | WordPress, Joomla, Drupal, TYPO3, Moodle (wappalyzer, `meta generator`, ścieżki `/wp-login.php`, `/user/login`, cookies `wordpress_*`, `MoodleSession`) |
| `framework` | Laravel (`laravel_session`, `XSRF-TOKEN`), Django (`csrftoken`, strona debug), Spring Boot (Whitelabel Error Page, `/actuator`), Express (`X-Powered-By: Express`), ASP.NET (`X-AspNet-Version`, `ASP.NET_SessionId`), Symfony (`X-Debug-Token`) |
| `app_server` | Tomcat, JBoss/WildFly, IIS, Jetty, nginx, Apache httpd, Node, gunicorn/uwsgi (nagłówek `Server`, domyślne strony, `-sV`) |
| `iot` | kamery (Hikvision, Dahua, GoAhead, RTSP 554), drukarki (HP, IPP 631, `devicetype=printer`), routery i switche (MikroTik, Ubiquiti, telnet BusyBox), UPS, BMC/IPMI |
| `admin_panel` | phpMyAdmin, Grafana, Jenkins, Kibana, Webmin, Tomcat Manager, panel routera, strona `/admin` z formularzem logowania |
| `staging` | nazwy `dev.`, `test.`, `stage.`, `staging.`, `uat.`, `preprod.` (vhost, CN/SAN, PTR), tytuły z „test/staging/dev”, nagłówki `X-Environment`, robots `Disallow: /`, strony debug |
| `default_page` | „Apache2 Default Page”, „Welcome to nginx!”, „IIS Windows Server”, „It works!” |
| `debug_exposure` | profiler Symfony, debug Laravel/Django, `phpinfo()`, listing katalogu „Index of /”, `/server-status`, `.git/HEAD`, `.env` |
| `cleartext_login` | formularz z `type=password` przez HTTP bez przekierowania na HTTPS |
| `tls_issue` | certyfikat wygasły, wygasający < 30 dni, self-signed, niezgodna nazwa, TLS 1.0/1.1, klucz RSA < 2048 |
| `eol_software` | wersje z ręcznej listy końca wsparcia (`signatures/builtin/eol.yaml`, np. PHP < 8.1, Apache 2.2, OpenSSH < 7.4, IIS 6/7, WordPress < 6.0) |

Źródła klasyfikacji: wappalyzergo (httpx `-td`), nmap (`devicetype`, `product`), nuclei (opcjonalnie), **wbudowany pakiet sygnatur** (`signatures/builtin/*.yaml`, ok. 80 reguł) i sygnatury użytkownika.

### 8.3. Pewność identyfikacji (odpowiedź na pytanie z treści zadania)

Każdy dowód $i$ dla twierdzenia (np. „endpoint X to WordPress”) ma wagę $w_i \in [0, 1]$. Łączenie dowodów niezależnych (*noisy-OR*):

$$
c_{\text{dowody}} = 1 - \prod_i (1 - w_i)
$$

Domyślne wagi:

| Dowód | $w_i$ |
|---|---|
| nmap `method=probed`, `conf=10` | 0,90 |
| nmap `method=probed`, `conf<10` | `conf/10 × 0,9` |
| nmap `method=table` (tylko numer portu) | 0,25 |
| wappalyzer (httpx `-td`) | 0,70 |
| nagłówek z jawną nazwą produktu (`Server`, `X-Powered-By`, `X-Generator`) | 0,80 |
| znany hash favicony | 0,80 |
| charakterystyczne cookie | 0,60 |
| ścieżka specyficzna dla produktu (po kontroli soft-404) | 0,75 |
| `meta generator` / wersja w stopce | 0,85 |
| sygnatura użytkownika | wartość `confidence` z sygnatury |
| nuclei technologies/panels | 0,75 |

Następnie korekta za **stabilność w czasie**:

$$
c = c_{\text{dowody}} \cdot \left(0{,}7 + 0{,}3 \cdot \frac{\text{widziane w ostatnich } n}{n}\right), \quad n = \min(5, \text{liczba przebiegów z pokryciem})
$$

oraz kara 0,9 za `recovered_on_retry` w bieżącym przebiegu.

- **Wersja** ma osobną pewność (często produkt jest pewny, a wersja nie).
- Każde twierdzenie przechowuje listę dowodów (`evidence`: źródło, pole, dopasowanie, waga). UI pokazuje „dlaczego tak sądzimy”.
- Progi prezentacji: ≥ 0,8 „pewne”, 0,5–0,8 „prawdopodobne”, < 0,5 „przypuszczenie” (wyszarzone). Ręczne nadpisanie technologii przez analityka ma pewność 1,0 i znacznik `manual`.

---

## 9. Silnik sygnatur

### 9.1. Założenia

- Sygnatura służy do **bezpiecznej detekcji cech**, a nie do eksploatacji.
- Dwa rodzaje (poprawka v1):
  - **pasywne**: działają wyłącznie na zapisanych obserwacjach. Działają też na danych z importu i formularza, a po dodaniu nowej sygnatury można je uruchomić na całej historii (retro-hunting);
  - **aktywne-bezpieczne**: mają sekcję `request` (ścieżka do pobrania). Prober wykonuje żądanie w Etapie 4, a dopasowanie działa na odpowiedzi. Ich wynik również trafia do obserwacji, więc retro-hunting działa na już pobranych ścieżkach.
- Wyrażenia regularne: silnik RE2 (pakiet `regexp` w Go). Liniowy czas działania, brak ReDoS z sygnatur użytkownika.
- Sygnatury są wersjonowane (każda edycja = nowa wersja, z audytem), mogą być włączane i wyłączane i mają właściciela.

### 9.2. Format (YAML, równoważnie JSON)

```yaml
id: asi-wordpress-login            # unikalny, [a-z0-9-]
name: WordPress – panel logowania
description: Publicznie dostępny formularz logowania WordPress.
author: cbi-team
version: 3
enabled: true
scope: http                        # http | service | host
categories: [cms, admin_panel]
severity: info                     # info | low | medium | high (dla DefectDojo, domyślnie info)
priority: 30                       # wkład do oceny "ciekawości" (0–100)
confidence: 0.9                    # waga dowodu w noisy-OR
tags: [wordpress, login]
technology:                        # opcjonalnie: dopasowanie ustala technologię
  name: WordPress
  category: cms
  version_from:                    # opcjonalnie: ekstrakcja wersji (1. grupa regex)
    part: body
    regex: '<meta name="generator" content="WordPress ([0-9.]+)"'
request:                           # obecna => sygnatura aktywna
  method: GET                      # GET | HEAD
  path: /wp-login.php
  follow_redirects: false
match:
  all:                             # all | any | not (zagnieżdżalne)
    - part: status
      op: in
      value: [200]
    - part: body
      op: regex
      value: 'id="wp-submit"'
    - any:
        - part: cookie_name
          op: equals
          value: wordpress_test_cookie
        - part: body
          op: contains
          value: 'wp-login.php?action=lostpassword'
export:
  defectdojo: true
  title: "WordPress login panel exposed"
```

### 9.3. Części (`part`) i operatory (`op`)

**Części dla `scope: http`:** `status`, `title`, `header` (z polem `name`), `header_names`, `cookie_name`, `cookie` (z `name` i `attr`: `secure|httponly|samesite|value_hmac`), `body` (do 256 KB), `body_hash`, `favicon_mmh3`, `final_url`, `redirect_location`, `redirect_chain`, `tech` (nazwa), `tech_version`, `tls_subject_cn`, `tls_san`, `tls_issuer`, `tls_expired`, `tls_days_left`, `tls_self_signed`, `tls_version`, `vhost`, `scheme`, `port`, `soft404` (bool – odpowiedź jak strona nieistniejąca).

**Części dla `scope: service`:** `port`, `proto`, `service`, `product`, `version`, `extrainfo`, `cpe`, `banner`, `devicetype`, `tls_*` (z `ssl-cert`).

**Części dla `scope: host`:** `hostname`, `ptr`, `open_ports`, `os`, `labels`.

**Operatory:** `equals`, `iequals`, `contains`, `icontains`, `regex`, `in`, `exists`, `not_exists`, `lt`, `gt`, `between`, `version_lt`, `version_gte` (porównanie wersji semantycznych lub luźnych, np. `5.6.40`).

### 9.4. Walidacja i ograniczenia bezpieczeństwa

Walidator (endpoint `/signatures/validate`, wywoływany też w edytorze na żywo) odrzuca sygnaturę, jeśli:
- `request.method` ∉ {GET, HEAD}, istnieje `request.body`, `request.headers` zawiera coś innego niż `Accept` / `Accept-Language`;
- `path` nie zaczyna się od `/`, zawiera `..`, schemat lub host (sygnatura nie może wskazać innego celu, ochrona przed SSRF), ma > 512 znaków, zawiera znaki typowe dla payloadów (`'`, `"`, `<`, `>`, `` ` ``, `${`, `;`, `|`, `%00`);
- sygnatura ma > 3 żądań;
- regex nie kompiluje się w RE2 lub ma > 2000 znaków;
- brak `id`, `name`, `match`; nieznany `part` lub `op`; zła kombinacja `part`/`scope`.

### 9.5. Wykonanie

- Pasywne: dla każdej nowej obserwacji, sygnatury filtrowane po `scope`. Wynik: `signature_matches` (aktywne/nieaktywne, pierwszy i ostatni raz, dowody stabilne).
- Aktywne: worker dostaje w zadaniu `probe` listę unikalnych ścieżek z włączonych sygnatur aktywnych. Serwer dopasowuje odpowiedzi.
- **Retro-hunting**: przy włączeniu lub edycji sygnatury pasywnej przycisk „Uruchom na historii” tworzy zadanie serwerowe, które dopasowuje ją do najnowszych obserwacji wszystkich encji (opcjonalnie do całej historii). Pokazuje się postęp i liczba trafień, bez ponownego skanu.
- **Test sygnatury**: w edytorze można wskazać encję (np. endpoint) i zobaczyć wynik dopasowania krok po kroku (które warunki spełnione).

### 9.6. Adaptery formatów

- **Format organizatorów**: zestaw przykładowych sygnatur dostarczą organizatorzy. Moduł `internal/signatures/adapters` ma interfejs `Adapter { Detect([]byte) bool; Convert([]byte) ([]Signature, error) }`. Adapter dla ich formatu powstaje po otrzymaniu plików. Import sygnatur wykrywa format automatycznie.
- **Podzbiór nuclei**: szablony `http` z matcherami `word`, `regex`, `status`, `dsl` (tylko `mmh3(base64_py(body))==` dla favicony) i ścieżkami `{{BaseURL}}/...` są konwertowane do formatu ASI, a pozostałe odrzucane z komunikatem.
- **Eksport** sygnatur: YAML lub JSON (pojedynczo lub paczka).

---

## 10. Ocena „ciekawości”, grupowanie podobnych usług

### 10.1. Ocena „ciekawości” (priorytet analityczny)

Wynik encji (0–100) to suma składników z widocznym rozbiciem, przeskalowana przez mnożniki:

| Składnik | Punkty |
|---|---|
| `admin_panel` | +30 |
| `debug_exposure` | +35 |
| `cleartext_login` | +25 |
| `staging` | +20 |
| `eol_software` | +25 |
| `iot` z panelem WWW | +20 |
| `default_page` | +10 |
| `tls_issue` (wygasły, self-signed na panelu) | +10 / +15 |
| nowe od ostatniego przebiegu (`*_NEW`) | +15 |
| zmiana wersji lub technologii | +10 |
| usługa na nietypowym porcie (HTTP poza 80/443/8080/8443) | +5 |
| dopasowanie sygnatury | +`priority` sygnatury |
| ręczny priorytet analityka (overlay) | zastępuje wynik |

Mnożniki: `FLAPPING` ×0,5 dla składników „nowości”, znalezisko oznaczone w DefectDojo jako FP lub risk accepted → 0 dla tego składnika, wyciszenie przez analityka → 0. Wynik ograniczony do 100. W UI widać rozbicie, np. „+30 panel admina, +20 staging, +15 nowe”.

### 10.2. Grupowanie podobnych usług

- **Klucz klastra** endpointu HTTP: `HMAC(favicon_mmh3 | tytuł znormalizowany | Server | posortowane technologie)`. Usługi innej niż HTTP: `HMAC(service | product | version-major)`.
- Widok „Klastry”: „47 hostów – *HP LaserJet MFP M426* (favicon 1234…, tytuł …)”, z listą członków i odstającymi (np. jedna drukarka z inną wersją firmware).
- Akcje grupowe na klastrze: tagowanie, wyciszenie, przypisanie kategorii (overlay dla wszystkich członków), eksport.

---

## 11. Model danych

PostgreSQL 16, migracje `goose` osadzone w binarce. Kolumny `*_enc` to `bytea` z szyfrogramem (sekcja 16). Poniżej opis tabel; szczegóły typów są w migracjach.

### 11.1. Bezpieczeństwo i administracja

| Tabela | Kolumny kluczowe |
|---|---|
| `users` | `id`, `email` (unikalny), `display_name`, `password_hash` (argon2id), `role_id`, `is_active`, `failed_logins`, `locked_until`, `last_login_at`, `created_at` |
| `roles` | `id`, `name` (unikalna), `description`, `is_system` (4 role domyślne – nieusuwalne, ale edytowalne przez ADMIN poza rolą ADMIN) |
| `role_permissions` | `role_id`, `permission` (tekst, np. `targets:create`) |
| `sessions` | `id_hash` (SHA-256 tokenu), `user_id`, `csrf_hash`, `created_at`, `expires_at`, `ip`, `user_agent` |
| `audit_log` | `id`, `at`, `user_id` / `worker_id`, `action`, `object_type`, `object_id`, `details` (jsonb, bez danych wrażliwych), `ip` |
| `settings` | `key`, `value` (jsonb); wartości wrażliwe (`dd_api_token`) w `value_enc` |
| `scope_allow` | `id`, `cidr` (`cidr`), `note`, `created_by` |
| `exclusions` | `id`, `kind` (`cidr`/`hostname`), `value`, `reason`, `created_by` |
| `encryption_keys` | `id` (key_id), `purpose` (`data`/`hmac`), `wrapped_key` (zaszyfrowany kluczem głównym), `active`, `created_at`, `retired_at` |
| `workers` | `id`, `name`, `token_hash`, `vantage` (opis punktu widzenia sieci), `capabilities` (jsonb), `tool_versions`, `last_heartbeat`, `status` |
| `killswitch` | wiersz singleton: `active`, `activated_by`, `activated_at`, `reason` |

### 11.2. Konfiguracja skanów

| Tabela | Kolumny kluczowe |
|---|---|
| `target_groups` | `id`, `name`, `description`, `timezone`, `default_profile_id`, `rate_pps`, `http_rps`, `max_parallel_sweeps`, `max_parallel_probes`, `always_allowed` (brak okien = zawsze) |
| `targets` | `id`, `group_id`, `kind` (`ip/cidr/range/domain`), `value`, `normalized` (`cidr[]`), `source` (`manual/csv_import/json_import/txt_import/api`), `enabled`, `tags`, `note_enc`, `created_by`, `created_at` |
| `scan_profiles` | `id`, `name`, `tcp_ports`, `udp_ports`, `discovery_engine`, `discovery_probes` (jsonb), `portscan_scope`, `nmap_intensity`, `nmap_scripts`, `http_enabled`, `prober_paths`, `active_signatures_enabled`, `nuclei_enabled`, `retries`, `timeouts` (jsonb), `retry_delays` |
| `windows` | `id`, `group_id`, `days_mask`, `start_time`, `end_time`, `kind` (`full/low_impact`), `profile_override_id`, `rate_factor` |
| `schedules` | `id`, `group_id`, `profile_id`, `cron`, `mode`, `overlap_policy`, `enabled`, `last_fired_at`, `next_fire_at` |

### 11.3. Wykonanie

| Tabela | Kolumny kluczowe |
|---|---|
| `scan_runs` | `id`, `group_id`, `schedule_id`, `mode`, `source` (`scanner/manual/import/reference`), `profile_snapshot` (jsonb), `status`, `cursor` (jsonb), `est_seconds`, `stats` (jsonb: adresy, żywe, porty, zadania, pakiety), `created_by`, `created_at`, `started_at`, `finished_at`, `paused_reason` |
| `tasks` | `id`, `run_id`, `kind` (`dns/sweep/probe/retry`), `payload` (jsonb: zakres, hosty, porty, ścieżki), `status` (`pending/leased/done/failed/aborted`), `attempt`, `lease_owner`, `lease_expires_at`, `rate_pps`, `http_rps`, `not_before`, `started_at`, `finished_at`, `duration_ms`, `stats`, `error` |
| `run_coverage` | `run_id`, `task_id`, `ip_range` (`cidr` lub para start/end `inet`), `tcp_ports` (`int4multirange`), `udp_ports`, `stages` |

### 11.4. Inwentarz i historia

| Tabela | Kolumny kluczowe |
|---|---|
| `hosts` | `id`, `ip` (`inet`, unikalny), `state`, `labels` (`text[]`: `FLAPPING`, `PERIODIC(...)`), `first_seen`, `last_seen`, `consecutive_misses`, `total_seen`, `flap_score`, `periodicity` (jsonb), `identity` (jsonb: ssh hostkey fp, devicetype), `stable_fp`, `score`, `score_breakdown` (jsonb), `group_id` |
| `hostnames` | `id`, `name` (unikalna), `first_seen`, `last_seen` |
| `host_hostnames` | `host_id`, `hostname_id`, `source` (`dns/ptr/tls_san/http_redirect/manual`), `last_seen` |
| `services` | `id`, `host_id`, `proto`, `port` (unikalne razem), `state`, `labels`, `first_seen`, `last_seen`, `consecutive_misses`, `total_seen`, `flap_score`, `service_name`, `product`, `version`, `extrainfo`, `devicetype`, `cpe` (`text[]`), `tunnel`, `nmap_method`, `nmap_conf`, `confidence`, `version_confidence`, `tls_summary` (jsonb jawny: CN, issuer, not_after, self_signed), `stable_fp`, `raw_enc` (baner, pełny cert, wyniki skryptów), `score`, `score_breakdown` |
| `http_endpoints` | `id`, `service_id`, `vhost` (pusty = IP), `scheme`, `url`, `state`, `status_code`, `title`, `server`, `powered_by`, `header_names` (`text[]`), `cookie_meta` (jsonb jawny: nazwa + flagi), `final_url`, `favicon_mmh3`, `body_sha256_hmac`, `tls_summary`, `soft404_baseline` (jsonb), `stable_fp`, `cluster_key`, `labels`, `raw_enc` (pełne nagłówki, cookies z wartościami, łańcuch przekierowań, fragment treści, wyniki ścieżek), `first_seen`, `last_seen`, `score`, `score_breakdown` |
| `technologies` | `id`, `entity_type`, `entity_id`, `name`, `version`, `category`, `confidence`, `version_confidence`, `evidence` (jsonb), `first_seen`, `last_seen`, `active` |
| `classifications` | `entity_type`, `entity_id`, `category`, `confidence`, `evidence`, `active` |
| `observations` | `id`, `run_id`, `task_id`, `observed_at`, `source`, `worker_id`, `entity_type`, `entity_key` (np. `10.77.1.10/tcp/443/https/portal.lab.local`), `up`, `stable` (jsonb – pola stabilne, jawne), `raw_enc`, `stable_fp`, `recovered_on_retry` – partycjonowana miesięcznie |
| `availability_history` | `entity_type`, `entity_id`, `run_id`, `at`, `up`, `bucket_tod`, `bucket_dow` |
| `changes` | `id`, `run_id`, `compared_run_id`, `at`, `entity_type`, `entity_key`, `change_type`, `diff` (jsonb `[{field, old, new}]`), `priority`, `acknowledged_by`, `acknowledged_at` |

### 11.5. Analiza i workflow

| Tabela | Kolumny kluczowe |
|---|---|
| `signatures` | `id`, `sig_id`, `version`, `kind` (`passive/active`), `scope`, `definition` (jsonb), `source_text` (YAML), `enabled`, `origin` (`builtin/user/imported`), `created_by`, `updated_at` |
| `signature_matches` | `id`, `signature_id`, `sig_version`, `entity_type`, `entity_id`, `evidence` (jsonb stabilne), `active`, `first_seen`, `last_seen`, `last_run_id` |
| `overrides` | `id`, `entity_type`, `entity_key` (**klucz naturalny**), `field`, `value` (jsonb), `scanner_value_at_edit` (jsonb), `updated_by`, `updated_at` |
| `tags`, `entity_tags` | `tags(id, name, color)`, `entity_tags(entity_type, entity_key, tag_id, created_by)` |
| `notes` | `id`, `entity_type`, `entity_key`, `body_enc`, `created_by`, `created_at`, `updated_at` |
| `suppressions` | `id`, `entity_key` lub `signature_id` lub oba, `reason`, `until`, `created_by` |
| `findings` | `id`, `entity_type`, `entity_key`, `rule` (sygnatura lub kategoria), `title`, `severity`, `description` (deterministyczny), `dedup_key`, `status` (`open/false_positive/risk_accepted/mitigated/out_of_scope`), `dd_finding_id`, `dd_test_id`, `last_pushed_at`, `last_synced_at`, `first_seen`, `last_seen`, `active` |
| `imports` | `id`, `kind` (`targets/observations/signatures`), `format`, `filename`, `status`, `stats`, `errors` (jsonb), `run_id`, `created_by`, `created_at` |
| `dd_sync_log` | `id`, `at`, `direction`, `status`, `details` |

### 11.6. Klucze naturalne

- Host: `ip`
- Usługa: `ip/proto/port`
- Endpoint: `ip/port/scheme/vhost` (`vhost` = `-` dla żądań na IP)

Nadpisania, tagi, notatki i wyciszenia odnoszą się do **kluczy naturalnych**, a nie do `id` wierszy. Przetrwają więc zniknięcie i ponowne pojawienie się encji oraz czyszczenie danych.

---

## 12. Warstwa nadpisań (overlay)

Wymóg 14: edycja wartości **niezależnie od stanu skanu** i **zachowanie zmian przy kolejnych skanach**.

- Dane ze skanera (`hosts`, `services`, `http_endpoints`, `technologies`, `classifications`) są nadpisywane przy każdej obserwacji. Ręczne edycje trafiają **wyłącznie** do `overrides` (pole po polu), `tags`, `notes`.
- **Widok efektywny** (read model) w API: `effective = merge(scanner, overrides)`, nadpisanie wygrywa. Odpowiedź API zawiera dla każdego nadpisanego pola trójkę `{value, scanner_value, overridden_by, overridden_at}`.
- **Konflikt**: jeśli bieżąca wartość skanera ≠ `scanner_value_at_edit`, pole ma flagę `conflict=true` (ikona w UI: „skaner widzi teraz *nginx 1.25*, a analityk ustawił *Apache*”). Analityk może zaakceptować wartość skanera (usuwa nadpisanie) albo potwierdzić swoją (aktualizuje `scanner_value_at_edit`).
- Edytowalne pola: produkt, wersja, nazwa usługi, kategorie, technologie (dodaj, usuń, zmień wersję), priorytet analityczny (zastępuje wynik), stan (np. „wycofany z eksploatacji”), właściciel/kontakt, opis, kategoria zasobu, `muted`.
- Edycja nie blokuje się w trakcie przebiegu. Worker nie pisze do `overrides`, więc nie ma konfliktu zapisów.
- Edycja konfiguracji (profile, harmonogramy, okna, grupy) zmienia rekordy konfiguracji bezpośrednio. Działające przebiegi mają migawkę profilu, a zmiany okien i budżetu obowiązują od najbliższego leasingu lub heartbeatu.
- Każda edycja jest w `audit_log`, a historia nadpisań pola jest widoczna w UI.

---

## 13. Import, eksport, formularz ręczny, ocena trafności

### 13.1. Zasada jednego pipeline'u (wymóg 11)

Każde źródło danych (skaner, formularz, CSV, JSON, nmap XML, wyniki referencyjne) jest zamieniane na **obserwacje w schemacie kanonicznym** i przechodzi identyczną ścieżkę: walidacja → przebieg-kontener (`scan_runs.source = manual|import|reference`) → zapis obserwacji i pokrycia (tylko importowane encje) → aktualizacja encji → sygnatury pasywne → klasyfikacja → pewność → scoring → zmiany → findings → dostępne w dashboardzie, edycji, eksporcie i DefectDojo.

Formularz i import **celów** (sekcja 3.2) to osobna ścieżka: cele są skanowane, a obserwacje przyjmowane.

### 13.2. Schemat kanoniczny (`asi.observation/v1`)

```json
{
  "schema": "asi.observation/v1",
  "observed_at": "2026-11-21T22:14:05Z",
  "source": "json_import",
  "host": {
    "ip": "10.77.1.10",
    "up": true,
    "up_reason": "syn-ack",
    "hostnames": [{"name": "portal.lab.local", "source": "dns"}],
    "ssh_hostkey_fp": null
  },
  "services": [
    {
      "proto": "tcp",
      "port": 443,
      "state": "open",
      "service": "https",
      "product": "nginx",
      "version": "1.24.0",
      "extrainfo": null,
      "cpe": ["cpe:/a:nginx:nginx:1.24.0"],
      "banner": null,
      "nmap": {"method": "probed", "conf": 10},
      "tls": {
        "version": "TLS1.3",
        "subject_cn": "portal.lab.local",
        "san": ["portal.lab.local", "www.portal.lab.local"],
        "issuer": "CN=Lab CA",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
        "self_signed": false,
        "sha256": "ab12..."
      },
      "http": [
        {
          "vhost": "portal.lab.local",
          "scheme": "https",
          "url": "https://portal.lab.local/",
          "status": 200,
          "title": "Portal AGH Lab",
          "headers": {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.1"},
          "cookies": [{"name": "wordpress_test_cookie", "value": "WP%20Cookie", "secure": true, "httponly": false, "samesite": "Lax"}],
          "redirect_chain": [],
          "final_url": "https://portal.lab.local/",
          "favicon_mmh3": "-1234567890",
          "body_sha256": "…",
          "body_snippet": "<!doctype html>…",
          "tech": [{"name": "WordPress", "version": "6.4.2", "category": "cms", "confidence": 0.9}],
          "paths": [{"path": "/wp-login.php", "status": 200, "length": 4512, "title": "Log In", "soft404": false}]
        }
      ]
    }
  ],
  "tags": ["import-demo"],
  "note": "Dodane ręcznie przez analityka"
}
```

Plik importu: `{"schema": "asi.export/v1", "generated_at": "...", "run": {...opcjonalnie...}, "observations": [ ... ]}` lub JSONL (jedna obserwacja na linię). Schemat jest opublikowany jako JSON Schema (`docs/schemas/observation.v1.json`), a walidacja zwraca błędy z dokładną ścieżką (`observations[3].services[0].port: must be 1..65535`).

### 13.3. CSV

Jeden wiersz = jedna usługa (z opcjonalnym endpointem HTTP; wiele endpointów = wiele wierszy). Separator `,`, kodowanie UTF-8, listy rozdzielane `;`:

```text
ip,hostnames,proto,port,state,service,product,version,cpe,http_scheme,http_vhost,http_status,http_title,http_server,technologies,categories,tls_subject_cn,tls_issuer,tls_not_after,cookie_names,header_names,tags,note,first_seen,last_seen,confidence,score,source
```

Import CSV wymaga minimum `ip`. `proto,port` dodają usługę, a kolumny `http_*` dodają endpoint. Nieznane kolumny są ignorowane z ostrzeżeniem.

### 13.4. Inne formaty importu (wykrywane automatycznie)

| Format | Rozpoznanie | Użycie |
|---|---|---|
| ASI JSON / JSONL | pole `schema` | podstawowy |
| ASI CSV | nagłówek z `ip` | podstawowy |
| nmap XML | `<nmaprun` | wyniki zewnętrznych skanów |
| naabu JSONL | pola `ip`,`port` | wyniki zewnętrzne |
| httpx JSONL | pola `url`,`status_code` | wyniki zewnętrzne |
| **format organizatorów** | adapter `internal/importexport/adapters/organizer.go` | **do napisania po otrzymaniu przykładu** |

### 13.5. Formularz ręczny

- **Dodaj cel(e)**: grupa, wartości (wiele linii), tagi, notatka.
- **Dodaj obserwację**: host (IP, nazwy), usługi (proto, port, usługa, produkt, wersja) i opcjonalnie dane HTTP (URL, status, tytuł, nagłówki jako pary klucz–wartość, cookies). Formularz generuje obserwację w schemacie kanonicznym i wysyła ją tym samym endpointem co import. Dane z formularza podlegają sygnaturom, diffom, edycji, eksportowi i DefectDojo jak każde inne.

### 13.6. Eksport

- Formaty: ASI JSON, JSONL, CSV. Zakres: wszystko, wynik filtra z widoku (ten sam język filtrów co w UI), jeden przebieg, diff dwóch przebiegów (lista zmian), klaster.
- Eksport zawiera **wartości efektywne** (z nadpisaniami) i opcjonalnie surowe (`include_raw=true`).
- Pola wrażliwe (wartości cookies, pełne nagłówki, fragmenty treści) są w eksporcie tylko z uprawnieniem `sensitive:read` i jawną opcją `include_sensitive=true`. Inaczej są maskowane. Każdy eksport jest audytowany (kto, jaki zakres, czy z danymi wrażliwymi).
- **Własność obiegu**: eksport ASI JSON → import do czystej instancji odtwarza encje, technologie, tagi i nadpisania (test automatyczny).

### 13.7. Ocena trafności względem wyników referencyjnych

Organizatorzy udostępnią „przykładowy zbiór wyników referencyjnych”. Moduł `eval`:
- import referencji jako przebieg `source=reference` (przez adapter);
- porównanie z wybranym przebiegiem skanera na wspólnym pokryciu: **precision / recall / F1** dla żywych hostów, par (ip, port), nazw usług, produktów, technologii i kategorii;
- raport w UI („Trafność”) i CLI `asi eval --reference <run> --candidate <run>` z listą rozbieżności;
- w labie demo rolę referencji pełni manifest `lab/expected.json` (sekcja 23), a wynik trafi na slajd.

---

## 14. Integracja z DefectDojo

### 14.1. Struktura w DefectDojo

- `Product Type`: `ASI` (konfigurowalne)
- `Product`: nazwa grupy celów (np. `ASI – Instytut_A`) albo jeden wspólny produkt (konfigurowalne)
- `Engagement`: `ASI Continuous Discovery` (typ CI/CD, bez daty końca)
- `Test`: jeden na kategorię znalezisk w grupie, typ `Generic Findings Import`, tytuł `ASI – <grupa> – <kategoria>`

Pierwsze wysłanie: `POST /api/v2/import-scan/` z `auto_create_context=true`, `product_type_name`, `product_name`, `engagement_name`, `test_title`, `scan_type="Generic Findings Import"`, `minimum_severity=Info`, `active=true`, `verified=false`. Z odpowiedzi zapisujemy `test` (id). Kolejne: `POST /api/v2/reimport-scan/` z `test=<id>`.

### 14.2. Co trafia do DefectDojo

Nie każdy otwarty port. Znalezisko powstaje, gdy:
- dopasowano sygnaturę z `export.defectdojo: true`;
- encja ma kategorię z listy eksportowej (domyślnie: `admin_panel`, `debug_exposure`, `cleartext_login`, `staging`, `eol_software`, `tls_issue` (wygasły/self-signed), `iot` z panelem);
- analityk kliknął „Wyślij do DefectDojo” na dowolnej encji (wtedy reguła = `manual:<kategoria wybrana>`).

Wyciszone encje i sygnatury nie są wysyłane.

### 14.3. Deduplikacja – ustalenia z kodu DefectDojo

Sprawdzone w kodzie DefectDojo (`dojo/settings/settings.dist.py`, `dojo/finding/models.py`, `dojo/importers/default_reimporter.py`):

1. Dla `Generic Findings Import` algorytm deduplikacji to **`hash_code`**, a nie `unique_id_from_tool`. Parser nie ma wpisu w `HASHCODE_FIELDS_PER_SCANNER`, więc działa wariant legacy: hash z `title + str(cwe) + str(line) + str(file_path) + description`.
2. Konsekwencja: **tytuł i opis muszą być w pełni deterministyczne**. Żadnych dat, liczników, wartości cookies, czasów odpowiedzi, wersji zmiennych między przebiegami. Wartości zmienne idą do pól spoza hasha (`references`, `impact`) albo w ogóle nie są wysyłane.
3. Reimport **pomija** istniejące znaleziska oznaczone jako `false_p`, `out_of_scope` lub `risk_accepted`: nie reaktywuje ich i nie tworzy duplikatu. Mechanizm „FP nie wraca przy następnym skanie” jest więc natywny dla DefectDojo i ASI z niego korzysta.
4. Pole `unique_id_from_tool` i tak wysyłamy (`dedup_key`), bo przydaje się do mapowania znalezisk przy pobieraniu statusów.
5. W konfiguracji instancji (System Settings) musi być włączona deduplikacja. Status jest sprawdzany przyciskiem „Test połączenia” (pobranie `/api/v2/system_settings/`) i wyświetlany jako ostrzeżenie.

**Format znaleziska (Generic Findings Import JSON):**

```json
{
  "findings": [
    {
      "title": "[ASI] Exposed admin panel: phpMyAdmin – 10.77.2.20:80",
      "severity": "Info",
      "description": "Kategoria: admin_panel\nSygnatura: asi-phpmyadmin (v2)\nEndpoint: http://10.77.2.20:80/phpmyadmin/\nDowody: title=\"phpMyAdmin\"; cookie_name=phpMyAdmin; path=/phpmyadmin/ status=200",
      "unique_id_from_tool": "asi:9f2c…(HMAC z ip|proto|port|vhost|rule)",
      "vuln_id_from_tool": "asi-phpmyadmin",
      "component_name": "phpMyAdmin",
      "component_version": "5.2.1",
      "references": "ASI: https://asi.local/hosts/10.77.2.20 (ostatnio widziane: 2026-11-21 22:14)",
      "endpoints": [{"protocol": "http", "host": "10.77.2.20", "port": 80, "path": "/phpmyadmin/"}],
      "tags": ["asi", "admin_panel"],
      "static_finding": false,
      "dynamic_finding": true
    }
  ]
}
```

Opis jest generowany z szablonu z polami stabilnymi w stałej kolejności. Wersja komponentu (zmienna) jest w polu `component_version` spoza hasha, a nie w opisie.

### 14.4. Reimport i przebiegi częściowe

- Reimport jest wykonywany po **zakończeniu** przebiegu (`COMPLETED`) z `close_old_findings=true`: znaleziska nieobecne w raporcie są zamykane (mitigated) przez DefectDojo.
- Dla przebiegów niepełnych (`SUPERSEDED`, `PAUSED_*` z ręcznym wysłaniem, import, formularz) reimport idzie z `close_old_findings=false`. Brak w częściowym raporcie nie oznacza, że coś zostało naprawione.
- Raport do reimportu zawiera **wszystkie aktywne** znaleziska testu (nie tylko nowe). Tak działa semantyka reimportu.
- „Wyślij do DefectDojo” na pojedynczej encji: reimport z `close_old_findings=false` do testu kategorii.
- Błędy (sieć, 4xx/5xx): retry z backoffem (3 próby), wpis w `dd_sync_log`, czerwony wskaźnik w UI, ponowienie przy następnej synchronizacji.

### 14.5. Pobieranie decyzji analityka

- Job co 15 min (demo: 1 min) i przycisk „Synchronizuj”: `GET /api/v2/findings/?test=<id>&limit=500` (paginacja) dla każdego testu ASI.
- Mapowanie po `unique_id_from_tool` (zapisujemy też `dd_finding_id`).
- Statusy: `false_p` → `false_positive`, `risk_accepted` → `risk_accepted`, `is_mitigated` → `mitigated`, `out_of_scope` → `out_of_scope`, `active` → `open`.
- Efekt w ASI: status widoczny przy encji, składnik scoringu zerowany, dashboard nie pokazuje encji w „najważniejszych znaleziskach”.
- **Źródło prawdy o statusie to DefectDojo.** Oznaczenie FP w UI ASI wysyła `PATCH /api/v2/findings/{id}/` z `{"false_p": true, "active": false}`, a następnie lokalnie zapisuje status po potwierdzeniu odpowiedzi. Przy rozbieżności wygrywa DefectDojo przy kolejnym pobraniu.

### 14.6. Ścieżka awaryjna

Jeśli import generyczny sprawi problem na instancji organizatorów, ASI może wysłać surowy XML nmapa (`scan_type="Nmap Scan"`) z danego przebiegu. DefectDojo ma natywne parsery `Nmap Scan`, `Naabu Scan`, `httpx Scan` i `Nuclei Scan`. To spełnia wymóg „narzędzi mogących integrować się z DefectDojo”, choć tworzy dużo znalezisk informacyjnych (po jednym na port).

### 14.7. Konfiguracja

URL instancji i token API (szyfrowany, sekcja 16) w panelu ADMIN, z przyciskiem „Test połączenia” (wersja, uprawnienia tokenu, status deduplikacji). Opcjonalnie z env (`ASI_DD_URL`, `ASI_DD_TOKEN`) przy pierwszym starcie.

---

## 15. RBAC, uwierzytelnianie, audyt

### 15.1. Model uprawnień (poprawka v1: role tworzalne)

Wymóg 12: „tworzenie i obsługa różnych ról”. Rola to **nazwany zbiór uprawnień** zapisany w bazie. ADMIN tworzy nowe role w UI (lista checkboxów uprawnień). Cztery role z wymogu 13 są tworzone przy pierwszym starcie (`is_system=true`).

**Uprawnienia:**

| Uprawnienie | Opis |
|---|---|
| `users:manage` | zarządzanie użytkownikami |
| `roles:manage` | tworzenie i edycja ról |
| `settings:manage` | ustawienia globalne, scope, wykluczenia, DefectDojo, klucze, workery |
| `audit:read` | podgląd audytu |
| `killswitch:use` | aktywacja wyłącznika awaryjnego |
| `targets:read` / `targets:create` / `targets:update` / `targets:delete` | cele i grupy celów |
| `config:read` / `config:create` / `config:update` / `config:delete` | profile, harmonogramy, okna |
| `scans:read` | przebiegi, zadania, postęp |
| `scans:start` | uruchomienie nowego przebiegu |
| `scans:control` | pauza, wznowienie, anulowanie istniejącego przebiegu |
| `scans:delete` | usuwanie przebiegów |
| `results:read` | inwentarz, zmiany, diff, dashboard, klastry |
| `results:update` | nadpisania, tagi, notatki, wyciszenia, potwierdzanie zmian |
| `results:create` | dodawanie obserwacji (formularz, import) |
| `results:delete` | usuwanie encji i obserwacji pochodzących z importu lub formularza |
| `signatures:read` / `signatures:create` / `signatures:update` / `signatures:delete` | sygnatury (także retro-hunting = update) |
| `export:use` | eksport JSON/CSV |
| `sensitive:read` | odsłanianie wartości wrażliwych (cookies, pełne nagłówki, treść) |
| `defectdojo:push` | wysyłanie do DefectDojo |
| `defectdojo:triage` | oznaczanie FP / risk accepted z UI ASI, synchronizacja |

**Role domyślne:**

| Uprawnienie | ADMIN (Administracja) | EDITOR (Dodawanie, usuwanie, modyfikacja) | MODIFIER (Modyfikacja i odczyt) | VIEWER (Odczyt) |
|---|:-:|:-:|:-:|:-:|
| `users:manage`, `roles:manage`, `settings:manage`, `audit:read` | ✔ | – | – | – |
| `killswitch:use` | ✔ | ✔ | – | – |
| `*:read` (targets, config, scans, results, signatures) | ✔ | ✔ | ✔ | ✔ |
| `targets:create/delete`, `config:create/delete`, `signatures:create/delete` | ✔ | ✔ | – | – |
| `targets:update`, `config:update`, `signatures:update` | ✔ | ✔ | ✔ | – |
| `scans:start`, `scans:delete` | ✔ | ✔ | – | – |
| `scans:control` | ✔ | ✔ | ✔ | – |
| `results:create`, `results:delete` (formularz, import) | ✔ | ✔ | – | – |
| `results:update` (nadpisania, tagi, notatki) | ✔ | ✔ | ✔ | – |
| `export:use` | ✔ | ✔ | ✔ | ✔ |
| `sensitive:read` | ✔ | ✔ | ✔ | – |
| `defectdojo:push` | ✔ | ✔ | – | – |
| `defectdojo:triage` | ✔ | ✔ | ✔ | – |

Uzasadnienie: „Modyfikacja” obejmuje zmianę istniejących wyników **i konfiguracji** (minimalny zakres z PDF: „edycja danych istniejących już skanów, wyników i konfiguracji”) oraz sterowanie istniejącym przebiegiem. Nie obejmuje tworzenia i usuwania. VIEWER widzi wszystko poza danymi wrażliwymi i może eksportować (wersja zamaskowana).

### 15.2. Egzekwowanie

- Każdy endpoint API deklaruje wymagane uprawnienie w tablicy routingu (`r.With(rbac.Require("targets:create")).Post(...)`). Brak deklaracji = test jednostkowy nie przechodzi (wszystkie trasy muszą mieć wymaganie lub jawne `rbac.Public`).
- UI pobiera `/api/v1/auth/me` (lista uprawnień) i ukrywa lub dezaktywuje akcje. To tylko wygoda: **źródłem egzekwowania jest API**.
- Odmowa = `403` z kodem `forbidden` i nazwą brakującego uprawnienia, wpis w audycie.
- Maskowanie pól wrażliwych w serializerze odpowiedzi zależy od `sensitive:read`.
- ADMIN nie może odebrać sobie ostatniej roli z `users:manage` (ochrona przed zablokowaniem systemu).

### 15.3. Uwierzytelnianie

- Konta lokalne. Hasła: **argon2id** (m=64 MiB, t=3, p=2), min. 12 znaków.
- Sesja: losowy token 32 B w cookie `asi_session` (`HttpOnly`, `Secure`, `SameSite=Strict`), w bazie tylko SHA-256 tokenu. Wygasa po 8 h, po 30 min bezczynności.
- CSRF: token w osobnym cookie i nagłówek `X-CSRF-Token` dla metod modyfikujących (double submit + porównanie z hashem w sesji).
- Blokada po 5 nieudanych logowaniach na 15 min, limit tempa na `/auth/login`.
- Nagłówki bezpieczeństwa UI: CSP (`default-src 'self'`), HSTS (przy TLS), `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`.
- Workery: token per worker (`asi_wk_…`), w bazie argon2id hash, nagłówek `Authorization: Bearer`. Tokeny generuje ADMIN w panelu workerów lub z env przy bootstrapie.
- Przyszłość (poza zakresem prototypu): OIDC/LDAP uczelni.

### 15.4. Audyt

Zdarzenia audytowane: logowanie (udane i nieudane), wylogowanie, zmiany użytkowników i ról, ustawień, scope, wykluczeń, kill switch, CRUD celów, konfiguracji i sygnatur, start, pauza i anulowanie przebiegów, importy, eksporty (z informacją o danych wrażliwych), nadpisania, wysyłki i triage DefectDojo, rotacja kluczy, operacje workerów (rejestracja, odrzucone cele spoza scope). Widok audytu z filtrami (`audit:read`).

---

## 16. Szyfrowanie danych w spoczynku

### 16.1. Klasyfikacja danych

PostgreSQL w wersji community nie ma natywnego TDE. Dlatego stosujemy **szyfrowanie na poziomie pól w aplikacji** (AES-256-GCM), które chroni dane także przed administratorem bazy i w kopiach zapasowych.

| Klasa | Przykłady | Ochrona | Uzasadnienie |
|---|---|---|---|
| **Sekrety** | token API DefectDojo, klucze danych | AES-256-GCM (kluczem głównym / danych) | ujawnienie = przejęcie integracji |
| **Uwierzytelnienie** | hasła, tokeny sesji i workerów | argon2id / SHA-256 (jednokierunkowo) | nie muszą być odszyfrowywane |
| **Surowe dowody** | pełne nagłówki, wartości cookies, fragmenty treści, banery, pełne certyfikaty, wyniki skryptów, łańcuchy przekierowań, wyniki ścieżek | AES-256-GCM (`*_raw_enc`) | mogą zawierać tokeny sesji, dane osobowe, informacje wewnętrzne |
| **Treści analityków** | notatki, opisy z formularza | AES-256-GCM (`*_enc`) | swobodny tekst, możliwe dane wrażliwe |
| **Wartości porównawcze** | odciski `stable_fp`, `body_sha256_hmac`, `value_hmac` cookies, klucz klastra | HMAC-SHA256 (osobny klucz) | porównywanie bez ujawniania wartości, odporność na ataki słownikowe |
| **Metadane indeksowane** | IP, port, protokół, stan, nazwa usługi, produkt, wersja, CPE, technologie, kategorie, tytuł, nazwy nagłówków i cookies, daty | jawne w bazie + szyfrowanie wolumenu (zalecane wdrożeniowo) | potrzebne do filtrowania, sortowania, zapytań zakresowych (CIDR) |

Decyzja o jawności metadanych jest świadomym kompromisem: zapytania typu „wszystkie hosty w `10.77.0.0/16` z WordPress < 6” wymagają jawnych kolumn. W dokumentacji wdrożeniowej zalecamy dodatkowo szyfrowanie wolumenu (LUKS) i szyfrowane kopie zapasowe (`pg_dump | age`).

### 16.2. Schemat kluczy

- **Klucz główny (KEK)**: 32 B z `ASI_MASTER_KEY` (base64) lub `ASI_MASTER_KEY_FILE` (Docker secret). Nigdy w repozytorium ani w bazie. Brak klucza = serwer nie startuje.
- **Klucze danych (DEK)**: losowe 32 B, w tabeli `encryption_keys` zaszyfrowane KEK-iem (AES-256-GCM). Dwa cele: `data` (szyfrowanie) i `hmac` (odciski). Jeden aktywny klucz na cel.
- **Format szyfrogramu**: `0x01 | key_id (4 B) | nonce (12 B, losowy przy każdym szyfrowaniu) | ciphertext | tag (16 B)`.
- **AAD** (dane uwierzytelniane): `"<tabela>.<kolumna>:<klucz naturalny lub id wiersza>"`. Szyfrogramu nie da się przenieść do innego wiersza ani kolumny bez wykrycia.
- **Rotacja**: `asi keys rotate` tworzy nowy aktywny DEK. Nowe zapisy używają nowego klucza, a zadanie tła przeszyfrowuje stare rekordy partiami. Stary klucz jest wycofywany po zakończeniu. Rotacja KEK: przeszyfrowanie samych DEK.
- Implementacja: `crypto/aes` + `crypto/cipher` (GCM) ze standardowej biblioteki Go, typ `EncryptedBytes` z metodami `Scan`/`Value` dla pgx.

### 16.3. Demonstracja

W demo: `psql -c "select raw_enc from http_endpoints limit 1"` pokazuje szyfrogram, a UI (z `sensitive:read`) pokazuje odszyfrowane nagłówki. VIEWER widzi wartości zamaskowane.

---

## 17. API REST

Prefiks `/api/v1`, JSON, błędy w formacie `{"error": {"code": "...", "message": "...", "details": {...}}}`, paginacja kursorowa (`?limit=&cursor=`), filtrowanie przez parametr `q` (język filtrów, np. `state:active tech:wordpress score>50 cidr:10.77.1.0/24 tag:prod`). W nawiasach wymagane uprawnienie.

**Auth i administracja**
- `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` (publiczne / zalogowany)
- `GET|POST /users`, `GET|PATCH|DELETE /users/{id}` (`users:manage`)
- `GET /permissions`, `GET|POST /roles`, `PATCH|DELETE /roles/{id}` (`roles:manage`)
- `GET|PATCH /settings`, `GET|POST|DELETE /scope`, `GET|POST|DELETE /exclusions` (`settings:manage`)
- `GET|POST /workers`, `DELETE /workers/{id}`, `POST /workers/{id}/token` (`settings:manage`)
- `GET /audit` (`audit:read`)
- `GET /killswitch` (`scans:read`), `POST /killswitch` `{active, reason}` (`killswitch:use`)
- `POST /keys/rotate` (`settings:manage`)

**Cele i konfiguracja**
- `GET|POST /target-groups`, `GET|PATCH|DELETE /target-groups/{id}`
- `GET|POST /targets`, `PATCH|DELETE /targets/{id}`, `POST /targets/import` (multipart: CSV/JSON/TXT) (`targets:*`)
- `GET|POST /profiles`, `PATCH|DELETE /profiles/{id}`
- `GET|POST /schedules`, `PATCH|DELETE /schedules/{id}`, `GET /schedules/{id}/estimate`
- `GET|POST /windows`, `PATCH|DELETE /windows/{id}` (`config:*`)
- `POST /estimate` (estymacja dla dowolnej grupy i profilu bez zapisu) (`config:read`)

**Przebiegi**
- `GET /runs`, `GET /runs/{id}`, `GET /runs/{id}/tasks`, `GET /runs/{id}/coverage` (`scans:read`)
- `POST /runs` `{group_id, profile_id?, mode, targets?: [...]}` (`scans:start`)
- `POST /runs/{id}/pause|resume|cancel` (`scans:control`), `DELETE /runs/{id}` (`scans:delete`)
- `GET /runs/{a}/diff/{b}?types=&q=` (`results:read`)
- `GET /events` – Server-Sent Events: postęp przebiegów, nowe zmiany, stan workerów (`scans:read`)

**Wyniki**
- `GET /dashboard` (KPI, aktywne przebiegi, top zmiany i znaleziska, wykresy) (`results:read`)
- `GET /hosts`, `GET /hosts/{ip}`, `GET /hosts/{ip}/timeline`, `GET /hosts/{ip}/observations`
- `GET /services`, `GET /services/{key}`, `GET /http-endpoints`, `GET /http-endpoints/{key}`
- `GET /changes?since=&type=&q=`, `POST /changes/{id}/ack` (`results:update`)
- `GET /clusters`, `GET /clusters/{key}`
- `PUT /overrides/{entity_type}/{key}/{field}`, `DELETE ...` (`results:update`)
- `GET|POST /tags`, `POST|DELETE /entities/{type}/{key}/tags` (`results:update`)
- `GET|POST /entities/{type}/{key}/notes`, `PATCH|DELETE /notes/{id}` (`results:update`)
- `GET|POST /suppressions`, `DELETE /suppressions/{id}` (`results:update`)
- `GET /entities/{type}/{key}/raw` (`sensitive:read`)

**Import, eksport, ocena**
- `POST /import/observations` (multipart lub JSON; `?dry_run=true` = tylko walidacja) (`results:create`)
- `POST /observations` (pojedyncza obserwacja z formularza) (`results:create`)
- `GET /imports`, `GET /imports/{id}` (`results:read`)
- `GET /export?format=json|jsonl|csv&scope=all|filter|run|diff|cluster&q=&include_raw=&include_sensitive=` (`export:use`, + `sensitive:read` dla danych wrażliwych)
- `POST /eval` `{reference_run_id, candidate_run_id}` (`results:read`)

**Sygnatury**
- `GET|POST /signatures`, `GET|PATCH|DELETE /signatures/{id}` (`signatures:*`)
- `POST /signatures/validate`, `POST /signatures/test` `{signature, entity_type, entity_key}` (`signatures:read`)
- `POST /signatures/{id}/retrohunt` (`signatures:update`), `POST /signatures/import`, `GET /signatures/export`

**DefectDojo**
- `GET /findings?status=&q=` (`results:read`)
- `POST /findings/push` `{entity keys | finding ids}` (`defectdojo:push`)
- `POST /findings/{id}/triage` `{status: false_positive|risk_accepted|open}` (`defectdojo:triage`)
- `POST /defectdojo/sync`, `GET /defectdojo/status` (`defectdojo:triage` / `results:read`)
- `POST /defectdojo/test` (`settings:manage`)

**Worker API** (`/worker/v1`, Bearer token workera)
- `POST /hello` (rejestracja zdolności i wersji narzędzi)
- `POST /lease` → zadanie lub `204`
- `POST /tasks/{id}/heartbeat` → `{command: continue|cancel|throttle, rate_pps?}`
- `POST /tasks/{id}/complete` (wyniki w formacie kanonicznym + pokrycie + statystyki, gzip)
- `POST /tasks/{id}/fail` `{error, retryable}`

Specyfikacja OpenAPI 3.1 generowana do `docs/openapi.yaml` i serwowana pod `/api/docs`.

---

## 18. Interfejs użytkownika

React 18 + TypeScript + Vite + Tailwind CSS, TanStack Query (dane), TanStack Table (tabele z wirtualizacją dla dziesiątek tysięcy wierszy), Recharts (wykresy). Ciemny i jasny motyw, język polski (teksty w jednym pliku, łatwe tłumaczenie). Budowane statycznie i osadzane w binarce Go (`embed`).

### 18.1. Widoki

1. **Logowanie.**
2. **Dashboard (delta-first)**
   - Karty KPI: aktywne hosty, aktywne usługi, nowe od ostatniego przebiegu, zniknięte (INACTIVE w ostatnich 7 dniach), niestabilne (FLAPPING), okresowe, otwarte znaleziska wg kategorii, certyfikaty wygasające < 30 dni.
   - Aktywne przebiegi: pasek postępu (adresy z kursora + zadania probe), bieżące tempo pps/rps vs budżet, ETA i ETA kalendarzowe, okno (czas do końca), przyciski pauza/wznów/anuluj (wg uprawnień).
   - **„Najważniejsze zmiany i znaleziska”**: lista sortowana po priorytecie, z rozbiciem punktów i szybkimi akcjami (otwórz, wycisz, wyślij do DefectDojo, potwierdź).
   - Wykres: liczba aktywnych hostów i usług w czasie (po przebiegach), słupki zmian (new/gone/changed) per przebieg.
   - Top klastry (największe grupy podobnych usług).
   - Status DefectDojo (ostatnia synchronizacja) i workerów.
3. **Inwentarz**: zakładki Hosty / Usługi / Web / Technologie. Pasek filtrów (język `q` z podpowiedziami), zapisane widoki, kolumny konfigurowalne, eksport bieżącego widoku, akcje grupowe (tag, wycisz, wyślij do DefectDojo).
4. **Szczegóły hosta**
   - nagłówek: IP, nazwy, stan, etykiety (FLAPPING, PERIODIC), wynik, tagi;
   - **oś czasu dostępności** (pasek po przebiegach) i **mapa cieplna 7×24**;
   - usługi i endpointy z technologiami, kategoriami i pewnością (tooltip „dlaczego” z dowodami);
   - panel **„Dane skanera | Wartość efektywna”** z edycją pól, ikoną konfliktu i historią nadpisań;
   - surowe dane (za `sensitive:read`, przycisk „Pokaż”);
   - historia zmian encji, notatki, znaleziska i statusy DefectDojo, przycisk „Wyślij do DefectDojo”, „Zmierz ponownie” (retry).
5. **Zmiany**: strumień zdarzeń z filtrami (typ, priorytet, grupa, czas), potwierdzanie.
6. **Porównanie przebiegów (Diff Viewer)**: wybór Run A i Run B (tej samej grupy), informacja o wspólnym pokryciu („porównano 12 288 adresów × 1000 portów; 4 096 adresów pominięto – brak w A”), filtry `ADDED` / `REMOVED` / `CHANGED`, widok pola przed i po.
7. **Klastry**: lista z licznością, podgląd (favicona, tytuł, technologie), członkowie, odstający.
8. **Skany**
   - przebiegi: lista, szczegóły z siatką zadań (kolor = status), wykres tempa, logi zadań i błędy;
   - grupy celów i cele: formularz dodawania (wiele linii), import pliku z raportem walidacji;
   - profile: edytor (porty, sondy, etapy, intensywność, ścieżki probera);
   - harmonogramy i okna: edytor tygodniowy (siatka dni × godzin), CRON z podglądem najbliższych uruchomień, **estymacja z ostrzeżeniem**.
9. **Sygnatury**: lista (wbudowane, użytkownika, zaimportowane; włącz/wyłącz), edytor YAML z podświetlaniem składni i walidacją na żywo, „Testuj na encji”, „Uruchom na historii”, historia wersji, import i eksport.
10. **Znaleziska / DefectDojo**: lista znalezisk ze statusami, filtr, akcje triage, log synchronizacji.
11. **Import / Eksport**: kreator importu obserwacji (wybór pliku, wykryty format, dry run z podglądem błędów, zatwierdzenie), formularz ręcznej obserwacji, eksport z wyborem zakresu i formatu, raport trafności (eval).
12. **Administracja**: użytkownicy, role (edytor checkboxów uprawnień), scope i wykluczenia, DefectDojo, klucze (rotacja), workery (tokeny, stan, zdolności, ostrzeżenie o trybie connect), audyt, **kill switch** (czerwony przycisk widoczny też w nagłówku dla uprawnionych).

### 18.2. Zachowanie zależne od roli

Elementy wymagające brakującego uprawnienia są ukryte (nawigacja) lub nieaktywne z podpowiedzią („Wymaga uprawnienia: targets:create”). Pola wrażliwe są pokazane jako `••••` z ikoną kłódki. W nagłówku widać nazwę roli zalogowanego użytkownika.

---

## 19. Konfiguracja

### 19.1. Zmienne środowiskowe

| Zmienna | Domyślnie | Opis |
|---|---|---|
| `ASI_DATABASE_URL` | – | DSN PostgreSQL (tylko serwer) |
| `ASI_MASTER_KEY` / `ASI_MASTER_KEY_FILE` | – | klucz główny 32 B base64 (tylko serwer) |
| `ASI_LISTEN` | `:8080` | adres nasłuchu |
| `ASI_BASE_URL` | `http://localhost:8080` | używany w linkach (np. w DefectDojo) |
| `ASI_TLS_CERT` / `ASI_TLS_KEY` | – | opcjonalny TLS |
| `ASI_TZ` | `Europe/Warsaw` | domyślna strefa grup |
| `ASI_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | – | pierwszy administrator |
| `ASI_SEED_DEMO_USERS` | `false` | tworzy użytkowników demo dla 4 ról |
| `ASI_DEMO_MODE` | `false` | skrócone progi (tabela niżej) |
| `ASI_GLOBAL_MAX_PPS` | `2000` | globalny sufit pakietów/s |
| `ASI_SCANNER_CONTACT` | `cbi@agh.edu.pl` | kontakt w User-Agent |
| `ASI_DD_URL` / `ASI_DD_TOKEN` | – | bootstrap integracji z DefectDojo |
| `ASI_WORKER_BOOTSTRAP_TOKENS` | – | lista `nazwa:token` tworzona przy starcie (compose) |
| `ASI_SERVER_URL` | – | (worker) adres serwera |
| `ASI_WORKER_TOKEN` / `ASI_WORKER_NAME` | – | (worker) uwierzytelnienie |
| `ASI_WORKER_MAX_NMAP` | `4` | (worker) równoległe procesy nmap |
| `ASI_LOG_LEVEL` | `info` | poziom logów (JSON, `slog`) |

### 19.2. Tryb demo

| Parametr | Produkcja | Demo |
|---|---|---|
| $K$ / $K_{\text{ephemeral}}$ | 3 / 1 | 2 / 1 |
| $T_{\min}$ nieaktywności | 72 h | 0 |
| Retry w przebiegu | 2 min, 10 min | 20 s, 60 s |
| $M$ (flapping), min. obserwacji | 10, 4 | 5, 3 |
| $T_{\text{target}}$ zadania | 60 s | 15 s |
| Synchronizacja DefectDojo | 15 min | 1 min |

---

## 20. Uruchomienie i wdrożenie

### 20.1. Jedno polecenie

```bash
cp .env.example .env && make keygen >> .env
docker compose up -d --build
```

UI: `http://localhost:8080`. Login z `.env` (`ASI_BOOTSTRAP_ADMIN_*`).

### 20.2. Usługi `docker-compose.yml`

| Usługa | Obraz | Uwagi |
|---|---|---|
| `postgres` | `postgres:16-alpine` | wolumen `pgdata`, healthcheck |
| `server` | `Dockerfile` target `server` (distroless) | migracje przy starcie, UI osadzone |
| `worker` | `Dockerfile` target `worker` (debian-slim + nmap, naabu, httpx, dnsx, nuclei, libpcap) | `cap_add: [NET_RAW, NET_ADMIN]`, skalowanie `--scale worker=N`, użytkownik nie-root z capabilities na binarkach (`setcap`) |

**Profile compose:**
- `lab`: środowisko testowe z sekcji 23 (`docker compose --profile lab up`). Workery podpięte do sieci `asi-lab`.
- `dojo`: lokalny DefectDojo (oficjalne obrazy `defectdojo/defectdojo-django` i `defectdojo/defectdojo-nginx` z przypiętą wersją, własny postgres i valkey, initializer z kontem admin i tokenem API zapisywanym do pliku wczytywanego przez `server`). Alternatywnie zewnętrzna instancja (organizatorów lub `demo.defectdojo.org`) przez `ASI_DD_URL`.

### 20.3. Uwagi sieciowe

- Worker skanuje z sieci, do której jest podpięty. W labie organizatorów trzeba podpiąć go do ich sieci Docker (`networks: external`) albo użyć `network_mode: host`. Plik `compose.override.example.yml` pokazuje oba warianty.
- Bez `NET_RAW` naabu przechodzi na connect scan, a nmap `-sn` nie użyje ARP ani ICMP. Worker raportuje to przy `hello`, a UI pokazuje ostrzeżenie.
- Wersje narzędzi są przypięte w `Dockerfile` (argumenty `NMAP_VERSION`, `NAABU_VERSION`, `HTTPX_VERSION`, `DNSX_VERSION`, `NUCLEI_VERSION`). Szablony nuclei są pobierane w czasie budowania obrazu (bez aktualizacji w runtime).

### 20.4. Uruchomienie bez Dockera (development)

`make dev`: postgres w kontenerze, `go run ./cmd/asi server`, `npm run dev` w `web/` (proxy do API), worker `sudo go run ./cmd/asi worker` lub z capabilities.

---

## 21. Struktura repozytorium

```text
asi/
├── cmd/asi/main.go                # subkomendy: server, worker, migrate, seed, keygen, keys, eval, sig
├── internal/
│   ├── config/                    # wczytywanie env, walidacja
│   ├── db/                        # pgx pool, transakcje, migracje (goose, embed)
│   │   └── migrations/*.sql
│   ├── crypto/                    # KEK/DEK, AES-GCM, HMAC, EncryptedBytes, rotacja
│   ├── auth/                      # argon2id, sesje, CSRF, rate limit logowania
│   ├── rbac/                      # uprawnienia, role domyślne, middleware Require
│   ├── audit/
│   ├── scope/                     # allowlista, wykluczenia, normalizacja celów, kursor IP
│   ├── api/                       # router chi, handlery, serializacja, maskowanie, SSE, OpenAPI
│   ├── workerapi/                 # API dla workerów
│   ├── scheduler/                 # cron, okna (strefy, DST, północ), polityka nakładania
│   ├── dispatcher/                # leasing, cięcie zadań, budżet, kill switch, retry
│   ├── estimator/                 # EWMA prędkości, ETA, ETA kalendarzowe
│   ├── worker/                    # pętla workera, heartbeat, uruchamianie narzędzi, kontrola uprawnień
│   ├── tools/                     # wrappery i parsery
│   │   ├── nmap/  naabu/  httpx/  dnsx/  nuclei/
│   │   └── */testdata/            # zapisane próbki wyjścia
│   ├── prober/                    # prober HTTP: soft-404, ścieżki, sygnatury aktywne
│   ├── observation/               # schemat kanoniczny, walidacja, stable_fp
│   ├── ingest/                    # zapis obserwacji, aktualizacja encji, pokrycie
│   ├── state/                     # automat stanowy, flapping, okresowość, nieaktywność
│   ├── diff/                      # diff przebiegów na pokryciu, strumień zmian
│   ├── signatures/                # parser, walidator, silnik, retro-hunting
│   │   └── adapters/              # nuclei, organizatorzy
│   ├── classify/                  # kategorie, pewność (noisy-OR), EOL
│   ├── scoring/                   # ciekawość
│   ├── cluster/                   # klucze klastrów
│   ├── overlay/                   # nadpisania, widok efektywny, konflikty
│   ├── importexport/              # JSON/JSONL/CSV, nmap XML, naabu, httpx, adaptery
│   ├── eval/                      # precision/recall względem referencji
│   └── defectdojo/                # klient API v2, mapowanie, reimport, sync
├── signatures/builtin/            # wbudowany pakiet sygnatur YAML + eol.yaml + favicons.yaml
├── web/                           # React + Vite + Tailwind
├── deploy/
│   ├── Dockerfile                 # multi-stage: web-build, go-build, server, worker
│   └── dojo/                      # konfiguracja profilu DefectDojo
├── lab/                           # środowisko testowe (sekcja 23)
├── docs/
│   ├── DOKUMENTACJA.md            # ten dokument
│   ├── openapi.yaml
│   ├── schemas/observation.v1.json
│   ├── SYGNATURY.md               # przewodnik pisania sygnatur
│   └── DEMO.md                    # scenariusz demo
├── scripts/                       # e2e, seed historii, pomocnicze
├── docker-compose.yml
├── compose.override.example.yml
├── .env.example
├── Makefile
└── README.md
```

Biblioteki Go: `go-chi/chi/v5`, `jackc/pgx/v5`, `pressly/goose/v3`, `robfig/cron/v3`, `golang.org/x/crypto/argon2`, `gopkg.in/yaml.v3`, `santhosh-tekuri/jsonschema/v6`, `hashicorp/go-version`, `stretchr/testify`. Logi: `log/slog`.

---

## 22. Strategia testów

| Poziom | Zakres |
|---|---|
| Jednostkowe | parsery narzędzi (na `testdata`), normalizacja celów i kursor, cięcie zadań i budżet, okna (północ, DST), estymacja, automat stanowy (tablice scenariuszy), flapping i okresowość, diff na pokryciu, stable_fp (odporność na zmienne pola), silnik i walidator sygnatur (w tym odrzucanie niebezpiecznych), noisy-OR, scoring, crypto (szyfrowanie, AAD, rotacja), mapowanie DefectDojo (determinizm opisu) |
| **Macierz RBAC** | test tablicowy: każda trasa API × każda rola domyślna → oczekiwany kod (200/201/204 vs 403). Generowany z tablicy routingu, więc nowa trasa bez wpisu nie przejdzie testu. Wynik eksportowany jako tabela do dokumentacji. |
| Integracyjne | PostgreSQL w kontenerze (`make test-integration`): ingest, overlay i konflikty, import/eksport w obie strony (własność obiegu), retro-hunting |
| DefectDojo | testy z atrapą HTTP (zapisane odpowiedzi API) + test ręczny lub opcjonalny na profilu `dojo`: import → reimport bez duplikatów → FP → reimport bez reaktywacji |
| E2E (lab) | `scripts/e2e.sh`: `compose --profile lab up`, przebieg 1, `lab/scenario.sh step2`, przebieg 2, asercje na zmianach i stanie, `asi eval` względem `lab/expected.json` z progami (np. recall hostów = 1,0, recall usług ≥ 0,95) |
| Frontend | testy komponentów kluczowych (filtr, edytor nadpisań) w Vitest, smoke test Playwright: logowanie każdą rolą i sprawdzenie widoczności akcji |

---

## 23. Środowisko laboratoryjne i demo

Celem jest możliwość testowania od pierwszej godziny, bez czekania na lab organizatorów, oraz powtarzalne demo.

### 23.1. Sieć

- Sieć Docker `asi-lab`: **`10.77.0.0/16`** (65 536 adresów). Usługi rozrzucone po różnych `/24`. Skan całego `/16` demonstruje obsługę >10 000 adresów: adaptacyjny podział, estymację, discovery, pauzę i wznowienie, a zdecydowana większość adresów jest pusta, jak w prawdziwej sieci.
- DNS labu: `dnsmasq` pod `10.77.0.53` ze strefą `lab.local`. Workery używają go jako resolvera.

### 23.2. Hosty labu

Uniwersalny obraz **`labweb`** (mały serwer Go) emuluje produkty na podstawie pliku profilu YAML: status, tytuł, nagłówki, cookies, favicona, treści ścieżek, catch-all (SPA), vhosty, TLS (w tym wygasły), banery TCP (tryb `tcp-banner`). Dzięki temu lab jest lekki, a obok są prawdziwe aplikacje dla wiarygodności.

| IP | Nazwa (DNS) | Co to jest | Co testuje |
|---|---|---|---|
| 10.77.1.10 | `blog.lab.local` | WordPress (prawdziwy) + MariaDB (wewn.) | CMS, wersja z `generator`, cookie, panel `/wp-login.php` |
| 10.77.1.11 | – | MariaDB 3306 wystawiona | identyfikacja usług innych niż HTTP |
| 10.77.1.20 | `wydzial.lab.local` | Drupal (prawdziwy) | CMS (`X-Generator`), `/user/login` |
| 10.77.1.30 | `moodle.lab.local` | `labweb`: Moodle | CMS, cookie `MoodleSession` |
| 10.77.2.10 | `grafana.lab.local` | Grafana (prawdziwa) | panel admina, framework |
| 10.77.2.20 | – | phpMyAdmin (prawdziwy) | panel admina, cookie `phpMyAdmin` |
| 10.77.2.30 | – | Tomcat 8080 (prawdziwy) | serwer aplikacyjny, strona domyślna, `/manager/html` (401) |
| 10.77.2.40 | `jenkins.lab.local` | `labweb`: Jenkins (`X-Jenkins`) | panel admina na porcie 8081 (niestandardowy) |
| 10.77.3.10 | `staging.lab.local` | `labweb`: staging (tytuł „Portal – STAGING”, `X-Environment: staging`, robots `Disallow: /`) | wykrywanie staging (vhost, tytuł, nagłówek, SAN) |
| 10.77.3.20 | `portal.lab.local`, `intranet.lab.local` | nginx z vhostami: różna treść zależnie od `Host`; na IP strona domyślna nginx | vhosty, strona domyślna |
| 10.77.3.30 | `spa.lab.local` | `labweb`: SPA catch-all (200 na każdą ścieżkę) | **kontrola soft-404** (brak fałszywego `/admin`) |
| 10.77.3.40 | `old.lab.local` | `labweb`: HTTPS 8443, certyfikat **wygasły** i self-signed, `X-Powered-By: PHP/5.6.40`, cookie `laravel_session` bez `Secure`, `X-Debug-Token`, formularz logowania na HTTP 80 | TLS, EOL, framework, cookies, debug, cleartext login |
| 10.77.4.10 | – | `labweb`: kamera IP (`Server: GoAhead-Webs`, tytuł „Network Camera”), baner RTSP 554, telnet 23 „BusyBox” | IoT |
| 10.77.4.20 | – | `labweb`: drukarka HP (tytuł „HP LaserJet MFP”), IPP 631, port 9100 | IoT, pomijanie 9100 w `-sV` |
| 10.77.4.30 | – | `labweb`: router MikroTik (tytuł „RouterOS router configuration page”), port 8291 | IoT / urządzenie sieciowe |
| 10.77.4.31–.35 | – | 5× `labweb`: drukarka HP (jedna z inną wersją firmware) | **grupowanie podobnych usług**, odstający |
| 10.77.5.10 | `ssh.lab.local` | OpenSSH (prawdziwy, wersja A) | usługa, wersja; w kroku 2 aktualizacja → `SERVICE_CHANGED` |
| 10.77.5.20 | `ftp.lab.local` | vsftpd + Redis 6379 | usługi; w kroku 2 FTP wyłączony → `SERVICE_GONE` (po K) |
| 10.77.6.10 | – | **flapper**: kontener przełączany przez skrypt scenariusza (lub losowo co N minut) | FLAPPING, retry, `recovered_on_retry` |
| 10.77.6.20 | – | host bez otwartych portów (odpowiada RST) | **discovery bez otwartych portów** |
| 10.77.6.30 | – | host DROP-ujący wszystko (iptables) | wykrycie tylko przez ARP w L2; dokumentuje ograniczenia |
| 10.77.7.10 | `nowy.lab.local` | `labweb`: Kibana, **pojawia się dopiero w kroku 2** | `HOST_NEW`, `SERVICE_NEW` |
| 10.77.8.0/24 | – | 20× `labweb` „stacja robocza” z RDP/SMB-podobnym banerem | wolumen, klastry |

### 23.3. Manifest prawdy

`lab/expected.json` (w schemacie `asi.observation/v1`) opisuje oczekiwany stan każdego kroku: hosty, porty, usługi, technologie, kategorie i oczekiwane zmiany między krokami. Służy jako referencja dla `asi eval` i asercji E2E.

### 23.4. Scenariusz zmian

`lab/scenario.sh <krok>`:
- `step1` (baseline): wszystko poza 10.77.7.10, flapper włączony;
- `step2`: wyłącz FTP (10.77.5.20:21), uruchom 10.77.7.10 (nowy host), podmień obraz SSH na nowszą wersję, zmień tytuł na `staging.lab.local`, zrotuj certyfikat `portal.lab.local`, wyłącz flappera, dodaj nowy port 8080 na 10.77.2.20;
- `step3`: włącz flappera, FTP dalej wyłączony (→ `INACTIVE` po K=2), przywróć tytuł staging;
- `reset`.

`scripts/seed-history.sh` importuje (przez **zwykły pipeline importu JSON**) syntetyczną historię 14 dni dla kilku hostów: komputer laboratoryjny aktywny 8–18 w dni robocze (→ `PERIODIC`), host losowo niestabilny (→ `FLAPPING`), host efemeryczny widziany raz. Wykresy dostępności i etykiety są widoczne bez czekania dwóch tygodni. Przy okazji demonstruje to import JSON.

### 23.5. Użytkownicy demo

`ASI_SEED_DEMO_USERS=true` tworzy `admin@lab`, `editor@lab`, `modifier@lab`, `viewer@lab` (hasła w `.env.example`).

### 23.6. Scenariusz demo (prezentacja do 10 slajdów)

1. **Problem i architektura**: trzy warstwy (DefectDojo ⇄ ASI ⇄ skanery open source), różnice względem SecureCodeBox (bez Kubernetesa, analiza zmian w czasie, okna i budżet ruchu, overlay, RBAC z szyfrowaniem).
2. **Bezpieczeństwo skanera**: scope, wykluczenia, globalny budżet, allowlista skryptów, soft-404, kill switch, User-Agent, audyt.
3. **Demo na żywo, skala**: import celu `10.77.0.0/16` → estymacja i ostrzeżenie okna → start z 3 workerami (`--scale worker=3`) → siatka zadań, tempo vs budżet.
4. **Demo na żywo, okno czasowe**: krótkie okno kończy się → `PAUSED_WINDOW` → okno się otwiera → wznowienie od kursora.
5. **Demo na żywo, wyniki**: dashboard, host WordPress (technologie z pewnością i dowodami), klaster drukarek, staging, SPA bez fałszywego `/admin`.
6. **Demo na żywo, zmiany**: `scenario.sh step2` → przebieg 2 (differential) → strumień zmian i diff viewer (NEW, GONE, CHANGED na wspólnym pokryciu).
7. **Demo na żywo, niestabilne hosty**: flapper z `recovered_on_retry`, mapa cieplna `PERIODIC` z zaseedowanej historii, reguła nieaktywności.
8. **Demo na żywo, sygnatury i DefectDojo**: nowa sygnatura w edytorze → test → retro-hunting bez skanu → wysłanie do DefectDojo → oznaczenie FP w DefectDojo → przebieg 3 → FP nie wraca, a znaleziska nie są zduplikowane.
9. **Demo na żywo, RBAC, overlay i szyfrowanie**: edycja produktu przez MODIFIER → przebieg nie nadpisuje, konflikt widoczny; VIEWER → 403 i maskowanie; `psql` z szyfrogramem; import CSV i eksport JSON.
10. **Wyniki i dalszy rozwój**: trafność (precision/recall z `asi eval`), czasy, macierz RBAC, plan wdrożenia w CBI AGH (OIDC, pasywne źródła danych, kolejne punkty widzenia sieci).

---

## 24. Odpowiedzi na pytania z treści zadania

**„W jaki sposób raportować zmianę?”**
Na dwóch poziomach (sekcja 6). (1) Diff dowolnych dwóch przebiegów, liczony **tylko na wspólnym pokryciu**, żeby przebieg częściowy lub z innym zestawem portów nie fałszował wyniku. (2) Strumień zdarzeń filtrowany automatem stanowym: „zniknięcie” jest raportowane dopiero po potwierdzeniu (`INACTIVE`), a nie po jednym braku odpowiedzi. Porównywane są wyłącznie pola stabilne (bez dat, tokenów i wartości sesji). Każde zdarzenie ma typ, listę zmienionych pól (stara i nowa wartość) i priorytet. Zdarzenia hostów niestabilnych są grupowane, nie mnożone.

**„Jak określić pewność wyniku identyfikacji technologii?”**
Wagi dowodów łączone noisy-OR, $c = 1 - \prod(1 - w_i)$, skorygowane o stabilność w czasie i karę za pomiar „dopiero za drugim razem” (sekcja 8.3). Dowód słaby (np. nazwa usługi zgadnięta przez nmapa z numeru portu, `method=table`) daje niską pewność, a kilka niezależnych dowodów (nagłówek + favicona + ścieżka) – wysoką. Pewność produktu i wersji liczona jest osobno. UI pokazuje listę dowodów.

**„Po jakim czasie braku odpowiedzi w sukcesywnych skanach raportować host jako nieaktywny?”**
Gdy jednocześnie: (1) brak odpowiedzi w $K$ kolejnych przebiegach, które ten host faktycznie obejmowały, po wyczerpaniu retry w każdym z nich ($K=3$; dla hostów widzianych tylko 1–2 razy $K=1$); (2) od ostatniej odpowiedzi minęło $T_{\min}$ (72 h; dla efemerycznych 24 h); (3) braki objęły porę dnia, w której host był dotąd aktywny. Host aktywny tylko w dzień (`PERIODIC`) nie zostanie uznany za nieaktywny przez skany nocne. Progi są konfigurowalne (sekcja 7.5).

---

## 25. Macierz zgodności z wymaganiami

### 25.1. Wymagania z sekcji „Wyzwanie” (1–16)

| # | Wymaganie | Realizacja (sekcja) |
|---|---|---|
| 1 | Wczytanie IP, CIDR, domen | 3.1–3.2, formularz, CSV/JSON/TXT |
| 2 | Bezpieczny, wielowątkowy skan discovery; czas trwania; podział na podgrupy | 2, 4, 5.3–5.5 (adaptacyjne zadania, estymacja, pomiar czasu, pula workerów) |
| 3 | Wykrycie aktywnych hostów | 4.3 (wiele sond, RST, ARP) |
| 4 | Identyfikacja usług | 4.4–4.5 (naabu, nmap `-sV`, UDP) |
| 5 | Tytuł, kod, nagłówki, cookies, TLS, przekierowania | 4.6, 8.1 |
| 6 | CMS, framework, serwer aplikacyjny, IoT | 8.2, 9 |
| 7 | Staging, panel administracyjny | 8.2, 4.6 (prober, soft-404) |
| 8 | Porównanie przebiegów | 6 |
| 9 | Nowe, znikające, zmienione usługi | 6.4, 7 |
| 10 | Własne sygnatury | 9 |
| 11 | Formularz + CSV/JSON przetwarzane tak samo | 13.1–13.5 |
| 12 | RBAC z możliwością tworzenia ról | 15.1 |
| 13 | Cztery konkretne role | 15.1 |
| 14 | Edycja niezależna od skanu, trwała | 12 |
| 15 | Czytelny UI dla każdej roli, dashboard | 18 |
| 16 | Szyfrowanie w spoczynku pól wrażliwych | 16 |
| – | Okna czasowe, częstotliwość, zatrzymanie i wznowienie po oknie | 5.6–5.8 |

### 25.2. Minimalny zakres funkcjonalny

| Element | Sekcja |
|---|---|
| import listy hostów lub zakresów | 3.2 |
| import wyników skanów JSON/CSV | 13 |
| >10 000 IP | 5.1, 5.3, 23.1 |
| okno czasowe i częstotliwość | 5.6, 5.8 |
| ograniczanie tempa | 2.2, 5.4 |
| aktywne hosty, identyfikacja usług | 4.3–4.5 |
| zapis do bazy | 11 |
| porównanie dwóch skanów | 6 |
| dashboard z najważniejszymi zmianami | 18.1 |
| eksport JSON/CSV | 13.6 |
| role | 15 |
| edycja istniejących skanów, wyników, konfiguracji | 12, 15.1 |
| szyfrowanie danych skanów | 16 |

### 25.3. Zakres dodatkowy (mile widziany)

| Element | Sekcja |
|---|---|
| harmonogram cyklicznych skanów | 5.8 |
| różnice zależne od pory dnia | 7.4 |
| ocena „ciekawości” | 10.1 |
| powtarzanie pomiarów dla niestabilnych | 7.2 |
| HTTP/HTTPS fingerprinting | 4.6, 8 |
| wykrywanie CMS i technologii | 8.2 |
| grupowanie podobnych usług | 10.2 |
| tagi | 11.5, 12 |
| eksport do DefectDojo (informational / evidence) | 14 |
| wizualizacja zmian w czasie | 18.1 (oś czasu, mapa cieplna, wykresy) |
| pasywne źródła danych | interfejs importu obserwacji (13) + PTR (4.2); adaptery dla udostępnionych źródeł (np. CT logs) |

### 25.4. Punkty weryfikacji z sekcji „Sposób testowania”

| # | Punkt | Gdzie wykazujemy |
|---|---|---|
| 1 | aktywne hosty | 4.3, eval (13.7) |
| 2 | identyfikacja usług | 4.5, eval |
| 3 | fingerprinting HTTP/HTTPS | 4.6, 8 |
| 4 | CMS, technologie | 8.2 |
| 5 | ciekawe nagłówki i cookies | 8.2, sygnatury wbudowane, scoring |
| 6 | customowe sygnatury | 9 (+ adapter formatu organizatorów) |
| 7 | porównanie skanów | 6 |
| 8 | hosty niestabilne i zmieniające odpowiedź | 7 (FLAPPING, UNSTABLE_RESPONSE, retry) |
| 9 | bezpieczeństwo i ostrożność | 2 |
| 10 | czytelność dashboardu | 18 |
| 11 | import i eksport | 13 |
| 12 | rozgraniczenie ról | 15, macierz RBAC (22) |

---

## 26. Ryzyka i kwestie otwarte

| Ryzyko / pytanie | Działanie |
|---|---|
| **Formaty organizatorów** (sygnatury, import/eksport, wyniki referencyjne) mogą różnić się od naszych | Adaptery (9.6, 13.4). Pobrać materiały z Discorda jak najwcześniej i od razu napisać adaptery i testy na ich plikach. |
| Lista dozwolonych portów i limity ruchu organizatorów | Wpisać jako globalne ustawienia (przecięcie z profilami) i domyślny budżet grupy. |
| Topologia labu (L2 czy routowana, sieć Docker) | `compose.override.example.yml` z wariantami. Test uprawnień workera przy starcie. |
| Wersja i ustawienia instancji DefectDojo (deduplikacja włączona?) | „Test połączenia” sprawdza i ostrzega. Ścieżka awaryjna przez Nmap XML (14.6). |
| Czy dostaniemy domeny lub subdomeny | Etap 0 gotowy. Bez domen sondujemy po IP i nazwach z SAN/PTR. |
| SYN scan wymaga uprawnień | `cap_add`, `setcap`. Ostrzeżenie w UI przy trybie connect. |
| Skan /16 w sieci Docker (ARP dla pustych adresów) może być wolniejszy niż w sieci routowanej | Zmierzyć na labie. Estymacja i tak uczy się z faktycznej prędkości. |
| Zakres prac | Plan w sekcji 27. Kolejność zgodna z punktami weryfikacji organizatorów. |

---

## 27. Plan implementacji

Kolejność kamieni milowych. Każdy kończy się działającym przyrostem z testami:

| # | Kamień milowy | Zawartość |
|---|---|---|
| M0 | Szkielet | repo, `Makefile`, `Dockerfile`, compose (postgres, server, worker), konfiguracja, slog, migracje bazowe, `keygen` |
| M1 | Bezpieczeństwo aplikacji | crypto (KEK/DEK, AES-GCM, HMAC), auth (argon2id, sesje, CSRF), RBAC (uprawnienia, role domyślne, middleware, macierz testów), audyt, bootstrap admina i użytkownicy demo |
| M2 | Cele i konfiguracja | scope, wykluczenia, grupy, cele (formularz, import CSV/JSON/TXT), profile, okna, harmonogramy, estymator |
| M3 | Wykonanie | dispatcher (kursor, adaptacyjne cięcie, budżet, leasing, heartbeat, kill switch), worker API, worker (kontrola uprawnień, uruchamianie narzędzi) |
| M4 | Narzędzia | wrappery i parsery: dnsx, nmap `-sn`, naabu, nmap `-sV`/`-sU`, httpx, prober (soft-404, ścieżki), nuclei (opcjonalnie); testdata |
| M5 | Ingest i stan | schemat kanoniczny, walidacja, obserwacje, pokrycie, encje, stable_fp, automat stanowy, retry, flapping, okresowość |
| M6 | Diff i zmiany | diff na pokryciu, strumień zmian, priorytety |
| M7 | Sygnatury i klasyfikacja | parser, walidator, silnik pasywny i aktywny, retro-hunting, pakiet wbudowany (~80 reguł), EOL, favicony, kategorie, pewność, scoring, klastry |
| M8 | Overlay | nadpisania, tagi, notatki, wyciszenia, widok efektywny, konflikty |
| M9 | Import/eksport/eval | JSON/JSONL/CSV, nmap XML, naabu/httpx JSONL, maskowanie, własność obiegu, eval |
| M10 | DefectDojo | klient, mapowanie deterministyczne, import i reimport, pobieranie statusów, triage, test połączenia, ścieżka awaryjna |
| M11 | Scheduler | cron, okna (północ, DST), pauza i wznowienie, polityka nakładania, przebiegi `liveness`, `differential` |
| M12 | UI | wszystkie widoki z sekcji 18, SSE, zachowanie zależne od roli |
| M13 | Lab i demo | `labweb`, compose profilu `lab`, dnsmasq, `expected.json`, `scenario.sh`, `seed-history.sh`, profil `dojo`, `e2e.sh` |
| M14 | Dokumentacja i prezentacja | README (szybki start), OpenAPI, `SYGNATURY.md`, `DEMO.md`, macierz RBAC, wyniki eval, slajdy |

---

*Koniec dokumentu.*

---

## 28. Implementacja – doprecyzowania i odstępstwa od specyfikacji

Sekcja opisuje decyzje podjęte w trakcie implementacji (stan kodu w repozytorium). Tam, gdzie wcześniejsze sekcje mówią inaczej, obowiązuje ta sekcja.

| Obszar | Specyfikacja | Implementacja | Powód |
|---|---|---|---|
| Etap 4 – HTTP | `httpx` jako proces | **natywny prober w Go** (`internal/prober`) z biblioteką **wappalyzergo** – tym samym silnikiem, którego używa `httpx -td` | pełna kontrola nad vhostami (Host + SNI), łańcuchem przekierowań, cookies, kontrolą soft-404 i ścieżkami sygnatur; brak parsowania wyjścia procesu; mniej zależności w obrazie workera |
| Etapy 3–4 | sekwencyjnie | **równolegle**: `nmap -sV` i prober HTTP działają jednocześnie; wynik HTTP dla portu, który nmap rozpoznał (`method=probed`) jako nie-HTTP, jest odrzucany | `-sV` na nietypowych usługach (IoT, własne serwery) potrafi trwać ~100 s na port – równoległość skraca zadanie do czasu wolniejszego etapu |
| Etap 0 – DNS | `dnsx` | resolver standardowej biblioteki Go | brak dodatkowego narzędzia; workery używają resolvera sieci, w której stoją |
| Worker | jedno zadanie naraz | **sloty** (`ASI_WORKER_SLOTS`, domyślnie 4); limity tempa i równoległości nadal egzekwuje dispatcher | wykorzystanie czasu oczekiwania na timeouty |
| Tokeny workerów | token per worker | token może być współdzielony przez repliki (`--scale worker=N`); każda nowa nazwa workera dostaje własny wiersz z tym samym tokenem | wygodne skalowanie w docker compose |
| Kubełki pory dnia | 4 × 6 h | **6 × 4 h osobno dla dni roboczych i weekendu** (12 kubełków); etykieta np. `PERIODIC(GODZ. 08-12,12-16; DNI ROBOCZE)` | host laboratoryjny działający 8–18 w dni robocze był z 4 kubełkami błędnie uznawany za nieaktywny; test na 14-dniowej historii |
| Adaptacyjny podział | N_min = 16, start ρ_alive = 0,3 | N_min = 32, start ρ_alive = 0,1 | rzeczywiste sieci są rzadkie; mniejszy narzut uruchamiania narzędzi |
| DefectDojo | Test per (grupa, kategoria) | **Test per grupa celów** (`ASI – <grupa>`), kategorie jako tagi | prostsza semantyka reimportu (raport = wszystkie aktywne znaleziska grupy) |
| Nuclei | opcjonalny proces w workerze | **adapter formatu** – szablony nuclei (word / regex / status / favicon) importowane jako sygnatury ASI i wykonywane przez prober | bezpieczeństwo (tylko GET/HEAD, walidacja ścieżek) i działanie na danych z importu; uruchamianie binarki nuclei nie jest zaimplementowane |
| Migracje | goose | własny migrator (`internal/db`, pliki SQL osadzone w binarce) | brak zależności |
| UI | Tailwind, Recharts | **ręcznie pisany CSS** (zmienne, tryb jasny/ciemny), wykresy w SVG, React Router; widoki ładowane na żądanie | pierwszy ekran ~64 KB JS gzip; spójny, nienachalny wygląd |

### Wyniki testu end-to-end w laboratorium

`scripts/e2e.sh` (uruchamiany przez `make e2e`) wykonuje: skan bazowy grupy „Lab – usługi” (2048 adresów) → `lab/scenario.sh step2` → skan w trybie differential → asercje. Sprawdza m.in.: wykrycie ≥ 25 hostów, WordPress, panele administracyjne, staging, IoT, EOL, logowanie przez HTTP, wygasły certyfikat, host bez otwartych portów, brak fałszywego `/admin` na SPA (soft-404), klaster drukarek z odstającą wersją firmware, zdarzenia HOST_NEW / HTTP_CHANGED / SERVICE_CHANGED po zmianach, diff z REMOVED / ADDED na wspólnym pokryciu oraz odmowy 403 dla roli VIEWER.

### Testy na szablonach organizatorów (`lab.zip`) i lokalnym DefectDojo

Każdy stos z `lab.zip` był uruchamiany osobno i skanowany przez worker w sieci hosta (`deploy/worker-hostnet.yml`, cel `127.0.0.1`, profil „Lab organizatorów (porty hosta)”).

| Stos | Wykryte (wybór) | Zmiany po modyfikacji |
|---|---|---|
| custom-network | RabbitMQ 3.13.7 (AMQP + panel), PostgreSQL, OpenSSH, instalator Gitea, httpbin (gunicorn 19.9.0), domyślna strona nginx | – |
| quickstart | usługi stosu | zatrzymanie usługi → `SERVICE_MISSING` (SUSPECT), potem `REMOVED` w diff; ponowny start → `SERVICE_RETURNED` / `ADDED`; kolejne cykle → etykieta flapping |
| vulnerable | WordPress 4.7.5 (EOL + odsłonięty instalator), PHP 5.6.30, DVWA, vsftpd 3.0.2, Adminer | – |
| modern | instalator WordPress (latest), phpMyAdmin, Redis 7.4.12, panel Nginx Proxy Manager (81), OpenResty 80/443 | – |
| modern-proxy | dashboard i API Traefika bez uwierzytelnienia, API Toxiproxy, WordPress za proxy | `ENABLE_LATENCY=true` → `RESPONSE_SLOW` („486 ms, wcześniej 8 ms”) |

DefectDojo uruchomione lokalnie (`make dojo`, obrazy z Docker Hub):
- ASI pobrało token i włączyło deduplikację;
- import 4 znalezisk do jednego Testu `ASI – Lab organizatorów`;
- FP oznaczony w DefectDojo został pobrany do ASI (wynik hosta 90 → 45);
- reimport po skanie differential nie stworzył duplikatów, a status FP został zachowany;
- FP oznaczony w ASI pojawił się w DefectDojo (`false_p=true`, `active=false`).

Zmiany w kodzie wynikające z tych testów:

| Problem | Poprawka |
|---|---|
| Traefik odpowiada TLS-em na portach HTTP, więc detekcja wybierała https/404 | `prober.Detect`: najpierw zwykłe `GET / HTTP/1.0`. TLS jest używany najpierw tylko na 443/8443/9443 i przy wskazówce z nmapa; odpowiedź 400 wspominająca https powoduje przejście na TLS. |
| Fałszywy vhost z domyślnego certyfikatu Traefika (`*.traefik.default`) | Nazwy z SAN typu `*.traefik.default` i `localhost` są pomijane. Vhosty są sondowane tylko z nazw pochodzących z DNS lub dodanych ręcznie. |
| Kilka sygnatur dawało znaleziska o tym samym tytule | Trafienia są grupowane po tytule eksportu. Opis zawiera wszystkie reguły i dowody i jest deterministyczny, bo od niego zależy `hash_code` DefectDojo. |
| Domyślnie wyłączona deduplikacja w DefectDojo | Przy konfiguracji user/hasło ASI włącza ją przez `PATCH /system_settings/`. |
| `tcpwrapped` / `service?` traktowane jako znane w trybie differential | Takie usługi są ponownie sondowane. Brak HTTP liczy się jako zniknięcie tylko wtedy, gdy usługa była faktycznie sondowana. |
| Brak sygnału „host/usługa nie odpowiada” przed upływem retencji | Zdarzenia `HOST_MISSING` / `SERVICE_MISSING` przy ACTIVE → SUSPECT oraz `*_RETURNED` przy powrocie. |
| Degradacja wydajności niewidoczna | Kolumna `http_endpoints.response_ms` (migracja 002). Zdarzenia `RESPONSE_SLOW` / `RESPONSE_NORMAL` przy co najmniej dwukrotnym wzroście i +300 ms. Kolumna czasu odpowiedzi w UI. |
| Usługi na 127.0.0.1 niewidoczne z kontenera | Worker w sieci hosta (`ASI_WORKER_LOOPBACK=1`, capability `loopback`). Dispatcher kieruje przebiegi z loopbackiem tylko do takich workerów. Skan portów na loopbacku używa `nmap -sT`. |
| Brak sygnatur dla usług z szablonów | `signatures/builtin/apps.yaml`: instalatory WordPress/Gitea, Gitea, panele RabbitMQ / Traefik / NPM / Adminer, DVWA, httpbin, Toxiproxy, wolna odpowiedź. WordPress wersja z `?ver=`, AMQP/MQTT jako odsłonięte bazy/kolejki. |

### Macierz RBAC

Pełna lista tras API z wymaganym uprawnieniem i dostępem dla czterech ról: [`docs/RBAC.md`](RBAC.md) (generowana testem `TestRBACMatrix`, który dodatkowo weryfikuje, że VIEWER nie wywołuje żadnej trasy modyfikującej, a MODIFIER żadnej tworzącej ani usuwającej).
