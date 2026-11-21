# ASI – skróty
DC  = docker compose
LAB = docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml

.PHONY: env up down lab lab-down logs seed scale test web build dev e2e dojo dojo-down hostworker

env: ## tworzy / uzupełnia .env z losowymi sekretami
	@./scripts/make-env.sh

up: env ## system bez laboratorium
	$(DC) up -d --build

down:
	$(DC) down

lab: env ## system + laboratorium (tryb demo, konta demo, scope 10.77.0.0/16)
	$(LAB) up -d --build

lab-down:
	$(LAB) --profile step2 down

logs:
	$(LAB) logs -f server worker

seed: ## syntetyczna historia 14 dni (flapping, okresowość) przez pipeline importu
	$(LAB) exec server asi seed-history

scale: ## trzy workery dzielące wspólny budżet ruchu
	$(LAB) up -d --scale worker=3 worker

test:
	go test ./...

web:
	cd web && npm ci && npm run build

build: web
	CGO_ENABLED=0 go build -o bin/asi ./cmd/asi

dev: ## serwer lokalnie (wymaga PostgreSQL i zmiennych z .env)
	set -a && . ./.env && set +a && go run ./cmd/asi server

e2e: ## pełny test w laboratorium: skan, zmiany, drugi skan, asercje
	./scripts/e2e.sh

dojo: env ## system + lokalny DefectDojo (http://localhost:8880, admin / DD_ADMIN_PASSWORD z .env)
	$(DC) -f docker-compose.yml -f deploy/defectdojo.yml up -d --build

dojo-down:
	$(DC) -f docker-compose.yml -f deploy/defectdojo.yml down

hostworker: ## dodatkowy worker w sieci hosta (skanowanie usług na portach tej maszyny / 127.0.0.1)
	$(DC) -f docker-compose.yml -f deploy/worker-hostnet.yml up -d --build worker-host
