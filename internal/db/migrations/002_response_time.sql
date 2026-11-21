-- Czas odpowiedzi endpointów WWW (np. opóźnienie wprowadzane przez proxy / Toxiproxy).
alter table http_endpoints add column if not exists response_ms integer not null default 0;
