-- ASI: schemat początkowy. Kolumny *_enc zawierają szyfrogramy AES-256-GCM (format w internal/crypto).

create table encryption_keys (
    id          integer primary key,
    purpose     text not null check (purpose in ('data','hmac')),
    wrapped     bytea not null,
    active      boolean not null default true,
    created_at  timestamptz not null default now(),
    retired_at  timestamptz
);

create table roles (
    id          uuid primary key default gen_random_uuid(),
    name        text not null unique,
    description text not null default '',
    is_system   boolean not null default false,
    created_at  timestamptz not null default now()
);

create table role_permissions (
    role_id    uuid not null references roles(id) on delete cascade,
    permission text not null,
    primary key (role_id, permission)
);

create table users (
    id             uuid primary key default gen_random_uuid(),
    email          text not null unique,
    display_name   text not null default '',
    password_hash  text not null,
    role_id        uuid not null references roles(id),
    is_active      boolean not null default true,
    failed_logins  integer not null default 0,
    locked_until   timestamptz,
    last_login_at  timestamptz,
    created_at     timestamptz not null default now()
);

create table sessions (
    id_hash      text primary key,
    user_id      uuid not null references users(id) on delete cascade,
    csrf_hash    text not null,
    created_at   timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    expires_at   timestamptz not null,
    ip           text,
    user_agent   text
);

create table audit_log (
    id          bigserial primary key,
    at          timestamptz not null default now(),
    user_id     uuid,
    actor       text not null default '',
    action      text not null,
    object_type text not null default '',
    object_id   text not null default '',
    details     jsonb not null default '{}',
    ip          text not null default ''
);
create index audit_log_at on audit_log (at desc);

create table settings (
    key        text primary key,
    value      jsonb not null default '{}',
    value_enc  bytea,
    updated_at timestamptz not null default now()
);

create table scope_allow (
    id         uuid primary key default gen_random_uuid(),
    cidr       cidr not null unique,
    note       text not null default '',
    created_by text not null default '',
    created_at timestamptz not null default now()
);

create table exclusions (
    id         uuid primary key default gen_random_uuid(),
    value      text not null unique,
    reason     text not null default '',
    created_by text not null default '',
    created_at timestamptz not null default now()
);

create table workers (
    id             uuid primary key default gen_random_uuid(),
    name           text not null unique,
    token_hash     text not null,
    vantage        text not null default '',
    capabilities   jsonb not null default '{}',
    tool_versions  jsonb not null default '{}',
    last_heartbeat timestamptz,
    current_task   uuid,
    current_rate   integer not null default 0,
    status         text not null default 'new',
    created_at     timestamptz not null default now()
);

create table scan_profiles (
    id         uuid primary key default gen_random_uuid(),
    name       text not null unique,
    config     jsonb not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table target_groups (
    id                  uuid primary key default gen_random_uuid(),
    name                text not null unique,
    description         text not null default '',
    timezone            text not null default 'Europe/Warsaw',
    profile_id          uuid references scan_profiles(id),
    rate_pps            integer not null default 500,
    http_rps            integer not null default 20,
    max_parallel_sweeps integer not null default 2,
    max_parallel_probes integer not null default 4,
    always_allowed      boolean not null default true,
    stats               jsonb not null default '{}',
    created_at          timestamptz not null default now()
);

create table targets (
    id          uuid primary key default gen_random_uuid(),
    group_id    uuid not null references target_groups(id) on delete cascade,
    kind        text not null,
    value       text not null,
    ranges      jsonb not null default '[]',
    source      text not null default 'manual',
    enabled     boolean not null default true,
    tags        text[] not null default '{}',
    note_enc    bytea,
    created_by  text not null default '',
    created_at  timestamptz not null default now(),
    unique (group_id, value)
);

create table windows (
    id          uuid primary key default gen_random_uuid(),
    group_id    uuid not null references target_groups(id) on delete cascade,
    days_mask   integer not null default 127,  -- bit 0 = poniedziałek
    start_min   integer not null,              -- minuty od północy
    end_min     integer not null,
    kind        text not null default 'full' check (kind in ('full','low_impact')),
    rate_factor real not null default 1.0,
    mode        text not null default ''
);

create table schedules (
    id             uuid primary key default gen_random_uuid(),
    group_id       uuid not null references target_groups(id) on delete cascade,
    profile_id     uuid references scan_profiles(id),
    cron           text not null,
    mode           text not null default 'baseline',
    overlap_policy text not null default 'skip',
    enabled        boolean not null default true,
    last_fired_at  timestamptz,
    next_fire_at   timestamptz,
    created_at     timestamptz not null default now()
);

create table scan_runs (
    id              uuid primary key default gen_random_uuid(),
    group_id        uuid references target_groups(id) on delete set null,
    schedule_id     uuid references schedules(id) on delete set null,
    mode            text not null default 'baseline',
    source          text not null default 'scanner',
    profile         jsonb not null default '{}',
    status          text not null default 'PENDING',
    ranges          jsonb not null default '[]',
    ipv6            text[] not null default '{}',
    cursor          jsonb not null default '{"idx":0,"off":0}',
    total_addresses bigint not null default 0,
    done_addresses  bigint not null default 0,
    phase           text not null default 'scan',
    est_seconds     integer not null default 0,
    stats           jsonb not null default '{}',
    note            text not null default '',
    created_by      text not null default '',
    created_at      timestamptz not null default now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    paused_reason   text not null default ''
);
create index scan_runs_group on scan_runs (group_id, created_at desc);

create table tasks (
    id               uuid primary key default gen_random_uuid(),
    run_id           uuid not null references scan_runs(id) on delete cascade,
    kind             text not null,
    payload          jsonb not null,
    status           text not null default 'pending',
    attempt          integer not null default 0,
    lease_owner      uuid,
    lease_expires_at timestamptz,
    rate_pps         integer not null default 0,
    http_rps         integer not null default 0,
    not_before       timestamptz not null default now(),
    cancel_requested boolean not null default false,
    addresses        integer not null default 0,
    est_seconds      real not null default 0,
    started_at       timestamptz,
    finished_at      timestamptz,
    duration_ms      integer not null default 0,
    stats            jsonb not null default '{}',
    error            text not null default '',
    created_at       timestamptz not null default now()
);
create index tasks_pending on tasks (status, not_before) where status in ('pending','leased');
create index tasks_run on tasks (run_id);

create table run_coverage (
    id        bigserial primary key,
    run_id    uuid not null references scan_runs(id) on delete cascade,
    task_id   uuid,
    ranges    jsonb not null default '[]',   -- [{"s":..,"e":..}] IPv4
    ips       text[] not null default '{}',  -- pojedyncze adresy (IPv6, import)
    tcp_ports text not null default '',
    udp_ports text not null default '',
    entities  text[] not null default '{}',  -- klucze encji (import/formularz)
    stages    text[] not null default '{}'
);
create index run_coverage_run on run_coverage (run_id);

-- ---------------- inwentarz ----------------

create table hosts (
    id                 uuid primary key default gen_random_uuid(),
    ip                 inet not null unique,
    group_id           uuid references target_groups(id) on delete set null,
    state              text not null default 'ACTIVE',
    labels             text[] not null default '{}',
    hostnames          text[] not null default '{}',
    os                 text not null default '',
    devicetype         text not null default '',
    first_seen         timestamptz not null default now(),
    last_seen          timestamptz not null default now(),
    last_run_id        uuid,
    consecutive_misses integer not null default 0,
    total_seen         integer not null default 0,
    flap_score         real not null default 0,
    periodicity        jsonb not null default '{}',
    identity           jsonb not null default '{}',
    stable_fp          text not null default '',
    score              integer not null default 0,
    score_breakdown    jsonb not null default '[]',
    source             text not null default 'scanner'
);

create table host_hostnames (
    host_id    uuid not null references hosts(id) on delete cascade,
    name       text not null,
    source     text not null,
    first_seen timestamptz not null default now(),
    last_seen  timestamptz not null default now(),
    primary key (host_id, name)
);
create index host_hostnames_name on host_hostnames (name);

create table services (
    id                 uuid primary key default gen_random_uuid(),
    host_id            uuid not null references hosts(id) on delete cascade,
    proto              text not null,
    port               integer not null,
    state              text not null default 'ACTIVE',
    labels             text[] not null default '{}',
    first_seen         timestamptz not null default now(),
    last_seen          timestamptz not null default now(),
    last_run_id        uuid,
    consecutive_misses integer not null default 0,
    total_seen         integer not null default 0,
    flap_score         real not null default 0,
    service_name       text not null default '',
    product            text not null default '',
    version            text not null default '',
    extrainfo          text not null default '',
    devicetype         text not null default '',
    cpe                text[] not null default '{}',
    tunnel             text not null default '',
    nmap_method        text not null default '',
    nmap_conf          integer not null default 0,
    confidence         real not null default 0,
    version_confidence real not null default 0,
    tls                jsonb,
    stable_fp          text not null default '',
    cluster_key        text not null default '',
    raw_enc            bytea,
    score              integer not null default 0,
    score_breakdown    jsonb not null default '[]',
    probed_at          timestamptz,
    unique (host_id, proto, port)
);

create table http_endpoints (
    id                 uuid primary key default gen_random_uuid(),
    service_id         uuid not null references services(id) on delete cascade,
    host_id            uuid not null references hosts(id) on delete cascade,
    vhost              text not null default '',
    scheme             text not null,
    url                text not null,
    state              text not null default 'ACTIVE',
    labels             text[] not null default '{}',
    status_code        integer not null default 0,
    title              text not null default '',
    server             text not null default '',
    powered_by         text not null default '',
    header_names       text[] not null default '{}',
    cookie_meta        jsonb not null default '[]',
    final_url          text not null default '',
    favicon_mmh3       text not null default '',
    body_hmac          text not null default '',
    tls                jsonb,
    stable_fp          text not null default '',
    cluster_key        text not null default '',
    raw_enc            bytea,
    first_seen         timestamptz not null default now(),
    last_seen          timestamptz not null default now(),
    last_run_id        uuid,
    consecutive_misses integer not null default 0,
    total_seen         integer not null default 0,
    flap_score         real not null default 0,
    fp_changes         integer[] not null default '{}',
    score              integer not null default 0,
    score_breakdown    jsonb not null default '[]',
    unique (service_id, scheme, vhost)
);

create table technologies (
    id                 bigserial primary key,
    entity_type        text not null,
    entity_id          uuid not null,
    host_id            uuid not null references hosts(id) on delete cascade,
    name               text not null,
    version            text not null default '',
    category           text not null default '',
    confidence         real not null default 0,
    version_confidence real not null default 0,
    evidence           jsonb not null default '[]',
    first_seen         timestamptz not null default now(),
    last_seen          timestamptz not null default now(),
    active             boolean not null default true,
    unique (entity_type, entity_id, name)
);
create index technologies_name on technologies (lower(name));

create table classifications (
    entity_type text not null,
    entity_id   uuid not null,
    host_id     uuid not null references hosts(id) on delete cascade,
    category    text not null,
    confidence  real not null default 0,
    evidence    jsonb not null default '[]',
    active      boolean not null default true,
    first_seen  timestamptz not null default now(),
    last_seen   timestamptz not null default now(),
    primary key (entity_type, entity_id, category)
);
create index classifications_cat on classifications (category) where active;

create table observations (
    id                 bigserial primary key,
    run_id             uuid references scan_runs(id) on delete cascade,
    task_id            uuid,
    observed_at        timestamptz not null,
    source             text not null,
    worker             text not null default '',
    entity_type        text not null,
    entity_key         text not null,
    up                 boolean not null,
    stable             jsonb not null default '{}',
    raw_enc            bytea,
    stable_fp          text not null default '',
    recovered_on_retry boolean not null default false
);
create index observations_entity on observations (entity_key, observed_at desc);
create index observations_run on observations (run_id);

create table availability_history (
    id          bigserial primary key,
    entity_type text not null,
    entity_id   uuid not null,
    run_id      uuid,
    at          timestamptz not null,
    up          boolean not null,
    retry       boolean not null default false,
    bucket_tod  smallint not null,
    weekend     boolean not null
);
create index availability_entity on availability_history (entity_id, at desc);

create table changes (
    id              bigserial primary key,
    run_id          uuid references scan_runs(id) on delete cascade,
    compared_run_id uuid,
    at              timestamptz not null default now(),
    entity_type     text not null,
    entity_key      text not null,
    host_ip         inet,
    change_type     text not null,
    summary         text not null default '',
    diff            jsonb not null default '[]',
    priority        integer not null default 0,
    acknowledged_by text,
    acknowledged_at timestamptz
);
create index changes_at on changes (at desc);
create index changes_host on changes (host_ip);

create table signatures (
    id          uuid primary key default gen_random_uuid(),
    sig_id      text not null unique,
    version     integer not null default 1,
    kind        text not null,
    scope       text not null,
    name        text not null,
    definition  jsonb not null,
    source_text text not null,
    enabled     boolean not null default true,
    origin      text not null default 'user',
    created_by  text not null default '',
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

create table signature_history (
    id          bigserial primary key,
    sig_id      text not null,
    version     integer not null,
    source_text text not null,
    changed_by  text not null default '',
    changed_at  timestamptz not null default now()
);

create table signature_matches (
    id          bigserial primary key,
    sig_id      text not null,
    sig_version integer not null default 1,
    entity_type text not null,
    entity_id   uuid not null,
    entity_key  text not null,
    host_id     uuid not null references hosts(id) on delete cascade,
    evidence    jsonb not null default '[]',
    active      boolean not null default true,
    first_seen  timestamptz not null default now(),
    last_seen   timestamptz not null default now(),
    last_run_id uuid,
    unique (sig_id, entity_type, entity_id)
);

-- ---------------- warstwa użytkownika ----------------

create table overrides (
    id                    uuid primary key default gen_random_uuid(),
    entity_type           text not null,
    entity_key            text not null,
    field                 text not null,
    value                 jsonb not null,
    scanner_value_at_edit jsonb,
    updated_by            text not null,
    updated_at            timestamptz not null default now(),
    unique (entity_type, entity_key, field)
);

create table override_history (
    id          bigserial primary key,
    entity_type text not null,
    entity_key  text not null,
    field       text not null,
    old_value   jsonb,
    new_value   jsonb,
    changed_by  text not null,
    changed_at  timestamptz not null default now()
);

create table tags (
    id    uuid primary key default gen_random_uuid(),
    name  text not null unique,
    color text not null default ''
);

create table entity_tags (
    entity_type text not null,
    entity_key  text not null,
    tag_id      uuid not null references tags(id) on delete cascade,
    created_by  text not null default '',
    primary key (entity_type, entity_key, tag_id)
);

create table notes (
    id          uuid primary key default gen_random_uuid(),
    entity_type text not null,
    entity_key  text not null,
    body_enc    bytea not null,
    created_by  text not null,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);
create index notes_entity on notes (entity_type, entity_key);

create table suppressions (
    id         uuid primary key default gen_random_uuid(),
    entity_key text not null default '',
    sig_id     text not null default '',
    reason     text not null default '',
    until      timestamptz,
    created_by text not null,
    created_at timestamptz not null default now()
);

create table findings (
    id                uuid primary key default gen_random_uuid(),
    entity_type       text not null,
    entity_key        text not null,
    host_ip           inet,
    group_id          uuid,
    rule              text not null,
    category          text not null default '',
    title             text not null,
    severity          text not null default 'Info',
    description       text not null,
    component_name    text not null default '',
    component_version text not null default '',
    endpoint          jsonb not null default '{}',
    dedup_key         text not null unique,
    status            text not null default 'open',
    exported          boolean not null default false,
    active            boolean not null default true,
    dd_finding_id     integer,
    dd_test_id        integer,
    last_pushed_at    timestamptz,
    last_synced_at    timestamptz,
    first_seen        timestamptz not null default now(),
    last_seen         timestamptz not null default now()
);
create index findings_entity on findings (entity_key);

create table imports (
    id         uuid primary key default gen_random_uuid(),
    kind       text not null,
    format     text not null default '',
    filename   text not null default '',
    status     text not null,
    stats      jsonb not null default '{}',
    errors     jsonb not null default '[]',
    run_id     uuid,
    created_by text not null default '',
    created_at timestamptz not null default now()
);

create table dd_sync_log (
    id        bigserial primary key,
    at        timestamptz not null default now(),
    direction text not null,
    status    text not null,
    details   text not null default ''
);
