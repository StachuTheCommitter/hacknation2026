package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/robfig/cron/v3"

	"asi/internal/model"
	"asi/internal/netx"
)

// ---------------- scope ----------------

type ScopeEntry struct {
	ID        string `json:"id"`
	Value     string `json:"value"`
	Note      string `json:"note"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

func (a *App) ListScope(ctx context.Context) ([]ScopeEntry, []ScopeEntry, error) {
	q := func(sql string) ([]ScopeEntry, error) {
		rows, err := a.DB.Query(ctx, sql)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, pgx.RowToStructByPos[ScopeEntry])
	}
	allow, err := q(`select id, cidr::text, note, created_by, to_char(created_at,'YYYY-MM-DD HH24:MI') from scope_allow order by cidr`)
	if err != nil {
		return nil, nil, err
	}
	excl, err := q(`select id, value, reason, created_by, to_char(created_at,'YYYY-MM-DD HH24:MI') from exclusions order by value`)
	return allow, excl, err
}

// Scope zwraca bieżącą listę dozwolonych zakresów i wykluczeń.
func (a *App) Scope(ctx context.Context) (netx.Scope, []string, []string, error) {
	allow, excl, err := a.ListScope(ctx)
	if err != nil {
		return netx.Scope{}, nil, nil, err
	}
	var al, ex []string
	for _, x := range allow {
		al = append(al, x.Value)
	}
	for _, x := range excl {
		ex = append(ex, x.Value)
	}
	return netx.NewScope(al, ex), al, ex, nil
}

func (a *App) AddScope(ctx context.Context, actor Actor, cidr, note string) error {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		if ad, err2 := netip.ParseAddr(strings.TrimSpace(cidr)); err2 == nil {
			p = netip.PrefixFrom(ad, ad.BitLen())
		} else {
			return Invalid("niepoprawny CIDR", nil)
		}
	}
	p = p.Masked()
	if p.Addr().Is4() && p.Bits() < 8 {
		return Invalid("zakres większy niż /8 nie może być dodany do scope", nil)
	}
	_, err = a.DB.Exec(ctx, `insert into scope_allow(cidr,note,created_by) values($1,$2,$3) on conflict(cidr) do update set note=$2`, p.String(), note, actor.Name())
	if err == nil {
		a.Audit(ctx, actor, "scope.add", "scope", p.String(), map[string]any{"note": note})
	}
	return err
}

func (a *App) DeleteScope(ctx context.Context, actor Actor, id string) error {
	var v string
	if err := a.DB.QueryRow(ctx, `delete from scope_allow where id=$1 returning cidr::text`, id).Scan(&v); err != nil {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "scope.delete", "scope", v, nil)
	return nil
}

func (a *App) AddExclusion(ctx context.Context, actor Actor, value, reason string) error {
	value = strings.TrimSpace(value)
	if _, err := netx.ParseTarget(value); err != nil {
		if _, err2 := netip.ParsePrefix(value); err2 != nil {
			return Invalid("niepoprawna wartość wykluczenia: "+err.Error(), nil)
		}
	}
	_, err := a.DB.Exec(ctx, `insert into exclusions(value,reason,created_by) values($1,$2,$3) on conflict(value) do update set reason=$2`, value, reason, actor.Name())
	if err == nil {
		a.Audit(ctx, actor, "exclusion.add", "exclusion", value, map[string]any{"reason": reason})
	}
	return err
}

func (a *App) DeleteExclusion(ctx context.Context, actor Actor, id string) error {
	var v string
	if err := a.DB.QueryRow(ctx, `delete from exclusions where id=$1 returning value`, id).Scan(&v); err != nil {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "exclusion.delete", "exclusion", v, nil)
	return nil
}

// ---------------- profile ----------------

type ProfileRow struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Config model.Profile `json:"config"`
	Ports  int           `json:"ports"`
}

func (a *App) ListProfiles(ctx context.Context) ([]ProfileRow, error) {
	rows, err := a.DB.Query(ctx, `select id, name, config from scan_profiles order by name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ProfileRow, error) {
		var p ProfileRow
		var raw []byte
		if err := r.Scan(&p.ID, &p.Name, &raw); err != nil {
			return p, err
		}
		json.Unmarshal(raw, &p.Config)
		p.Config.Fill()
		ps, _ := netx.ParsePorts(p.Config.TCPPorts)
		p.Ports = len(ps)
		return p, nil
	})
}

func (a *App) GetProfile(ctx context.Context, id string) (model.Profile, error) {
	var raw []byte
	p := model.DefaultProfile()
	if id == "" {
		return p, nil
	}
	if err := a.DB.QueryRow(ctx, `select config from scan_profiles where id=$1`, id).Scan(&raw); err != nil {
		return p, ErrNotFound
	}
	p = model.Profile{}
	json.Unmarshal(raw, &p)
	p.Fill()
	return p, nil
}

func validateProfile(p *model.Profile) error {
	p.Fill()
	var errs []string
	if _, err := netx.ParsePorts(p.TCPPorts); err != nil {
		errs = append(errs, "tcp_ports: "+err.Error())
	}
	if p.UDPPorts != "" {
		if ps, err := netx.ParsePorts(p.UDPPorts); err != nil {
			errs = append(errs, "udp_ports: "+err.Error())
		} else if len(ps) > 50 {
			errs = append(errs, "udp_ports: maksymalnie 50 portów UDP")
		}
	}
	for _, path := range p.ProberPaths {
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "'\"<>`;|") {
			errs = append(errs, "prober_paths: niedozwolona ścieżka "+path)
		}
	}
	if p.DiscoveryEngine != "nmap" && p.DiscoveryEngine != "naabu" && p.DiscoveryEngine != "none" {
		errs = append(errs, "discovery_engine: nmap | naabu | none")
	}
	if p.PortscanEngine != "nmap" && p.PortscanEngine != "naabu" {
		errs = append(errs, "portscan_engine: nmap | naabu")
	}
	if p.PortscanScope != "alive" && p.PortscanScope != "all" {
		errs = append(errs, "portscan_scope: alive | all")
	}
	if len(errs) > 0 {
		return Invalid("niepoprawny profil", errs)
	}
	return nil
}

func (a *App) SaveProfile(ctx context.Context, actor Actor, id, name string, p model.Profile) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", Invalid("nazwa profilu jest wymagana", nil)
	}
	if err := validateProfile(&p); err != nil {
		return "", err
	}
	if id == "" {
		err := a.DB.QueryRow(ctx, `insert into scan_profiles(name,config) values($1,$2) returning id`, name, jsonb(p)).Scan(&id)
		if err != nil {
			return "", Invalid("profil o tej nazwie już istnieje", nil)
		}
		a.Audit(ctx, actor, "profile.create", "profile", id, map[string]any{"name": name})
		return id, nil
	}
	ct, err := a.DB.Exec(ctx, `update scan_profiles set name=$2, config=$3, updated_at=now() where id=$1`, id, name, jsonb(p))
	if err != nil {
		return "", err
	}
	if ct.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	a.Audit(ctx, actor, "profile.update", "profile", id, map[string]any{"name": name})
	return id, nil
}

func (a *App) DeleteProfile(ctx context.Context, actor Actor, id string) error {
	_, err := a.DB.Exec(ctx, `delete from scan_profiles where id=$1`, id)
	if err != nil {
		return Invalid("profil jest używany przez grupę lub harmonogram", nil)
	}
	a.Audit(ctx, actor, "profile.delete", "profile", id, nil)
	return nil
}

// ---------------- grupy celów ----------------

type GroupInput struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	Timezone          string `json:"timezone"`
	ProfileID         string `json:"profile_id"`
	RatePPS           int    `json:"rate_pps"`
	HTTPRPS           int    `json:"http_rps"`
	MaxParallelSweeps int    `json:"max_parallel_sweeps"`
	MaxParallelProbes int    `json:"max_parallel_probes"`
	AlwaysAllowed     bool   `json:"always_allowed"`
}

type Group struct {
	ID string `json:"id"`
	GroupInput
	ProfileName string     `json:"profile_name"`
	Targets     int        `json:"targets"`
	Addresses   int64      `json:"addresses"`
	Hosts       int        `json:"hosts"`
	LastRun     *RunBrief  `json:"last_run,omitempty"`
	Window      *WinStatus `json:"window,omitempty"`
}

type RunBrief struct {
	ID         string     `json:"id"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (in *GroupInput) normalize() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return Invalid("nazwa grupy jest wymagana", nil)
	}
	if in.Timezone == "" {
		in.Timezone = "Europe/Warsaw"
	}
	if _, err := time.LoadLocation(in.Timezone); err != nil {
		return Invalid("nieznana strefa czasowa "+in.Timezone, nil)
	}
	if in.RatePPS <= 0 {
		in.RatePPS = 500
	}
	if in.HTTPRPS <= 0 {
		in.HTTPRPS = 20
	}
	if in.MaxParallelSweeps <= 0 {
		in.MaxParallelSweeps = 2
	}
	if in.MaxParallelProbes <= 0 {
		in.MaxParallelProbes = 4
	}
	in.RatePPS = min(in.RatePPS, 100000)
	in.HTTPRPS = min(in.HTTPRPS, 1000)
	return nil
}

func nullUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (a *App) CreateGroup(ctx context.Context, actor Actor, in GroupInput) (*Group, error) {
	if err := in.normalize(); err != nil {
		return nil, err
	}
	var id string
	err := a.DB.QueryRow(ctx, `insert into target_groups(name,description,timezone,profile_id,rate_pps,http_rps,max_parallel_sweeps,max_parallel_probes,always_allowed)
		values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning id`, in.Name, in.Description, in.Timezone, nullUUID(in.ProfileID), in.RatePPS, in.HTTPRPS,
		in.MaxParallelSweeps, in.MaxParallelProbes, in.AlwaysAllowed).Scan(&id)
	if err != nil {
		return nil, Invalid("grupa o tej nazwie już istnieje", nil)
	}
	a.Audit(ctx, actor, "group.create", "group", id, map[string]any{"name": in.Name})
	return a.GetGroup(ctx, id)
}

func (a *App) UpdateGroup(ctx context.Context, actor Actor, id string, in GroupInput) (*Group, error) {
	if err := in.normalize(); err != nil {
		return nil, err
	}
	ct, err := a.DB.Exec(ctx, `update target_groups set name=$2,description=$3,timezone=$4,profile_id=$5,rate_pps=$6,http_rps=$7,
		max_parallel_sweeps=$8,max_parallel_probes=$9,always_allowed=$10 where id=$1`, id, in.Name, in.Description, in.Timezone, nullUUID(in.ProfileID),
		in.RatePPS, in.HTTPRPS, in.MaxParallelSweeps, in.MaxParallelProbes, in.AlwaysAllowed)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	a.Audit(ctx, actor, "group.update", "group", id, map[string]any{"name": in.Name, "rate_pps": in.RatePPS})
	return a.GetGroup(ctx, id)
}

func (a *App) DeleteGroup(ctx context.Context, actor Actor, id string) error {
	ct, err := a.DB.Exec(ctx, `delete from target_groups where id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "group.delete", "group", id, nil)
	return nil
}

const groupSelect = `select g.id, g.name, g.description, g.timezone, coalesce(g.profile_id::text,''), g.rate_pps, g.http_rps,
	g.max_parallel_sweeps, g.max_parallel_probes, g.always_allowed, coalesce(p.name,''),
	(select count(*) from targets t where t.group_id=g.id),
	(select count(*) from hosts h where h.group_id=g.id and h.state<>'INACTIVE')
	from target_groups g left join scan_profiles p on p.id=g.profile_id`

func (a *App) scanGroup(r pgx.Row) (*Group, error) {
	var g Group
	err := r.Scan(&g.ID, &g.Name, &g.Description, &g.Timezone, &g.ProfileID, &g.RatePPS, &g.HTTPRPS, &g.MaxParallelSweeps,
		&g.MaxParallelProbes, &g.AlwaysAllowed, &g.ProfileName, &g.Targets, &g.Hosts)
	return &g, err
}

func (a *App) ListGroups(ctx context.Context) ([]*Group, error) {
	rows, err := a.DB.Query(ctx, groupSelect+` order by g.name`)
	if err != nil {
		return nil, err
	}
	var out []*Group
	for rows.Next() {
		g, err := a.scanGroup(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, g)
	}
	rows.Close()
	for _, g := range out {
		a.enrichGroup(ctx, g)
	}
	return out, nil
}

func (a *App) GetGroup(ctx context.Context, id string) (*Group, error) {
	g, err := a.scanGroup(a.DB.QueryRow(ctx, groupSelect+` where g.id=$1`, id))
	if err != nil {
		return nil, ErrNotFound
	}
	a.enrichGroup(ctx, g)
	return g, nil
}

func (a *App) enrichGroup(ctx context.Context, g *Group) {
	rs, _, _ := a.groupRanges(ctx, g.ID)
	g.Addresses = int64(netx.Total(rs))
	var rb RunBrief
	if a.DB.QueryRow(ctx, `select id,status,created_at,finished_at from scan_runs where group_id=$1 and source='scanner' order by created_at desc limit 1`, g.ID).
		Scan(&rb.ID, &rb.Status, &rb.CreatedAt, &rb.FinishedAt) == nil {
		g.LastRun = &rb
	}
	ws, _ := a.WindowStatus(ctx, g.ID, time.Now())
	g.Window = ws
}

// ---------------- cele ----------------

type TargetRow struct {
	ID        string   `json:"id"`
	GroupID   string   `json:"group_id"`
	Kind      string   `json:"kind"`
	Value     string   `json:"value"`
	Addresses int64    `json:"addresses"`
	Source    string   `json:"source"`
	Enabled   bool     `json:"enabled"`
	Tags      []string `json:"tags"`
	CreatedBy string   `json:"created_by"`
	CreatedAt string   `json:"created_at"`
}

func (a *App) ListTargets(ctx context.Context, groupID string) ([]TargetRow, error) {
	rows, err := a.DB.Query(ctx, `select id, group_id, kind, value, ranges, source, enabled, tags, created_by, to_char(created_at,'YYYY-MM-DD HH24:MI')
		from targets where ($1='' or group_id::text=$1) order by created_at, value`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (TargetRow, error) {
		var t TargetRow
		var raw []byte
		err := r.Scan(&t.ID, &t.GroupID, &t.Kind, &t.Value, &raw, &t.Source, &t.Enabled, &t.Tags, &t.CreatedBy, &t.CreatedAt)
		var rs []netx.Range
		json.Unmarshal(raw, &rs)
		t.Addresses = int64(netx.Total(rs))
		if t.Kind == "ip" && len(rs) == 0 {
			t.Addresses = 1
		}
		return t, err
	})
}

type Rejected struct {
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

type TargetReport struct {
	Accepted   int        `json:"accepted"`
	Duplicates int        `json:"duplicates"`
	Rejected   []Rejected `json:"rejected"`
	Addresses  int64      `json:"addresses"`
	Notes      []string   `json:"notes,omitempty"`
}

// AddTargets waliduje (składnia, scope, rozmiar) i zapisuje cele – wspólna ścieżka dla formularza, CSV, JSON i API.
func (a *App) AddTargets(ctx context.Context, actor Actor, groupID string, values []string, source string, tags []string) (*TargetReport, error) {
	if _, err := a.GetGroup(ctx, groupID); err != nil {
		return nil, err
	}
	scope, _, _, err := a.Scope(ctx)
	if err != nil {
		return nil, err
	}
	rep := &TargetReport{Rejected: []Rejected{}}
	if tags == nil {
		tags = []string{}
	}
outer:
	for _, v := range values {
		t, err := netx.ParseTarget(v)
		if err != nil {
			rep.Rejected = append(rep.Rejected, Rejected{v, err.Error()})
			continue
		}
		switch {
		case t.IPv6 != "":
			if !scope.Allowed(t.IPv6) {
				rep.Rejected = append(rep.Rejected, Rejected{v, "poza dozwolonym zakresem (scope)"})
				continue
			}
		case t.Kind != "domain":
			in := netx.Intersect(t.Ranges, scope.Allow)
			if netx.Total(in) != netx.Total(t.Ranges) {
				rep.Rejected = append(rep.Rejected, Rejected{v, "poza dozwolonym zakresem (scope) – dodaj zakres w Administracja → Scope"})
				continue
			}
			// adresy specjalne (loopback – np. lab na tej samej maszynie) są dozwolone tylko, gdy administrator
			// jawnie dodał je do scope; multicast nigdy
			for _, r := range t.Ranges {
				if a := netx.U32ToAddr(r.Start); a.IsMulticast() || a.IsUnspecified() {
					rep.Rejected = append(rep.Rejected, Rejected{v, "adres specjalny (multicast / 0.0.0.0)"})
					continue outer
				} else if a.IsLoopback() {
					rep.Notes = append(rep.Notes, v+": adres loopback – skanowany z workera w trybie TCP connect (worker musi działać w sieci hosta)")
				}
			}
			if ex := netx.Intersect(t.Ranges, scope.Exclude); len(ex) > 0 {
				rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %d adresów z listy wykluczeń zostanie pominiętych", v, netx.Total(ex)))
			}
		}
		ct, err := a.DB.Exec(ctx, `insert into targets(group_id,kind,value,ranges,source,tags,created_by) values($1,$2,$3,$4,$5,$6,$7) on conflict(group_id,value) do nothing`,
			groupID, t.Kind, t.Value, jsonb(t.Ranges), source, tags, actor.Name())
		if err != nil {
			return nil, err
		}
		if ct.RowsAffected() == 0 {
			rep.Duplicates++
		} else {
			rep.Accepted++
			rep.Addresses += int64(netx.Total(t.Ranges))
		}
	}
	a.Audit(ctx, actor, "targets.add", "group", groupID, map[string]any{"accepted": rep.Accepted, "rejected": len(rep.Rejected), "source": source})
	return rep, nil
}

func (a *App) UpdateTarget(ctx context.Context, actor Actor, id string, enabled bool, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	ct, err := a.DB.Exec(ctx, `update targets set enabled=$2, tags=$3 where id=$1`, id, enabled, tags)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "target.update", "target", id, map[string]any{"enabled": enabled})
	return nil
}

func (a *App) DeleteTarget(ctx context.Context, actor Actor, id string) error {
	var v string
	if err := a.DB.QueryRow(ctx, `delete from targets where id=$1 returning value`, id).Scan(&v); err != nil {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "target.delete", "target", id, map[string]any{"value": v})
	return nil
}

// groupRanges zwraca scalone zakresy IPv4, adresy IPv6 i domeny włączonych celów grupy.
func (a *App) groupRanges(ctx context.Context, groupID string) ([]netx.Range, []string, []string) {
	rows, err := a.DB.Query(ctx, `select kind, value, ranges from targets where group_id=$1 and enabled`, groupID)
	if err != nil {
		return nil, nil, nil
	}
	defer rows.Close()
	var rs []netx.Range
	var v6, domains []string
	for rows.Next() {
		var kind, val string
		var raw []byte
		rows.Scan(&kind, &val, &raw)
		var r []netx.Range
		json.Unmarshal(raw, &r)
		switch {
		case kind == "domain":
			domains = append(domains, val)
		case len(r) == 0 && kind == "ip":
			v6 = append(v6, val)
		default:
			rs = append(rs, r...)
		}
	}
	return netx.Merge(rs), v6, domains
}

// ---------------- okna czasowe ----------------

type Window struct {
	ID         string  `json:"id"`
	GroupID    string  `json:"group_id"`
	DaysMask   int     `json:"days_mask"`
	StartMin   int     `json:"start_min"`
	EndMin     int     `json:"end_min"`
	Kind       string  `json:"kind"`
	RateFactor float64 `json:"rate_factor"`
	Mode       string  `json:"mode"`
}

func (a *App) ListWindows(ctx context.Context, groupID string) ([]Window, error) {
	rows, err := a.DB.Query(ctx, `select id, group_id, days_mask, start_min, end_min, kind, rate_factor, mode from windows where ($1='' or group_id::text=$1) order by start_min`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Window, error) {
		var w Window
		var rf float32
		err := r.Scan(&w.ID, &w.GroupID, &w.DaysMask, &w.StartMin, &w.EndMin, &w.Kind, &rf, &w.Mode)
		w.RateFactor = float64(rf)
		return w, err
	})
}

func (w *Window) validate() error {
	if w.DaysMask <= 0 || w.DaysMask > 127 {
		return Invalid("wybierz co najmniej jeden dzień", nil)
	}
	if w.StartMin < 0 || w.StartMin >= 1440 || w.EndMin < 0 || w.EndMin > 1440 || w.StartMin == w.EndMin {
		return Invalid("niepoprawne godziny okna", nil)
	}
	if w.Kind == "" {
		w.Kind = "full"
	}
	if w.Kind != "full" && w.Kind != "low_impact" {
		return Invalid("kind: full | low_impact", nil)
	}
	if w.RateFactor <= 0 || w.RateFactor > 1 {
		w.RateFactor = map[string]float64{"full": 1, "low_impact": 0.1}[w.Kind]
	}
	if w.Kind == "low_impact" && w.Mode == "" {
		w.Mode = "liveness"
	}
	return nil
}

func (a *App) SaveWindow(ctx context.Context, actor Actor, w Window) (string, error) {
	if err := w.validate(); err != nil {
		return "", err
	}
	if w.ID == "" {
		err := a.DB.QueryRow(ctx, `insert into windows(group_id,days_mask,start_min,end_min,kind,rate_factor,mode) values($1,$2,$3,$4,$5,$6,$7) returning id`,
			w.GroupID, w.DaysMask, w.StartMin, w.EndMin, w.Kind, w.RateFactor, w.Mode).Scan(&w.ID)
		if err != nil {
			return "", err
		}
	} else {
		ct, err := a.DB.Exec(ctx, `update windows set days_mask=$2,start_min=$3,end_min=$4,kind=$5,rate_factor=$6,mode=$7 where id=$1`,
			w.ID, w.DaysMask, w.StartMin, w.EndMin, w.Kind, w.RateFactor, w.Mode)
		if err != nil {
			return "", err
		}
		if ct.RowsAffected() == 0 {
			return "", ErrNotFound
		}
	}
	a.Audit(ctx, actor, "window.save", "window", w.ID, map[string]any{"group": w.GroupID, "start": w.StartMin, "end": w.EndMin, "kind": w.Kind})
	return w.ID, nil
}

func (a *App) DeleteWindow(ctx context.Context, actor Actor, id string) error {
	ct, _ := a.DB.Exec(ctx, `delete from windows where id=$1`, id)
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "window.delete", "window", id, nil)
	return nil
}

// WinStatus – bieżący stan okien grupy.
type WinStatus struct {
	Open       bool       `json:"open"`
	Kind       string     `json:"kind"`
	RateFactor float64    `json:"rate_factor"`
	Mode       string     `json:"mode,omitempty"`
	Remaining  int        `json:"remaining_sec"` // -1 = bez limitu
	NextOpen   *time.Time `json:"next_open,omitempty"`
	ClosesAt   *time.Time `json:"closes_at,omitempty"`
	HasWindows bool       `json:"has_windows"`
}

// EvalWindows ocenia okna w strefie loc (obsługa przejścia przez północ i zmiany czasu).
func EvalWindows(ws []Window, loc *time.Location, always bool, now time.Time) WinStatus {
	if len(ws) == 0 {
		if always {
			return WinStatus{Open: true, Kind: "full", RateFactor: 1, Remaining: -1}
		}
		return WinStatus{Open: false, Remaining: 0}
	}
	st := WinStatus{HasWindows: true}
	local := now.In(loc)
	type inst struct {
		start, end time.Time
		w          Window
	}
	instances := func(day time.Time) []inst {
		var out []inst
		wd := (int(day.Weekday()) + 6) % 7 // 0 = poniedziałek
		for _, w := range ws {
			if w.DaysMask&(1<<wd) == 0 {
				continue
			}
			base := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, loc)
			s := base.Add(time.Duration(w.StartMin) * time.Minute)
			e := base.Add(time.Duration(w.EndMin) * time.Minute)
			if w.EndMin <= w.StartMin {
				e = base.AddDate(0, 0, 1).Add(time.Duration(w.EndMin) * time.Minute)
			}
			out = append(out, inst{s, e, w})
		}
		return out
	}
	var best *inst
	for d := -1; d <= 0; d++ {
		for _, in := range instances(local.AddDate(0, 0, d)) {
			if !local.Before(in.start) && local.Before(in.end) {
				// pierwszeństwo: okno pełne nad low_impact; dłuższe nad krótszym
				if best == nil || (best.w.Kind == "low_impact" && in.w.Kind == "full") || (best.w.Kind == in.w.Kind && in.end.After(best.end)) {
					c := in
					best = &c
				}
			}
		}
	}
	if best != nil {
		st.Open = true
		st.Kind = best.w.Kind
		st.RateFactor = best.w.RateFactor
		st.Mode = best.w.Mode
		st.Remaining = int(best.end.Sub(local).Seconds())
		ce := best.end.UTC()
		st.ClosesAt = &ce
		return st
	}
	for d := 0; d <= 8; d++ {
		var cands []time.Time
		for _, in := range instances(local.AddDate(0, 0, d)) {
			if in.start.After(local) {
				cands = append(cands, in.start)
			}
		}
		if len(cands) > 0 {
			sort.Slice(cands, func(i, j int) bool { return cands[i].Before(cands[j]) })
			n := cands[0].UTC()
			st.NextOpen = &n
			break
		}
	}
	return st
}

func (a *App) WindowStatus(ctx context.Context, groupID string, now time.Time) (*WinStatus, error) {
	var tz string
	var always bool
	if err := a.DB.QueryRow(ctx, `select timezone, always_allowed from target_groups where id=$1`, groupID).Scan(&tz, &always); err != nil {
		return nil, ErrNotFound
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	ws, err := a.ListWindows(ctx, groupID)
	if err != nil {
		return nil, err
	}
	st := EvalWindows(ws, loc, always, now)
	return &st, nil
}

// ---------------- harmonogramy ----------------

type Schedule struct {
	ID            string     `json:"id"`
	GroupID       string     `json:"group_id"`
	GroupName     string     `json:"group_name"`
	ProfileID     string     `json:"profile_id"`
	Cron          string     `json:"cron"`
	Mode          string     `json:"mode"`
	OverlapPolicy string     `json:"overlap_policy"`
	Enabled       bool       `json:"enabled"`
	LastFiredAt   *time.Time `json:"last_fired_at"`
	NextFireAt    *time.Time `json:"next_fire_at"`
	NextRuns      []string   `json:"next_runs,omitempty"`
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

func nextFire(expr, tz string, after time.Time) (time.Time, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	sch, err := cronParser.Parse(expr)
	if err != nil {
		return time.Time{}, err
	}
	return sch.Next(after.In(loc)).UTC(), nil
}

func (a *App) ListSchedules(ctx context.Context, groupID string) ([]Schedule, error) {
	rows, err := a.DB.Query(ctx, `select s.id, s.group_id, g.name, coalesce(s.profile_id::text,''), s.cron, s.mode, s.overlap_policy, s.enabled, s.last_fired_at, s.next_fire_at, g.timezone
		from schedules s join target_groups g on g.id=s.group_id where ($1='' or s.group_id::text=$1) order by g.name, s.cron`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Schedule, error) {
		var s Schedule
		var tz string
		err := r.Scan(&s.ID, &s.GroupID, &s.GroupName, &s.ProfileID, &s.Cron, &s.Mode, &s.OverlapPolicy, &s.Enabled, &s.LastFiredAt, &s.NextFireAt, &tz)
		t := time.Now()
		for i := 0; i < 3; i++ {
			n, err := nextFire(s.Cron, tz, t)
			if err != nil {
				break
			}
			loc, _ := time.LoadLocation(tz)
			s.NextRuns = append(s.NextRuns, n.In(loc).Format("2006-01-02 15:04"))
			t = n
		}
		return s, err
	})
}

var validModes = map[string]bool{"baseline": true, "differential": true, "liveness": true}

func (a *App) SaveSchedule(ctx context.Context, actor Actor, s Schedule) (string, error) {
	if !validModes[s.Mode] {
		s.Mode = "baseline"
	}
	if s.OverlapPolicy != "skip" && s.OverlapPolicy != "supersede" && s.OverlapPolicy != "queue" {
		s.OverlapPolicy = "skip"
	}
	g, err := a.GetGroup(ctx, s.GroupID)
	if err != nil {
		return "", err
	}
	n, err := nextFire(s.Cron, g.Timezone, time.Now())
	if err != nil {
		return "", Invalid("niepoprawne wyrażenie CRON: "+err.Error(), nil)
	}
	if s.ID == "" {
		err = a.DB.QueryRow(ctx, `insert into schedules(group_id,profile_id,cron,mode,overlap_policy,enabled,next_fire_at) values($1,$2,$3,$4,$5,$6,$7) returning id`,
			s.GroupID, nullUUID(s.ProfileID), s.Cron, s.Mode, s.OverlapPolicy, s.Enabled, n).Scan(&s.ID)
	} else {
		var ct interface{ RowsAffected() int64 }
		ct, err = a.DB.Exec(ctx, `update schedules set profile_id=$2,cron=$3,mode=$4,overlap_policy=$5,enabled=$6,next_fire_at=$7 where id=$1`,
			s.ID, nullUUID(s.ProfileID), s.Cron, s.Mode, s.OverlapPolicy, s.Enabled, n)
		if err == nil && ct.RowsAffected() == 0 {
			return "", ErrNotFound
		}
	}
	if err != nil {
		return "", err
	}
	a.Audit(ctx, actor, "schedule.save", "schedule", s.ID, map[string]any{"cron": s.Cron, "mode": s.Mode, "group": g.Name})
	return s.ID, nil
}

func (a *App) DeleteSchedule(ctx context.Context, actor Actor, id string) error {
	ct, _ := a.DB.Exec(ctx, `delete from schedules where id=$1`, id)
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "schedule.delete", "schedule", id, nil)
	return nil
}

var errNoRows = pgx.ErrNoRows

func isNoRows(err error) bool { return errors.Is(err, errNoRows) }
