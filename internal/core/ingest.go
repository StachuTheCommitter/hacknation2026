package core

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"asi/internal/model"
	"asi/internal/netx"
	"asi/internal/obs"
)

// ingestCtx – kontekst zapisu obserwacji (przebieg, źródło).
type ingestCtx struct {
	runID    string
	groupID  string
	taskID   string
	worker   string
	source   string
	baseline bool // pierwszy przebieg grupy: zmiany zapisujemy z priorytetem 0
	runStart time.Time
	at       time.Time // znacznik czasu zmian (import historyczny); zero = teraz
	changes  []pendingChange
}

type pendingChange struct {
	entityType, entityKey, hostIP, changeType, summary string
	diff                                               []FieldDiff
	base                                               int
	scoreOf                                            func() int
}

type FieldDiff struct {
	Field string `json:"field"`
	Old   any    `json:"old"`
	New   any    `json:"new"`
}

func (ic *ingestCtx) change(entityType, key, ip, typ, summary string, base int, diff []FieldDiff, score func() int) {
	ic.changes = append(ic.changes, pendingChange{entityType, key, ip, typ, summary, diff, base, score})
}

func (a *App) newIngestCtx(ctx context.Context, run *Run, taskID, worker, source string) *ingestCtx {
	ic := &ingestCtx{runID: run.ID, groupID: run.GroupID, taskID: taskID, worker: worker, source: source, runStart: run.CreatedAt}
	if source != "scanner" && run.StartedAt != nil && time.Since(*run.StartedAt) > time.Minute {
		ic.at = *run.StartedAt
	}
	if run.GroupID != "" && source == "scanner" {
		var n int
		a.DB.QueryRow(ctx, `select count(*) from scan_runs where group_id=$1 and source='scanner' and status in ('COMPLETED','SUPERSEDED') and id<>$2`, run.GroupID, run.ID).Scan(&n)
		ic.baseline = n == 0
	}
	return ic
}

// flushChanges zapisuje zebrane zmiany z priorytetem zależnym od oceny encji.
func (a *App) flushChanges(ctx context.Context, ic *ingestCtx) {
	for _, c := range ic.changes {
		prio := c.base
		if c.scoreOf != nil {
			prio += c.scoreOf() / 2
		}
		if ic.baseline {
			prio = 0
		}
		var ip any
		if c.hostIP != "" {
			ip = c.hostIP
		}
		if c.diff == nil {
			c.diff = []FieldDiff{}
		}
		at := time.Now()
		if !ic.at.IsZero() {
			at = ic.at
		}
		a.DB.Exec(ctx, `insert into changes(run_id,entity_type,entity_key,host_ip,change_type,summary,diff,priority,at) values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			nullUUID(ic.runID), c.entityType, c.entityKey, ip, c.changeType, c.summary, jsonb(c.diff), min(prio, 100), at)
	}
	if len(ic.changes) > 0 {
		a.Events.Publish("changes", map[string]any{"count": len(ic.changes)})
	}
	ic.changes = nil
}

// ---------------- sweep / retry ----------------

func (a *App) ingestSweep(ctx context.Context, run *Run, taskID, worker string, res *model.Result, retry bool) error {
	ic := a.newIngestCtx(ctx, run, taskID, worker, "scanner")
	cov := res.Coverage
	if !retry {
		a.DB.Exec(ctx, `insert into run_coverage(run_id,task_id,ranges,ips,tcp_ports,udp_ports,stages) values($1,$2,$3,$4,$5,$6,$7)`,
			run.ID, taskID, jsonb(cov.Ranges), nonNil(cov.IPs), cov.TCPPorts, cov.UDPPorts, nonNil(cov.Stages))
	}
	now := time.Now().UTC()
	var probeHosts []model.ProbeHost
	for _, h := range res.Hosts {
		if !h.Up {
			continue
		}
		up := true
		o := obs.Observation{ObservedAt: now, Source: "scanner", Host: obs.Host{IP: h.IP, Up: &up, UpReason: h.Reason, MAC: h.MAC}, Retry: retry}
		if h.PTR != "" {
			o.Host.Hostnames = []obs.Hostname{{Name: h.PTR, Source: "ptr"}}
		}
		hostID, _, err := a.upsertHost(ctx, ic, &o)
		if err != nil {
			return err
		}
		var ports []model.ProbePort
		for _, p := range h.Ports {
			svcID, isNew, prevProbed, err := a.touchService(ctx, ic, hostID, h.IP, p.Proto, p.Port, now, retry)
			if err != nil {
				return err
			}
			_ = svcID
			pp := model.ProbePort{Proto: p.Proto, Port: p.Port}
			if run.Mode == "differential" && !isNew && prevProbed {
				pp.Known = true
			}
			ports = append(ports, pp)
		}
		a.recordHostObs(ctx, ic, hostID, o.Host, portKeys(h.Ports), retry)
		if retry || len(ports) == 0 {
			continue
		}
		if run.Mode == "liveness" {
			var state string
			var firstSeen time.Time
			a.DB.QueryRow(ctx, `select state, first_seen from hosts where id=$1`, hostID).Scan(&state, &firstSeen)
			if state == "ACTIVE" && firstSeen.Before(run.CreatedAt) {
				var seenRecently bool
				a.DB.QueryRow(ctx, `select exists(select 1 from availability_history where entity_id=$1 and up and at > now()-interval '24 hours')`, hostID).Scan(&seenRecently)
				if seenRecently {
					continue // znany i widziany niedawno – w oknie dziennym tylko potwierdzamy dostępność
				}
			}
		}
		ph := model.ProbeHost{IP: h.IP, Ports: ports}
		rows, _ := a.DB.Query(ctx, `select name from host_hostnames where host_id=$1 and source in ('dns','manual','tls_san','http_redirect') order by name limit 10`, hostID)
		for rows.Next() {
			var n string
			rows.Scan(&n)
			ph.Hostnames = append(ph.Hostnames, n)
		}
		rows.Close()
		probeHosts = append(probeHosts, ph)
	}
	a.flushChanges(ctx, ic)
	return a.enqueueProbes(ctx, run, probeHosts)
}

func portKeys(ps []model.PortHit) []string {
	var out []string
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s/%d", p.Proto, p.Port))
	}
	return out
}

// enqueueProbes dzieli hosty na zadania probe (limit hostów i portów na zadanie).
func (a *App) enqueueProbes(ctx context.Context, run *Run, hosts []model.ProbeHost) error {
	batch := max(run.Profile.MaxProbeHostsBatch, 1)
	var cur []model.ProbeHost
	ports := 0
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		_, err := a.insertTask(ctx, run.ID, model.TaskProbe, model.Payload{Hosts: cur}, time.Now(), len(cur))
		cur, ports = nil, 0
		return err
	}
	for _, h := range hosts {
		if len(cur) >= batch || ports+len(h.Ports) > 200 {
			if err := flush(); err != nil {
				return err
			}
		}
		cur = append(cur, h)
		ports += len(h.Ports)
	}
	return flush()
}

// ---------------- DNS ----------------

func (a *App) ingestDNS(ctx context.Context, run *Run, res *model.Result) error {
	scope, _, _, _ := a.Scope(ctx)
	var add []netx.Range
	for _, rec := range res.DNS {
		for _, ip := range rec.IPs {
			if !scope.Allowed(ip) {
				a.DB.Exec(ctx, `insert into changes(run_id,entity_type,entity_key,change_type,summary,priority) values($1,'host',$2,'DOMAIN_OUT_OF_SCOPE',$3,5)`,
					run.ID, rec.Name, fmt.Sprintf("%s → %s (poza scope, nie skanowano)", rec.Name, ip))
				continue
			}
			t, err := netx.ParseTarget(ip)
			if err != nil || len(t.Ranges) == 0 {
				continue
			}
			// zapamiętujemy nazwę dla hosta (vhost)
			a.DB.Exec(ctx, `insert into hosts(ip,group_id,state,source) values($1,$2,'SUSPECT','dns') on conflict(ip) do nothing`, ip, nullUUID(run.GroupID))
			a.DB.Exec(ctx, `insert into host_hostnames(host_id,name,source) select id,$2,'dns' from hosts where ip=$1 on conflict(host_id,name) do update set last_seen=now()`, ip, rec.Name)
			a.refreshHostnames(ctx, ip)
			if !netx.ContainsU32(run.ranges, t.Ranges[0].Start) {
				add = append(add, t.Ranges...)
			}
		}
	}
	if len(add) > 0 {
		// adresy z DNS spoza zakresów grupy dopisujemy do kursora przebiegu
		nr := append(append([]netx.Range{}, run.ranges...), netx.Merge(add)...)
		a.DB.Exec(ctx, `update scan_runs set ranges=$2, total_addresses=total_addresses+$3 where id=$1`, run.ID, jsonb(nr), netx.Total(netx.Merge(add)))
	}
	return nil
}

func (a *App) refreshHostnames(ctx context.Context, ip string) {
	a.DB.Exec(ctx, `update hosts set hostnames=coalesce((select array_agg(name order by name) from host_hostnames where host_id=hosts.id),'{}') where ip=$1`, ip)
}

// ---------------- probe ----------------

func (a *App) ingestProbe(ctx context.Context, run *Run, taskID, worker string, res *model.Result) error {
	ic := a.newIngestCtx(ctx, run, taskID, worker, "scanner")
	var rescan []model.ProbeHost
	for i := range res.Observations {
		o := res.Observations[i]
		o.Source = "scanner"
		if errs := obs.Normalize(&o, ""); len(errs) > 0 {
			continue
		}
		drift, err := a.ingestObservation(ctx, ic, &o)
		if err != nil {
			return err
		}
		if len(drift) > 0 && run.Mode == "differential" {
			rescan = append(rescan, model.ProbeHost{IP: o.Host.IP, Ports: drift})
		}
	}
	a.DB.Exec(ctx, `insert into run_coverage(run_id,task_id,stages) values($1,$2,'{probe}')`, run.ID, taskID)
	a.flushChanges(ctx, ic)
	// wykryto podmianę usługi na znanym porcie → pełny pomiar tylko tego hosta
	return a.enqueueProbes(ctx, run, rescan)
}

// ---------------- encje ----------------

func (a *App) upsertHost(ctx context.Context, ic *ingestCtx, o *obs.Observation) (string, bool, error) {
	h := o.Host
	var id string
	var inserted bool
	state := "ACTIVE"
	if !h.IsUp() {
		state = "SUSPECT"
	}
	err := a.DB.QueryRow(ctx, `insert into hosts(ip,group_id,state,first_seen,last_seen,last_run_id,source,os,devicetype)
		values($1,$2,$3,$4,$4,$5,$6,$7,$8)
		on conflict(ip) do update set
		  last_seen = case when $9 then greatest(hosts.last_seen,excluded.last_seen) else hosts.last_seen end,
		  last_run_id = coalesce(excluded.last_run_id, hosts.last_run_id),
		  group_id = coalesce(hosts.group_id, excluded.group_id),
		  state = case when hosts.source='dns' and $9 then 'ACTIVE' else hosts.state end,
		  source = case when hosts.source='dns' and $9 then excluded.source else hosts.source end,
		  os = coalesce(nullif(excluded.os,''), hosts.os),
		  devicetype = coalesce(nullif(excluded.devicetype,''), hosts.devicetype)
		returning id, (xmax = 0)`, h.IP, nullUUID(ic.groupID), state, o.ObservedAt, nullUUID(ic.runID), ic.source, h.OS, h.DeviceType, h.IsUp()).Scan(&id, &inserted)
	if err != nil {
		return "", false, err
	}
	for _, hn := range h.Hostnames {
		if hn.Name == "" {
			continue
		}
		a.DB.Exec(ctx, `insert into host_hostnames(host_id,name,source) values($1,$2,$3) on conflict(host_id,name) do update set last_seen=now()`, id, hn.Name, hn.Source)
	}
	if len(h.Hostnames) > 0 {
		a.refreshHostnames(ctx, h.IP)
	}
	if h.SSHHostkeyFP != "" {
		var prev string
		a.DB.QueryRow(ctx, `select coalesce(identity->>'ssh_hostkey','') from hosts where id=$1`, id).Scan(&prev)
		if prev != "" && prev != h.SSHHostkeyFP {
			ic.change("host", h.IP, h.IP, "IDENTITY_CHANGED", "Zmienił się klucz SSH hosta – pod tym adresem może działać inne urządzenie", 20,
				[]FieldDiff{{"ssh_hostkey", prev, h.SSHHostkeyFP}}, nil)
		}
		a.DB.Exec(ctx, `update hosts set identity=identity||jsonb_build_object('ssh_hostkey',$2::text) where id=$1`, id, h.SSHHostkeyFP)
	}
	if inserted && h.IsUp() {
		ic.change("host", h.IP, h.IP, "HOST_NEW", "Nowy host "+h.IP, 15, nil, func() int { return a.hostScore(ctx, id) })
	}
	return id, inserted, nil
}

func (a *App) recordHostObs(ctx context.Context, ic *ingestCtx, hostID string, h obs.Host, ports []string, retry bool) {
	st := obs.HostStable(h, ports)
	a.DB.Exec(ctx, `insert into observations(run_id,task_id,observed_at,source,worker,entity_type,entity_key,up,stable,stable_fp,recovered_on_retry)
		values($1,$2,now(),$3,$4,'host',$5,$6,$7,$8,$9)`, nullUUID(ic.runID), nullUUID(ic.taskID), ic.source, ic.worker, h.IP, h.IsUp(), jsonb(st),
		a.Keys.MAC(obs.Canonical(st)), retry)
}

// touchService – usługa zauważona przez skan portów (pomiar minimalny).
func (a *App) touchService(ctx context.Context, ic *ingestCtx, hostID, ip, proto string, port int, at time.Time, retry bool) (string, bool, bool, error) {
	var id string
	var inserted bool
	var probed *time.Time
	err := a.DB.QueryRow(ctx, `insert into services(host_id,proto,port,first_seen,last_seen,last_run_id) values($1,$2,$3,$4,$4,$5)
		on conflict(host_id,proto,port) do update set last_seen=greatest(services.last_seen,excluded.last_seen), last_run_id=coalesce(excluded.last_run_id,services.last_run_id)
		returning id, (xmax=0), probed_at`, hostID, proto, port, at, nullUUID(ic.runID)).Scan(&id, &inserted, &probed)
	if err != nil {
		return "", false, false, err
	}
	key := obs.ServiceKey(ip, proto, port)
	a.DB.Exec(ctx, `insert into observations(run_id,task_id,observed_at,source,worker,entity_type,entity_key,up,recovered_on_retry) values($1,$2,$3,$4,$5,'service',$6,true,$7)`,
		nullUUID(ic.runID), nullUUID(ic.taskID), at, ic.source, ic.worker, key, retry)
	if inserted {
		ic.change("service", key, ip, "SERVICE_NEW", fmt.Sprintf("Nowy otwarty port %s/%d na %s", proto, port, ip), 15, nil, func() int { return a.entityScore(ctx, "services", id) })
	}
	return id, inserted, probed != nil, nil
}

// prevStable – ostatnia pełna obserwacja encji z innego przebiegu (baza porównania).
func (a *App) prevStable(ctx context.Context, key, runID string) (map[string]any, string) {
	var raw []byte
	var fp string
	err := a.DB.QueryRow(ctx, `select stable, stable_fp from observations where entity_key=$1 and stable_fp<>'' and up and (run_id is distinct from $2)
		order by observed_at desc, id desc limit 1`, key, nullUUID(runID)).Scan(&raw, &fp)
	if err != nil {
		return nil, ""
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m, fp
}

// diffStable porównuje dwie mapy pól stabilnych.
func diffStable(old, new map[string]any) []FieldDiff {
	var out []FieldDiff
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range new {
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		o, n := normalizeVal(old[k]), normalizeVal(new[k])
		if !reflect.DeepEqual(o, n) {
			out = append(out, FieldDiff{k, o, n})
		}
	}
	return out
}

func normalizeVal(v any) any {
	b, _ := json.Marshal(v)
	var out any
	json.Unmarshal(b, &out)
	switch x := out.(type) {
	case nil:
		return ""
	case []any:
		if len(x) == 0 {
			return ""
		}
	}
	return out
}

// IngestObservation – wspólny pipeline obserwacji (skaner, formularz, import). Zwraca porty z wykrytą podmianą usługi.
func (a *App) ingestObservation(ctx context.Context, ic *ingestCtx, o *obs.Observation) ([]model.ProbePort, error) {
	hostID, _, err := a.upsertHost(ctx, ic, o)
	if err != nil {
		return nil, err
	}
	var portKeysUp []string
	var drift []model.ProbePort
	hostnames := hostNames(ctx, a, hostID)
	for si := range o.Services {
		s := &o.Services[si]
		up := s.IsOpen() && o.Host.IsUp()
		if up {
			portKeysUp = append(portKeysUp, fmt.Sprintf("%s/%d", s.Proto, s.Port))
		}
		svcID, changedHTTP, err := a.upsertService(ctx, ic, hostID, o, s, hostnames)
		if err != nil {
			return nil, err
		}
		if changedHTTP && s.Light {
			drift = append(drift, model.ProbePort{Proto: s.Proto, Port: s.Port})
		}
		_ = svcID
	}
	if ic.source != "scanner" || len(o.Services) > 0 {
		a.recordHostObs(ctx, ic, hostID, o.Host, portKeysUp, o.Retry)
	}
	a.analyzeHost(ctx, ic, hostID)
	return drift, nil
}

func hostNames(ctx context.Context, a *App, hostID string) []string {
	var names []string
	a.DB.QueryRow(ctx, `select hostnames from hosts where id=$1`, hostID).Scan(&names)
	return names
}

// serviceRaw – dane surowe usługi (szyfrowane).
type serviceRaw struct {
	Banner  string            `json:"banner,omitempty"`
	Scripts map[string]string `json:"scripts,omitempty"`
	TLS     *obs.TLS          `json:"tls,omitempty"`
	CPE     []string          `json:"cpe,omitempty"`
}

func (a *App) upsertService(ctx context.Context, ic *ingestCtx, hostID string, o *obs.Observation, s *obs.Service, hostnames []string) (string, bool, error) {
	ip := o.Host.IP
	key := obs.ServiceKey(ip, s.Proto, s.Port)
	up := s.IsOpen() && o.Host.IsUp()
	var id string
	var inserted bool
	var probed *time.Time
	err := a.DB.QueryRow(ctx, `insert into services(host_id,proto,port,first_seen,last_seen,last_run_id) values($1,$2,$3,$4,$4,$5)
		on conflict(host_id,proto,port) do update set
		  last_seen = case when $6 then greatest(services.last_seen,excluded.last_seen) else services.last_seen end,
		  last_run_id = coalesce(excluded.last_run_id,services.last_run_id)
		returning id,(xmax=0),probed_at`, hostID, s.Proto, s.Port, o.ObservedAt, nullUUID(ic.runID), up).Scan(&id, &inserted, &probed)
	if err != nil {
		return "", false, err
	}
	if !up {
		a.DB.Exec(ctx, `insert into observations(run_id,task_id,observed_at,source,worker,entity_type,entity_key,up) values($1,$2,$3,$4,$5,'service',$6,false)`,
			nullUUID(ic.runID), nullUUID(ic.taskID), o.ObservedAt, ic.source, ic.worker, key)
		return id, false, nil
	}
	if inserted && ic.source != "scanner" {
		ic.change("service", key, ip, "SERVICE_NEW", fmt.Sprintf("Nowa usługa %s/%d na %s (%s)", s.Proto, s.Port, ip, ic.source), 15, nil,
			func() int { return a.entityScore(ctx, "services", id) })
	}
	light := s.Light && probed != nil
	bannerDrift := false
	var stable map[string]any
	var fp string
	if light {
		stable, fp = a.prevStable(ctx, key, ic.runID)
		// podmiana usługi poza HTTP: inny baner niż przy ostatnim pełnym pomiarze → pełny pomiar hosta
		if s.Banner != "" {
			var ct []byte
			a.DB.QueryRow(ctx, `select raw_enc from services where id=$1`, id).Scan(&ct)
			if pt, err := a.Keys.Decrypt("services.raw_enc:"+id, ct); err == nil && len(pt) > 0 {
				var prev serviceRaw
				json.Unmarshal(pt, &prev)
				old := strings.TrimSpace(strings.SplitN(prev.Banner, "\n", 2)[0])
				if old != "" && old != s.Banner {
					bannerDrift = true
				}
			}
		}
	} else {
		raw := serviceRaw{Banner: s.Banner, Scripts: s.Scripts, TLS: s.TLS, CPE: s.CPE}
		rawEnc, _ := a.Keys.Encrypt("services.raw_enc:"+id, jsonb(raw))
		method, conf := "", 0
		if s.Nmap != nil {
			method, conf = s.Nmap.Method, s.Nmap.Conf
		}
		var tlsSum any
		if s.TLS != nil {
			tlsSum = tlsSummary(s.TLS)
		}
		_, err = a.DB.Exec(ctx, `update services set service_name=$2, product=$3, version=$4, extrainfo=$5, devicetype=$6, cpe=$7, tunnel=$8,
			nmap_method=$9, nmap_conf=$10, tls=$11, raw_enc=$12, probed_at=$13 where id=$1`,
			id, s.Service, s.Product, s.Version, s.ExtraInfo, s.DeviceType, nonNil(s.CPE), s.Tunnel, method, conf, tlsSum, rawEnc, o.ObservedAt)
		if err != nil {
			return "", false, err
		}
		stable = obs.ServiceStable(*s)
		fp = a.Keys.MAC(obs.Canonical(stable))
		if prev, prevFP := a.prevStable(ctx, key, ic.runID); prevFP != "" && prevFP != fp {
			d := diffStable(prev, stable)
			if len(d) > 0 {
				ic.change("service", key, ip, "SERVICE_CHANGED", fmt.Sprintf("Zmiana usługi %s/%d na %s: %s", s.Proto, s.Port, ip, fieldList(d)), 10, d,
					func() int { return a.entityScore(ctx, "services", id) })
			}
		}
		a.DB.Exec(ctx, `update services set stable_fp=$2 where id=$1`, id, fp)
	}
	a.DB.Exec(ctx, `insert into observations(run_id,task_id,observed_at,source,worker,entity_type,entity_key,up,stable,stable_fp,recovered_on_retry)
		values($1,$2,$3,$4,$5,'service',$6,true,$7,$8,$9)`, nullUUID(ic.runID), nullUUID(ic.taskID), o.ObservedAt, ic.source, ic.worker, key, jsonb(stable), fp, o.Retry)

	changedHTTP := false
	for hi := range s.HTTP {
		ch, err := a.upsertHTTP(ctx, ic, hostID, id, ip, s, &s.HTTP[hi], hostnames, o.ObservedAt)
		if err != nil {
			return "", false, err
		}
		changedHTTP = changedHTTP || ch
	}
	a.analyzeService(ctx, ic, hostID, id, ip, s, hostnames, light)
	return id, changedHTTP || bannerDrift, nil
}

func fieldList(d []FieldDiff) string {
	var f []string
	for _, x := range d {
		f = append(f, x.Field)
	}
	return strings.Join(f, ", ")
}

func tlsSummary(t *obs.TLS) map[string]any {
	if t == nil {
		return nil
	}
	return map[string]any{"subject_cn": t.SubjectCN, "issuer": t.Issuer, "not_after": t.NotAfter, "self_signed": t.SelfSigned,
		"version": t.Version, "san": t.SAN, "trusted": t.Trusted, "expired": t.Expired(time.Now()), "days_left": t.DaysLeft(time.Now())}
}

// httpRaw – dane surowe endpointu (szyfrowane).
type httpRaw struct {
	Headers       obs.Headers      `json:"headers,omitempty"`
	Cookies       []obs.Cookie     `json:"cookies,omitempty"`
	RedirectChain []obs.Redirect   `json:"redirect_chain,omitempty"`
	BodySnippet   string           `json:"body_snippet,omitempty"`
	Paths         []obs.PathResult `json:"paths,omitempty"`
	Soft404       *obs.Baseline    `json:"soft404_baseline,omitempty"`
	TLS           *obs.TLS         `json:"tls,omitempty"`
	ResponseMs    int              `json:"response_ms,omitempty"`
}

const maxSnippet = 64 * 1024

func (a *App) loadHTTPRaw(ctx context.Context, id string) *httpRaw {
	var ct []byte
	if a.DB.QueryRow(ctx, `select raw_enc from http_endpoints where id=$1`, id).Scan(&ct) != nil || len(ct) == 0 {
		return nil
	}
	pt, err := a.Keys.Decrypt("http_endpoints.raw_enc:"+id, ct)
	if err != nil {
		return nil
	}
	var r httpRaw
	json.Unmarshal(pt, &r)
	return &r
}

func (a *App) upsertHTTP(ctx context.Context, ic *ingestCtx, hostID, svcID, ip string, s *obs.Service, h *obs.HTTP, hostnames []string, at time.Time) (bool, error) {
	key := obs.HTTPKey(ip, s.Port, h.Scheme, h.Vhost)
	var id string
	var inserted bool
	if h.URL == "" {
		host := ip
		if h.Vhost != "" {
			host = h.Vhost
		}
		h.URL = fmt.Sprintf("%s://%s:%d/", h.Scheme, host, s.Port)
	}
	err := a.DB.QueryRow(ctx, `insert into http_endpoints(service_id,host_id,vhost,scheme,url,first_seen,last_seen,last_run_id) values($1,$2,$3,$4,$5,$6,$6,$7)
		on conflict(service_id,scheme,vhost) do update set last_seen=greatest(http_endpoints.last_seen,excluded.last_seen), last_run_id=coalesce(excluded.last_run_id,http_endpoints.last_run_id), url=excluded.url
		returning id,(xmax=0)`, svcID, hostID, h.Vhost, h.Scheme, h.URL, at, nullUUID(ic.runID)).Scan(&id, &inserted)
	if err != nil {
		return false, err
	}
	if h.Light { // tryb szybki: przenosimy ścieżki, faviconę i bazę soft-404 z poprzedniego pomiaru
		if prev := a.loadHTTPRaw(ctx, id); prev != nil {
			h.Paths, h.Soft404 = prev.Paths, prev.Soft404
		}
		if h.FaviconMMH3 == "" {
			a.DB.QueryRow(ctx, `select favicon_mmh3 from http_endpoints where id=$1`, id).Scan(&h.FaviconMMH3)
		}
	}
	if !h.CleartextLogin && h.Scheme == "http" && len(h.RedirectChain) == 0 && passwordRe.MatchString(h.Body+h.BodySnippet) {
		h.CleartextLogin = true
	}
	if h.TLS == nil && s.TLS != nil && h.Scheme == "https" {
		h.TLS = s.TLS
	}
	snippet := h.BodySnippet
	if snippet == "" {
		snippet = h.Body
	}
	if len(snippet) > maxSnippet {
		snippet = snippet[:maxSnippet]
	}
	paths := make([]obs.PathResult, len(h.Paths))
	for i, p := range h.Paths {
		p.Body = truncate(p.Body, 16*1024)
		paths[i] = p
	}
	raw := httpRaw{Headers: h.Headers, Cookies: h.Cookies, RedirectChain: h.RedirectChain, BodySnippet: snippet, Paths: paths, Soft404: h.Soft404, TLS: h.TLS, ResponseMs: h.ResponseMs}
	rawEnc, _ := a.Keys.Encrypt("http_endpoints.raw_enc:"+id, jsonb(raw))
	type cm struct {
		Name     string `json:"name"`
		Secure   bool   `json:"secure"`
		HTTPOnly bool   `json:"httponly"`
		SameSite string `json:"samesite,omitempty"`
	}
	var cookies []cm
	for _, c := range h.Cookies {
		cookies = append(cookies, cm{c.Name, c.Secure, c.HTTPOnly, c.SameSite})
	}
	if cookies == nil {
		cookies = []cm{}
	}
	var tlsSum any
	if h.TLS != nil {
		tlsSum = tlsSummary(h.TLS)
	}
	bodyMAC := ""
	if h.BodySHA256 != "" {
		bodyMAC = a.Keys.MAC(h.BodySHA256)
	}
	_, err = a.DB.Exec(ctx, `update http_endpoints set status_code=$2,title=$3,server=$4,powered_by=$5,header_names=$6,cookie_meta=$7,final_url=$8,
		favicon_mmh3=$9, body_hmac=$10, tls=$11, raw_enc=$12 where id=$1`, id, h.Status, truncate(h.Title, 300), h.Headers.Get("Server"), h.Headers.Get("X-Powered-By"),
		nonNil(h.Headers.Names()), jsonb(cookies), h.FinalURL, h.FaviconMMH3, bodyMAC, tlsSum, rawEnc)
	if err != nil {
		return false, err
	}
	if inserted && ic.source != "scanner" {
		ic.change("http", key, ip, "SERVICE_NEW", "Nowy endpoint WWW "+h.URL, 10, nil, nil)
	}
	techs := a.analyzeHTTP(ctx, ic, hostID, id, key, ip, s.Port, h, hostnames, inserted)
	stable := obs.HTTPStable(*h, techs)
	fp := a.Keys.MAC(obs.Canonical(stable))
	changed := false
	if prev, prevFP := a.prevStable(ctx, key, ic.runID); prevFP != "" && prevFP != fp {
		d := diffStable(prev, stable)
		if len(d) > 0 {
			changed = true
			typ := "HTTP_CHANGED"
			onlyTLS := true
			for _, x := range d {
				if !strings.HasPrefix(x.Field, "tls_") {
					onlyTLS = false
				}
			}
			if onlyTLS {
				typ = "TLS_CHANGED"
			}
			ic.change("http", key, ip, typ, fmt.Sprintf("Zmiana %s: %s", h.URL, fieldList(d)), 10, d, func() int { return a.entityScore(ctx, "http_endpoints", id) })
			a.DB.Exec(ctx, `update http_endpoints set fp_changes = (fp_changes || 1)[greatest(array_length(fp_changes,1)-3,1):] where id=$1`, id)
		}
	} else if prevFP != "" {
		a.DB.Exec(ctx, `update http_endpoints set fp_changes = (fp_changes || 0)[greatest(array_length(fp_changes,1)-3,1):] where id=$1`, id)
	}
	a.DB.Exec(ctx, `update http_endpoints set stable_fp=$2 where id=$1`, id, fp)
	a.DB.Exec(ctx, `insert into observations(run_id,task_id,observed_at,source,worker,entity_type,entity_key,up,stable,stable_fp)
		values($1,$2,$3,$4,$5,'http',$6,true,$7,$8)`, nullUUID(ic.runID), nullUUID(ic.taskID), at, ic.source, ic.worker, key, jsonb(stable), fp)
	// nazwy z certyfikatu – kandydaci na vhosty
	if h.TLS != nil {
		for _, n := range append([]string{h.TLS.SubjectCN}, h.TLS.SAN...) {
			n = strings.ToLower(strings.TrimPrefix(n, "*."))
			if n != "" && strings.Contains(n, ".") && !strings.ContainsAny(n, " *") {
				a.DB.Exec(ctx, `insert into host_hostnames(host_id,name,source) values($1,$2,'tls_san') on conflict(host_id,name) do update set last_seen=now()`, hostID, n)
			}
		}
		a.refreshHostnames(ctx, ip)
	}
	return changed, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
