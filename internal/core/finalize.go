package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"asi/internal/model"
	"asi/internal/netx"
	"asi/internal/obs"
)

// ---------------- pokrycie przebiegu ----------------

type Coverage struct {
	Ranges   []netx.Range
	IPs      map[string]bool
	TCP      netx.PortSet
	UDP      netx.PortSet
	Entities map[string]bool
	Probed   bool
}

func (a *App) runCoverage(ctx context.Context, runID string) *Coverage {
	c := &Coverage{IPs: map[string]bool{}, TCP: netx.PortSet{}, UDP: netx.PortSet{}, Entities: map[string]bool{}}
	rows, err := a.DB.Query(ctx, `select ranges, ips, tcp_ports, udp_ports, entities, stages from run_coverage where run_id=$1`, runID)
	if err != nil {
		return c
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var ips, ents, stages []string
		var tcp, udp string
		rows.Scan(&raw, &ips, &tcp, &udp, &ents, &stages)
		var rs []netx.Range
		json.Unmarshal(raw, &rs)
		c.Ranges = append(c.Ranges, rs...)
		for _, ip := range ips {
			c.IPs[ip] = true
		}
		for p := range netx.NewPortSet(tcp) {
			c.TCP[p] = true
		}
		for p := range netx.NewPortSet(udp) {
			c.UDP[p] = true
		}
		for _, e := range ents {
			c.Entities[e] = true
		}
		for _, s := range stages {
			if s == "probe" {
				c.Probed = true
			}
		}
	}
	c.Ranges = netx.Merge(c.Ranges)
	return c
}

func (c *Coverage) HasIP(ip string) bool { return c.IPs[ip] || netx.Contains(c.Ranges, ip) }

// Covers – czy przebieg mierzył daną encję (klucz naturalny).
func (c *Coverage) Covers(key string) bool {
	if c.Entities[key] {
		return true
	}
	p := strings.Split(key, "/")
	if len(p) >= 2 && c.Entities[p[0]] && len(p) < 3 {
		return true
	}
	if !c.HasIP(p[0]) {
		return false
	}
	if len(p) < 3 {
		return true
	}
	port := atoi(p[2])
	if p[1] == "udp" {
		return c.UDP[port]
	}
	if !c.TCP[port] {
		return false
	}
	if len(p) > 3 { // endpoint HTTP – tylko jeśli przebieg sondował usługi
		return c.Probed
	}
	return true
}

// ---------------- sprawdzanie i finalizacja przebiegów ----------------

// CheckRuns przechodzi przez aktywne przebiegi: retry, finalizacja.
func (a *App) CheckRuns(ctx context.Context) {
	a.finalizeMu.Lock()
	defer a.finalizeMu.Unlock()
	rows, err := a.DB.Query(ctx, `select id from scan_runs where status='RUNNING' and source='scanner'`)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		r, err := a.GetRun(ctx, id)
		if err != nil {
			continue
		}
		var open int
		a.DB.QueryRow(ctx, `select count(*) from tasks where run_id=$1 and status in ('pending','leased')`, id).Scan(&open)
		if open > 0 || netx.Remaining(r.ranges, r.cursor) > 0 {
			continue
		}
		if err := a.advanceRun(ctx, r); err != nil {
			slog.Error("finalizacja przebiegu", "run", id, "err", err)
		}
	}
}

// advanceRun: scan → retry1 → retry2 → finalizacja.
func (a *App) advanceRun(ctx context.Context, r *Run) error {
	delays := r.Profile.RetryDelaysSec
	if a.Cfg.DemoMode {
		delays = nil
		for _, d := range a.Th.RetryDelays {
			delays = append(delays, int(d.Seconds()))
		}
	}
	step := 0
	switch r.Phase {
	case "scan":
		step = 0
	case "retry1":
		step = 1
	default:
		step = 2
	}
	if step < len(delays) && step < 2 && r.Mode != "liveness" {
		missing := a.missingEntities(ctx, r)
		if len(missing) > 0 {
			phase := fmt.Sprintf("retry%d", step+1)
			a.DB.Exec(ctx, `update scan_runs set phase=$2 where id=$1`, r.ID, phase)
			nb := time.Now().Add(time.Duration(delays[step]) * time.Second)
			for i := 0; i < len(missing); i += 32 {
				end := min(i+32, len(missing))
				a.insertTask(ctx, r.ID, model.TaskRetry, model.Payload{Hosts: missing[i:end], Retry: step + 1}, nb, end-i)
			}
			slog.Info("powtórny pomiar niestabilnych encji", "run", r.ID, "hosts", len(missing), "phase", phase)
			return nil
		}
	}
	return a.finalizeRun(ctx, r)
}

// missingEntities – znane (ACTIVE/SUSPECT) hosty i usługi z pokrycia, które nie odpowiedziały w tym przebiegu.
func (a *App) missingEntities(ctx context.Context, r *Run) []model.ProbeHost {
	cov := a.runCoverage(ctx, r.ID)
	seen := a.seenKeys(ctx, r.ID)
	rows, err := a.DB.Query(ctx, `select host(h.ip), h.id, coalesce(array_agg(s.proto||'/'||s.port) filter (where s.id is not null and s.state<>'INACTIVE'), '{}')
		from hosts h left join services s on s.host_id=h.id where h.state in ('ACTIVE','SUSPECT') and ($1='' or h.group_id::text=$1) group by h.ip, h.id`, r.GroupID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []model.ProbeHost
	for rows.Next() {
		var ip, id string
		var svcs []string
		rows.Scan(&ip, &id, &svcs)
		if !cov.HasIP(ip) {
			continue
		}
		ph := model.ProbeHost{IP: ip}
		hostMissing := !seen[ip]
		for _, s := range svcs {
			p := strings.SplitN(s, "/", 2)
			key := obs.ServiceKey(ip, p[0], atoi(p[1]))
			if cov.Covers(key) && !seen[key] {
				ph.Ports = append(ph.Ports, model.ProbePort{Proto: p[0], Port: atoi(p[1])})
			}
		}
		if hostMissing || len(ph.Ports) > 0 {
			out = append(out, ph)
		}
	}
	return out
}

// seenKeys – encje widziane (up) w przebiegu.
func (a *App) seenKeys(ctx context.Context, runID string) map[string]bool {
	m := map[string]bool{}
	rows, _ := a.DB.Query(ctx, `select distinct entity_key from observations where run_id=$1 and up`, runID)
	for rows.Next() {
		var k string
		rows.Scan(&k)
		m[k] = true
	}
	rows.Close()
	return m
}

func (a *App) retryKeys(ctx context.Context, runID string) map[string]bool {
	m := map[string]bool{}
	rows, _ := a.DB.Query(ctx, `select distinct entity_key from observations where run_id=$1 and up and recovered_on_retry`, runID)
	for rows.Next() {
		var k string
		rows.Scan(&k)
		m[k] = true
	}
	rows.Close()
	return m
}

func bucketOf(t time.Time, loc *time.Location) (int, bool) {
	l := t.In(loc)
	return l.Hour() / 6, l.Weekday() == time.Saturday || l.Weekday() == time.Sunday
}

var bucketNames = []string{"NOC", "RANO", "POPOŁUDNIE", "WIECZÓR"}

type entityState struct {
	table, etype, id, key, ip, state, labelsStr string
	misses, total                               int
	lastSeen                                    time.Time
	labels                                      []string
}

// finalizeRun – automat stanowy dostępności, flapping, okresowość, zmiany, DefectDojo.
func (a *App) finalizeRun(ctx context.Context, r *Run) error {
	cov := a.runCoverage(ctx, r.ID)
	seen := a.seenKeys(ctx, r.ID)
	retried := a.retryKeys(ctx, r.ID)
	ic := a.newIngestCtx(ctx, r, "", "", r.Source)
	loc := time.UTC
	if r.GroupID != "" {
		var tz string
		a.DB.QueryRow(ctx, `select timezone from target_groups where id=$1`, r.GroupID).Scan(&tz)
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		}
	}
	now := time.Now()
	if r.Source != "scanner" && r.StartedAt != nil {
		now = *r.StartedAt // import historyczny: znacznik czasu pomiaru
	}
	bucket, weekend := bucketOf(now, loc)
	stats := map[string]int{}

	q := `select 'hosts','host',h.id::text, host(h.ip), host(h.ip), h.state, h.consecutive_misses, h.total_seen, h.last_seen, h.labels from hosts h where ($1='' or h.group_id::text=$1 or $2)
	union all select 'services','service',s.id::text, host(h.ip)||'/'||s.proto||'/'||s.port, host(h.ip), s.state, s.consecutive_misses, s.total_seen, s.last_seen, s.labels
	  from services s join hosts h on h.id=s.host_id where ($1='' or h.group_id::text=$1 or $2)
	union all select 'http_endpoints','http',e.id::text, host(h.ip)||'/tcp/'||s.port||'/'||e.scheme||'/'||coalesce(nullif(e.vhost,''),'-'), host(h.ip), e.state, e.consecutive_misses, e.total_seen, e.last_seen, e.labels
	  from http_endpoints e join services s on s.id=e.service_id join hosts h on h.id=e.host_id where ($1='' or h.group_id::text=$1 or $2)`
	rows, err := a.DB.Query(ctx, q, r.GroupID, r.Source != "scanner")
	if err != nil {
		return err
	}
	var ents []entityState
	for rows.Next() {
		var e entityState
		if err := rows.Scan(&e.table, &e.etype, &e.id, &e.key, &e.ip, &e.state, &e.misses, &e.total, &e.lastSeen, &e.labels); err != nil {
			rows.Close()
			return err
		}
		if cov.Covers(e.key) {
			ents = append(ents, e)
		}
	}
	rows.Close()
	hostUp := map[string]bool{}
	for _, e := range ents {
		if e.etype == "host" && seen[e.key] {
			hostUp[e.ip] = true
		}
	}
	for _, e := range ents {
		up := seen[e.key]
		if e.etype != "host" && !hostUp[e.ip] {
			up = false
		}
		retry := retried[e.key]
		a.DB.Exec(ctx, `insert into availability_history(entity_type,entity_id,run_id,at,up,retry,bucket_tod,weekend) values($1,$2,$3,$4,$5,$6,$7,$8)`,
			e.etype, e.id, r.ID, now, up, retry, bucket, weekend)
		per, labels := a.availabilityLabels(ctx, e.id, e.labels)
		newState := e.state
		misses := e.misses
		total := e.total
		if up {
			misses = 0
			total++
			if e.state == "INACTIVE" {
				ic.change(e.etype, e.key, e.ip, map[string]string{"host": "HOST_RETURNED", "service": "SERVICE_RETURNED", "http": "SERVICE_RETURNED"}[e.etype],
					fmt.Sprintf("%s znów odpowiada", e.key), 8, nil, nil)
				stats["returned"]++
			}
			newState = "ACTIVE"
		} else {
			// periodyczne: braki liczą się tylko w kubełkach, w których encja bywa aktywna
			if len(per.Active) == 0 || containsInt(per.Active, bucket) {
				misses++
			}
			kEff, tMin := a.Th.K, a.Th.InactiveAfter
			if total <= 2 {
				kEff, tMin = a.Th.KEphemeral, a.Th.InactiveAfterEphem
			}
			if misses >= kEff && now.Sub(e.lastSeen) >= tMin && a.missesSpanBuckets(ctx, e.id, kEff, per) {
				if e.state != "INACTIVE" {
					typ := map[string]string{"host": "HOST_GONE", "service": "SERVICE_GONE", "http": "SERVICE_GONE"}[e.etype]
					ic.change(e.etype, e.key, e.ip, typ, fmt.Sprintf("%s nie odpowiada (%d kolejne przebiegi) – oznaczono jako nieaktywne", e.key, misses), 10, nil, nil)
					stats["gone"]++
					a.DB.Exec(ctx, `update findings set active=false where entity_key=$1 or entity_key like $1||'/%'`, e.key)
				}
				newState = "INACTIVE"
			} else if e.state != "INACTIVE" {
				newState = "SUSPECT"
			}
		}
		if contains(labels, "FLAPPING") && !contains(e.labels, "FLAPPING") {
			ic.change(e.etype, e.key, e.ip, "STATE_FLAPPING", fmt.Sprintf("%s – niestabilna dostępność (flap rate %.2f)", e.key, per.Flap), 6, nil, nil)
		}
		if per.Label != "" && !containsPrefix(e.labels, "PERIODIC") {
			ic.change(e.etype, e.key, e.ip, "STATE_PERIODIC", fmt.Sprintf("%s – dostępność zależna od pory dnia: %s", e.key, per.Label), 4, nil, nil)
		}
		a.DB.Exec(ctx, fmt.Sprintf(`update %s set state=$2, consecutive_misses=$3, total_seen=$4, labels=$5, flap_score=$6 where id=$1`, e.table),
			e.id, newState, misses, total, nonNil(labels), per.Flap)
		if e.etype == "host" {
			a.DB.Exec(ctx, `update hosts set periodicity=$2 where id=$1`, e.id, jsonb(per))
			if up {
				stats["hosts_up"]++
			}
		}
		if e.etype == "service" && up {
			stats["services_up"]++
		}
	}
	var nNew, nChanged int
	a.DB.QueryRow(ctx, `select count(*) filter (where change_type in ('HOST_NEW','SERVICE_NEW')), count(*) filter (where change_type in ('SERVICE_CHANGED','HTTP_CHANGED','TLS_CHANGED'))
		from changes where run_id=$1`, r.ID).Scan(&nNew, &nChanged)
	stats["new"], stats["changed"] = nNew, nChanged
	a.flushChanges(ctx, ic)
	// oceny hostów po zmianie stanów
	hrows, _ := a.DB.Query(ctx, `select id from hosts where last_run_id=$1`, r.ID)
	var hids []string
	for hrows.Next() {
		var id string
		hrows.Scan(&id)
		hids = append(hids, id)
	}
	hrows.Close()
	for _, id := range hids {
		a.updateHostScore(ctx, id)
	}
	status := "COMPLETED"
	a.DB.Exec(ctx, `update scan_runs set status=$2, finished_at=coalesce(finished_at, now()), phase='done', stats=stats||$3 where id=$1`, r.ID, status, jsonb(stats))
	a.Events.Publish("run", map[string]any{"id": r.ID, "status": status})
	slog.Info("przebieg zakończony", "run", r.ID, "stats", stats)
	if r.Source == "scanner" {
		go a.autoPush(context.Background(), r.GroupID, true)
	}
	return nil
}

func (a *App) autoPush(ctx context.Context, groupID string, closeOld bool) {
	cfg := a.DDConfig(ctx)
	if !cfg.AutoPush || cfg.URL == "" || !cfg.HasToken {
		return
	}
	key := groupID
	if key == "" {
		key = "none"
	}
	if _, err := a.PushGroup(ctx, key, closeOld); err != nil {
		slog.Warn("automatyczna wysyłka do DefectDojo", "err", err)
	}
}

func containsInt(l []int, v int) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func containsPrefix(l []string, p string) bool {
	for _, x := range l {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}

// Periodicity – wynik analizy dostępności (sekcje 7.3–7.4).
type Periodicity struct {
	Flap    float64            `json:"flap"`
	Samples int                `json:"samples"`
	Buckets map[string]float64 `json:"buckets"`
	Counts  map[string]int     `json:"counts"`
	Active  []int              `json:"active_buckets"`
	Label   string             `json:"label"`
	Weekday float64            `json:"weekday"`
	Weekend float64            `json:"weekend"`
	Retries int                `json:"retries"`
}

// availabilityLabels liczy flap rate (okno M) i okresowość (kubełki pory dnia).
func (a *App) availabilityLabels(ctx context.Context, entityID string, old []string) (Periodicity, []string) {
	rows, _ := a.DB.Query(ctx, `select up, retry, bucket_tod, weekend from availability_history where entity_id=$1 order by at desc limit 500`, entityID)
	type pt struct {
		up, retry, weekend bool
		b                  int
	}
	var pts []pt
	for rows.Next() {
		var p pt
		rows.Scan(&p.up, &p.retry, &p.b, &p.weekend)
		pts = append(pts, p)
	}
	rows.Close()
	per := Periodicity{Buckets: map[string]float64{}, Counts: map[string]int{}, Samples: len(pts)}
	// flap rate na ostatnich M obserwacjach (retry = pół przejścia)
	m := min(a.Th.FlapWindow, len(pts))
	trans := 0.0
	for i := 1; i < m; i++ {
		if pts[i].up != pts[i-1].up {
			trans++
		}
	}
	for i := 0; i < m; i++ {
		if pts[i].retry {
			trans += 0.5
			per.Retries++
		}
	}
	if m > 1 {
		per.Flap = trans / float64(m-1)
	}
	upB, nB := [4]int{}, [4]int{}
	upWD, nWD, upWE, nWE := 0, 0, 0, 0
	for _, p := range pts {
		nB[p.b]++
		if p.up {
			upB[p.b]++
		}
		if p.weekend {
			nWE++
			if p.up {
				upWE++
			}
		} else {
			nWD++
			if p.up {
				upWD++
			}
		}
	}
	hi, lo := false, false
	usable := 0
	for b := 0; b < 4; b++ {
		if nB[b] == 0 {
			continue
		}
		ratio := float64(upB[b]) / float64(nB[b])
		per.Buckets[bucketNames[b]] = ratio
		per.Counts[bucketNames[b]] = nB[b]
		if nB[b] >= 3 {
			usable++
			if ratio >= 0.85 {
				hi = true
				per.Active = append(per.Active, b)
			}
			if ratio <= 0.10 {
				lo = true
			}
		}
	}
	if nWD > 0 {
		per.Weekday = float64(upWD) / float64(nWD)
	}
	if nWE > 0 {
		per.Weekend = float64(upWE) / float64(nWE)
	}
	labels := []string{}
	for _, l := range old {
		if l != "FLAPPING" && !strings.HasPrefix(l, "PERIODIC") {
			labels = append(labels, l)
		}
	}
	if hi && lo && usable >= 2 {
		var names []string
		for _, b := range per.Active {
			names = append(names, bucketNames[b])
		}
		sort.Strings(names)
		per.Label = strings.Join(names, ",")
		if nWE >= 3 && nWD >= 3 && per.Weekday >= 0.5 && per.Weekend <= 0.1 {
			per.Label += "; DNI ROBOCZE"
		}
		labels = append(labels, "PERIODIC("+per.Label+")")
	} else {
		per.Active = nil
		// histereza: etykieta znika dopiero przy F < 0.2
		wasFlapping := contains(old, "FLAPPING")
		if m >= a.Th.FlapMin && (per.Flap >= 0.4 || (wasFlapping && per.Flap >= 0.2)) {
			labels = append(labels, "FLAPPING")
		}
	}
	return per, labels
}

// missesSpanBuckets – braki muszą obejmować porę dnia, w której encja bywa aktywna (sekcja 7.5).
func (a *App) missesSpanBuckets(ctx context.Context, entityID string, k int, per Periodicity) bool {
	if len(per.Active) > 0 {
		return true // braki liczone już tylko w aktywnych kubełkach
	}
	var distinctAll int
	a.DB.QueryRow(ctx, `select count(distinct bucket_tod) from availability_history where entity_id=$1`, entityID).Scan(&distinctAll)
	if distinctAll <= 1 {
		return true
	}
	var distinctMiss int
	a.DB.QueryRow(ctx, `select count(distinct bucket_tod) from (select bucket_tod, up from availability_history where entity_id=$1 order by at desc limit $2) x where not up`, entityID, k).Scan(&distinctMiss)
	return distinctMiss >= 2 || k <= 1
}
