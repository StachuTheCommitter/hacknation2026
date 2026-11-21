package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/model"
	"asi/internal/netx"
)

// Run – przebieg skanu.
type Run struct {
	ID             string         `json:"id"`
	GroupID        string         `json:"group_id"`
	GroupName      string         `json:"group_name"`
	ScheduleID     string         `json:"schedule_id,omitempty"`
	Mode           string         `json:"mode"`
	Source         string         `json:"source"`
	Status         string         `json:"status"`
	Phase          string         `json:"phase"`
	TotalAddresses int64          `json:"total_addresses"`
	DoneAddresses  int64          `json:"done_addresses"`
	EstSeconds     int            `json:"est_seconds"`
	Stats          map[string]any `json:"stats"`
	Note           string         `json:"note"`
	CreatedBy      string         `json:"created_by"`
	CreatedAt      time.Time      `json:"created_at"`
	StartedAt      *time.Time     `json:"started_at"`
	FinishedAt     *time.Time     `json:"finished_at"`
	PausedReason   string         `json:"paused_reason"`
	Profile        model.Profile  `json:"profile"`
	Tasks          map[string]int `json:"tasks,omitempty"`
	ETA            *ETA           `json:"eta,omitempty"`
	Rate           int            `json:"rate_pps"`

	ranges []netx.Range
	ipv6   []string
	cursor netx.Cursor
}

const runSelect = `select r.id, coalesce(r.group_id::text,''), coalesce(g.name,''), coalesce(r.schedule_id::text,''), r.mode, r.source, r.status, r.phase,
	r.total_addresses, r.done_addresses, r.est_seconds, r.stats, r.note, r.created_by, r.created_at, r.started_at, r.finished_at, r.paused_reason,
	r.profile, r.ranges, r.ipv6, r.cursor from scan_runs r left join target_groups g on g.id=r.group_id`

func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	var stats, prof, ranges, cur []byte
	err := row.Scan(&r.ID, &r.GroupID, &r.GroupName, &r.ScheduleID, &r.Mode, &r.Source, &r.Status, &r.Phase, &r.TotalAddresses, &r.DoneAddresses,
		&r.EstSeconds, &stats, &r.Note, &r.CreatedBy, &r.CreatedAt, &r.StartedAt, &r.FinishedAt, &r.PausedReason, &prof, &ranges, &r.ipv6, &cur)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(stats, &r.Stats)
	json.Unmarshal(prof, &r.Profile)
	r.Profile.Fill()
	json.Unmarshal(ranges, &r.ranges)
	json.Unmarshal(cur, &r.cursor)
	return &r, nil
}

func (a *App) GetRun(ctx context.Context, id string) (*Run, error) {
	r, err := scanRun(a.DB.QueryRow(ctx, runSelect+` where r.id=$1`, id))
	if err != nil {
		return nil, ErrNotFound
	}
	r.Tasks = map[string]int{}
	rows, _ := a.DB.Query(ctx, `select status, count(*) from tasks where run_id=$1 group by status`, id)
	for rows.Next() {
		var s string
		var n int
		rows.Scan(&s, &n)
		r.Tasks[s] = n
	}
	rows.Close()
	a.DB.QueryRow(ctx, `select coalesce(sum(rate_pps),0) from tasks where run_id=$1 and status='leased'`, id).Scan(&r.Rate)
	if r.Status == "RUNNING" || r.Status == "PAUSED_WINDOW" || r.Status == "PAUSED_MANUAL" || r.Status == "PENDING" {
		r.ETA = a.runETA(ctx, r)
	}
	return r, nil
}

type RunFilter struct {
	GroupID string
	Status  string
	Source  string
	Limit   int
}

func (a *App) ListRuns(ctx context.Context, f RunFilter) ([]*Run, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := a.DB.Query(ctx, runSelect+` where ($1='' or r.group_id::text=$1) and ($2='' or r.status=$2) and ($3='' or r.source=$3)
		order by r.created_at desc limit $4`, f.GroupID, f.Status, f.Source, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

type RunInput struct {
	GroupID    string   `json:"group_id"`
	ProfileID  string   `json:"profile_id"`
	Mode       string   `json:"mode"`
	Targets    []string `json:"targets"` // opcjonalnie: podzbiór (np. ponowny pomiar hosta)
	Note       string   `json:"note"`
	ScheduleID string   `json:"-"`
}

// CreateRun tworzy przebieg skanera dla grupy.
func (a *App) CreateRun(ctx context.Context, actor Actor, in RunInput) (*Run, error) {
	g, err := a.GetGroup(ctx, in.GroupID)
	if err != nil {
		return nil, err
	}
	if !validModes[in.Mode] {
		in.Mode = "baseline"
	}
	profID := in.ProfileID
	if profID == "" {
		profID = g.ProfileID
	}
	prof, err := a.GetProfile(ctx, profID)
	if err != nil {
		return nil, err
	}
	scope, _, _, err := a.Scope(ctx)
	if err != nil {
		return nil, err
	}
	var ranges []netx.Range
	var v6, domains []string
	if len(in.Targets) > 0 {
		for _, v := range in.Targets {
			t, err := netx.ParseTarget(v)
			if err != nil {
				return nil, Invalid(err.Error(), nil)
			}
			switch {
			case t.Kind == "domain":
				domains = append(domains, t.Value)
			case t.IPv6 != "":
				v6 = append(v6, t.IPv6)
			default:
				ranges = append(ranges, t.Ranges...)
			}
		}
		ranges = netx.Merge(ranges)
	} else {
		ranges, v6, domains = a.groupRanges(ctx, g.ID)
	}
	clipped, dropped := scope.Clip(ranges)
	var v6ok []string
	for _, ip := range v6 {
		if scope.Allowed(ip) {
			v6ok = append(v6ok, ip)
		}
	}
	if len(clipped) == 0 && len(v6ok) == 0 && len(domains) == 0 {
		return nil, Invalid("brak celów w dozwolonym zakresie – dodaj cele do grupy lub zakres do scope", nil)
	}
	if in.Mode == "liveness" {
		// tryb dzienny: porty ograniczone do znanych otwartych portów grupy
		var ports []int
		rows, _ := a.DB.Query(ctx, `select distinct s.port from services s join hosts h on h.id=s.host_id where h.group_id=$1 and s.proto='tcp' and s.state<>'INACTIVE'`, g.ID)
		for rows.Next() {
			var p int
			rows.Scan(&p)
			ports = append(ports, p)
		}
		rows.Close()
		if len(ports) > 0 {
			prof.TCPPorts = netx.FormatPorts(ports)
		} else {
			prof.TCPPorts = "top-100"
		}
		prof.UDPPorts = ""
	}
	total := int64(netx.Total(clipped)) + int64(len(v6ok))
	ws, _ := a.WindowStatus(ctx, g.ID, time.Now())
	status := "RUNNING"
	reason := ""
	if ws != nil && !ws.Open {
		status, reason = "PAUSED_WINDOW", "poza oknem czasowym – start w najbliższym oknie"
	}
	note := in.Note
	if dropped > 0 {
		note = strings.TrimSpace(note + fmt.Sprintf(" (pominięto %d adresów spoza scope lub wykluczonych)", dropped))
	}
	est := a.Estimate(ctx, g, prof, uint64(total), 1)
	var id string
	err = a.DB.QueryRow(ctx, `insert into scan_runs(group_id,schedule_id,mode,source,profile,status,ranges,ipv6,total_addresses,est_seconds,note,created_by,started_at,paused_reason)
		values($1,$2,$3,'scanner',$4,$5,$6,$7,$8,$9,$10,$11,now(),$12) returning id`,
		g.ID, nullUUID(in.ScheduleID), in.Mode, jsonb(prof), status, jsonb(clipped), nonNil(v6ok), total, int(est.Seconds), note, actor.Name(), reason).Scan(&id)
	if err != nil {
		return nil, err
	}
	if len(domains) > 0 {
		a.insertTask(ctx, id, model.TaskDNS, model.Payload{Domains: domains}, time.Now(), 0)
	}
	if len(v6ok) > 0 {
		a.insertTask(ctx, id, model.TaskSweep, model.Payload{IPs: v6ok}, time.Now(), len(v6ok))
	}
	a.Audit(ctx, actor, "run.start", "run", id, map[string]any{"group": g.Name, "mode": in.Mode, "addresses": total})
	a.Events.Publish("run", map[string]any{"id": id, "status": status})
	return a.GetRun(ctx, id)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a *App) insertTask(ctx context.Context, runID, kind string, p model.Payload, notBefore time.Time, addrs int) (string, error) {
	var id string
	err := a.DB.QueryRow(ctx, `insert into tasks(run_id,kind,payload,not_before,addresses) values($1,$2,$3,$4,$5) returning id`,
		runID, kind, jsonb(p), notBefore, addrs).Scan(&id)
	return id, err
}

// ControlRun – pauza, wznowienie, anulowanie.
func (a *App) ControlRun(ctx context.Context, actor Actor, id, action string) (*Run, error) {
	r, err := a.GetRun(ctx, id)
	if err != nil {
		return nil, err
	}
	switch action {
	case "pause":
		if r.Status != "RUNNING" && r.Status != "PAUSED_WINDOW" {
			return nil, Invalid("przebieg nie jest aktywny", nil)
		}
		a.DB.Exec(ctx, `update scan_runs set status='PAUSED_MANUAL', paused_reason=$2 where id=$1`, id, "wstrzymany przez "+actor.Name())
		a.DB.Exec(ctx, `update tasks set cancel_requested=true where run_id=$1 and status='leased'`, id)
	case "resume":
		if r.Status != "PAUSED_MANUAL" {
			return nil, Invalid("przebieg nie jest wstrzymany ręcznie", nil)
		}
		a.DB.Exec(ctx, `update scan_runs set status='RUNNING', paused_reason='' where id=$1`, id)
	case "cancel":
		if r.Status == "COMPLETED" || r.Status == "CANCELLED" {
			return nil, Invalid("przebieg jest już zakończony", nil)
		}
		a.DB.Exec(ctx, `update scan_runs set status='CANCELLED', finished_at=now(), paused_reason=$2 where id=$1`, id, "anulowany przez "+actor.Name())
		a.DB.Exec(ctx, `update tasks set cancel_requested=true where run_id=$1 and status='leased'`, id)
		a.DB.Exec(ctx, `update tasks set status='aborted' where run_id=$1 and status='pending'`, id)
	default:
		return nil, Invalid("nieznana akcja", nil)
	}
	a.Audit(ctx, actor, "run."+action, "run", id, nil)
	a.Events.Publish("run", map[string]any{"id": id})
	return a.GetRun(ctx, id)
}

func (a *App) DeleteRun(ctx context.Context, actor Actor, id string) error {
	ct, _ := a.DB.Exec(ctx, `delete from scan_runs where id=$1 and status not in ('RUNNING')`, id)
	if ct.RowsAffected() == 0 {
		return Invalid("nie można usunąć aktywnego przebiegu", nil)
	}
	a.Audit(ctx, actor, "run.delete", "run", id, nil)
	return nil
}

// TaskRow – zadanie w widoku przebiegu.
type TaskRow struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Status     string         `json:"status"`
	Attempt    int            `json:"attempt"`
	Addresses  int            `json:"addresses"`
	RatePPS    int            `json:"rate_pps"`
	DurationMs int            `json:"duration_ms"`
	EstSeconds float64        `json:"est_seconds"`
	Worker     string         `json:"worker"`
	Label      string         `json:"label"`
	Error      string         `json:"error"`
	Stats      map[string]any `json:"stats"`
	StartedAt  *time.Time     `json:"started_at"`
}

func (a *App) ListTasks(ctx context.Context, runID string) ([]TaskRow, error) {
	rows, err := a.DB.Query(ctx, `select t.id, t.kind, t.status, t.attempt, t.addresses, t.rate_pps, t.duration_ms, t.est_seconds, coalesce(w.name,''), t.payload, t.error, t.stats, t.started_at
		from tasks t left join workers w on w.id=t.lease_owner where t.run_id=$1 order by t.created_at`, runID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (TaskRow, error) {
		var t TaskRow
		var p, st []byte
		var est float32
		err := r.Scan(&t.ID, &t.Kind, &t.Status, &t.Attempt, &t.Addresses, &t.RatePPS, &t.DurationMs, &est, &t.Worker, &p, &t.Error, &st, &t.StartedAt)
		t.EstSeconds = float64(est)
		var pl model.Payload
		json.Unmarshal(p, &pl)
		json.Unmarshal(st, &t.Stats)
		switch {
		case len(pl.Ranges) > 0:
			t.Label = pl.Ranges[0].String()
			if len(pl.Ranges) > 1 {
				t.Label += fmt.Sprintf(" +%d", len(pl.Ranges)-1)
			}
		case len(pl.Hosts) > 0:
			t.Label = pl.Hosts[0].IP
			if len(pl.Hosts) > 1 {
				t.Label += fmt.Sprintf(" +%d hostów", len(pl.Hosts)-1)
			}
		case len(pl.Domains) > 0:
			t.Label = strings.Join(pl.Domains, ", ")
		case len(pl.IPs) > 0:
			t.Label = pl.IPs[0]
		}
		return t, err
	})
}

// ---------------- estymacja (sekcja 5.5) ----------------

// GroupStats – wyuczone parametry wydajności grupy (EWMA).
type GroupStats struct {
	IPsPerSec    float64 `json:"ips_per_sec"`
	AliveRatio   float64 `json:"alive_ratio"`
	OpenPerAlive float64 `json:"open_per_alive"`
	ProbeSecPort float64 `json:"probe_sec_per_port"`
	Samples      int     `json:"samples"`
	ProbeSamples int     `json:"probe_samples"`
}

func (a *App) groupStats(ctx context.Context, groupID string) GroupStats {
	var raw []byte
	a.DB.QueryRow(ctx, `select stats from target_groups where id=$1`, groupID).Scan(&raw)
	var s GroupStats
	json.Unmarshal(raw, &s)
	if s.AliveRatio == 0 {
		s.AliveRatio = 0.1
	}
	if s.OpenPerAlive == 0 {
		s.OpenPerAlive = 3
	}
	if s.ProbeSecPort == 0 {
		s.ProbeSecPort = 4
	}
	return s
}

func ewma(old, v float64, n int) float64 {
	if n == 0 || old == 0 {
		return v
	}
	return 0.7*old + 0.3*v
}

func discoveryProbes(p model.Profile) float64 {
	n := 0.0
	if p.DiscoveryICMP {
		n += 2
	}
	syn, _ := netx.ParsePorts(p.DiscoveryTCPSyn)
	ack, _ := netx.ParsePorts(p.DiscoveryTCPAck)
	n += float64(len(syn) + len(ack))
	return math.Max(n, 1)
}

// theoreticalIPsPerSec – prędkość przed pierwszym pomiarem.
func theoreticalIPsPerSec(rate float64, p model.Profile, st GroupStats) float64 {
	ports, _ := netx.ParsePorts(p.TCPPorts)
	perIP := discoveryProbes(p) + st.AliveRatio*float64(len(ports))*(1+float64(p.Retries)*0.5)
	return math.Max(rate/perIP, 0.5)
}

type Estimate struct {
	Seconds      float64 `json:"seconds"`
	Discovery    float64 `json:"discovery_sec"`
	Portscan     float64 `json:"portscan_sec"`
	Probe        float64 `json:"probe_sec"`
	Addresses    uint64  `json:"addresses"`
	Ports        int     `json:"ports"`
	RatePPS      int     `json:"rate_pps"`
	EstAlive     int     `json:"est_alive"`
	EstOpen      int     `json:"est_open"`
	Packets      float64 `json:"packets"`
	Learned      bool    `json:"learned"`
	Windows      int     `json:"windows_needed,omitempty"`
	FinishAt     string  `json:"finish_at,omitempty"`
	Warning      string  `json:"warning,omitempty"`
	ChunkSize    int     `json:"chunk_size"`
	ChunkSeconds float64 `json:"chunk_seconds"`
}

// Estimate liczy szacowany czas przebiegu (wzór z sekcji 5.5).
func (a *App) Estimate(ctx context.Context, g *Group, p model.Profile, addrs uint64, rateFactor float64) Estimate {
	st := a.groupStats(ctx, g.ID)
	rate := math.Min(float64(g.RatePPS)*rateFactor, float64(a.Cfg.GlobalMaxPPS))
	ports, _ := netx.ParsePorts(p.TCPPorts)
	udp, _ := netx.ParsePorts(p.UDPPorts)
	alive := float64(addrs) * st.AliveRatio
	if p.PortscanScope == "all" {
		alive = float64(addrs)
	}
	open := alive * st.OpenPerAlive
	e := Estimate{Addresses: addrs, Ports: len(ports) + len(udp), RatePPS: int(rate), EstAlive: int(alive), EstOpen: int(open), Learned: st.Samples > 0}
	e.Discovery = float64(addrs) * discoveryProbes(p) / rate
	pk := alive * float64(len(ports)+len(udp)) * (1 + float64(p.Retries)*0.5)
	e.Portscan = pk / rate
	e.Packets = float64(addrs)*discoveryProbes(p) + pk
	if st.Samples > 2 && st.IPsPerSec > 0 { // prędkość zmierzona zastępuje teoretyczną
		measured := float64(addrs) / st.IPsPerSec
		e.Discovery = measured * e.Discovery / math.Max(e.Discovery+e.Portscan, 1e-9)
		e.Portscan = measured - e.Discovery
	}
	e.Probe = open * st.ProbeSecPort / float64(max(g.MaxParallelProbes, 1))
	e.Seconds = e.Discovery + e.Portscan + e.Probe
	ips := st.IPsPerSec
	if ips <= 0 {
		ips = theoreticalIPsPerSec(rate/float64(max(g.MaxParallelSweeps, 1)), p, st)
	}
	e.ChunkSize = a.chunkSize(ips)
	e.ChunkSeconds = float64(e.ChunkSize) / ips
	// rozłożenie na okna czasowe
	if g.Window != nil && g.Window.HasWindows {
		fin, n := a.calendarFinish(ctx, g, e.Seconds)
		if !fin.IsZero() {
			loc, _ := time.LoadLocation(g.Timezone)
			e.FinishAt = fin.In(loc).Format("2006-01-02 15:04")
			e.Windows = n
			if n > 1 {
				e.Warning = fmt.Sprintf("Skan zajmie ok. %d okien czasowych. Rozważ większy budżet pakietów, szersze okno lub tryb differential.", n)
			}
		} else {
			e.Warning = "Skan nie zmieści się w oknach czasowych w ciągu 14 dni."
		}
	}
	return e
}

func (a *App) chunkSize(ipsPerSec float64) int {
	n := ipsPerSec * a.Th.TaskTarget.Seconds()
	return int(math.Max(32, math.Min(4096, n)))
}

// calendarFinish symuluje przyszłe okna (krok 5 min, horyzont 14 dni).
func (a *App) calendarFinish(ctx context.Context, g *Group, seconds float64) (time.Time, int) {
	ws, _ := a.ListWindows(ctx, g.ID)
	loc, err := time.LoadLocation(g.Timezone)
	if err != nil {
		loc = time.UTC
	}
	t := time.Now()
	left := seconds
	windows := 0
	wasOpen := false
	for i := 0; i < 14*24*12; i++ {
		st := EvalWindows(ws, loc, g.AlwaysAllowed, t)
		if st.Open {
			if !wasOpen {
				windows++
			}
			left -= 300 * st.RateFactor
			if left <= 0 {
				return t.Add(time.Duration((left + 300*st.RateFactor) * float64(time.Second))), windows
			}
		}
		wasOpen = st.Open
		t = t.Add(5 * time.Minute)
	}
	return time.Time{}, windows
}

type ETA struct {
	RemainingSec int     `json:"remaining_sec"`
	Progress     float64 `json:"progress"`
	FinishAt     string  `json:"finish_at,omitempty"`
	IPsPerSec    float64 `json:"ips_per_sec"`
}

func (a *App) runETA(ctx context.Context, r *Run) *ETA {
	if r.GroupID == "" {
		return nil
	}
	g, err := a.GetGroup(ctx, r.GroupID)
	if err != nil {
		return nil
	}
	st := a.groupStats(ctx, g.ID)
	remainAddr := netx.Remaining(r.ranges, r.cursor)
	var pendingProbe int
	a.DB.QueryRow(ctx, `select coalesce(sum(jsonb_array_length(coalesce(payload->'hosts','[]'::jsonb))),0) from tasks where run_id=$1 and status in ('pending','leased') and kind in ('probe','retry')`, r.ID).Scan(&pendingProbe)
	ips := st.IPsPerSec
	if ips <= 0 {
		ips = theoreticalIPsPerSec(float64(g.RatePPS)/float64(max(g.MaxParallelSweeps, 1)), r.Profile, st)
	}
	par := float64(max(g.MaxParallelSweeps, 1))
	sec := float64(remainAddr)/(ips*par) + float64(remainAddr)*st.AliveRatio*st.OpenPerAlive*st.ProbeSecPort/float64(max(g.MaxParallelProbes, 1)) +
		float64(pendingProbe)*st.OpenPerAlive*st.ProbeSecPort/float64(max(g.MaxParallelProbes, 1))
	prog := 0.0
	if r.TotalAddresses > 0 {
		prog = float64(r.DoneAddresses) / float64(r.TotalAddresses)
	}
	e := &ETA{RemainingSec: int(sec), Progress: math.Min(prog, 1), IPsPerSec: ips * par}
	if g.Window != nil && g.Window.HasWindows {
		if fin, _ := a.calendarFinish(ctx, g, sec); !fin.IsZero() {
			loc, _ := time.LoadLocation(g.Timezone)
			e.FinishAt = fin.In(loc).Format("2006-01-02 15:04")
		}
	}
	return e
}
