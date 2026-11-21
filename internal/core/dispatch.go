package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/auth"
	"asi/internal/model"
	"asi/internal/netx"
)

// ---------------- workery ----------------

type Worker struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Vantage       string            `json:"vantage"`
	Capabilities  map[string]bool   `json:"capabilities"`
	Tools         map[string]string `json:"tools"`
	LastHeartbeat *time.Time        `json:"last_heartbeat"`
	Status        string            `json:"status"`
	Online        bool              `json:"online"`
	CurrentRate   int               `json:"current_rate"`
	CurrentTask   string            `json:"current_task"`
	Warnings      []string          `json:"warnings"`
}

// AuthWorker sprawdza token workera (Bearer) i zwraca jego id. Token może być współdzielony przez
// kilka replik (docker compose --scale worker=N): każda nowa nazwa dostaje własny wiersz z tym samym tokenem.
func (a *App) AuthWorker(ctx context.Context, name, token string) (string, error) {
	if len(token) < 16 {
		return "", errors.New("niepoprawny token")
	}
	rows, err := a.DB.Query(ctx, `select id, name, token_hash, vantage from workers order by (name=$1) desc, created_at`, name)
	if err != nil {
		return "", err
	}
	type w struct{ id, name, hash, vantage string }
	var list []w
	for rows.Next() {
		var x w
		rows.Scan(&x.id, &x.name, &x.hash, &x.vantage)
		list = append(list, x)
	}
	rows.Close()
	for _, x := range list {
		if !auth.CheckPassword(x.hash, token) {
			continue
		}
		if x.name == name || name == "" {
			return x.id, nil
		}
		var id string
		err := a.DB.QueryRow(ctx, `insert into workers(name,token_hash,vantage,status) values($1,$2,$3,'new')
			on conflict(name) do update set token_hash=excluded.token_hash returning id`, name, x.hash, x.vantage).Scan(&id)
		if err == nil {
			a.Audit(ctx, Actor{Email: "worker:" + name}, "worker.register", "worker", id, map[string]any{"template": x.name})
		}
		return id, err
	}
	return "", errors.New("nieznany worker lub token")
}

func (a *App) WorkerHello(ctx context.Context, workerID string, h model.Hello) error {
	caps := map[string]any{}
	for k, v := range h.Capabilities {
		caps[k] = v
	}
	caps["warnings"] = h.Warnings
	_, err := a.DB.Exec(ctx, `update workers set capabilities=$2, tool_versions=$3, last_heartbeat=now(), status='online' where id=$1`, workerID, jsonb(caps), jsonb(h.Tools))
	a.Audit(ctx, Actor{Email: "worker:" + h.Name}, "worker.hello", "worker", workerID, map[string]any{"tools": h.Tools, "warnings": h.Warnings})
	return err
}

func (a *App) ListWorkers(ctx context.Context) ([]Worker, error) {
	rows, err := a.DB.Query(ctx, `select id, name, vantage, capabilities, tool_versions, last_heartbeat, status, current_rate, coalesce(current_task::text,'') from workers order by name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Worker, error) {
		var w Worker
		var caps, tools []byte
		err := r.Scan(&w.ID, &w.Name, &w.Vantage, &caps, &tools, &w.LastHeartbeat, &w.Status, &w.CurrentRate, &w.CurrentTask)
		var raw map[string]any
		json.Unmarshal(caps, &raw)
		w.Capabilities = map[string]bool{}
		for k, v := range raw {
			if b, ok := v.(bool); ok {
				w.Capabilities[k] = b
			}
			if k == "warnings" {
				if l, ok := v.([]any); ok {
					for _, x := range l {
						w.Warnings = append(w.Warnings, fmt.Sprint(x))
					}
				}
			}
		}
		json.Unmarshal(tools, &w.Tools)
		w.Online = w.LastHeartbeat != nil && time.Since(*w.LastHeartbeat) < 45*time.Second
		return w, err
	})
}

func (a *App) DeleteWorker(ctx context.Context, actor Actor, id string) error {
	ct, _ := a.DB.Exec(ctx, `delete from workers where id=$1`, id)
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "worker.delete", "worker", id, nil)
	return nil
}

// ---------------- kill switch ----------------

type KillSwitch struct {
	Active      bool   `json:"active"`
	Reason      string `json:"reason"`
	ActivatedBy string `json:"activated_by"`
	At          string `json:"at"`
}

func (a *App) KillSwitch(ctx context.Context) KillSwitch {
	var k KillSwitch
	a.GetSetting(ctx, "killswitch", &k)
	return k
}

func (a *App) SetKillSwitch(ctx context.Context, actor Actor, active bool, reason string) error {
	k := KillSwitch{Active: active, Reason: reason, ActivatedBy: actor.Name(), At: time.Now().Format(time.RFC3339)}
	if err := a.SetSetting(ctx, "killswitch", k); err != nil {
		return err
	}
	if active {
		a.DB.Exec(ctx, `update tasks set cancel_requested=true where status='leased'`)
	}
	a.Audit(ctx, actor, map[bool]string{true: "killswitch.activate", false: "killswitch.release"}[active], "killswitch", "", map[string]any{"reason": reason})
	a.Events.Publish("killswitch", k)
	return nil
}

// ---------------- leasing (sekcja 5.2–5.4) ----------------

type groupCtx struct {
	g      *Group
	win    *WinStatus
	sweeps int
	probes int
}

// Lease przydziela workerowi kolejne zadanie albo zwraca nil, gdy nie ma pracy.
func (a *App) Lease(ctx context.Context, workerID string) (*model.Lease, error) {
	a.dispatchMu.Lock()
	defer a.dispatchMu.Unlock()
	a.DB.Exec(ctx, `update workers set last_heartbeat=now(), status='online' where id=$1`, workerID)
	if a.KillSwitch(ctx).Active {
		return nil, nil
	}
	a.expireLeases(ctx)

	var leasedPPS int
	a.DB.QueryRow(ctx, `select coalesce(sum(rate_pps),0) from tasks where status='leased'`).Scan(&leasedPPS)
	globalLeft := a.Cfg.GlobalMaxPPS - leasedPPS

	runs, err := a.ListRuns(ctx, RunFilter{Status: "RUNNING", Limit: 50})
	if err != nil {
		return nil, err
	}
	// najstarsze najpierw
	for i, j := 0, len(runs)-1; i < j; i, j = i+1, j-1 {
		runs[i], runs[j] = runs[j], runs[i]
	}
	groups := map[string]*groupCtx{}
	for _, r := range runs {
		if r.GroupID == "" {
			continue
		}
		gc := groups[r.GroupID]
		if gc == nil {
			g, err := a.GetGroup(ctx, r.GroupID)
			if err != nil {
				continue
			}
			gc = &groupCtx{g: g, win: g.Window}
			a.DB.QueryRow(ctx, `select count(*) filter (where t.kind='sweep'), count(*) filter (where t.kind<>'sweep')
				from tasks t join scan_runs r on r.id=t.run_id where r.group_id=$1 and t.status='leased'`, g.ID).Scan(&gc.sweeps, &gc.probes)
			groups[r.GroupID] = gc
		}
		if gc.win == nil || !gc.win.Open {
			continue
		}
		factor := gc.win.RateFactor
		if factor <= 0 {
			factor = 1
		}
		// 1) zadania probe / retry / dns
		if gc.probes < gc.g.MaxParallelProbes {
			if l, err := a.leasePending(ctx, r, gc, workerID, "kind<>'sweep'", factor, globalLeft); l != nil || err != nil {
				return l, err
			}
		}
		if gc.sweeps >= gc.g.MaxParallelSweeps {
			continue
		}
		// 2) zwrócone do kolejki zadania sweep
		if l, err := a.leasePending(ctx, r, gc, workerID, "kind='sweep'", factor, globalLeft); l != nil || err != nil {
			return l, err
		}
		// 3) wycięcie nowego zadania z kursora
		if r.Phase != "scan" || netx.Remaining(r.ranges, r.cursor) == 0 {
			continue
		}
		rate := int(float64(gc.g.RatePPS) * factor / float64(gc.g.MaxParallelSweeps))
		rate = min(rate, globalLeft)
		if rate < 10 {
			continue
		}
		st := a.groupStats(ctx, gc.g.ID)
		ips := st.IPsPerSec / float64(max(gc.g.MaxParallelSweeps, 1)) // prędkość jednego zadania
		if ips <= 0 {
			ips = theoreticalIPsPerSec(float64(rate), r.Profile, st)
		}
		ips *= factor
		n := float64(a.chunkSize(ips))
		if gc.win.Remaining >= 0 { // okno skończone: zadanie musi się zmieścić z marginesem 20%
			fit := ips * float64(gc.win.Remaining) / 1.2
			if fit < 32 {
				continue
			}
			n = math.Min(n, fit)
		}
		chunk, next := netx.Take(r.ranges, r.cursor, uint64(n))
		if len(chunk) == 0 {
			continue
		}
		addrs := netx.Total(chunk)
		id, err := a.insertTask(ctx, r.ID, model.TaskSweep, model.Payload{Ranges: chunk}, time.Now(), int(addrs))
		if err != nil {
			return nil, err
		}
		a.DB.Exec(ctx, `update scan_runs set cursor=$2 where id=$1`, r.ID, jsonb(next))
		a.DB.Exec(ctx, `update tasks set est_seconds=$2 where id=$1`, id, float64(addrs)/ips)
		return a.markLeased(ctx, r, id, workerID, rate, 0)
	}
	return nil, nil
}

func (a *App) leasePending(ctx context.Context, r *Run, gc *groupCtx, workerID, kindCond string, factor float64, globalLeft int) (*model.Lease, error) {
	var id, kind string
	err := a.DB.QueryRow(ctx, `select id, kind from tasks where run_id=$1 and status='pending' and not_before<=now() and `+kindCond+` order by created_at limit 1 for update skip locked`, r.ID).Scan(&id, &kind)
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rate, rps int
	if kind == model.TaskSweep {
		rate = int(float64(gc.g.RatePPS) * factor / float64(gc.g.MaxParallelSweeps))
	} else {
		rate = int(float64(gc.g.RatePPS) * factor / float64(gc.g.MaxParallelProbes+gc.g.MaxParallelSweeps))
		rps = max(1, int(float64(gc.g.HTTPRPS)*factor/float64(gc.g.MaxParallelProbes)))
	}
	rate = max(min(rate, globalLeft), 0)
	if rate < 5 && kind != model.TaskDNS {
		return nil, nil
	}
	return a.markLeased(ctx, r, id, workerID, rate, rps)
}

func (a *App) markLeased(ctx context.Context, r *Run, taskID, workerID string, rate, rps int) (*model.Lease, error) {
	exp := time.Now().Add(a.Th.LeaseTTL)
	var kind string
	var payload []byte
	err := a.DB.QueryRow(ctx, `update tasks set status='leased', lease_owner=$2, lease_expires_at=$3, rate_pps=$4, http_rps=$5, attempt=attempt+1,
		started_at=now(), cancel_requested=false where id=$1 returning kind, payload`, taskID, workerID, exp, rate, rps).Scan(&kind, &payload)
	if err != nil {
		return nil, err
	}
	a.DB.Exec(ctx, `update workers set current_task=$2, current_rate=$3 where id=$1`, workerID, taskID, rate)
	var p model.Payload
	json.Unmarshal(payload, &p)
	_, allow, excl, _ := a.Scope(ctx)
	l := &model.Lease{TaskID: taskID, RunID: r.ID, Kind: kind, Mode: r.Mode, RatePPS: rate, HTTPRPS: rps, Profile: r.Profile,
		Payload: p, Scope: allow, Exclusions: excl, UserAgent: a.Cfg.UserAgent(), Deadline: exp}
	if r.Profile.ActiveSignatures {
		l.Paths = a.Sigs.ActivePaths()
	}
	a.Events.Publish("task", map[string]any{"run_id": r.ID, "task_id": taskID, "status": "leased"})
	return l, nil
}

// expireLeases zwraca do kolejki zadania, których worker przestał się odzywać.
func (a *App) expireLeases(ctx context.Context) {
	rows, _ := a.DB.Query(ctx, `update tasks set status=case when attempt>=3 then 'failed' else 'pending' end,
		error=case when attempt>=3 then 'lease wygasł 3 razy (worker nie odpowiada)' else error end, lease_owner=null
		where status='leased' and lease_expires_at < now() returning id`)
	for rows.Next() {
		var id string
		rows.Scan(&id)
		slog.Warn("lease wygasł, zadanie wraca do kolejki", "task", id)
	}
	rows.Close()
}

// Heartbeat przedłuża lease i przekazuje polecenia (cancel przy końcu okna, kill switch, pauzie).
func (a *App) Heartbeat(ctx context.Context, workerID, taskID string) model.HeartbeatReply {
	a.DB.Exec(ctx, `update workers set last_heartbeat=now(), status='online' where id=$1`, workerID)
	var cancel bool
	var status, runStatus string
	err := a.DB.QueryRow(ctx, `select t.cancel_requested, t.status, r.status from tasks t join scan_runs r on r.id=t.run_id where t.id=$1 and t.lease_owner=$2`, taskID, workerID).
		Scan(&cancel, &status, &runStatus)
	if err != nil || status != "leased" {
		return model.HeartbeatReply{Command: "cancel"}
	}
	if cancel || runStatus != "RUNNING" || a.KillSwitch(ctx).Active {
		return model.HeartbeatReply{Command: "cancel"}
	}
	a.DB.Exec(ctx, `update tasks set lease_expires_at=$2 where id=$1`, taskID, time.Now().Add(a.Th.LeaseTTL))
	return model.HeartbeatReply{Command: "continue"}
}

// Abort – worker przerwał zadanie na polecenie (okno, pauza, kill switch): wraca do kolejki bez liczenia próby.
func (a *App) Abort(ctx context.Context, workerID, taskID string) {
	a.DB.Exec(ctx, `update tasks set status=case when (select status from scan_runs where id=tasks.run_id)='CANCELLED' then 'aborted' else 'pending' end,
		attempt=greatest(attempt-1,0), lease_owner=null, cancel_requested=false where id=$1 and lease_owner=$2`, taskID, workerID)
	a.DB.Exec(ctx, `update workers set current_task=null, current_rate=0 where id=$1`, workerID)
}

// Fail – błąd wykonania zadania.
func (a *App) Fail(ctx context.Context, workerID, taskID, msg string, retryable bool) {
	a.DB.Exec(ctx, `update tasks set status=case when $3 and attempt<3 then 'pending' else 'failed' end, error=$4, lease_owner=null,
		not_before=now()+interval '10 seconds', finished_at=case when $3 and attempt<3 then null else now() end where id=$1 and lease_owner=$2`, taskID, workerID, retryable, msg)
	a.DB.Exec(ctx, `update workers set current_task=null, current_rate=0 where id=$1`, workerID)
	slog.Warn("zadanie nieudane", "task", taskID, "err", msg)
}

// Complete przyjmuje wynik zadania.
func (a *App) Complete(ctx context.Context, workerID, taskID string, res *model.Result) error {
	var runID, kind, status string
	var started *time.Time
	var addrs int
	err := a.DB.QueryRow(ctx, `select run_id, kind, status, started_at, addresses from tasks where id=$1 and lease_owner=$2`, taskID, workerID).Scan(&runID, &kind, &status, &started, &addrs)
	if err != nil {
		return ErrNotFound
	}
	if status != "leased" {
		return Invalid("zadanie nie jest przydzielone temu workerowi", nil)
	}
	run, err := a.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	var wname string
	a.DB.QueryRow(ctx, `select name from workers where id=$1`, workerID).Scan(&wname)
	dur := time.Since(*started)
	switch kind {
	case model.TaskSweep:
		err = a.ingestSweep(ctx, run, taskID, wname, res, false)
	case model.TaskRetry:
		err = a.ingestSweep(ctx, run, taskID, wname, res, true)
	case model.TaskProbe:
		err = a.ingestProbe(ctx, run, taskID, wname, res)
	case model.TaskDNS:
		err = a.ingestDNS(ctx, run, res)
	}
	if err != nil {
		a.Fail(ctx, workerID, taskID, "błąd przetwarzania wyniku: "+err.Error(), false)
		return err
	}
	stats := res.Stats
	if stats == nil {
		stats = map[string]any{}
	}
	if len(res.Warnings) > 0 {
		stats["warnings"] = res.Warnings
	}
	a.DB.Exec(ctx, `update tasks set status='done', finished_at=now(), duration_ms=$2, stats=$3, lease_owner=lease_owner where id=$1`, taskID, dur.Milliseconds(), jsonb(stats))
	a.DB.Exec(ctx, `update workers set current_task=null, current_rate=0 where id=$1`, workerID)
	if kind == model.TaskSweep {
		a.DB.Exec(ctx, `update scan_runs set done_addresses=done_addresses+$2 where id=$1`, runID, addrs)
		a.learn(ctx, run.GroupID, addrs, dur, res)
	}
	if kind == model.TaskProbe {
		a.learnProbe(ctx, run.GroupID, dur, res)
	}
	a.Events.Publish("task", map[string]any{"run_id": runID, "task_id": taskID, "status": "done"})
	go a.CheckRuns(context.Background())
	return nil
}

// learn aktualizuje EWMA przepustowości grupy (adaptacyjny rozmiar zadań).
func (a *App) learn(ctx context.Context, groupID string, addrs int, dur time.Duration, res *model.Result) {
	if groupID == "" || addrs == 0 {
		return
	}
	st := a.groupStats(ctx, groupID)
	var g Group
	a.DB.QueryRow(ctx, `select max_parallel_sweeps from target_groups where id=$1`, groupID).Scan(&g.MaxParallelSweeps)
	ips := float64(addrs) / math.Max(dur.Seconds(), 0.5) * float64(max(g.MaxParallelSweeps, 1))
	alive, open := 0, 0
	for _, h := range res.Hosts {
		if h.Up {
			alive++
			open += len(h.Ports)
		}
	}
	st.IPsPerSec = ewma(st.IPsPerSec, ips, st.Samples)
	st.AliveRatio = ewma(st.AliveRatio, float64(alive)/float64(addrs), st.Samples)
	if alive > 0 {
		st.OpenPerAlive = ewma(st.OpenPerAlive, float64(open)/float64(alive), st.Samples)
	}
	st.Samples++
	a.DB.Exec(ctx, `update target_groups set stats=$2 where id=$1`, groupID, jsonb(st))
}

func (a *App) learnProbe(ctx context.Context, groupID string, dur time.Duration, res *model.Result) {
	ports := 0
	for _, o := range res.Observations {
		ports += len(o.Services)
	}
	if groupID == "" || ports == 0 {
		return
	}
	st := a.groupStats(ctx, groupID)
	st.ProbeSecPort = ewma(st.ProbeSecPort, dur.Seconds()/float64(ports), st.ProbeSamples)
	st.ProbeSamples++
	a.DB.Exec(ctx, `update target_groups set stats=$2 where id=$1`, groupID, jsonb(st))
}
