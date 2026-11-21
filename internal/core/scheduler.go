package core

import (
	"context"
	"log/slog"
	"time"
)

// RunScheduler – pętla control plane: cron, okna czasowe, wygasłe lease, finalizacja, synchronizacja DefectDojo.
func (a *App) RunScheduler(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	lastDD := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		a.fireSchedules(ctx)
		a.applyWindows(ctx)
		a.dispatchMu.Lock()
		a.expireLeases(ctx)
		a.dispatchMu.Unlock()
		a.CheckRuns(ctx)
		if time.Since(lastDD) > a.Th.DDSyncEvery {
			lastDD = time.Now()
			cfg := a.DDConfig(ctx)
			if cfg.URL != "" && cfg.HasToken && len(cfg.Tests) > 0 {
				if _, err := a.PullStatuses(ctx); err != nil {
					slog.Warn("synchronizacja DefectDojo", "err", err)
				}
			}
		}
	}
}

// fireSchedules tworzy przebiegi z harmonogramów z polityką nakładania (skip / supersede / queue).
func (a *App) fireSchedules(ctx context.Context) {
	rows, err := a.DB.Query(ctx, `select s.id, s.group_id, coalesce(s.profile_id::text,''), s.cron, s.mode, s.overlap_policy, g.timezone
		from schedules s join target_groups g on g.id=s.group_id where s.enabled and s.next_fire_at <= now()`)
	if err != nil {
		return
	}
	type sch struct{ id, group, profile, cron, mode, policy, tz string }
	var due []sch
	for rows.Next() {
		var s sch
		rows.Scan(&s.id, &s.group, &s.profile, &s.cron, &s.mode, &s.policy, &s.tz)
		due = append(due, s)
	}
	rows.Close()
	for _, s := range due {
		next, err := nextFire(s.cron, s.tz, time.Now())
		if err != nil {
			continue
		}
		a.DB.Exec(ctx, `update schedules set last_fired_at=now(), next_fire_at=$2 where id=$1`, s.id, next)
		var activeID string
		a.DB.QueryRow(ctx, `select id from scan_runs where group_id=$1 and source='scanner' and status in ('RUNNING','PAUSED_WINDOW','PAUSED_MANUAL','PENDING') order by created_at desc limit 1`, s.group).Scan(&activeID)
		actor := Actor{Email: "harmonogram"}
		if activeID != "" {
			switch s.policy {
			case "skip":
				a.Audit(ctx, actor, "schedule.skip", "schedule", s.id, map[string]any{"reason": "poprzedni przebieg wciąż trwa", "run": activeID})
				continue
			case "queue":
				var queued int
				a.DB.QueryRow(ctx, `select count(*) from scan_runs where group_id=$1 and status='PENDING'`, s.group).Scan(&queued)
				if queued > 0 {
					continue
				}
			case "supersede":
				a.DB.Exec(ctx, `update scan_runs set status='SUPERSEDED', finished_at=now(), paused_reason='zastąpiony nowym przebiegiem z harmonogramu' where id=$1`, activeID)
				a.DB.Exec(ctx, `update tasks set cancel_requested=true where run_id=$1 and status='leased'`, activeID)
				a.DB.Exec(ctx, `update tasks set status='aborted' where run_id=$1 and status='pending'`, activeID)
			}
		}
		r, err := a.CreateRun(ctx, actor, RunInput{GroupID: s.group, ProfileID: s.profile, Mode: s.mode, ScheduleID: s.id})
		if err != nil {
			slog.Warn("harmonogram", "schedule", s.id, "err", err)
			continue
		}
		if activeID != "" && s.policy == "queue" {
			a.DB.Exec(ctx, `update scan_runs set status='PENDING', paused_reason='w kolejce za poprzednim przebiegiem' where id=$1`, r.ID)
		}
	}
	// kolejka: przebieg PENDING startuje, gdy poprzedni się zakończy
	a.DB.Exec(ctx, `update scan_runs r set status='RUNNING', paused_reason='' where status='PENDING' and source='scanner'
		and not exists(select 1 from scan_runs o where o.group_id=r.group_id and o.id<>r.id and o.status in ('RUNNING','PAUSED_WINDOW','PAUSED_MANUAL'))`)
}

// applyWindows wstrzymuje przebiegi poza oknem i wznawia je w kolejnym oknie (sekcja 5.6).
func (a *App) applyWindows(ctx context.Context) {
	rows, err := a.DB.Query(ctx, `select id, group_id, status from scan_runs where status in ('RUNNING','PAUSED_WINDOW') and source='scanner' and group_id is not null`)
	if err != nil {
		return
	}
	type rr struct{ id, group, status string }
	var list []rr
	for rows.Next() {
		var r rr
		rows.Scan(&r.id, &r.group, &r.status)
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		ws, err := a.WindowStatus(ctx, r.group, time.Now())
		if err != nil {
			continue
		}
		switch {
		case r.status == "RUNNING" && !ws.Open:
			a.DB.Exec(ctx, `update scan_runs set status='PAUSED_WINDOW', paused_reason='okno czasowe zamknięte – wznowienie w kolejnym oknie' where id=$1`, r.id)
			ct, _ := a.DB.Exec(ctx, `update tasks set cancel_requested=true where run_id=$1 and status='leased'`, r.id)
			a.Audit(ctx, System, "run.pause_window", "run", r.id, map[string]any{"cancelled_tasks": ct.RowsAffected()})
			a.Events.Publish("run", map[string]any{"id": r.id, "status": "PAUSED_WINDOW"})
		case r.status == "PAUSED_WINDOW" && ws.Open:
			a.DB.Exec(ctx, `update scan_runs set status='RUNNING', paused_reason='' where id=$1`, r.id)
			a.Audit(ctx, System, "run.resume_window", "run", r.id, nil)
			a.Events.Publish("run", map[string]any{"id": r.id, "status": "RUNNING"})
		}
	}
}
