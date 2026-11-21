package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"asi/internal/core"
	"asi/internal/model"
	"asi/internal/netx"
	"asi/internal/obs"
	"asi/internal/rbac"
	"asi/internal/sigs"
)

const (
	GET    = http.MethodGet
	POST   = http.MethodPost
	PUT    = http.MethodPut
	PATCH  = http.MethodPatch
	DELETE = http.MethodDelete
)

func ok() (any, error) { return map[string]bool{"ok": true}, nil }

func (s *Server) routes() {
	a := s.App

	// ---- uwierzytelnianie ----
	s.add(POST, "/auth/login", rbac.Public, func(c *Ctx) (any, error) {
		var in struct{ Email, Password string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		if !s.allowLogin(clientIP(c.R)) {
			return nil, errTooMany
		}
		sess, err := a.Login(c.R.Context(), in.Email, in.Password, clientIP(c.R), c.R.UserAgent())
		if err != nil {
			return nil, err
		}
		s.setSessionCookies(c.W, sess)
		return map[string]string{"csrf": sess.CSRF}, nil
	})
	s.add(POST, "/auth/logout", rbac.Authenticated, func(c *Ctx) (any, error) {
		if ck, err := c.R.Cookie(sessionCookie); err == nil {
			a.Logout(c.R.Context(), ck.Value, *c.Actor)
		}
		http.SetCookie(c.W, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
		http.SetCookie(c.W, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", MaxAge: -1})
		return ok()
	})
	s.add(GET, "/auth/me", rbac.Authenticated, func(c *Ctx) (any, error) { return a.Me(c.R.Context(), *c.Actor) })
	s.add(GET, "/meta", rbac.Authenticated, func(c *Ctx) (any, error) {
		return map[string]any{"categories": core.CategoryLabels, "override_fields": core.OverrideFields, "parts": map[string][]string{
			"http": sigs.Parts("http"), "service": sigs.Parts("service"), "host": sigs.Parts("host")}, "ops": sigs.Ops(),
			"demo_mode": a.Cfg.DemoMode, "default_profile": model.DefaultProfile(), "csv_columns": core.CSVColumns}, nil
	})

	// ---- administracja ----
	s.add(GET, "/users", "users:manage", func(c *Ctx) (any, error) { return a.ListUsers(c.R.Context()) })
	s.add(POST, "/users", "users:manage", func(c *Ctx) (any, error) {
		var in core.UserInput
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		id, err := a.CreateUser(c.R.Context(), *c.Actor, in)
		return map[string]string{"id": id}, err
	})
	s.add(PATCH, "/users/{id}", "users:manage", func(c *Ctx) (any, error) {
		var in core.UserInput
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.UpdateUser(c.R.Context(), *c.Actor, c.Param("id"), in)
	})
	s.add(DELETE, "/users/{id}", "users:manage", func(c *Ctx) (any, error) { return nil, a.DeleteUser(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/permissions", rbac.Authenticated, func(c *Ctx) (any, error) { return rbac.Catalog, nil })
	s.add(GET, "/roles", rbac.Authenticated, func(c *Ctx) (any, error) { return a.ListRoles(c.R.Context()) })
	s.add(POST, "/roles", "roles:manage", func(c *Ctx) (any, error) {
		var r core.Role
		if err := c.Bind(&r); err != nil {
			return nil, err
		}
		r.ID = ""
		id, err := a.SaveRole(c.R.Context(), *c.Actor, r)
		return map[string]string{"id": id}, err
	})
	s.add(PUT, "/roles/{id}", "roles:manage", func(c *Ctx) (any, error) {
		var r core.Role
		if err := c.Bind(&r); err != nil {
			return nil, err
		}
		r.ID = c.Param("id")
		_, err := a.SaveRole(c.R.Context(), *c.Actor, r)
		return nil, err
	})
	s.add(DELETE, "/roles/{id}", "roles:manage", func(c *Ctx) (any, error) { return nil, a.DeleteRole(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/scope", "targets:read", func(c *Ctx) (any, error) {
		allow, excl, err := a.ListScope(c.R.Context())
		return map[string]any{"allow": allow, "exclusions": excl}, err
	})
	s.add(POST, "/scope", "settings:manage", func(c *Ctx) (any, error) {
		var in struct{ CIDR, Note string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.AddScope(c.R.Context(), *c.Actor, in.CIDR, in.Note)
	})
	s.add(DELETE, "/scope/{id}", "settings:manage", func(c *Ctx) (any, error) { return nil, a.DeleteScope(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(POST, "/exclusions", "settings:manage", func(c *Ctx) (any, error) {
		var in struct{ Value, Reason string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.AddExclusion(c.R.Context(), *c.Actor, in.Value, in.Reason)
	})
	s.add(DELETE, "/exclusions/{id}", "settings:manage", func(c *Ctx) (any, error) { return nil, a.DeleteExclusion(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/workers", "scans:read", func(c *Ctx) (any, error) { return a.ListWorkers(c.R.Context()) })
	s.add(POST, "/workers", "settings:manage", func(c *Ctx) (any, error) {
		var in struct{ Name, Vantage string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		tok, err := a.GenerateWorkerToken(c.R.Context(), *c.Actor, in.Name, in.Vantage)
		return map[string]string{"token": tok, "name": in.Name}, err
	})
	s.add(DELETE, "/workers/{id}", "settings:manage", func(c *Ctx) (any, error) { return nil, a.DeleteWorker(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/audit", "audit:read", func(c *Ctx) (any, error) {
		return a.ListAudit(c.R.Context(), c.Query("q"), c.QueryInt("limit", 200), c.QueryInt("offset", 0))
	})
	s.add(GET, "/killswitch", "scans:read", func(c *Ctx) (any, error) { return a.KillSwitch(c.R.Context()), nil })
	s.add(POST, "/killswitch", "killswitch:use", func(c *Ctx) (any, error) {
		var in struct {
			Active bool   `json:"active"`
			Reason string `json:"reason"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.KillSwitch(c.R.Context()), a.SetKillSwitch(c.R.Context(), *c.Actor, in.Active, in.Reason)
	})
	s.add(POST, "/keys/rotate", "settings:manage", func(c *Ctx) (any, error) {
		n, err := a.RotateDataKey(c.R.Context(), *c.Actor)
		return map[string]int{"reencrypted": n}, err
	})
	s.add(GET, "/encryption", "settings:manage", func(c *Ctx) (any, error) {
		rows, err := a.DB.Query(c.R.Context(), `select id, purpose, active, created_at, retired_at from encryption_keys order by id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var id int
			var p string
			var act bool
			var cr time.Time
			var ret *time.Time
			rows.Scan(&id, &p, &act, &cr, &ret)
			out = append(out, map[string]any{"id": id, "purpose": p, "active": act, "created_at": cr, "retired_at": ret})
		}
		return out, nil
	})

	// ---- cele i konfiguracja ----
	s.add(GET, "/target-groups", "targets:read", func(c *Ctx) (any, error) { return a.ListGroups(c.R.Context()) })
	s.add(POST, "/target-groups", "targets:create", func(c *Ctx) (any, error) {
		var in core.GroupInput
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.CreateGroup(c.R.Context(), *c.Actor, in)
	})
	s.add(GET, "/target-groups/{id}", "targets:read", func(c *Ctx) (any, error) { return a.GetGroup(c.R.Context(), c.Param("id")) })
	s.add(PUT, "/target-groups/{id}", "targets:update", func(c *Ctx) (any, error) {
		var in core.GroupInput
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.UpdateGroup(c.R.Context(), *c.Actor, c.Param("id"), in)
	})
	s.add(DELETE, "/target-groups/{id}", "targets:delete", func(c *Ctx) (any, error) { return nil, a.DeleteGroup(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/targets", "targets:read", func(c *Ctx) (any, error) { return a.ListTargets(c.R.Context(), c.Query("group_id")) })
	s.add(POST, "/targets", "targets:create", func(c *Ctx) (any, error) {
		var in struct {
			GroupID string   `json:"group_id"`
			Text    string   `json:"text"`
			Values  []string `json:"values"`
			Tags    []string `json:"tags"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		vals := append(in.Values, netx.SplitTargets(in.Text)...)
		if len(vals) == 0 {
			return nil, core.Invalid("podaj co najmniej jeden cel", nil)
		}
		return a.AddTargets(c.R.Context(), *c.Actor, in.GroupID, vals, "manual", in.Tags)
	})
	s.add(POST, "/targets/import", "targets:create", func(c *Ctx) (any, error) {
		data, name, err := readUpload(c)
		if err != nil {
			return nil, err
		}
		return a.ImportTargetsFile(c.R.Context(), *c.Actor, c.R.FormValue("group_id"), data, name)
	})
	s.add(PATCH, "/targets/{id}", "targets:update", func(c *Ctx) (any, error) {
		var in struct {
			Enabled bool     `json:"enabled"`
			Tags    []string `json:"tags"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.UpdateTarget(c.R.Context(), *c.Actor, c.Param("id"), in.Enabled, in.Tags)
	})
	s.add(DELETE, "/targets/{id}", "targets:delete", func(c *Ctx) (any, error) { return nil, a.DeleteTarget(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(POST, "/targets/validate", "targets:read", func(c *Ctx) (any, error) {
		var in struct{ Text string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		scope, _, _, _ := a.Scope(c.R.Context())
		var out []map[string]any
		var total uint64
		for _, v := range netx.SplitTargets(in.Text) {
			t, err := netx.ParseTarget(v)
			item := map[string]any{"value": v}
			if err != nil {
				item["error"] = err.Error()
			} else {
				item["kind"], item["normalized"] = t.Kind, t.Value
				n := netx.Total(t.Ranges)
				item["addresses"] = n
				total += n
				if t.Kind != "domain" && t.IPv6 == "" && netx.Total(netx.Intersect(t.Ranges, scope.Allow)) != n {
					item["error"] = "poza dozwolonym zakresem (scope)"
				}
			}
			out = append(out, item)
		}
		return map[string]any{"items": out, "addresses": total}, nil
	})
	s.add(GET, "/profiles", "config:read", func(c *Ctx) (any, error) { return a.ListProfiles(c.R.Context()) })
	s.add(POST, "/profiles", "config:create", func(c *Ctx) (any, error) {
		var in struct {
			Name   string        `json:"name"`
			Config model.Profile `json:"config"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		id, err := a.SaveProfile(c.R.Context(), *c.Actor, "", in.Name, in.Config)
		return map[string]string{"id": id}, err
	})
	s.add(PUT, "/profiles/{id}", "config:update", func(c *Ctx) (any, error) {
		var in struct {
			Name   string        `json:"name"`
			Config model.Profile `json:"config"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		_, err := a.SaveProfile(c.R.Context(), *c.Actor, c.Param("id"), in.Name, in.Config)
		return nil, err
	})
	s.add(DELETE, "/profiles/{id}", "config:delete", func(c *Ctx) (any, error) { return nil, a.DeleteProfile(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/windows", "config:read", func(c *Ctx) (any, error) { return a.ListWindows(c.R.Context(), c.Query("group_id")) })
	s.add(POST, "/windows", "config:create", func(c *Ctx) (any, error) {
		var w core.Window
		if err := c.Bind(&w); err != nil {
			return nil, err
		}
		w.ID = ""
		id, err := a.SaveWindow(c.R.Context(), *c.Actor, w)
		return map[string]string{"id": id}, err
	})
	s.add(PUT, "/windows/{id}", "config:update", func(c *Ctx) (any, error) {
		var w core.Window
		if err := c.Bind(&w); err != nil {
			return nil, err
		}
		w.ID = c.Param("id")
		_, err := a.SaveWindow(c.R.Context(), *c.Actor, w)
		return nil, err
	})
	s.add(DELETE, "/windows/{id}", "config:delete", func(c *Ctx) (any, error) { return nil, a.DeleteWindow(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/schedules", "config:read", func(c *Ctx) (any, error) { return a.ListSchedules(c.R.Context(), c.Query("group_id")) })
	s.add(POST, "/schedules", "config:create", func(c *Ctx) (any, error) {
		var in core.Schedule
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		in.ID = ""
		id, err := a.SaveSchedule(c.R.Context(), *c.Actor, in)
		return map[string]string{"id": id}, err
	})
	s.add(PUT, "/schedules/{id}", "config:update", func(c *Ctx) (any, error) {
		var in core.Schedule
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		in.ID = c.Param("id")
		_, err := a.SaveSchedule(c.R.Context(), *c.Actor, in)
		return nil, err
	})
	s.add(DELETE, "/schedules/{id}", "config:delete", func(c *Ctx) (any, error) { return nil, a.DeleteSchedule(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(POST, "/estimate", "config:read", func(c *Ctx) (any, error) {
		var in struct {
			GroupID   string `json:"group_id"`
			ProfileID string `json:"profile_id"`
			Mode      string `json:"mode"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		g, err := a.GetGroup(c.R.Context(), in.GroupID)
		if err != nil {
			return nil, err
		}
		pid := in.ProfileID
		if pid == "" {
			pid = g.ProfileID
		}
		p, err := a.GetProfile(c.R.Context(), pid)
		if err != nil {
			return nil, err
		}
		if in.Mode == "liveness" {
			p.TCPPorts = "top-100"
		}
		return a.Estimate(c.R.Context(), g, p, uint64(g.Addresses), 1), nil
	})

	// ---- przebiegi ----
	s.add(GET, "/runs", "scans:read", func(c *Ctx) (any, error) {
		return a.ListRuns(c.R.Context(), core.RunFilter{GroupID: c.Query("group_id"), Status: c.Query("status"), Source: c.Query("source"), Limit: c.QueryInt("limit", 100)})
	})
	s.add(POST, "/runs", "scans:start", func(c *Ctx) (any, error) {
		var in core.RunInput
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.CreateRun(c.R.Context(), *c.Actor, in)
	})
	s.add(GET, "/runs/{id}", "scans:read", func(c *Ctx) (any, error) { return a.GetRun(c.R.Context(), c.Param("id")) })
	s.add(GET, "/runs/{id}/tasks", "scans:read", func(c *Ctx) (any, error) { return a.ListTasks(c.R.Context(), c.Param("id")) })
	for _, act := range []string{"pause", "resume", "cancel"} {
		act := act
		s.add(POST, "/runs/{id}/"+act, "scans:control", func(c *Ctx) (any, error) { return a.ControlRun(c.R.Context(), *c.Actor, c.Param("id"), act) })
	}
	s.add(DELETE, "/runs/{id}", "scans:delete", func(c *Ctx) (any, error) { return nil, a.DeleteRun(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/runs/{a}/diff/{b}", "results:read", func(c *Ctx) (any, error) { return a.DiffRuns(c.R.Context(), c.Param("a"), c.Param("b")) })
	s.addRaw(GET, "/events", "scans:read", s.events)

	// ---- wyniki ----
	s.add(GET, "/dashboard", "results:read", func(c *Ctx) (any, error) { return a.Dashboard(c.R.Context()) })
	page := func(c *Ctx) core.Page {
		return core.Page{Limit: c.QueryInt("limit", 100), Offset: c.QueryInt("offset", 0), Sort: c.Query("sort")}
	}
	s.add(GET, "/hosts", "results:read", func(c *Ctx) (any, error) {
		rows, total, err := a.ListHosts(c.R.Context(), c.Query("q"), page(c))
		return map[string]any{"items": rows, "total": total}, err
	})
	s.add(GET, "/hosts/{ip}", "results:read", func(c *Ctx) (any, error) {
		d, err := a.HostDetail(c.R.Context(), c.Param("ip"))
		if err == nil && !c.Actor.Can("sensitive:read") {
			maskDetail(d)
		}
		return d, err
	})
	s.add(GET, "/services", "results:read", func(c *Ctx) (any, error) {
		rows, total, err := a.ListServices(c.R.Context(), c.Query("q"), page(c))
		return map[string]any{"items": rows, "total": total}, err
	})
	s.add(GET, "/web", "results:read", func(c *Ctx) (any, error) {
		rows, total, err := a.ListWeb(c.R.Context(), c.Query("q"), page(c))
		return map[string]any{"items": rows, "total": total}, err
	})
	s.add(GET, "/technologies", "results:read", func(c *Ctx) (any, error) { return a.ListTechnologies(c.R.Context(), c.Query("q")) })
	s.add(GET, "/changes", "results:read", func(c *Ctx) (any, error) {
		since := time.Now().Add(-30 * 24 * time.Hour)
		if d, err := time.ParseDuration(c.Query("since")); err == nil {
			since = time.Now().Add(-d)
		}
		return a.ListChanges(c.R.Context(), core.ChangeFilter{Type: c.Query("type"), IP: c.Query("ip"), Q: c.Query("q"), RunID: c.Query("run_id"), Since: since,
			MinPriority: c.QueryInt("min_priority", -1), Unacked: c.Query("unacked") == "true", Limit: c.QueryInt("limit", 200), Offset: c.QueryInt("offset", 0)})
	})
	s.add(POST, "/changes/ack", "results:update", func(c *Ctx) (any, error) {
		var in struct {
			IDs []int64 `json:"ids"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.AckChange(c.R.Context(), *c.Actor, in.IDs)
	})
	s.add(GET, "/clusters", "results:read", func(c *Ctx) (any, error) { return a.ListClusters(c.R.Context(), c.QueryInt("limit", 200)) })
	s.add(GET, "/clusters/{key}", "results:read", func(c *Ctx) (any, error) { return a.GetCluster(c.R.Context(), c.Param("key")) })
	s.add(PUT, "/overrides", "results:update", func(c *Ctx) (any, error) {
		var in struct {
			EntityType string `json:"entity_type"`
			Key        string `json:"key"`
			Field      string `json:"field"`
			Value      any    `json:"value"`
			Confirm    bool   `json:"confirm"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		if in.Confirm {
			return nil, a.ConfirmOverride(c.R.Context(), *c.Actor, in.EntityType, in.Key, in.Field)
		}
		return nil, a.SetOverride(c.R.Context(), *c.Actor, in.EntityType, in.Key, in.Field, in.Value)
	})
	s.add(DELETE, "/overrides", "results:update", func(c *Ctx) (any, error) {
		return nil, a.DeleteOverride(c.R.Context(), *c.Actor, c.Query("entity_type"), c.Query("key"), c.Query("field"))
	})
	s.add(GET, "/tags", "results:read", func(c *Ctx) (any, error) { return a.ListTags(c.R.Context()) })
	s.add(POST, "/tags", "results:update", func(c *Ctx) (any, error) {
		var in struct {
			EntityType string   `json:"entity_type"`
			Keys       []string `json:"keys"`
			Tag        string   `json:"tag"`
			Remove     bool     `json:"remove"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		for _, k := range in.Keys {
			if err := a.TagEntity(c.R.Context(), *c.Actor, in.EntityType, k, in.Tag, !in.Remove); err != nil {
				return nil, err
			}
		}
		return ok()
	})
	s.add(POST, "/notes", "results:update", func(c *Ctx) (any, error) {
		var in struct {
			EntityType string `json:"entity_type"`
			Key        string `json:"key"`
			Body       string `json:"body"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		id, err := a.AddNote(c.R.Context(), *c.Actor, in.EntityType, in.Key, in.Body)
		return map[string]string{"id": id}, err
	})
	s.add(DELETE, "/notes/{id}", "results:update", func(c *Ctx) (any, error) { return nil, a.DeleteNote(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/suppressions", "results:read", func(c *Ctx) (any, error) { return a.ListSuppressions(c.R.Context()) })
	s.add(POST, "/suppressions", "results:update", func(c *Ctx) (any, error) {
		var in core.Suppression
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.AddSuppression(c.R.Context(), *c.Actor, in)
	})
	s.add(DELETE, "/suppressions/{id}", "results:update", func(c *Ctx) (any, error) { return nil, a.DeleteSuppression(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(GET, "/raw", "sensitive:read", func(c *Ctx) (any, error) {
		v, err := a.RawData(c.R.Context(), c.Query("entity_type"), c.Query("key"))
		if err == nil {
			a.Audit(c.R.Context(), *c.Actor, "sensitive.read", c.Query("entity_type"), c.Query("key"), nil)
		}
		return v, err
	})
	s.add(POST, "/retry", "scans:start", func(c *Ctx) (any, error) {
		var in struct {
			IP string `json:"ip"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		var gid string
		a.DB.QueryRow(c.R.Context(), `select coalesce(group_id::text,'') from hosts where ip=$1::inet`, in.IP).Scan(&gid)
		if gid == "" {
			return nil, core.Invalid("host nie należy do żadnej grupy celów", nil)
		}
		return a.CreateRun(c.R.Context(), *c.Actor, core.RunInput{GroupID: gid, Mode: "baseline", Targets: []string{in.IP}, Note: "ponowny pomiar hosta " + in.IP})
	})

	// ---- import / eksport / ocena ----
	s.add(POST, "/import/observations", "results:create", func(c *Ctx) (any, error) {
		data, name, err := readUpload(c)
		if err != nil {
			return nil, err
		}
		return a.ImportObservations(c.R.Context(), *c.Actor, data, name, c.R.FormValue("group_id"), "", c.Query("dry_run") == "true" || c.R.FormValue("dry_run") == "true")
	})
	s.add(POST, "/observations", "results:create", func(c *Ctx) (any, error) {
		var in struct {
			obs.Observation
			GroupID string `json:"group_id"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		in.Observation.Source = "manual"
		b, _ := json.Marshal(in.Observation)
		return a.ImportObservations(c.R.Context(), *c.Actor, b, "formularz", in.GroupID, "manual", false)
	})
	s.add(GET, "/imports", "results:read", func(c *Ctx) (any, error) {
		rows, err := a.DB.Query(c.R.Context(), `select id, kind, format, filename, status, stats, coalesce(run_id::text,''), created_by, created_at from imports order by created_at desc limit 50`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var id, kind, format, fn, status, run, by string
			var stats json.RawMessage
			var at time.Time
			rows.Scan(&id, &kind, &format, &fn, &status, &stats, &run, &by, &at)
			out = append(out, map[string]any{"id": id, "kind": kind, "format": format, "filename": fn, "status": status, "stats": stats, "run_id": run, "created_by": by, "created_at": at})
		}
		return out, nil
	})
	s.addRaw(GET, "/export", "export:use", func(c *Ctx) (any, error) {
		opt := core.ExportOptions{Format: c.Query("format"), Q: c.Query("q"), RunID: c.Query("run_id"), IncludeRaw: c.Query("include_raw") == "true",
			IncludeSensitive: c.Query("include_sensitive") == "true"}
		if opt.IncludeSensitive && !c.Actor.Can("sensitive:read") {
			return nil, core.Invalid("eksport danych wrażliwych wymaga uprawnienia sensitive:read", nil)
		}
		if opt.Format == "" {
			opt.Format = "json"
		}
		var buf bytes.Buffer
		if err := a.Export(c.R.Context(), *c.Actor, opt, &buf); err != nil {
			return nil, err
		}
		ext := map[string]string{"csv": "csv", "jsonl": "jsonl"}[opt.Format]
		if ext == "" {
			ext = "json"
		}
		ct := map[string]string{"csv": "text/csv; charset=utf-8", "jsonl": "application/x-ndjson"}[opt.Format]
		if ct == "" {
			ct = "application/json"
		}
		c.W.Header().Set("Content-Type", ct)
		c.W.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="asi-export-%s.%s"`, time.Now().Format("20060102-1504"), ext))
		c.W.Write(buf.Bytes())
		return nil, nil
	})
	s.add(POST, "/eval", "results:read", func(c *Ctx) (any, error) {
		var in struct {
			Reference string `json:"reference_run_id"`
			Candidate string `json:"candidate_run_id"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.Evaluate(c.R.Context(), in.Reference, in.Candidate)
	})

	// ---- sygnatury ----
	s.add(GET, "/signatures", "signatures:read", func(c *Ctx) (any, error) { return a.ListSignatures(c.R.Context()) })
	s.add(GET, "/signatures/{id}", "signatures:read", func(c *Ctx) (any, error) { return a.GetSignature(c.R.Context(), c.Param("id")) })
	s.add(POST, "/signatures", "signatures:create", func(c *Ctx) (any, error) {
		var in struct{ Source string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.SaveSignature(c.R.Context(), *c.Actor, in.Source, "user", true)
	})
	s.add(PUT, "/signatures/{id}", "signatures:update", func(c *Ctx) (any, error) {
		var in struct{ Source string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.SaveSignature(c.R.Context(), *c.Actor, in.Source, "user", false)
	})
	s.add(POST, "/signatures/{id}/toggle", "signatures:update", func(c *Ctx) (any, error) {
		var in struct {
			Enabled bool `json:"enabled"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.SetSignatureEnabled(c.R.Context(), *c.Actor, c.Param("id"), in.Enabled)
	})
	s.add(DELETE, "/signatures/{id}", "signatures:delete", func(c *Ctx) (any, error) { return nil, a.DeleteSignature(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(POST, "/signatures/validate", "signatures:read", func(c *Ctx) (any, error) {
		var in struct{ Source string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		sg, errs := core.ParseSignature(in.Source)
		res := map[string]any{"valid": len(errs) == 0, "errors": errs}
		if sg != nil && len(errs) == 0 {
			res["id"], res["kind"], res["scope"] = sg.ID, map[bool]string{true: "active", false: "passive"}[sg.Active()], sg.Scope
		}
		return res, nil
	})
	s.add(POST, "/signatures/test", "signatures:read", func(c *Ctx) (any, error) {
		var in struct {
			Source    string `json:"source"`
			EntityKey string `json:"entity_key"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.TestSignature(c.R.Context(), in.Source, strings.TrimSpace(in.EntityKey))
	})
	s.add(POST, "/signatures/{id}/retrohunt", "signatures:update", func(c *Ctx) (any, error) { return a.Retrohunt(c.R.Context(), *c.Actor, c.Param("id")) })
	s.add(POST, "/signatures/import", "signatures:create", func(c *Ctx) (any, error) {
		data, _, err := readUpload(c)
		if err != nil {
			return nil, err
		}
		return a.ImportSignatures(c.R.Context(), *c.Actor, string(data))
	})
	s.addRaw(GET, "/signatures-export", "signatures:read", func(c *Ctx) (any, error) {
		list, err := a.ListSignatures(c.R.Context())
		if err != nil {
			return nil, err
		}
		c.W.Header().Set("Content-Type", "application/yaml")
		c.W.Header().Set("Content-Disposition", `attachment; filename="asi-signatures.yaml"`)
		for i, s := range list {
			if c.Query("origin") != "" && s.Origin != c.Query("origin") {
				continue
			}
			if i > 0 {
				io.WriteString(c.W, "---\n")
			}
			io.WriteString(c.W, s.Source)
		}
		return nil, nil
	})

	// ---- DefectDojo ----
	s.add(GET, "/findings", "results:read", func(c *Ctx) (any, error) {
		rows, total, err := a.ListFindings(c.R.Context(), core.FindingFilter{Status: c.Query("status"), Q: c.Query("q"), Active: c.Query("active"), GroupID: c.Query("group_id"),
			Limit: c.QueryInt("limit", 100), Offset: c.QueryInt("offset", 0)})
		return map[string]any{"items": rows, "total": total}, err
	})
	s.add(POST, "/findings/push", "defectdojo:push", func(c *Ctx) (any, error) {
		var in struct {
			Keys []string `json:"keys"`
			IDs  []string `json:"ids"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return a.PushRequested(c.R.Context(), *c.Actor, in.Keys, in.IDs)
	})
	s.add(POST, "/findings/{id}/triage", "defectdojo:triage", func(c *Ctx) (any, error) {
		var in struct{ Status string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.Triage(c.R.Context(), *c.Actor, c.Param("id"), in.Status)
	})
	s.add(POST, "/defectdojo/sync", "defectdojo:triage", func(c *Ctx) (any, error) {
		res := map[string]any{}
		groups := map[string]bool{}
		rows, _ := a.DB.Query(c.R.Context(), `select distinct coalesce(group_id::text,'none') from findings where exported and active`)
		for rows.Next() {
			var g string
			rows.Scan(&g)
			groups[g] = true
		}
		rows.Close()
		if c.Actor.Can("defectdojo:push") {
			for g := range groups {
				r, err := a.PushGroup(c.R.Context(), g, false)
				if err != nil {
					return nil, core.Invalid(err.Error(), nil)
				}
				res["push_"+g] = r
			}
		}
		st, err := a.PullStatuses(c.R.Context())
		if err != nil {
			return nil, core.Invalid(err.Error(), nil)
		}
		res["statuses"] = st
		a.Audit(c.R.Context(), *c.Actor, "defectdojo.sync", "defectdojo", "", nil)
		return res, nil
	})
	s.add(GET, "/defectdojo", "results:read", func(c *Ctx) (any, error) {
		cfg := a.DDConfig(c.R.Context())
		rows, _ := a.DB.Query(c.R.Context(), `select at, direction, status, details from dd_sync_log order by id desc limit 30`)
		var log []map[string]any
		for rows.Next() {
			var at time.Time
			var d, s, det string
			rows.Scan(&at, &d, &s, &det)
			log = append(log, map[string]any{"at": at, "direction": d, "status": s, "details": det})
		}
		rows.Close()
		return map[string]any{"config": cfg, "log": log}, nil
	})
	s.add(PUT, "/defectdojo", "settings:manage", func(c *Ctx) (any, error) {
		var in struct {
			core.DDConfig
			Token string `json:"token"`
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		return nil, a.SaveDDConfig(c.R.Context(), *c.Actor, in.DDConfig, in.Token)
	})
	s.add(POST, "/defectdojo/test", "settings:manage", func(c *Ctx) (any, error) { return a.DDTest(c.R.Context()), nil })
}

// readUpload czyta plik z multipart (pole "file") albo surowe ciało.
func readUpload(c *Ctx) ([]byte, string, error) {
	ct := c.R.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/") {
		if err := c.R.ParseMultipartForm(64 << 20); err != nil {
			return nil, "", core.Invalid("niepoprawny formularz: "+err.Error(), nil)
		}
		f, h, err := c.R.FormFile("file")
		if err != nil {
			if txt := c.R.FormValue("text"); txt != "" {
				return []byte(txt), "tekst", nil
			}
			return nil, "", core.Invalid("brak pliku (pole file)", nil)
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, 64<<20))
		return b, h.Filename, err
	}
	b, err := io.ReadAll(io.LimitReader(c.R.Body, 64<<20))
	return b, c.Query("filename"), err
}

// maskDetail ukrywa dane wrażliwe dla ról bez sensitive:read.
func maskDetail(d *core.HostDetail) {
	for i := range d.Services {
		for j := range d.Services[i].Web {
			d.Services[i].Web[j].Cookies = json.RawMessage(maskCookies(d.Services[i].Web[j].Cookies))
		}
	}
}

func maskCookies(raw json.RawMessage) []byte {
	var cs []map[string]any
	json.Unmarshal(raw, &cs)
	for _, c := range cs {
		delete(c, "value")
	}
	b, _ := json.Marshal(cs)
	if cs == nil {
		return []byte("[]")
	}
	return b
}
