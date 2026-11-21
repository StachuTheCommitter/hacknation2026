package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/dd"
	"asi/internal/obs"
)

// DDConfig – konfiguracja integracji z DefectDojo (token przechowywany zaszyfrowany).
type DDConfig struct {
	URL         string         `json:"url"`
	AutoPush    bool           `json:"auto_push"`
	ProductType string         `json:"product_type"`
	Product     string         `json:"product"`
	Engagement  string         `json:"engagement"`
	InsecureTLS bool           `json:"insecure_tls"`
	Tests       map[string]int `json:"tests"` // grupa → id testu w DefectDojo
	HasToken    bool           `json:"has_token"`
	LastSync    string         `json:"last_sync"`
	LastError   string         `json:"last_error"`
}

func (a *App) DDConfig(ctx context.Context) DDConfig {
	var c DDConfig
	a.GetSetting(ctx, "defectdojo", &c)
	if c.ProductType == "" {
		c.ProductType = "ASI"
	}
	if c.Product == "" {
		c.Product = "ASI"
	}
	if c.Engagement == "" {
		c.Engagement = "ASI Continuous Discovery"
	}
	if c.Tests == nil {
		c.Tests = map[string]int{}
	}
	tok, _ := a.GetSecret(ctx, "dd_token")
	c.HasToken = tok != ""
	return c
}

func (a *App) SaveDDConfig(ctx context.Context, actor Actor, c DDConfig, token string) error {
	old := a.DDConfig(ctx)
	c.URL = strings.TrimRight(strings.TrimSpace(c.URL), "/")
	if c.URL != old.URL {
		c.Tests = map[string]int{} // nowa instancja – nowe testy
	} else {
		c.Tests = old.Tests
	}
	c.LastSync, c.LastError = old.LastSync, old.LastError
	if err := a.SetSetting(ctx, "defectdojo", c); err != nil {
		return err
	}
	if token != "" {
		if err := a.SetSecret(ctx, "dd_token", token); err != nil {
			return err
		}
	}
	a.Audit(ctx, actor, "defectdojo.config", "settings", "defectdojo", map[string]any{"url": c.URL, "auto_push": c.AutoPush, "token_changed": token != ""})
	return nil
}

func (a *App) ddClient(ctx context.Context) (*dd.Client, DDConfig, error) {
	c := a.DDConfig(ctx)
	tok, err := a.GetSecret(ctx, "dd_token")
	if err != nil {
		return nil, c, err
	}
	if c.URL == "" || tok == "" {
		return nil, c, Invalid("integracja z DefectDojo nie jest skonfigurowana (Administracja → DefectDojo)", nil)
	}
	return dd.New(c.URL, tok, c.InsecureTLS), c, nil
}

func (a *App) DDTest(ctx context.Context) dd.Info {
	cl, _, err := a.ddClient(ctx)
	if err != nil {
		return dd.Info{Message: err.Error()}
	}
	return cl.Test(ctx)
}

func (a *App) ddLog(ctx context.Context, dir, status, details string) {
	a.DB.Exec(ctx, `insert into dd_sync_log(direction,status,details) values($1,$2,$3)`, dir, status, truncate(details, 2000))
	c := a.DDConfig(ctx)
	c.LastSync = time.Now().Format(time.RFC3339)
	if status == "error" {
		c.LastError = details
	} else {
		c.LastError = ""
	}
	a.SetSetting(ctx, "defectdojo", c)
}

// ---------------- znaleziska ----------------

type Finding struct {
	ID               string         `json:"id"`
	EntityType       string         `json:"entity_type"`
	EntityKey        string         `json:"entity_key"`
	HostIP           string         `json:"host_ip"`
	GroupName        string         `json:"group_name"`
	Rule             string         `json:"rule"`
	Category         string         `json:"category"`
	Title            string         `json:"title"`
	Severity         string         `json:"severity"`
	Description      string         `json:"description"`
	ComponentName    string         `json:"component_name"`
	ComponentVersion string         `json:"component_version"`
	Status           string         `json:"status"`
	Exported         bool           `json:"exported"`
	Active           bool           `json:"active"`
	DDFindingID      *int           `json:"dd_finding_id"`
	LastPushedAt     *time.Time     `json:"last_pushed_at"`
	FirstSeen        time.Time      `json:"first_seen"`
	LastSeen         time.Time      `json:"last_seen"`
	Endpoint         map[string]any `json:"endpoint"`
}

var sevMap = map[string]string{"info": "Info", "low": "Low", "medium": "Medium", "high": "High"}

// syncFindings tworzy znaleziska z dopasowań sygnatur oznaczonych do eksportu.
func (a *App) syncFindings(ctx context.Context, etype, key, ip, hostID, groupID string, hits []sigHit, evaluated map[string]bool, url string, port int, proto, vhost string, techs []obs.Tech) {
	matched := map[string]bool{}
	for _, x := range hits {
		sg := x.sg
		if sg.Export == nil || !sg.Export.DefectDojo || matched[sg.ID] {
			continue
		}
		matched[sg.ID] = true
		rule := "sig:" + sg.ID
		cat := ""
		if len(sg.Categories) > 0 {
			cat = sg.Categories[0]
		}
		title := sg.Export.Title
		if title == "" {
			title = sg.Name
		}
		where := fmt.Sprintf("%s:%d", ip, port)
		if vhost != "" {
			where = fmt.Sprintf("%s (%s:%d)", vhost, ip, port)
		}
		fullTitle := fmt.Sprintf("[ASI] %s – %s", title, where)
		ev := append([]string(nil), x.res.Evidence...)
		sort.Strings(ev)
		desc := fmt.Sprintf("Kategoria: %s\nReguła: %s (sygnatura ASI)\nEndpoint: %s\nDowody:\n- %s\n\nObserwacja informacyjna z discovery ASI – wymaga oceny analityka.",
			cat, sg.ID, url, strings.Join(ev, "\n- "))
		comp, ver := "", ""
		if sg.Technology != nil {
			comp, ver = sg.Technology.Name, x.res.Version
		}
		ep := map[string]any{"protocol": strings.ToLower(proto), "host": ip, "port": port}
		if proto != "tcp" && proto != "udp" {
			ep["protocol"] = proto
		}
		for _, r := range sg.AllRequests() {
			ep["path"] = r.Path
			break
		}
		dedup := a.Keys.MAC("finding", key, rule)
		a.DB.Exec(ctx, `insert into findings(entity_type,entity_key,host_ip,group_id,rule,category,title,severity,description,component_name,component_version,endpoint,dedup_key,exported)
			values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,true)
			on conflict(dedup_key) do update set title=excluded.title, severity=excluded.severity, description=excluded.description, component_name=excluded.component_name,
			component_version=excluded.component_version, endpoint=excluded.endpoint, active=true, last_seen=now(), group_id=coalesce(findings.group_id,excluded.group_id)`,
			etype, key, ip, nullUUID(groupID), rule, cat, fullTitle, sevMap[sg.Severity], desc, comp, ver, jsonb(ep), dedup)
	}
	for id := range evaluated {
		if !matched[id] {
			a.DB.Exec(ctx, `update findings set active=false where entity_key=$1 and rule=$2 and active`, key, "sig:"+id)
		}
	}
}

type FindingFilter struct {
	Status  string
	Q       string
	Active  string
	GroupID string
	Limit   int
	Offset  int
}

func (a *App) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	where := `($1='' or f.status=$1) and ($2='' or f.title ilike '%'||$2||'%' or f.entity_key ilike '%'||$2||'%' or f.category=$2)
		and ($3='' or f.active=($3='true')) and ($4='' or f.group_id::text=$4)`
	var total int
	a.DB.QueryRow(ctx, `select count(*) from findings f where `+where, f.Status, f.Q, f.Active, f.GroupID).Scan(&total)
	rows, err := a.DB.Query(ctx, `select f.id, f.entity_type, f.entity_key, coalesce(host(f.host_ip),''), coalesce(g.name,''), f.rule, f.category, f.title, f.severity, f.description,
		f.component_name, f.component_version, f.status, f.exported, f.active, f.dd_finding_id, f.last_pushed_at, f.first_seen, f.last_seen, f.endpoint
		from findings f left join target_groups g on g.id=f.group_id where `+where+` order by f.active desc, case f.severity when 'High' then 0 when 'Medium' then 1 when 'Low' then 2 else 3 end, f.last_seen desc limit $5 offset $6`,
		f.Status, f.Q, f.Active, f.GroupID, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Finding, error) {
		var x Finding
		var ep []byte
		err := r.Scan(&x.ID, &x.EntityType, &x.EntityKey, &x.HostIP, &x.GroupName, &x.Rule, &x.Category, &x.Title, &x.Severity, &x.Description, &x.ComponentName,
			&x.ComponentVersion, &x.Status, &x.Exported, &x.Active, &x.DDFindingID, &x.LastPushedAt, &x.FirstSeen, &x.LastSeen, &ep)
		json.Unmarshal(ep, &x.Endpoint)
		return x, err
	})
	return out, total, err
}

// buildReport – raport Generic Findings Import dla grupy (wszystkie aktywne, eksportowane znaleziska).
func (a *App) buildReport(ctx context.Context, groupKey string) ([]dd.Finding, error) {
	rows, err := a.DB.Query(ctx, `select title, severity, description, dedup_key, rule, component_name, component_version, endpoint, category, entity_key, status
		from findings where exported and active and coalesce(group_id::text,'none')=$1 order by dedup_key`, groupKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dd.Finding
	for rows.Next() {
		var f dd.Finding
		var rule, cat, key, status string
		var ep []byte
		if err := rows.Scan(&f.Title, &f.Severity, &f.Description, &f.UniqueIDFromTool, &rule, &f.ComponentName, &f.ComponentVersion, &ep, &cat, &key, &status); err != nil {
			return nil, err
		}
		f.UniqueIDFromTool = "asi:" + f.UniqueIDFromTool
		f.VulnIDFromTool = strings.TrimPrefix(rule, "sig:")
		var e dd.Endpoint
		json.Unmarshal(ep, &e)
		if e.Host != "" {
			f.Endpoints = []dd.Endpoint{e}
		}
		f.References = fmt.Sprintf("%s/hosts/%s", a.Cfg.BaseURL, strings.SplitN(key, "/", 2)[0])
		f.Tags = []string{"asi"}
		if cat != "" {
			f.Tags = append(f.Tags, cat)
		}
		f.DynamicFinding = true
		out = append(out, f)
	}
	return out, rows.Err()
}

// PushGroup wysyła znaleziska grupy do DefectDojo (import przy pierwszym razie, potem reimport).
func (a *App) PushGroup(ctx context.Context, groupKey string, closeOld bool) (map[string]any, error) {
	cl, cfg, err := a.ddClient(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := a.buildReport(ctx, groupKey)
	if err != nil {
		return nil, err
	}
	groupName := "Bez grupy"
	if groupKey != "none" {
		a.DB.QueryRow(ctx, `select name from target_groups where id=$1`, groupKey).Scan(&groupName)
	}
	if findings == nil {
		findings = []dd.Finding{}
	}
	file, _ := json.MarshalIndent(map[string]any{"findings": findings}, "", "  ")
	testID := cfg.Tests[groupKey]
	p := dd.ImportParams{ScanType: "Generic Findings Import", ProductType: cfg.ProductType, Product: cfg.Product, Engagement: cfg.Engagement,
		TestTitle: "ASI – " + groupName, TestID: testID, CloseOld: closeOld, FileName: "asi-findings.json", File: file}
	newID, resp, err := cl.Import(ctx, p)
	if err != nil {
		var apiErr *dd.APIError
		if testID > 0 && asAPIErr(err, &apiErr) && apiErr.Status == 404 { // test usunięty po stronie DD – zakładamy od nowa
			p.TestID = 0
			newID, resp, err = cl.Import(ctx, p)
		}
		if err != nil {
			a.ddLog(ctx, "push", "error", err.Error())
			return nil, err
		}
	}
	cfg = a.DDConfig(ctx)
	cfg.Tests[groupKey] = newID
	a.SetSetting(ctx, "defectdojo", cfg)
	a.DB.Exec(ctx, `update findings set last_pushed_at=now(), dd_test_id=$2 where exported and active and coalesce(group_id::text,'none')=$1`, groupKey, newID)
	a.ddLog(ctx, "push", "ok", fmt.Sprintf("%s: %d znalezisk, test %d, close_old=%t", groupName, len(findings), newID, closeOld))
	stats := map[string]any{"test_id": newID, "findings": len(findings), "close_old_findings": closeOld}
	if s, ok := resp["statistics"]; ok {
		stats["statistics"] = s
	}
	if _, err := a.PullStatuses(ctx); err != nil {
		slog.Warn("pobranie statusów DD", "err", err)
	}
	return stats, nil
}

func asAPIErr(err error, target **dd.APIError) bool {
	e, ok := err.(*dd.APIError)
	if ok {
		*target = e
	}
	return ok
}

// PushRequested – wysyłka ręczna (przycisk „Wyślij do DefectDojo”) – bez zamykania starych znalezisk.
func (a *App) PushRequested(ctx context.Context, actor Actor, keys []string, ids []string) (map[string]any, error) {
	for _, k := range keys {
		var n int
		a.DB.QueryRow(ctx, `select count(*) from findings where entity_key=$1 or entity_key like $1||'/%'`, k).Scan(&n)
		if n == 0 {
			if err := a.manualFinding(ctx, k); err != nil {
				return nil, err
			}
		}
		a.DB.Exec(ctx, `update findings set exported=true where entity_key=$1 or entity_key like $1||'/%'`, k)
	}
	for _, id := range ids {
		a.DB.Exec(ctx, `update findings set exported=true where id=$1`, id)
	}
	groups := map[string]bool{}
	rows, _ := a.DB.Query(ctx, `select distinct coalesce(group_id::text,'none') from findings where exported and active and (entity_key = any($1) or id::text = any($2) or split_part(entity_key,'/',1) = any($1))`, nonNil(keys), nonNil(ids))
	for rows.Next() {
		var g string
		rows.Scan(&g)
		groups[g] = true
	}
	rows.Close()
	res := map[string]any{}
	for g := range groups {
		r, err := a.PushGroup(ctx, g, false)
		if err != nil {
			return nil, err
		}
		res[g] = r
	}
	a.Audit(ctx, actor, "defectdojo.push", "findings", strings.Join(keys, ","), map[string]any{"groups": len(groups)})
	return res, nil
}

// manualFinding – znalezisko informacyjne z encji bez dopasowanej sygnatury eksportowej.
func (a *App) manualFinding(ctx context.Context, key string) error {
	parts := strings.Split(key, "/")
	ip := parts[0]
	var groupID *string
	var hostScore int
	if a.DB.QueryRow(ctx, `select group_id::text, score from hosts where ip=$1::inet`, ip).Scan(&groupID, &hostScore) != nil {
		return ErrNotFound
	}
	title := fmt.Sprintf("[ASI] Obserwacja przekazana przez analityka – %s", key)
	var cats []string
	a.DB.QueryRow(ctx, `select coalesce(array_agg(distinct category),'{}') from classifications c join hosts h on h.id=c.host_id where h.ip=$1::inet and c.active`, ip).Scan(&cats)
	sort.Strings(cats)
	desc := fmt.Sprintf("Encja: %s\nKategorie: %s\n\nObserwacja przekazana ręcznie z ASI jako evidence do dalszej analizy.", key, strings.Join(cats, ", "))
	port := 0
	if len(parts) >= 3 {
		port = atoi(parts[2])
	}
	g := ""
	if groupID != nil {
		g = *groupID
	}
	_, err := a.DB.Exec(ctx, `insert into findings(entity_type,entity_key,host_ip,group_id,rule,category,title,severity,description,endpoint,dedup_key,exported)
		values($1,$2,$3,$4,'manual','manual',$5,'Info',$6,$7,$8,true) on conflict(dedup_key) do update set exported=true, active=true`,
		map[bool]string{true: "service", false: "host"}[len(parts) >= 3], key, ip, nullUUID(g), title, desc, jsonb(map[string]any{"host": ip, "port": port}), a.Keys.MAC("finding", key, "manual"))
	return err
}

// PullStatuses pobiera decyzje analityków z DefectDojo (FP, risk accepted, mitigated).
func (a *App) PullStatuses(ctx context.Context) (map[string]int, error) {
	cl, cfg, err := a.ddClient(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	var changedKeys []string
	for _, testID := range cfg.Tests {
		remote, err := cl.Findings(ctx, testID)
		if err != nil {
			a.ddLog(ctx, "pull", "error", err.Error())
			return nil, err
		}
		for _, rf := range remote {
			uid := strings.TrimPrefix(rf.UniqueIDFromTool, "asi:")
			if uid == "" {
				continue
			}
			st := rf.Status()
			if st == "duplicate" {
				continue
			}
			counts[st]++
			var key, old string
			if a.DB.QueryRow(ctx, `update findings set dd_finding_id=$2, dd_test_id=$3, last_synced_at=now(),
				status=$4 where dedup_key=$1 returning entity_key, (select status from findings where dedup_key=$1)`, uid, rf.ID, testID, st).Scan(&key, &old) == nil && old != st {
				changedKeys = append(changedKeys, key)
			}
		}
	}
	for _, k := range changedKeys {
		a.RescoreKey(ctx, k)
	}
	a.ddLog(ctx, "pull", "ok", fmt.Sprintf("statusy: %v, zmienione: %d", counts, len(changedKeys)))
	return counts, nil
}

// Triage – decyzja analityka w UI ASI (synchronizowana do DefectDojo, które pozostaje źródłem prawdy).
func (a *App) Triage(ctx context.Context, actor Actor, id, status string) error {
	if status != "false_positive" && status != "risk_accepted" && status != "open" {
		return Invalid("status: false_positive | risk_accepted | open", nil)
	}
	var ddID *int
	var key string
	if a.DB.QueryRow(ctx, `select dd_finding_id, entity_key from findings where id=$1`, id).Scan(&ddID, &key) != nil {
		return ErrNotFound
	}
	if ddID != nil {
		cl, _, err := a.ddClient(ctx)
		if err == nil {
			fields := map[string]any{"false_p": status == "false_positive", "active": status == "open"}
			if status == "risk_accepted" {
				fields = map[string]any{"risk_accepted": true, "active": false}
			}
			if status == "open" {
				fields["risk_accepted"] = false
			}
			if err := cl.Patch(ctx, *ddID, fields); err != nil {
				a.ddLog(ctx, "patch", "error", err.Error())
				return Invalid("DefectDojo odrzuciło zmianę: "+err.Error(), nil)
			}
		}
	}
	a.DB.Exec(ctx, `update findings set status=$2 where id=$1`, id, status)
	a.RescoreKey(ctx, key)
	a.Audit(ctx, actor, "finding.triage", "finding", id, map[string]any{"status": status, "synced_to_dd": ddID != nil})
	return nil
}
