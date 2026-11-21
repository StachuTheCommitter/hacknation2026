package core

import (
	"context"
	"encoding/json"
	"strings"

	"asi/internal/obs"
	"asi/internal/sigs"
)

// TestSignature ocenia sygnaturę na wskazanej encji krok po kroku (bez zapisu).
func (a *App) TestSignature(ctx context.Context, src, entityKey string) (map[string]any, error) {
	sg, errs := ParseSignature(src)
	if len(errs) > 0 {
		return map[string]any{"valid": false, "errors": errs}, nil
	}
	subjects, err := a.subjectsFor(ctx, sg.Scope, entityKey, sg)
	if err != nil {
		return nil, err
	}
	var results []map[string]any
	matched := false
	for label, sub := range subjects {
		r := sg.Eval(sub, true)
		matched = matched || r.Matched
		results = append(results, map[string]any{"subject": label, "matched": r.Matched, "version": r.Version, "trace": r.Trace})
	}
	return map[string]any{"valid": true, "matched": matched, "results": results, "active": sg.Active()}, nil
}

// subjectsFor buduje podmioty ewaluacji z zapisanych (odszyfrowanych) danych encji.
func (a *App) subjectsFor(ctx context.Context, scope, key string, sg *sigs.Signature) (map[string]sigs.Subject, error) {
	out := map[string]sigs.Subject{}
	p := strings.Split(key, "/")
	ip := p[0]
	var hostnames []string
	a.DB.QueryRow(ctx, `select hostnames from hosts where ip=$1::inet`, ip).Scan(&hostnames)
	switch scope {
	case "http":
		id := a.httpIDByKey(ctx, key)
		if id == "" {
			return nil, Invalid("wskaż endpoint WWW (klucz ip/tcp/port/schemat/vhost)", nil)
		}
		h := a.httpFromDB(ctx, id)
		var techs []obs.Tech
		rows, _ := a.DB.Query(ctx, `select name, version from technologies where entity_type='http' and entity_id=$1 and active`, id)
		for rows.Next() {
			var t obs.Tech
			rows.Scan(&t.Name, &t.Version)
			techs = append(techs, t)
		}
		rows.Close()
		base := httpBase(ip, atoi(p[2]), hostnames, h, techs)
		if sg == nil || !sg.Active() {
			out["GET /"] = rootSubject(base, h)
		}
		if sg != nil {
			for _, rq := range sg.AllRequests() {
				found := false
				for _, pr := range h.Paths {
					if pr.Path == rq.Path {
						out["GET "+pr.Path] = pathSubject(base, pr)
						found = true
					}
				}
				if !found {
					out["GET "+rq.Path+" (nie pobrano jeszcze – zostanie sprawdzone w kolejnym skanie)"] = sigs.MapSubject{}
				}
			}
		}
	case "service":
		if len(p) < 3 {
			return nil, Invalid("wskaż usługę (klucz ip/proto/port)", nil)
		}
		s := obs.Service{Proto: p[1], Port: atoi(p[2])}
		var cpe []string
		var id string
		if a.DB.QueryRow(ctx, `select s.id, service_name, product, version, extrainfo, devicetype, cpe, tunnel from services s join hosts h on h.id=s.host_id where h.ip=$1::inet and proto=$2 and port=$3`,
			ip, s.Proto, s.Port).Scan(&id, &s.Service, &s.Product, &s.Version, &s.ExtraInfo, &s.DeviceType, &cpe, &s.Tunnel) != nil {
			return nil, ErrNotFound
		}
		s.CPE = cpe
		if raw, err := a.RawData(ctx, "service", key); err == nil {
			b, _ := json.Marshal(raw)
			var sr serviceRaw
			json.Unmarshal(b, &sr)
			s.Banner, s.TLS = sr.Banner, sr.TLS
		}
		out[key] = serviceSubject(ip, &s, hostnames)
	case "host":
		m := sigs.MapSubject{}
		m.Add("ip", ip)
		m.Add("hostname", hostnames...)
		out[ip] = m
	}
	return out, nil
}

func (a *App) httpFromDB(ctx context.Context, id string) *obs.HTTP {
	h := &obs.HTTP{}
	var tlsRaw []byte
	a.DB.QueryRow(ctx, `select e.scheme, e.vhost, e.url, e.status_code, e.title, e.final_url, e.favicon_mmh3 from http_endpoints e where e.id=$1`, id).
		Scan(&h.Scheme, &h.Vhost, &h.URL, &h.Status, &h.Title, &h.FinalURL, &h.FaviconMMH3)
	_ = tlsRaw
	if raw := a.loadHTTPRaw(ctx, id); raw != nil {
		h.Headers, h.Cookies, h.RedirectChain, h.BodySnippet, h.Paths, h.Soft404, h.TLS = raw.Headers, raw.Cookies, raw.RedirectChain, raw.BodySnippet, raw.Paths, raw.Soft404, raw.TLS
		h.CleartextLogin = h.Scheme == "http" && passwordRe.MatchString(h.BodySnippet)
	}
	return h
}

// Retrohunt uruchamia sygnaturę na zapisanych danych wszystkich aktywnych encji – bez ponownego skanu.
func (a *App) Retrohunt(ctx context.Context, actor Actor, sigID string) (map[string]any, error) {
	var src string
	if a.DB.QueryRow(ctx, `select source_text from signatures where sig_id=$1`, sigID).Scan(&src) != nil {
		return nil, ErrNotFound
	}
	sg, errs := ParseSignature(src)
	if len(errs) > 0 {
		return nil, Invalid("sygnatura niepoprawna", errs)
	}
	type ent struct{ id, key, hostID, ip, group string }
	var ents []ent
	var q string
	switch sg.Scope {
	case "http":
		q = `select e.id, host(h.ip)||'/tcp/'||s.port||'/'||e.scheme||'/'||coalesce(nullif(e.vhost,''),'-'), h.id, host(h.ip), coalesce(h.group_id::text,'')
			from http_endpoints e join services s on s.id=e.service_id join hosts h on h.id=e.host_id where e.state<>'INACTIVE'`
	case "service":
		q = `select s.id, host(h.ip)||'/'||s.proto||'/'||s.port, h.id, host(h.ip), coalesce(h.group_id::text,'') from services s join hosts h on h.id=s.host_id where s.state<>'INACTIVE'`
	default:
		q = `select h.id, host(h.ip), h.id, host(h.ip), coalesce(h.group_id::text,'') from hosts h where h.state<>'INACTIVE'`
	}
	rows, err := a.DB.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e ent
		rows.Scan(&e.id, &e.key, &e.hostID, &e.ip, &e.group)
		ents = append(ents, e)
	}
	rows.Close()
	matched, checked, skipped := 0, 0, 0
	var hits []string
	for _, e := range ents {
		subs, err := a.subjectsFor(ctx, sg.Scope, e.key, sg)
		if err != nil {
			continue
		}
		evaluable := false
		var hit *sigs.Result
		for label, sub := range subs {
			if strings.Contains(label, "nie pobrano") {
				continue
			}
			evaluable = true
			if r := sg.Eval(sub, false); r.Matched {
				hit = &r
				break
			}
		}
		if !evaluable {
			skipped++
			continue
		}
		checked++
		ic := &ingestCtx{groupID: e.group, source: "retrohunt", baseline: false}
		etype := map[string]string{"http": "http", "service": "service", "host": "host"}[sg.Scope]
		if hit != nil {
			matched++
			hits = append(hits, e.key)
			a.saveMatches(ctx, ic, etype, e.id, e.key, e.hostID, e.ip, []sigHit{{sg, *hit}}, map[string]bool{sg.ID: true})
			a.syncFindings(ctx, etype, e.key, e.ip, e.hostID, e.group, []sigHit{{sg, *hit}}, map[string]bool{sg.ID: true}, e.key, portOfKey(e.key), protoOfKey(e.key), vhostOfKey(e.key), nil)
		} else {
			a.saveMatches(ctx, ic, etype, e.id, e.key, e.hostID, e.ip, nil, map[string]bool{sg.ID: true})
			a.syncFindings(ctx, etype, e.key, e.ip, e.hostID, e.group, nil, map[string]bool{sg.ID: true}, "", 0, "", "", nil)
		}
		for _, c := range sg.Categories {
			if hit != nil {
				a.DB.Exec(ctx, `insert into classifications(entity_type,entity_id,host_id,category,confidence,evidence) values($1,$2,$3,$4,$5,$6)
					on conflict(entity_type,entity_id,category) do update set confidence=greatest(classifications.confidence, excluded.confidence), active=true, last_seen=now()`,
					etype, e.id, e.hostID, c, sg.Confidence, jsonb([]Evidence{{"signature", sg.ID, sg.Confidence}}))
			}
		}
		a.flushChanges(ctx, ic)
		if hit != nil {
			a.RescoreKey(ctx, e.key)
		}
	}
	a.Audit(ctx, actor, "signature.retrohunt", "signature", sigID, map[string]any{"checked": checked, "matched": matched})
	if len(hits) > 50 {
		hits = hits[:50]
	}
	return map[string]any{"checked": checked, "matched": matched, "skipped": skipped, "hits": hits}, nil
}

func portOfKey(k string) int {
	p := strings.Split(k, "/")
	if len(p) >= 3 {
		return atoi(p[2])
	}
	return 0
}

func protoOfKey(k string) string {
	p := strings.Split(k, "/")
	if len(p) >= 4 {
		return p[3]
	}
	if len(p) >= 2 {
		return p[1]
	}
	return ""
}

func vhostOfKey(k string) string {
	p := strings.Split(k, "/")
	if len(p) >= 5 && p[4] != "-" {
		return p[4]
	}
	return ""
}
