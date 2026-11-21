package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"asi/internal/nmapxml"
	"asi/internal/obs"
)

// ---------------- wykrywanie formatu i parsowanie ----------------

type ParsedImport struct {
	Format       string
	Run          *obs.RunInfo
	Observations []obs.Observation
	Errors       []obs.FieldError
}

// ParseObservations rozpoznaje format pliku: ASI JSON/JSONL/CSV, nmap XML, naabu/httpx JSONL.
func ParseObservations(data []byte, filename string) (*ParsedImport, error) {
	trim := bytes.TrimSpace(data)
	p := &ParsedImport{}
	switch {
	case bytes.HasPrefix(trim, []byte("<?xml")) || bytes.Contains(trim[:min(len(trim), 2000)], []byte("<nmaprun")):
		run, err := nmapxml.Parse(bytes.NewReader(trim))
		if err != nil {
			return nil, fmt.Errorf("nmap XML: %w", err)
		}
		p.Format = "nmap-xml"
		p.Observations = run.ToObservations("nmap_import")
	case bytes.HasPrefix(trim, []byte("{")) && !isJSONL(trim) || bytes.HasPrefix(trim, []byte("[")):
		p.Format = "asi-json"
		if bytes.HasPrefix(trim, []byte("[")) {
			if err := json.Unmarshal(trim, &p.Observations); err != nil {
				return nil, fmt.Errorf("JSON: %w", err)
			}
			break
		}
		var f obs.File
		if err := json.Unmarshal(trim, &f); err != nil {
			return nil, fmt.Errorf("JSON: %w", err)
		}
		if f.Observations == nil { // pojedyncza obserwacja
			var o obs.Observation
			if err := json.Unmarshal(trim, &o); err != nil || o.Host.IP == "" {
				return nil, fmt.Errorf("JSON: brak pola observations ani host.ip")
			}
			p.Observations = []obs.Observation{o}
		} else {
			p.Observations, p.Run = f.Observations, f.Run
		}
	case isJSONL(trim):
		return parseJSONL(trim)
	default:
		obsList, errs, err := parseCSV(trim)
		if err != nil {
			return nil, err
		}
		p.Format, p.Observations, p.Errors = "asi-csv", obsList, errs
	}
	for i := range p.Observations {
		if p.Observations[i].Source == "" {
			p.Observations[i].Source = map[string]string{"asi-csv": "csv_import", "nmap-xml": "nmap_import"}[p.Format]
			if p.Observations[i].Source == "" {
				p.Observations[i].Source = "json_import"
			}
		}
		p.Errors = append(p.Errors, obs.Normalize(&p.Observations[i], fmt.Sprintf("observations[%d].", i))...)
	}
	return p, nil
}

func isJSONL(b []byte) bool {
	lines := bytes.SplitN(b, []byte("\n"), 3)
	return len(lines) >= 2 && bytes.HasPrefix(bytes.TrimSpace(lines[0]), []byte("{")) && bytes.HasPrefix(bytes.TrimSpace(lines[1]), []byte("{"))
}

// parseJSONL – obserwacje ASI albo wyniki naabu / httpx (jeden obiekt na linię).
func parseJSONL(b []byte) (*ParsedImport, error) {
	p := &ParsedImport{}
	byIP := map[string]*obs.Observation{}
	order := []string{}
	get := func(ip string) *obs.Observation {
		if o := byIP[ip]; o != nil {
			return o
		}
		up := true
		o := &obs.Observation{Host: obs.Host{IP: ip, Up: &up}}
		byIP[ip] = o
		order = append(order, ip)
		return o
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		l := bytes.TrimSpace(sc.Bytes())
		if len(l) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			p.Errors = append(p.Errors, obs.FieldError{Path: fmt.Sprintf("linia %d", line), Msg: err.Error()})
			continue
		}
		switch {
		case m["host"] != nil && m["observed_at"] != nil || m["schema"] == obs.Schema:
			var o obs.Observation
			json.Unmarshal(l, &o)
			p.Format = "asi-jsonl"
			p.Observations = append(p.Observations, o)
		case m["status_code"] != nil || m["status-code"] != nil: // httpx
			p.Format = "httpx-jsonl"
			ip := str(m["host"])
			if v := str(m["ip"]); v != "" {
				ip = v
			}
			port := atoi(str(m["port"]))
			scheme := str(m["scheme"])
			if port == 0 {
				port = map[string]int{"https": 443}[scheme]
				if port == 0 {
					port = 80
				}
			}
			o := get(ip)
			h := obs.HTTP{Scheme: scheme, URL: str(m["url"]), Status: int(num(m["status_code"]) + num(m["status-code"])), Title: str(m["title"]),
				FaviconMMH3: str(m["favicon"]), FinalURL: str(m["final_url"])}
			if hd, ok := m["header"].(map[string]any); ok {
				h.Headers = obs.Headers{}
				for k, v := range hd {
					h.Headers[httpCanon(k)] = []string{fmt.Sprint(v)}
				}
			}
			if ws := str(m["webserver"]); ws != "" {
				if h.Headers == nil {
					h.Headers = obs.Headers{}
				}
				h.Headers["Server"] = []string{ws}
			}
			if techs, ok := m["tech"].([]any); ok {
				for _, t := range techs {
					name, ver, _ := strings.Cut(fmt.Sprint(t), ":")
					h.Tech = append(h.Tech, obs.Tech{Name: name, Version: ver, Source: "httpx"})
				}
			}
			o.Services = appendHTTP(o.Services, port, h)
		case m["port"] != nil && m["ip"] != nil || m["port"] != nil && m["host"] != nil: // naabu
			p.Format = "naabu-jsonl"
			ip := str(m["ip"])
			if ip == "" {
				ip = str(m["host"])
			}
			port := atoi(str(m["port"]))
			if pm, ok := m["port"].(map[string]any); ok {
				port = int(num(pm["Port"]))
			}
			proto := str(m["protocol"])
			if proto == "" {
				proto = "tcp"
			}
			o := get(ip)
			o.Services = append(o.Services, obs.Service{Proto: proto, Port: port, State: "open"})
		default:
			p.Errors = append(p.Errors, obs.FieldError{Path: fmt.Sprintf("linia %d", line), Msg: "nierozpoznany format rekordu"})
		}
	}
	for _, ip := range order {
		p.Observations = append(p.Observations, *byIP[ip])
	}
	for i := range p.Observations {
		if p.Observations[i].Source == "" {
			p.Observations[i].Source = "json_import"
		}
		p.Errors = append(p.Errors, obs.Normalize(&p.Observations[i], fmt.Sprintf("observations[%d].", i))...)
	}
	return p, nil
}

func appendHTTP(svcs []obs.Service, port int, h obs.HTTP) []obs.Service {
	for i := range svcs {
		if svcs[i].Port == port && svcs[i].Proto == "tcp" {
			svcs[i].HTTP = append(svcs[i].HTTP, h)
			return svcs
		}
	}
	return append(svcs, obs.Service{Proto: "tcp", Port: port, State: "open", Service: h.Scheme, HTTP: []obs.HTTP{h}})
}

func httpCanon(k string) string {
	parts := strings.Split(strings.ReplaceAll(k, "_", "-"), "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

// CSVColumns – kolumny eksportu/importu CSV (sekcja 13.3).
var CSVColumns = []string{"ip", "hostnames", "proto", "port", "state", "service", "product", "version", "cpe", "http_scheme", "http_vhost", "http_status",
	"http_title", "http_server", "technologies", "categories", "tls_subject_cn", "tls_issuer", "tls_not_after", "cookie_names", "header_names", "tags", "note",
	"first_seen", "last_seen", "confidence", "score", "source"}

func parseCSV(b []byte) ([]obs.Observation, []obs.FieldError, error) {
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	head, err := r.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("CSV: %w", err)
	}
	if len(head) > 0 {
		head[0] = strings.TrimPrefix(head[0], "\ufeff")
	}
	if len(head) == 1 && strings.Contains(head[0], ";") {
		return nil, nil, fmt.Errorf("CSV: wykryto separator ';' – użyj przecinka")
	}
	idx := map[string]int{}
	for i, h := range head {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	if _, ok := idx["ip"]; !ok {
		return nil, nil, fmt.Errorf("CSV: brak kolumny ip (wymagana); oczekiwane kolumny: %s", strings.Join(CSVColumns, ","))
	}
	var errs []obs.FieldError
	byIP := map[string]*obs.Observation{}
	var order []string
	line := 1
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		line++
		if err != nil {
			errs = append(errs, obs.FieldError{Path: fmt.Sprintf("wiersz %d", line), Msg: err.Error()})
			continue
		}
		col := func(n string) string {
			if i, ok := idx[n]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		ip := col("ip")
		if ip == "" {
			continue
		}
		o := byIP[ip]
		if o == nil {
			up := true
			o = &obs.Observation{Host: obs.Host{IP: ip, Up: &up}, Source: "csv_import"}
			if v := col("source"); v != "" && v != "scanner" {
				o.Source = v
			}
			for _, n := range splitList(col("hostnames")) {
				o.Host.Hostnames = append(o.Host.Hostnames, obs.Hostname{Name: n, Source: "manual"})
			}
			o.Tags = splitList(col("tags"))
			o.Note = col("note")
			if ts, err := time.Parse(time.RFC3339, col("last_seen")); err == nil {
				o.ObservedAt = ts
			}
			byIP[ip] = o
			order = append(order, ip)
		}
		port := atoi(col("port"))
		if port == 0 {
			continue
		}
		proto := col("proto")
		if proto == "" {
			proto = "tcp"
		}
		var svc *obs.Service
		for i := range o.Services {
			if o.Services[i].Port == port && o.Services[i].Proto == proto {
				svc = &o.Services[i]
			}
		}
		if svc == nil {
			o.Services = append(o.Services, obs.Service{Proto: proto, Port: port, State: col("state"), Service: col("service"), Product: col("product"),
				Version: col("version"), CPE: splitList(col("cpe"))})
			svc = &o.Services[len(o.Services)-1]
			if svc.State == "ACTIVE" || svc.State == "SUSPECT" {
				svc.State = "open"
			} else if svc.State == "INACTIVE" {
				svc.State = "closed"
			}
		}
		if sch := col("http_scheme"); sch != "" || col("http_status") != "" {
			h := obs.HTTP{Scheme: sch, Vhost: col("http_vhost"), Status: atoi(col("http_status")), Title: col("http_title"), Headers: obs.Headers{}}
			if s := col("http_server"); s != "" {
				h.Headers["Server"] = []string{s}
			}
			for _, n := range splitList(col("header_names")) {
				if _, ok := h.Headers[httpCanon(n)]; !ok {
					h.Headers[httpCanon(n)] = []string{""}
				}
			}
			for _, c := range splitList(col("cookie_names")) {
				h.Cookies = append(h.Cookies, obs.Cookie{Name: c})
			}
			for _, t := range splitList(col("technologies")) {
				name, ver := t, ""
				if i := strings.LastIndex(t, " "); i > 0 && strings.ContainsAny(t[i+1:], "0123456789") {
					name, ver = t[:i], t[i+1:]
				}
				h.Tech = append(h.Tech, obs.Tech{Name: name, Version: ver, Source: "import", Confidence: 0.6})
			}
			if cn := col("tls_subject_cn"); cn != "" {
				h.TLS = &obs.TLS{SubjectCN: cn, Issuer: col("tls_issuer")}
				if t, err := time.Parse(time.RFC3339, col("tls_not_after")); err == nil {
					h.TLS.NotAfter = t
				} else if t, err := time.Parse("2006-01-02", col("tls_not_after")); err == nil {
					h.TLS.NotAfter = t
				}
			}
			svc.HTTP = append(svc.HTTP, h)
		}
	}
	var out []obs.Observation
	for _, ip := range order {
		out = append(out, *byIP[ip])
	}
	return out, errs, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ";") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------- import obserwacji (ten sam pipeline co skaner) ----------------

type ImportResult struct {
	ID           string            `json:"id"`
	Format       string            `json:"format"`
	DryRun       bool              `json:"dry_run"`
	Observations int               `json:"observations"`
	Hosts        int               `json:"hosts"`
	Services     int               `json:"services"`
	HTTP         int               `json:"http"`
	Errors       []obs.FieldError  `json:"errors"`
	RunID        string            `json:"run_id,omitempty"`
	Changes      int               `json:"changes"`
	Preview      []obs.Observation `json:"preview,omitempty"`
}

// ImportObservations – import pliku lub obserwacji z formularza.
func (a *App) ImportObservations(ctx context.Context, actor Actor, data []byte, filename, groupID, source string, dryRun bool) (*ImportResult, error) {
	if len(data) > 64<<20 {
		return nil, Invalid("plik większy niż 64 MB", nil)
	}
	p, err := ParseObservations(data, filename)
	if err != nil {
		return nil, Invalid(err.Error(), nil)
	}
	return a.importParsed(ctx, actor, p, filename, groupID, source, dryRun)
}

func (a *App) importParsed(ctx context.Context, actor Actor, p *ParsedImport, filename, groupID, source string, dryRun bool) (*ImportResult, error) {
	res := &ImportResult{Format: p.Format, DryRun: dryRun, Observations: len(p.Observations), Errors: p.Errors}
	if res.Errors == nil {
		res.Errors = []obs.FieldError{}
	}
	scope, _, _, _ := a.Scope(ctx)
	var valid []obs.Observation
	for i, o := range p.Observations {
		if !scope.Allowed(o.Host.IP) {
			res.Errors = append(res.Errors, obs.FieldError{Path: fmt.Sprintf("observations[%d].host.ip", i), Msg: "adres " + o.Host.IP + " poza dozwolonym zakresem (scope)"})
			continue
		}
		if source != "" {
			o.Source = source
		}
		valid = append(valid, o)
		res.Hosts++
		res.Services += len(o.Services)
		for _, s := range o.Services {
			res.HTTP += len(s.HTTP)
		}
	}
	if dryRun {
		res.Preview = valid[:min(len(valid), 5)]
		return res, nil
	}
	hasFatal := false
	for _, e := range p.Errors {
		if strings.Contains(e.Msg, "niepoprawny adres") {
			hasFatal = true
		}
	}
	if len(valid) == 0 || hasFatal {
		return res, Invalid("import odrzucony – popraw błędy walidacji", res.Errors)
	}
	// przebieg-kontener importu: pokrycie = tylko importowane encje
	started := time.Now().UTC()
	for _, o := range valid {
		if !o.ObservedAt.IsZero() && o.ObservedAt.Before(started) && time.Since(o.ObservedAt) < 10*365*24*time.Hour {
			started = o.ObservedAt
		}
	}
	if p.Run != nil && !p.Run.StartedAt.IsZero() {
		started = p.Run.StartedAt
	}
	if groupID == "" && p.Run != nil && p.Run.Group != "" {
		a.DB.QueryRow(ctx, `select id from target_groups where name=$1`, p.Run.Group).Scan(&groupID)
	}
	src := valid[0].Source
	runSource := "import"
	if src == "manual" {
		runSource = "manual"
	}
	var runID string
	err := a.DB.QueryRow(ctx, `insert into scan_runs(group_id,mode,source,status,created_by,created_at,started_at,note,phase) values($1,'import',$2,'RUNNING',$3,$4,$4,$5,'import') returning id`,
		nullUUID(groupID), runSource, actor.Name(), started, filename).Scan(&runID)
	if err != nil {
		return nil, err
	}
	run, _ := a.GetRun(ctx, runID)
	ic := a.newIngestCtx(ctx, run, "", "", src)
	var ents []string
	for i := range valid {
		o := &valid[i]
		ents = append(ents, o.Host.IP)
		for _, s := range o.Services {
			ents = append(ents, obs.ServiceKey(o.Host.IP, s.Proto, s.Port))
			for _, h := range s.HTTP {
				ents = append(ents, obs.HTTPKey(o.Host.IP, s.Port, h.Scheme, h.Vhost))
			}
		}
		if _, err := a.ingestObservation(ctx, ic, o); err != nil {
			return nil, err
		}
		for _, t := range o.Tags {
			a.TagEntity(ctx, actor, "host", o.Host.IP, t, true)
		}
		if o.Note != "" {
			a.AddNote(ctx, actor, "host", o.Host.IP, o.Note)
		}
	}
	res.Changes = len(ic.changes)
	a.flushChanges(ctx, ic)
	a.DB.Exec(ctx, `insert into run_coverage(run_id,entities) values($1,$2)`, runID, ents)
	if err := a.finalizeRun(ctx, run); err != nil {
		return nil, err
	}
	res.RunID = runID
	var impID string
	a.DB.QueryRow(ctx, `insert into imports(kind,format,filename,status,stats,errors,run_id,created_by) values('observations',$1,$2,'done',$3,$4,$5,$6) returning id`,
		p.Format, filename, jsonb(map[string]int{"hosts": res.Hosts, "services": res.Services, "http": res.HTTP}), jsonb(res.Errors), runID, actor.Name()).Scan(&impID)
	res.ID = impID
	a.Audit(ctx, actor, "import.observations", "import", impID, map[string]any{"format": p.Format, "hosts": res.Hosts, "file": filename})
	a.Events.Publish("import", map[string]any{"id": impID})
	return res, nil
}

// ImportTargetsFile – import celów z CSV / JSON / TXT.
func (a *App) ImportTargetsFile(ctx context.Context, actor Actor, groupID string, data []byte, filename string) (*TargetReport, error) {
	trim := bytes.TrimSpace(data)
	var values, tags []string
	source := "txt_import"
	switch {
	case bytes.HasPrefix(trim, []byte("{")) || bytes.HasPrefix(trim, []byte("[")):
		source = "json_import"
		var doc struct {
			Targets []json.RawMessage `json:"targets"`
		}
		if bytes.HasPrefix(trim, []byte("[")) {
			json.Unmarshal(trim, &doc.Targets)
		} else if err := json.Unmarshal(trim, &doc); err != nil {
			return nil, Invalid("JSON: "+err.Error(), nil)
		}
		for _, t := range doc.Targets {
			var s string
			if json.Unmarshal(t, &s) == nil {
				values = append(values, s)
				continue
			}
			var o struct {
				Value string   `json:"value"`
				Tags  []string `json:"tags"`
			}
			json.Unmarshal(t, &o)
			if o.Value != "" {
				values = append(values, o.Value)
				tags = append(tags, o.Tags...)
			}
		}
	case strings.HasSuffix(strings.ToLower(filename), ".csv") || bytes.Contains(trim[:min(len(trim), 200)], []byte("value")):
		source = "csv_import"
		r := csv.NewReader(bytes.NewReader(trim))
		r.FieldsPerRecord = -1
		recs, err := r.ReadAll()
		if err != nil {
			return nil, Invalid("CSV: "+err.Error(), nil)
		}
		col := 0
		start := 0
		if len(recs) > 0 {
			for i, h := range recs[0] {
				if strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")), "value") {
					col, start = i, 1
				}
			}
		}
		for _, rec := range recs[start:] {
			if col < len(rec) && strings.TrimSpace(rec[col]) != "" {
				values = append(values, strings.TrimSpace(rec[col]))
			}
		}
	default:
		for _, l := range strings.Split(string(trim), "\n") {
			values = append(values, strings.Fields(strings.SplitN(l, "#", 2)[0]+" ")...)
		}
	}
	sort.Strings(tags)
	return a.AddTargets(ctx, actor, groupID, values, source, dedupeStrings(tags))
}

func dedupeStrings(s []string) []string {
	out := []string{}
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// ---------------- eksport ----------------

type ExportOptions struct {
	Format           string // json | jsonl | csv
	Q                string
	RunID            string
	IncludeRaw       bool
	IncludeSensitive bool
}

// Export buduje obserwacje z bieżącego stanu (wartości efektywne – z nadpisaniami).
func (a *App) Export(ctx context.Context, actor Actor, opt ExportOptions, w io.Writer) error {
	hosts, _, err := a.ListHosts(ctx, opt.Q, Page{Limit: 1000000})
	if err != nil {
		return err
	}
	var runHosts map[string]bool
	if opt.RunID != "" {
		runHosts = map[string]bool{}
		rows, _ := a.DB.Query(ctx, `select distinct split_part(entity_key,'/',1) from observations where run_id=$1 and up`, opt.RunID)
		for rows.Next() {
			var ip string
			rows.Scan(&ip)
			runHosts[ip] = true
		}
		rows.Close()
	}
	var list []obs.Observation
	csvRows := [][]string{}
	for _, h := range hosts {
		if runHosts != nil && !runHosts[h.IP] {
			continue
		}
		o, rows := a.exportHost(ctx, h, opt)
		list = append(list, o)
		csvRows = append(csvRows, rows...)
	}
	a.Audit(ctx, actor, "export", "export", opt.Format, map[string]any{"q": opt.Q, "hosts": len(list), "sensitive": opt.IncludeSensitive, "raw": opt.IncludeRaw})
	switch opt.Format {
	case "csv":
		cw := csv.NewWriter(w)
		cw.Write(CSVColumns)
		cw.WriteAll(csvRows)
		cw.Flush()
		return cw.Error()
	case "jsonl":
		enc := json.NewEncoder(w)
		for _, o := range list {
			enc.Encode(o)
		}
		return nil
	default:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if list == nil {
			list = []obs.Observation{}
		}
		return enc.Encode(obs.File{Schema: "asi.export/v1", GeneratedAt: time.Now().UTC(), Observations: list})
	}
}

func (a *App) exportHost(ctx context.Context, h HostRow, opt ExportOptions) (obs.Observation, [][]string) {
	up := h.State != "INACTIVE"
	o := obs.Observation{Schema: obs.Schema, ObservedAt: h.LastSeen, Source: "asi_export", Host: obs.Host{IP: h.IP, Up: &up, OS: h.OS, DeviceType: h.DeviceType}, Tags: h.Tags}
	for _, n := range h.Hostnames {
		o.Host.Hostnames = append(o.Host.Hostnames, obs.Hostname{Name: n, Source: "export"})
	}
	hov := h.Overrides
	if v, ok := hov["os"].(string); ok {
		o.Host.OS = v
	}
	if v, ok := hov["devicetype"].(string); ok {
		o.Host.DeviceType = v
	}
	if v, ok := hov["description"].(string); ok {
		o.Note = v
	}
	o.Extra = map[string]any{"state": h.State, "labels": h.Labels, "score": h.Score, "categories": h.Categories, "first_seen": h.FirstSeen, "group": h.Group}
	if len(hov) > 0 {
		o.Extra["overrides"] = hov
	}
	svcs, _, _ := a.ListServices(ctx, "ip:"+h.IP, Page{Limit: 1000})
	var rows [][]string
	for _, s := range svcs {
		sv := obs.Service{Proto: s.Proto, Port: s.Port, State: "open", Service: s.Service, Product: s.Product, Version: s.Version, ExtraInfo: s.ExtraInfo,
			DeviceType: s.DeviceType, CPE: s.CPE, Tunnel: s.Tunnel}
		if s.Method != "" {
			sv.Nmap = &obs.NmapInfo{Method: s.Method, Conf: s.Conf}
		}
		if v, ok := s.Overrides["product"].(string); ok {
			sv.Product = v
		}
		if v, ok := s.Overrides["version"].(string); ok {
			sv.Version = v
		}
		if v, ok := s.Overrides["service_name"].(string); ok {
			sv.Service = v
		}
		if opt.IncludeRaw && opt.IncludeSensitive {
			if raw, err := a.RawData(ctx, "service", s.Key); err == nil {
				if m, ok := raw.(map[string]any); ok {
					sv.Banner = str(m["banner"])
				}
			}
		}
		webs, _, _ := a.ListWeb(ctx, "ip:"+h.IP+" port:"+strconv.Itoa(s.Port), Page{Limit: 100})
		base := []string{h.IP, strings.Join(h.Hostnames, ";"), s.Proto, strconv.Itoa(s.Port), s.State, sv.Service, sv.Product, sv.Version, strings.Join(s.CPE, ";")}
		tail := func(hh *obs.HTTP, techs, cats string) []string {
			r := append([]string{}, base...)
			if hh != nil {
				tlsCN, tlsIss, tlsNA := "", "", ""
				if hh.TLS != nil {
					tlsCN, tlsIss = hh.TLS.SubjectCN, hh.TLS.Issuer
					if !hh.TLS.NotAfter.IsZero() {
						tlsNA = hh.TLS.NotAfter.Format(time.RFC3339)
					}
				}
				var cn []string
				for _, c := range hh.Cookies {
					cn = append(cn, c.Name)
				}
				r = append(r, hh.Scheme, hh.Vhost, strconv.Itoa(hh.Status), hh.Title, hh.Headers.Get("Server"), techs, cats, tlsCN, tlsIss, tlsNA,
					strings.Join(cn, ";"), strings.Join(hh.Headers.Names(), ";"))
			} else {
				r = append(r, "", "", "", "", "", "", strings.Join(s.Categories, ";"), "", "", "", "", "")
			}
			return append(r, strings.Join(h.Tags, ";"), str(hov["description"]), s.FirstSeen.Format(time.RFC3339), s.LastSeen.Format(time.RFC3339),
				fmt.Sprintf("%.2f", s.Confidence), strconv.Itoa(max(s.Score, h.Score)), h.Source)
		}
		if len(webs) == 0 {
			rows = append(rows, tail(nil, "", ""))
		}
		for _, wr := range webs {
			hh := obs.HTTP{Scheme: wr.Scheme, Vhost: wr.Vhost, URL: wr.URL, Status: wr.Status, Title: wr.Title, FinalURL: wr.FinalURL, FaviconMMH3: wr.Favicon, Headers: obs.Headers{}}
			if v, ok := wr.Overrides["title"].(string); ok {
				hh.Title = v
			}
			for _, n := range wr.HeaderNames {
				hh.Headers[httpCanon(n)] = []string{"••••"}
			}
			if wr.Server != "" {
				hh.Headers["Server"] = []string{wr.Server}
			}
			if wr.PoweredBy != "" {
				hh.Headers["X-Powered-By"] = []string{wr.PoweredBy}
			}
			var cookies []obs.Cookie
			json.Unmarshal(wr.Cookies, &cookies)
			hh.Cookies = cookies
			var tlsm map[string]any
			if json.Unmarshal(wr.TLS, &tlsm) == nil && tlsm != nil {
				hh.TLS = &obs.TLS{SubjectCN: str(tlsm["subject_cn"]), Issuer: str(tlsm["issuer"])}
				if t, err := time.Parse(time.RFC3339, str(tlsm["not_after"])); err == nil {
					hh.TLS.NotAfter = t
				}
			}
			if opt.IncludeRaw && opt.IncludeSensitive {
				if raw := a.loadHTTPRaw(ctx, wr.ID); raw != nil {
					hh.Headers, hh.Cookies, hh.RedirectChain, hh.BodySnippet, hh.Paths, hh.TLS = raw.Headers, raw.Cookies, raw.RedirectChain, raw.BodySnippet, raw.Paths, raw.TLS
				}
			}
			var techs []obs.Tech
			json.Unmarshal(wr.Techs, &techs)
			var tnames []string
			for i := range techs {
				techs[i].Source = "asi"
				tnames = append(tnames, strings.TrimSpace(techs[i].Name+" "+techs[i].Version))
			}
			if v, ok := wr.Overrides["technologies"].([]any); ok {
				techs = nil
				tnames = nil
				for _, t := range v {
					techs = append(techs, obs.Tech{Name: fmt.Sprint(t), Source: "manual", Confidence: 1})
					tnames = append(tnames, fmt.Sprint(t))
				}
			}
			hh.Tech = techs
			var cats []struct {
				Category string `json:"category"`
			}
			json.Unmarshal(wr.Categories, &cats)
			var cn []string
			for _, c := range cats {
				cn = append(cn, c.Category)
			}
			sv.HTTP = append(sv.HTTP, hh)
			rows = append(rows, tail(&hh, strings.Join(tnames, ";"), strings.Join(cn, ";")))
		}
		o.Services = append(o.Services, sv)
	}
	return o, rows
}
