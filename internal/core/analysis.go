package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"asi/internal/obs"
	"asi/internal/sigs"
)

// ---------------- pewność (sekcja 8.3) ----------------

type Evidence struct {
	Source string  `json:"source"`
	Detail string  `json:"detail"`
	Weight float64 `json:"weight"`
}

type claim struct {
	name, version, category string
	ev                      []Evidence
	versionW                float64
}

// NoisyOR łączy wagi niezależnych dowodów: 1 - Π(1 - w).
func NoisyOR(ws []float64) float64 {
	p := 1.0
	for _, w := range ws {
		p *= 1 - math.Max(0, math.Min(w, 0.999))
	}
	return 1 - p
}

func (c *claim) confidence() float64 {
	var ws []float64
	seen := map[string]bool{}
	for _, e := range c.ev {
		k := e.Source + "|" + e.Detail
		if seen[k] {
			continue
		}
		seen[k] = true
		ws = append(ws, e.Weight)
	}
	return NoisyOR(ws)
}

type claims map[string]*claim

// techAliases ujednolica nazwy z różnych źródeł (nagłówek Server, nmap, wappalyzer).
var techAliases = map[string]string{
	"apache": "Apache HTTP Server", "apache httpd": "Apache HTTP Server", "apache http server": "Apache HTTP Server",
	"nginx": "Nginx", "microsoft-iis": "IIS", "microsoft iis httpd": "IIS", "iis": "IIS", "openresty": "OpenResty",
	"apache tomcat": "Apache Tomcat", "apache tomcat/coyote jsp engine": "Apache Tomcat", "tomcat": "Apache Tomcat",
	"lighttpd": "lighttpd", "openssh": "OpenSSH", "php": "PHP",
}

func canonTech(name string) string {
	if a, ok := techAliases[strings.ToLower(strings.TrimSpace(name))]; ok {
		return a
	}
	return strings.TrimSpace(name)
}

func (cs claims) add(name, version, category string, e Evidence) {
	name = canonTech(name)
	if name == "" {
		return
	}
	k := strings.ToLower(name)
	c := cs[k]
	if c == nil {
		c = &claim{name: name, category: category}
		cs[k] = c
	}
	if c.category == "" {
		c.category = category
	}
	c.ev = append(c.ev, e)
	if version != "" && e.Weight >= c.versionW {
		c.version, c.versionW = version, e.Weight
	}
}

// temporalFactor – korekta o stabilność w czasie (widziane w k z n ostatnich pomiarów).
func (a *App) temporalFactor(ctx context.Context, entityID string) float64 {
	var up, total int
	a.DB.QueryRow(ctx, `select count(*) filter (where up), count(*) from (select up from availability_history where entity_id=$1 order by at desc limit 5) x`, entityID).Scan(&up, &total)
	if total == 0 {
		return 1
	}
	return 0.7 + 0.3*float64(up)/float64(total)
}

// ---------------- mapowanie kategorii ----------------

var wappCategory = map[string]string{
	"cms": "cms", "blogs": "cms", "wikis": "cms", "lms": "cms", "ecommerce": "cms", "message boards": "cms", "documentation": "api_docs",
	"web frameworks": "framework", "web servers": "web_server", "reverse proxies": "web_server", "programming languages": "language",
	"databases": "database", "database managers": "admin_panel", "control systems": "iot", "webcams": "iot", "network devices": "iot",
	"hosting panels": "admin_panel", "dev tools": "dev_tools", "ci": "admin_panel", "issue trackers": "app",
}

var appServers = map[string]bool{"apache tomcat": true, "tomcat": true, "jboss": true, "wildfly": true, "jetty": true, "weblogic": true,
	"websphere": true, "glassfish": true, "microsoft-iis": true, "iis": true, "gunicorn": true, "uwsgi": true, "node.js": true, "kestrel": true}

func techCategory(name string, cats []string) string {
	if appServers[strings.ToLower(name)] {
		return "app_server"
	}
	for _, c := range cats {
		if m := wappCategory[strings.ToLower(c)]; m != "" {
			return m
		}
	}
	if len(cats) > 0 {
		return strings.ToLower(cats[0])
	}
	return ""
}

var iotDeviceTypes = map[string]bool{"printer": true, "webcam": true, "router": true, "switch": true, "wap": true, "media device": true,
	"power-device": true, "storage-misc": true, "phone": true, "voip phone": true, "game console": true, "specialized": true, "remote management": true, "broadband router": true, "security-misc": true}

// ---------------- podmioty dla sygnatur ----------------

var sessionCookieRe = regexp.MustCompile(`(?i)sess|sid$|^sid|token|auth|jwt`)
var passwordRe = regexp.MustCompile(`(?i)<input[^>]+type=["']?password`)

func boolStr(b bool) string { return strconv.FormatBool(b) }

func addTLS(m sigs.MapSubject, t *obs.TLS) {
	if t == nil {
		return
	}
	now := time.Now()
	m.Add("tls_subject_cn", t.SubjectCN)
	m.Add("tls_san", t.SAN...)
	m.Add("tls_issuer", t.Issuer)
	m.Add("tls_expired", boolStr(t.Expired(now)))
	m.Add("tls_days_left", strconv.Itoa(t.DaysLeft(now)))
	m.Add("tls_self_signed", boolStr(t.SelfSigned))
	m.Add("tls_version", t.Version)
}

func addHeaders(m sigs.MapSubject, h obs.Headers) {
	var raw strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			m.Add("header:"+strings.ToLower(k), v)
			raw.WriteString(k + ": " + v + "\n")
		}
		m.Add("header_names", strings.ToLower(k))
	}
	m.Add("headers_raw", raw.String())
}

func httpBase(ip string, port int, hostnames []string, h *obs.HTTP, techs []obs.Tech) sigs.MapSubject {
	m := sigs.MapSubject{}
	m.Add("ip", ip)
	m.Add("port", strconv.Itoa(port))
	m.Add("scheme", h.Scheme)
	m.Add("vhost", h.Vhost)
	m.Add("hostname", hostnames...)
	m.Add("favicon_mmh3", h.FaviconMMH3)
	m.Add("final_url", h.FinalURL)
	for _, r := range h.RedirectChain {
		m.Add("redirect_chain", r.URL)
		if r.Location != "" && len(m["redirect_location"]) == 0 {
			m.Add("redirect_location", r.Location)
		}
	}
	for _, t := range techs {
		m.Add("tech", t.Name)
		m.Add("tech_version:"+strings.ToLower(t.Name), t.Version)
	}
	addTLS(m, h.TLS)
	m.Add("cleartext_login", boolStr(h.CleartextLogin))
	if h.ResponseMs > 0 {
		m.Add("response_ms", strconv.Itoa(h.ResponseMs))
	}
	return m
}

func rootSubject(base sigs.MapSubject, h *obs.HTTP) sigs.MapSubject {
	m := sigs.MapSubject{}
	for k, v := range base {
		m[k] = v
	}
	body := h.Body
	if body == "" {
		body = h.BodySnippet
	}
	m.Add("status", strconv.Itoa(h.Status))
	m.Add("title", h.Title)
	m.Add("body", body)
	m.Add("body_hash", h.BodySHA256)
	m.Add("length", strconv.Itoa(len(body)))
	m.Add("path", "/")
	m.Add("soft404", "false")
	addHeaders(m, h.Headers)
	for _, c := range h.Cookies {
		m.Add("cookie_name", c.Name)
		ln := strings.ToLower(c.Name)
		m.Add("cookie:"+ln+":secure", boolStr(c.Secure))
		m.Add("cookie:"+ln+":httponly", boolStr(c.HTTPOnly))
		m.Add("cookie:"+ln+":samesite", c.SameSite)
		m.Add("cookie:"+ln, c.Name)
		if sessionCookieRe.MatchString(c.Name) && (!c.HTTPOnly || (h.Scheme == "https" && !c.Secure)) {
			m.Add("cookie_insecure_session", c.Name)
		}
	}
	return m
}

func pathSubject(base sigs.MapSubject, p obs.PathResult) sigs.MapSubject {
	m := sigs.MapSubject{}
	for k, v := range base {
		m[k] = v
	}
	m.Add("status", strconv.Itoa(p.Status))
	m.Add("title", p.Title)
	m.Add("body", p.Body)
	m.Add("length", strconv.Itoa(p.Length))
	m.Add("path", p.Path)
	m.Add("soft404", boolStr(p.Soft404))
	if p.PatternMatch != nil {
		m.Add("pattern_match", boolStr(*p.PatternMatch))
	}
	if p.Location != "" {
		m.Add("redirect_location", p.Location)
	}
	addHeaders(m, p.Headers)
	for _, c := range p.Headers["Set-Cookie"] {
		if i := strings.Index(c, "="); i > 0 {
			m.Add("cookie_name", strings.TrimSpace(c[:i]))
		}
	}
	return m
}

// ---------------- analiza endpointu HTTP ----------------

type sigHit struct {
	sg  *sigs.Signature
	res sigs.Result
}

// evalHTTPSigs ocenia sygnatury HTTP. evaluated=false oznacza, że sygnatura nie mogła zostać oceniona (tryb szybki).
func evalHTTPSigs(list []*sigs.Signature, base sigs.MapSubject, h *obs.HTTP) (hits []sigHit, evaluated map[string]bool) {
	evaluated = map[string]bool{}
	root := rootSubject(base, h)
	for _, sg := range list {
		if sg.Scope != "http" {
			continue
		}
		if !sg.Active() {
			evaluated[sg.ID] = true
			if r := sg.Eval(root, false); r.Matched {
				hits = append(hits, sigHit{sg, r})
			}
			continue
		}
		tried := false
		for _, rq := range sg.AllRequests() {
			for _, p := range h.Paths {
				if p.Path == rq.Path {
					tried = true
					if r := sg.Eval(pathSubject(base, p), false); r.Matched {
						r.Evidence = append([]string{"GET " + p.Path}, r.Evidence...)
						hits = append(hits, sigHit{sg, r})
						goto done
					}
				}
			}
		}
	done:
		if tried || !h.Light {
			evaluated[sg.ID] = true
		}
	}
	return
}

func (a *App) analyzeHTTP(ctx context.Context, ic *ingestCtx, hostID, epID, key, ip string, port int, h *obs.HTTP, hostnames []string, isNew bool) []string {
	list := a.Sigs.All()
	cs := claims{}
	for _, t := range h.Tech {
		w := t.Confidence
		if w == 0 {
			w = 0.7
		}
		src := t.Source
		if src == "" {
			src = "wappalyzer"
		}
		cs.add(t.Name, t.Version, techCategory(t.Name, t.Categories), Evidence{src, "fingerprint " + t.Name, w})
	}
	if srv := h.Headers.Get("Server"); srv != "" {
		name, ver := splitProduct(srv)
		if name != "" && !strings.EqualFold(name, "unknown") {
			cs.add(name, ver, techCategory(name, []string{"web servers"}), Evidence{"header", "Server: " + srv, 0.8})
		}
	}
	// dwa przebiegi: sygnatury mogą zależeć od technologii wykrytych przez inne sygnatury
	var hits []sigHit
	var evaluated map[string]bool
	for pass := 0; pass < 2; pass++ {
		base := httpBase(ip, port, hostnames, h, cs.techList())
		hits, evaluated = evalHTTPSigs(list, base, h)
		for _, x := range hits {
			if x.sg.Technology != nil {
				cs.add(x.sg.Technology.Name, x.res.Version, x.sg.Technology.Category, Evidence{"signature", x.sg.ID, x.sg.Confidence})
			}
		}
	}
	cats := map[string][]Evidence{}
	for _, x := range hits {
		for _, c := range x.sg.Categories {
			cats[c] = append(cats[c], Evidence{"signature", x.sg.ID, x.sg.Confidence})
		}
	}
	for _, c := range cs {
		if c.category == "cms" || c.category == "framework" || c.category == "app_server" || c.category == "admin_panel" || c.category == "iot" {
			cats[c.category] = append(cats[c.category], Evidence{"technology", c.name, c.confidence() * 0.9})
		}
	}
	tf := a.temporalFactor(ctx, epID)
	techs := a.saveTechs(ctx, "http", epID, hostID, cs, tf, h.Light)
	a.saveCategories(ctx, "http", epID, hostID, cats, tf)
	a.saveMatches(ctx, ic, "http", epID, key, hostID, ip, hits, evaluated)
	// klucz klastra: favicona | tytuł | Server | technologie
	var names []string
	for _, t := range techs {
		names = append(names, strings.ToLower(t.Name))
	}
	sort.Strings(names)
	cluster := a.Keys.MAC("http", h.FaviconMMH3, obs.NormTitle(h.Title), h.Headers.Get("Server"), strings.Join(names, ","))
	a.DB.Exec(ctx, `update http_endpoints set cluster_key=$2 where id=$1`, epID, cluster)
	a.scoreEntity(ctx, "http_endpoints", epID, key, port, h.Scheme, ic)
	a.syncFindings(ctx, "http", key, ip, hostID, ic.groupID, hits, evaluated, h.URL, port, h.Scheme, h.Vhost, techs)
	var out []string
	for _, t := range techs {
		out = append(out, t.Name+":"+t.Version)
	}
	return out
}

func (cs claims) techList() []obs.Tech {
	var out []obs.Tech
	for _, c := range cs {
		out = append(out, obs.Tech{Name: c.name, Version: c.version, Category: c.category, Confidence: c.confidence()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var productRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9 ._-]*?)(?:/([0-9][0-9A-Za-z.\-]*))?(?:\s|$|\()`)

func splitProduct(s string) (string, string) {
	m := productRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", ""
	}
	return strings.TrimSpace(m[1]), m[2]
}

// saveTechs zapisuje technologie z pewnością (noisy-OR × czynnik czasowy).
func (a *App) saveTechs(ctx context.Context, etype, eid, hostID string, cs claims, tf float64, light bool) []obs.Tech {
	var out []obs.Tech
	var keep []string
	for _, c := range cs {
		conf := c.confidence() * tf
		vconf := c.versionW * tf
		a.DB.Exec(ctx, `insert into technologies(entity_type,entity_id,host_id,name,version,category,confidence,version_confidence,evidence)
			values($1,$2,$3,$4,$5,$6,$7,$8,$9) on conflict(entity_type,entity_id,name) do update set version=excluded.version, category=excluded.category,
			confidence=excluded.confidence, version_confidence=excluded.version_confidence, evidence=excluded.evidence, last_seen=now(), active=true`,
			etype, eid, hostID, c.name, c.version, c.category, conf, vconf, jsonb(c.ev))
		keep = append(keep, c.name)
		out = append(out, obs.Tech{Name: c.name, Version: c.version, Category: c.category, Confidence: conf})
	}
	if !light {
		a.DB.Exec(ctx, `update technologies set active=false where entity_type=$1 and entity_id=$2 and not (name = any($3))`, etype, eid, nonNil(keep))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (a *App) saveCategories(ctx context.Context, etype, eid, hostID string, cats map[string][]Evidence, tf float64) {
	var keep []string
	for cat, ev := range cats {
		var ws []float64
		for _, e := range ev {
			ws = append(ws, e.Weight)
		}
		conf := NoisyOR(ws) * tf
		a.DB.Exec(ctx, `insert into classifications(entity_type,entity_id,host_id,category,confidence,evidence) values($1,$2,$3,$4,$5,$6)
			on conflict(entity_type,entity_id,category) do update set confidence=excluded.confidence, evidence=excluded.evidence, active=true, last_seen=now()`,
			etype, eid, hostID, cat, conf, jsonb(ev))
		keep = append(keep, cat)
	}
	a.DB.Exec(ctx, `update classifications set active=false where entity_type=$1 and entity_id=$2 and not (category = any($3))`, etype, eid, nonNil(keep))
}

func (a *App) saveMatches(ctx context.Context, ic *ingestCtx, etype, eid, key, hostID, ip string, hits []sigHit, evaluated map[string]bool) {
	matched := map[string]bool{}
	for _, x := range hits {
		if matched[x.sg.ID] {
			continue
		}
		matched[x.sg.ID] = true
		var wasActive *bool
		a.DB.QueryRow(ctx, `select active from signature_matches where sig_id=$1 and entity_type=$2 and entity_id=$3`, x.sg.ID, etype, eid).Scan(&wasActive)
		a.DB.Exec(ctx, `insert into signature_matches(sig_id,sig_version,entity_type,entity_id,entity_key,host_id,evidence,last_run_id) values($1,$2,$3,$4,$5,$6,$7,$8)
			on conflict(sig_id,entity_type,entity_id) do update set evidence=excluded.evidence, active=true, last_seen=now(), last_run_id=excluded.last_run_id, sig_version=excluded.sig_version`,
			x.sg.ID, max(x.sg.Version, 1), etype, eid, key, hostID, jsonb(x.res.Evidence), nullUUID(ic.runID))
		if (wasActive == nil || !*wasActive) && x.sg.Priority >= 10 && ic != nil {
			sg := x.sg
			ic.change(etype, key, ip, "SIGNATURE_MATCH_NEW", fmt.Sprintf("%s – %s", sg.Name, key), sg.Priority, []FieldDiff{{"signature", nil, sg.ID}}, nil)
		}
	}
	for id := range evaluated {
		if matched[id] {
			continue
		}
		ct, _ := a.DB.Exec(ctx, `update signature_matches set active=false where sig_id=$1 and entity_type=$2 and entity_id=$3 and active`, id, etype, eid)
		if ct.RowsAffected() > 0 && ic != nil {
			ic.change(etype, key, ip, "SIGNATURE_MATCH_GONE", fmt.Sprintf("Sygnatura %s przestała pasować – %s", id, key), 3, []FieldDiff{{"signature", id, nil}}, nil)
		}
	}
}

// ---------------- analiza usługi ----------------

func serviceSubject(ip string, s *obs.Service, hostnames []string) sigs.MapSubject {
	m := sigs.MapSubject{}
	m.Add("ip", ip)
	m.Add("port", strconv.Itoa(s.Port))
	m.Add("proto", s.Proto)
	m.Add("service", s.Service)
	m.Add("product", s.Product)
	m.Add("version", s.Version)
	m.Add("extrainfo", s.ExtraInfo)
	m.Add("cpe", s.CPE...)
	m.Add("banner", s.Banner)
	m.Add("devicetype", s.DeviceType)
	m.Add("tunnel", s.Tunnel)
	m.Add("hostname", hostnames...)
	addTLS(m, s.TLS)
	return m
}

func (a *App) analyzeService(ctx context.Context, ic *ingestCtx, hostID, svcID, ip string, s *obs.Service, hostnames []string, light bool) {
	if light { // pola usługi z poprzedniego pomiaru
		var cpe []string
		a.DB.QueryRow(ctx, `select service_name, product, version, extrainfo, devicetype, cpe, tunnel from services where id=$1`, svcID).
			Scan(&s.Service, &s.Product, &s.Version, &s.ExtraInfo, &s.DeviceType, &cpe, &s.Tunnel)
		s.CPE = cpe
	}
	key := obs.ServiceKey(ip, s.Proto, s.Port)
	cs := claims{}
	if s.Product != "" {
		w := 0.6
		if s.Nmap != nil {
			switch {
			case s.Nmap.Method == "probed" && s.Nmap.Conf >= 10:
				w = 0.9
			case s.Nmap.Method == "probed":
				w = float64(s.Nmap.Conf) / 10 * 0.9
			default:
				w = 0.25
			}
		}
		cat := ""
		if iotDeviceTypes[strings.ToLower(s.DeviceType)] {
			cat = "iot"
		}
		cs.add(s.Product, s.Version, cat, Evidence{"nmap", fmt.Sprintf("%s %s (%s)", s.Product, s.Version, methodLabel(s.Nmap)), w})
	}
	sub := serviceSubject(ip, s, hostnames)
	var hits []sigHit
	evaluated := map[string]bool{}
	for _, sg := range a.Sigs.All() {
		if sg.Scope != "service" {
			continue
		}
		evaluated[sg.ID] = true
		if r := sg.Eval(sub, false); r.Matched {
			hits = append(hits, sigHit{sg, r})
			if sg.Technology != nil {
				cs.add(sg.Technology.Name, r.Version, sg.Technology.Category, Evidence{"signature", sg.ID, sg.Confidence})
			}
		}
	}
	cats := map[string][]Evidence{}
	for _, x := range hits {
		for _, c := range x.sg.Categories {
			cats[c] = append(cats[c], Evidence{"signature", x.sg.ID, x.sg.Confidence})
		}
	}
	if iotDeviceTypes[strings.ToLower(s.DeviceType)] {
		cats["iot"] = append(cats["iot"], Evidence{"nmap", "devicetype " + s.DeviceType, 0.7})
	}
	tf := a.temporalFactor(ctx, svcID)
	techs := a.saveTechs(ctx, "service", svcID, hostID, cs, tf, false)
	conf := 0.0
	if c := cs[strings.ToLower(canonTech(s.Product))]; c != nil {
		conf = c.confidence() * tf
	} else if s.Service != "" {
		conf = 0.25
		if s.Nmap != nil && s.Nmap.Method == "probed" {
			conf = float64(s.Nmap.Conf) / 10 * 0.9
		}
	}
	// usługa odpowiedziała po HTTP – sam protokół jest pewny, nawet gdy nmap zgadł nazwę z numeru portu
	if len(s.HTTP) > 0 && conf < 0.8 && strings.HasPrefix(s.Service, "http") {
		conf = 0.85
	}
	vconf := 0.0
	if s.Version != "" {
		vconf = conf * 0.9
	}
	a.saveCategories(ctx, "service", svcID, hostID, cats, tf)
	a.saveMatches(ctx, ic, "service", svcID, key, hostID, ip, hits, evaluated)
	major := strings.SplitN(s.Version, ".", 2)[0]
	cluster := a.Keys.MAC("svc", s.Service, s.Product, major)
	a.DB.Exec(ctx, `update services set confidence=$2, version_confidence=$3, cluster_key=$4 where id=$1`, svcID, conf, vconf, cluster)
	a.scoreEntity(ctx, "services", svcID, key, s.Port, "", ic)
	a.syncFindings(ctx, "service", key, ip, hostID, ic.groupID, hits, evaluated, fmt.Sprintf("%s://%s:%d", s.Proto, ip, s.Port), s.Port, s.Proto, "", techs)
}

func methodLabel(n *obs.NmapInfo) string {
	if n == nil {
		return "brak danych nmap"
	}
	if n.Method == "table" {
		return "zgadnięte z numeru portu"
	}
	return fmt.Sprintf("%s, conf %d/10", n.Method, n.Conf)
}

// ---------------- analiza hosta ----------------

func (a *App) analyzeHost(ctx context.Context, ic *ingestCtx, hostID string) {
	var ip, os, dev string
	var names, labels []string
	if a.DB.QueryRow(ctx, `select host(ip), os, devicetype, hostnames, labels from hosts where id=$1`, hostID).Scan(&ip, &os, &dev, &names, &labels) != nil {
		return
	}
	m := sigs.MapSubject{}
	m.Add("ip", ip)
	m.Add("hostname", names...)
	m.Add("os", os)
	m.Add("devicetype", dev)
	m.Add("labels", labels...)
	rows, _ := a.DB.Query(ctx, `select proto||'/'||port from services where host_id=$1 and state<>'INACTIVE'`, hostID)
	for rows.Next() {
		var p string
		rows.Scan(&p)
		m.Add("open_ports", p)
	}
	rows.Close()
	var hits []sigHit
	evaluated := map[string]bool{}
	for _, sg := range a.Sigs.All() {
		if sg.Scope != "host" {
			continue
		}
		evaluated[sg.ID] = true
		if r := sg.Eval(m, false); r.Matched {
			hits = append(hits, sigHit{sg, r})
		}
	}
	a.saveMatches(ctx, ic, "host", hostID, ip, hostID, ip, hits, evaluated)
	a.updateHostScore(ctx, hostID)
}

// ---------------- ocena „ciekawości” (sekcja 10.1) ----------------

type ScoreItem struct {
	Label  string `json:"label"`
	Points int    `json:"points"`
}

var categoryPoints = map[string]int{
	"admin_panel": 30, "debug_exposure": 35, "cleartext_login": 25, "staging": 20, "eol_software": 25, "iot": 20,
	"default_page": 10, "tls_issue": 10, "exposed_installer": 40, "exposed_service": 15, "weak_config": 5, "info_disclosure": 3, "cms": 5, "framework": 2, "app_server": 2,
}

var CategoryLabels = map[string]string{
	"admin_panel": "panel administracyjny", "debug_exposure": "ekspozycja debug / plików", "cleartext_login": "logowanie przez HTTP",
	"staging": "środowisko testowe", "eol_software": "oprogramowanie bez wsparcia", "iot": "urządzenie IoT", "default_page": "strona domyślna",
	"tls_issue": "problem z TLS", "exposed_service": "usługa wystawiona do sieci", "weak_config": "słaba konfiguracja", "info_disclosure": "ujawnienie wersji",
	"exposed_installer": "instalator dostępny publicznie", "slow_response": "wolna odpowiedź", "app": "aplikacja",
	"cms": "CMS", "framework": "framework", "app_server": "serwer aplikacyjny", "web_server": "serwer WWW", "technology": "technologia",
}

func (a *App) scoreEntity(ctx context.Context, table, id, key string, port int, scheme string, ic *ingestCtx) int {
	etype := map[string]string{"http_endpoints": "http", "services": "service"}[table]
	var items []ScoreItem
	rows, _ := a.DB.Query(ctx, `select category, confidence from classifications where entity_type=$1 and entity_id=$2 and active and confidence>=0.45`, etype, id)
	for rows.Next() {
		var cat string
		var conf float32
		rows.Scan(&cat, &conf)
		if p := categoryPoints[cat]; p > 0 {
			if cat == "iot" && etype == "service" {
				p = 10
			}
			items = append(items, ScoreItem{CategoryLabels[cat], p})
		}
	}
	rows.Close()
	// sygnatury z wysokim priorytetem (połowa wagi – kategorie już liczone)
	rows, _ = a.DB.Query(ctx, `select m.sig_id, coalesce((s.definition->>'priority')::int,0) from signature_matches m join signatures s on s.sig_id=m.sig_id
		where m.entity_type=$1 and m.entity_id=$2 and m.active order by 2 desc limit 3`, etype, id)
	for rows.Next() {
		var sid string
		var pr int
		rows.Scan(&sid, &pr)
		if pr >= 20 {
			items = append(items, ScoreItem{"sygnatura " + sid, pr / 2})
		}
	}
	rows.Close()
	var firstSeen time.Time
	var labels []string
	a.DB.QueryRow(ctx, fmt.Sprintf(`select first_seen, labels from %s where id=$1`, table), id).Scan(&firstSeen, &labels)
	flapping := contains(labels, "FLAPPING")
	if ic != nil && !ic.baseline && ic.source == "scanner" && !firstSeen.Before(ic.runStart) {
		p := 15
		if flapping {
			p = 7
		}
		items = append(items, ScoreItem{"nowe od ostatniego przebiegu", p})
	}
	if etype == "http" && port != 80 && port != 443 && port != 8080 && port != 8443 {
		items = append(items, ScoreItem{"WWW na nietypowym porcie", 5})
	}
	// statusy z DefectDojo: FP / risk accepted zerują
	var suppressed int
	a.DB.QueryRow(ctx, `select count(*) from findings where entity_key=$1 and status in ('false_positive','risk_accepted')`, key).Scan(&suppressed)
	total := 0
	for _, it := range items {
		total += it.Points
	}
	if suppressed > 0 {
		items = append(items, ScoreItem{"znalezisko oznaczone w DefectDojo (FP / risk accepted)", -total / 2})
		total -= total / 2
	}
	var muted bool
	a.DB.QueryRow(ctx, `select exists(select 1 from suppressions where (entity_key=$1 or entity_key=split_part($1,'/',1)) and sig_id='' and (until is null or until>now()))
		or exists(select 1 from overrides where entity_key=$1 and field='muted' and value='true')`, key).Scan(&muted)
	if muted {
		items = append(items, ScoreItem{"wyciszone przez analityka", -total})
		total = 0
	}
	var manual *int
	var raw []byte
	if a.DB.QueryRow(ctx, `select value from overrides where entity_type=$1 and entity_key=$2 and field='priority'`, etype, key).Scan(&raw) == nil {
		var v int
		if json.Unmarshal(raw, &v) == nil {
			manual = &v
		}
	}
	if manual != nil {
		items = []ScoreItem{{"priorytet ustawiony ręcznie", *manual}}
		total = *manual
	}
	total = max(0, min(total, 100))
	if items == nil {
		items = []ScoreItem{}
	}
	a.DB.Exec(ctx, fmt.Sprintf(`update %s set score=$2, score_breakdown=$3 where id=$1`, table), id, total, jsonb(items))
	return total
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s || strings.HasPrefix(x, s+"(") {
			return true
		}
	}
	return false
}

func (a *App) entityScore(ctx context.Context, table, id string) int {
	var s int
	a.DB.QueryRow(ctx, fmt.Sprintf(`select score from %s where id=$1`, table), id).Scan(&s)
	return s
}

func (a *App) hostScore(ctx context.Context, id string) int {
	var s int
	a.DB.QueryRow(ctx, `select score from hosts where id=$1`, id).Scan(&s)
	return s
}

// updateHostScore – wynik hosta = najwyższy wynik jego usług i endpointów (+ etykiety).
func (a *App) updateHostScore(ctx context.Context, hostID string) {
	var best int
	var bestBreak []byte
	a.DB.QueryRow(ctx, `select score, score_breakdown from (
		select score, score_breakdown from services where host_id=$1 and state<>'INACTIVE'
		union all select score, score_breakdown from http_endpoints where host_id=$1 and state<>'INACTIVE') x order by score desc limit 1`, hostID).Scan(&best, &bestBreak)
	if bestBreak == nil {
		bestBreak = []byte("[]")
	}
	var ip string
	a.DB.QueryRow(ctx, `select host(ip) from hosts where id=$1`, hostID).Scan(&ip)
	var raw []byte
	if a.DB.QueryRow(ctx, `select value from overrides where entity_type='host' and entity_key=$1 and field='priority'`, ip).Scan(&raw) == nil {
		var v int
		if json.Unmarshal(raw, &v) == nil {
			best = v
			bestBreak = jsonb([]ScoreItem{{"priorytet ustawiony ręcznie", v}})
		}
	}
	a.DB.Exec(ctx, `update hosts set score=$2, score_breakdown=$3 where id=$1`, hostID, best, bestBreak)
}

// RescoreAll przelicza oceny (po zmianie statusów w DefectDojo lub wyciszeniu).
func (a *App) RescoreKey(ctx context.Context, key string) {
	ip := strings.SplitN(key, "/", 2)[0]
	rows, _ := a.DB.Query(ctx, `select 'services', s.id::text, host(h.ip)||'/'||s.proto||'/'||s.port, s.port, '' from services s join hosts h on h.id=s.host_id where h.ip=$1::inet
		union all select 'http_endpoints', e.id::text, host(h.ip)||'/tcp/'||s.port||'/'||e.scheme||'/'||coalesce(nullif(e.vhost,''),'-'), s.port, e.scheme
		from http_endpoints e join services s on s.id=e.service_id join hosts h on h.id=e.host_id where h.ip=$1::inet`, ip)
	type item struct {
		table, id, key, scheme string
		port                   int
	}
	var items []item
	for rows.Next() {
		var it item
		rows.Scan(&it.table, &it.id, &it.key, &it.port, &it.scheme)
		items = append(items, it)
	}
	rows.Close()
	for _, it := range items {
		a.scoreEntity(ctx, it.table, it.id, it.key, it.port, it.scheme, nil)
	}
	var hid string
	if a.DB.QueryRow(ctx, `select id from hosts where ip=$1::inet`, ip).Scan(&hid) == nil {
		a.updateHostScore(ctx, hid)
	}
}
