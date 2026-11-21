package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/obs"
)

// ---------------- język filtrów ----------------
//
// Przykłady: "wordpress", "state:active tech:wordpress score>30", "cidr:10.77.1.0/24 cat:admin_panel", "tag:prod port:8080 label:flapping"

type filterBuilder struct {
	where []string
	args  []any
}

func (f *filterBuilder) arg(v any) string {
	f.args = append(f.args, v)
	return "$" + strconv.Itoa(len(f.args))
}

type Page struct {
	Limit  int
	Offset int
	Sort   string
}

func normPage(p Page) Page {
	if p.Limit <= 0 || p.Limit > 1000 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

// parseQuery tłumaczy zapytanie na warunki SQL. hostAlias/entity: kontekst listy.
func parseQuery(q, kind string, f *filterBuilder) {
	for _, tok := range strings.Fields(q) {
		key, val, op := "", tok, ":"
		for _, o := range []string{">=", "<=", ":", ">", "<"} {
			if i := strings.Index(tok, o); i > 0 {
				key, val, op = strings.ToLower(tok[:i]), tok[i+len(o):], o
				break
			}
		}
		if val == "" {
			continue
		}
		etypeCond := map[string]string{"host": "c.host_id=h.id", "service": "c.entity_type='service' and c.entity_id=s.id", "http": "c.entity_type='http' and c.entity_id=e.id"}[kind]
		techCond := map[string]string{"host": "t.host_id=h.id", "service": "t.entity_type='service' and t.entity_id=s.id", "http": "t.entity_type='http' and t.entity_id=e.id"}[kind]
		stateCol := map[string]string{"host": "h.state", "service": "s.state", "http": "e.state"}[kind]
		labelCol := map[string]string{"host": "h.labels", "service": "s.labels", "http": "e.labels"}[kind]
		scoreCol := map[string]string{"host": "h.score", "service": "s.score", "http": "e.score"}[kind]
		entKey := map[string]string{"host": "host(h.ip)", "service": "host(h.ip)||'/'||s.proto||'/'||s.port",
			"http": "host(h.ip)||'/tcp/'||s.port||'/'||e.scheme||'/'||coalesce(nullif(e.vhost,''),'-')"}[kind]
		switch key {
		case "state":
			f.where = append(f.where, stateCol+"="+f.arg(strings.ToUpper(val)))
		case "tech":
			f.where = append(f.where, "exists(select 1 from technologies t where "+techCond+" and t.active and t.name ilike "+f.arg("%"+val+"%")+")")
		case "cat", "category":
			f.where = append(f.where, "exists(select 1 from classifications c where "+etypeCond+" and c.active and c.confidence>=0.45 and c.category="+f.arg(val)+")")
		case "cidr", "net":
			if p, err := netip.ParsePrefix(val); err == nil {
				f.where = append(f.where, "h.ip <<= "+f.arg(p.String())+"::cidr")
			}
		case "ip":
			f.where = append(f.where, "host(h.ip)="+f.arg(val))
		case "port":
			if kind == "host" {
				f.where = append(f.where, "exists(select 1 from services s2 where s2.host_id=h.id and s2.port="+f.arg(atoi(val))+" and s2.state<>'INACTIVE')")
			} else {
				f.where = append(f.where, "s.port="+f.arg(atoi(val)))
			}
		case "service":
			if kind == "host" {
				f.where = append(f.where, "exists(select 1 from services s2 where s2.host_id=h.id and s2.service_name ilike "+f.arg(val+"%")+")")
			} else {
				f.where = append(f.where, "s.service_name ilike "+f.arg(val+"%"))
			}
		case "product":
			pc := "s.product"
			if kind == "host" {
				f.where = append(f.where, "exists(select 1 from services s2 where s2.host_id=h.id and s2.product ilike "+f.arg("%"+val+"%")+")")
				continue
			}
			f.where = append(f.where, pc+" ilike "+f.arg("%"+val+"%"))
		case "label":
			f.where = append(f.where, "exists(select 1 from unnest("+labelCol+") l where l ilike "+f.arg(val+"%")+")")
		case "tag":
			f.where = append(f.where, "exists(select 1 from entity_tags et join tags tg on tg.id=et.tag_id where et.entity_key="+entKey+" and tg.name="+f.arg(strings.ToLower(val))+")")
		case "group":
			f.where = append(f.where, "h.group_id in (select id from target_groups where name ilike "+f.arg("%"+val+"%")+")")
		case "score":
			if n, err := strconv.Atoi(val); err == nil {
				o := op
				if o == ":" {
					o = ">="
				}
				f.where = append(f.where, scoreCol+o+f.arg(n))
			}
		case "new":
			f.where = append(f.where, "h.first_seen > now() - "+f.arg(val)+"::interval")
		case "finding":
			f.where = append(f.where, "exists(select 1 from findings fi where fi.host_ip=h.ip and fi.active and fi.status="+f.arg(val)+")")
		case "status":
			if kind == "http" {
				f.where = append(f.where, "e.status_code="+f.arg(atoi(val)))
			}
		case "source":
			f.where = append(f.where, "h.source="+f.arg(val))
		default:
			like := f.arg("%" + tok + "%")
			switch kind {
			case "host":
				f.where = append(f.where, "(host(h.ip) like "+like+" or array_to_string(h.hostnames,' ') ilike "+like+")")
			case "service":
				f.where = append(f.where, "(host(h.ip) like "+like+" or s.product ilike "+like+" or s.service_name ilike "+like+" or array_to_string(h.hostnames,' ') ilike "+like+")")
			case "http":
				f.where = append(f.where, "(e.url ilike "+like+" or e.title ilike "+like+" or e.server ilike "+like+" or host(h.ip) like "+like+")")
			}
		}
	}
}

func (f *filterBuilder) sql() string {
	if len(f.where) == 0 {
		return "true"
	}
	return strings.Join(f.where, " and ")
}

// ---------------- hosty ----------------

type HostRow struct {
	ID         string          `json:"id"`
	IP         string          `json:"ip"`
	Hostnames  []string        `json:"hostnames"`
	State      string          `json:"state"`
	Labels     []string        `json:"labels"`
	Score      int             `json:"score"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	Group      string          `json:"group"`
	Services   int             `json:"services"`
	Ports      []string        `json:"ports"`
	Techs      []string        `json:"techs"`
	Categories []string        `json:"categories"`
	Tags       []string        `json:"tags"`
	OS         string          `json:"os"`
	DeviceType string          `json:"devicetype"`
	Overrides  map[string]any  `json:"overrides,omitempty"`
	Breakdown  json.RawMessage `json:"score_breakdown,omitempty"`
	Source     string          `json:"source"`
}

func (a *App) ListHosts(ctx context.Context, q string, p Page) ([]HostRow, int, error) {
	p = normPage(p)
	f := &filterBuilder{}
	if !strings.Contains(q, "state:") {
		f.where = append(f.where, "h.state<>'INACTIVE'")
		if strings.Contains(q, "all:") {
			f.where = nil
			q = strings.ReplaceAll(q, "all:", "")
		}
	}
	parseQuery(q, "host", f)
	var total int
	if err := a.DB.QueryRow(ctx, `select count(*) from hosts h where `+f.sql(), f.args...).Scan(&total); err != nil {
		return nil, 0, Invalid("niepoprawne zapytanie", err.Error())
	}
	order := map[string]string{"ip": "h.ip", "last_seen": "h.last_seen desc", "first_seen": "h.first_seen desc", "": "h.score desc, h.ip"}[p.Sort]
	if order == "" {
		order = "h.score desc, h.ip"
	}
	rows, err := a.DB.Query(ctx, `select h.id, host(h.ip), h.hostnames, h.state, h.labels, h.score, h.first_seen, h.last_seen, coalesce(g.name,''), h.os, h.devicetype, h.score_breakdown, h.source,
		(select count(*) from services s where s.host_id=h.id and s.state<>'INACTIVE'),
		(select coalesce(array_agg(s.port::text||case when s.proto='udp' then '/udp' else '' end order by s.port),'{}') from services s where s.host_id=h.id and s.state<>'INACTIVE'),
		(select coalesce(array_agg(distinct t.name),'{}') from technologies t where t.host_id=h.id and t.active and t.confidence>=0.5),
		(select coalesce(array_agg(distinct c.category),'{}') from classifications c where c.host_id=h.id and c.active and c.confidence>=0.45),
		(select coalesce(array_agg(tg.name order by tg.name),'{}') from entity_tags et join tags tg on tg.id=et.tag_id where et.entity_type='host' and et.entity_key=host(h.ip))
		from hosts h left join target_groups g on g.id=h.group_id where `+f.sql()+` order by `+order+fmt.Sprintf(` limit %d offset %d`, p.Limit, p.Offset), f.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (HostRow, error) {
		var h HostRow
		var br []byte
		err := r.Scan(&h.ID, &h.IP, &h.Hostnames, &h.State, &h.Labels, &h.Score, &h.FirstSeen, &h.LastSeen, &h.Group, &h.OS, &h.DeviceType, &br, &h.Source,
			&h.Services, &h.Ports, &h.Techs, &h.Categories, &h.Tags)
		h.Breakdown = br
		return h, err
	})
	if err != nil {
		return nil, 0, err
	}
	keys := make([]string, len(out))
	for i, h := range out {
		keys[i] = h.IP
	}
	ovs := a.OverridesFor(ctx, "host", keys)
	for i := range out {
		out[i].Overrides = ovs[out[i].IP]
	}
	return out, total, nil
}

// ---------------- usługi ----------------

type ServiceRow struct {
	ID          string          `json:"id"`
	Key         string          `json:"key"`
	IP          string          `json:"ip"`
	Hostnames   []string        `json:"hostnames"`
	Proto       string          `json:"proto"`
	Port        int             `json:"port"`
	State       string          `json:"state"`
	Service     string          `json:"service"`
	Product     string          `json:"product"`
	Version     string          `json:"version"`
	ExtraInfo   string          `json:"extrainfo"`
	DeviceType  string          `json:"devicetype"`
	CPE         []string        `json:"cpe"`
	Tunnel      string          `json:"tunnel"`
	Method      string          `json:"nmap_method"`
	Conf        int             `json:"nmap_conf"`
	Confidence  float64         `json:"confidence"`
	VersionConf float64         `json:"version_confidence"`
	Labels      []string        `json:"labels"`
	Score       int             `json:"score"`
	Breakdown   json.RawMessage `json:"score_breakdown"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	TLS         json.RawMessage `json:"tls"`
	Categories  []string        `json:"categories"`
	Overrides   map[string]any  `json:"overrides,omitempty"`
	Misses      int             `json:"consecutive_misses"`
	TotalSeen   int             `json:"total_seen"`
	Flap        float64         `json:"flap_score"`
}

const serviceCols = `s.id, host(h.ip)||'/'||s.proto||'/'||s.port, host(h.ip), h.hostnames, s.proto, s.port, s.state, s.service_name, s.product, s.version, s.extrainfo, s.devicetype, s.cpe, s.tunnel,
	s.nmap_method, s.nmap_conf, s.confidence, s.version_confidence, s.labels, s.score, s.score_breakdown, s.first_seen, s.last_seen, s.tls,
	(select coalesce(array_agg(c.category),'{}') from classifications c where c.entity_type='service' and c.entity_id=s.id and c.active and c.confidence>=0.45),
	s.consecutive_misses, s.total_seen, s.flap_score`

func scanService(r pgx.CollectableRow) (ServiceRow, error) {
	var s ServiceRow
	var br, tls []byte
	var conf, vconf, flap float32
	err := r.Scan(&s.ID, &s.Key, &s.IP, &s.Hostnames, &s.Proto, &s.Port, &s.State, &s.Service, &s.Product, &s.Version, &s.ExtraInfo, &s.DeviceType, &s.CPE, &s.Tunnel,
		&s.Method, &s.Conf, &conf, &vconf, &s.Labels, &s.Score, &br, &s.FirstSeen, &s.LastSeen, &tls, &s.Categories, &s.Misses, &s.TotalSeen, &flap)
	s.Confidence, s.VersionConf, s.Flap = float64(conf), float64(vconf), float64(flap)
	s.Breakdown, s.TLS = br, tls
	return s, err
}

func (a *App) ListServices(ctx context.Context, q string, p Page) ([]ServiceRow, int, error) {
	p = normPage(p)
	f := &filterBuilder{}
	if !strings.Contains(q, "state:") {
		f.where = append(f.where, "s.state<>'INACTIVE'")
	}
	parseQuery(q, "service", f)
	var total int
	if err := a.DB.QueryRow(ctx, `select count(*) from services s join hosts h on h.id=s.host_id where `+f.sql(), f.args...).Scan(&total); err != nil {
		return nil, 0, Invalid("niepoprawne zapytanie", err.Error())
	}
	rows, err := a.DB.Query(ctx, `select `+serviceCols+` from services s join hosts h on h.id=s.host_id where `+f.sql()+
		fmt.Sprintf(` order by s.score desc, h.ip, s.port limit %d offset %d`, p.Limit, p.Offset), f.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, scanService)
	if err != nil {
		return nil, 0, err
	}
	keys := make([]string, len(out))
	for i, s := range out {
		keys[i] = s.Key
	}
	ovs := a.OverridesFor(ctx, "service", keys)
	for i := range out {
		out[i].Overrides = ovs[out[i].Key]
	}
	return out, total, nil
}

// ---------------- endpointy WWW ----------------

type WebRow struct {
	ID          string          `json:"id"`
	Key         string          `json:"key"`
	IP          string          `json:"ip"`
	Port        int             `json:"port"`
	Scheme      string          `json:"scheme"`
	Vhost       string          `json:"vhost"`
	URL         string          `json:"url"`
	State       string          `json:"state"`
	Status      int             `json:"status"`
	Title       string          `json:"title"`
	Server      string          `json:"server"`
	PoweredBy   string          `json:"powered_by"`
	HeaderNames []string        `json:"header_names"`
	Cookies     json.RawMessage `json:"cookies"`
	FinalURL    string          `json:"final_url"`
	Favicon     string          `json:"favicon_mmh3"`
	TLS         json.RawMessage `json:"tls"`
	Labels      []string        `json:"labels"`
	Score       int             `json:"score"`
	Breakdown   json.RawMessage `json:"score_breakdown"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	Techs       json.RawMessage `json:"techs"`
	Categories  json.RawMessage `json:"categories"`
	Matches     json.RawMessage `json:"matches"`
	ClusterKey  string          `json:"cluster_key"`
	Overrides   map[string]any  `json:"overrides,omitempty"`
}

const webCols = `e.id, host(h.ip)||'/tcp/'||s.port||'/'||e.scheme||'/'||coalesce(nullif(e.vhost,''),'-'), host(h.ip), s.port, e.scheme, e.vhost, e.url, e.state, e.status_code, e.title, e.server,
	e.powered_by, e.header_names, e.cookie_meta, e.final_url, e.favicon_mmh3, e.tls, e.labels, e.score, e.score_breakdown, e.first_seen, e.last_seen,
	(select coalesce(jsonb_agg(jsonb_build_object('name',t.name,'version',t.version,'category',t.category,'confidence',round(t.confidence::numeric,2),'version_confidence',round(t.version_confidence::numeric,2),'evidence',t.evidence) order by t.confidence desc),'[]') from technologies t where t.entity_type='http' and t.entity_id=e.id and t.active),
	(select coalesce(jsonb_agg(jsonb_build_object('category',c.category,'confidence',round(c.confidence::numeric,2),'evidence',c.evidence) order by c.confidence desc),'[]') from classifications c where c.entity_type='http' and c.entity_id=e.id and c.active and c.confidence>=0.3),
	(select coalesce(jsonb_agg(jsonb_build_object('sig_id',m.sig_id,'evidence',m.evidence,'first_seen',m.first_seen) order by m.sig_id),'[]') from signature_matches m where m.entity_type='http' and m.entity_id=e.id and m.active),
	e.cluster_key`

func scanWeb(r pgx.CollectableRow) (WebRow, error) {
	var w WebRow
	var ck, tls, br, techs, cats, ms []byte
	err := r.Scan(&w.ID, &w.Key, &w.IP, &w.Port, &w.Scheme, &w.Vhost, &w.URL, &w.State, &w.Status, &w.Title, &w.Server, &w.PoweredBy, &w.HeaderNames, &ck,
		&w.FinalURL, &w.Favicon, &tls, &w.Labels, &w.Score, &br, &w.FirstSeen, &w.LastSeen, &techs, &cats, &ms, &w.ClusterKey)
	w.Cookies, w.TLS, w.Breakdown, w.Techs, w.Categories, w.Matches = ck, tls, br, techs, cats, ms
	return w, err
}

func (a *App) ListWeb(ctx context.Context, q string, p Page) ([]WebRow, int, error) {
	p = normPage(p)
	f := &filterBuilder{}
	if !strings.Contains(q, "state:") {
		f.where = append(f.where, "e.state<>'INACTIVE'")
	}
	parseQuery(q, "http", f)
	base := ` from http_endpoints e join services s on s.id=e.service_id join hosts h on h.id=e.host_id where `
	var total int
	if err := a.DB.QueryRow(ctx, `select count(*)`+base+f.sql(), f.args...).Scan(&total); err != nil {
		return nil, 0, Invalid("niepoprawne zapytanie", err.Error())
	}
	rows, err := a.DB.Query(ctx, `select `+webCols+base+f.sql()+fmt.Sprintf(` order by e.score desc, h.ip, s.port limit %d offset %d`, p.Limit, p.Offset), f.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, scanWeb)
	if err != nil {
		return nil, 0, err
	}
	keys := make([]string, len(out))
	for i, w := range out {
		keys[i] = w.Key
	}
	ovs := a.OverridesFor(ctx, "http", keys)
	for i := range out {
		out[i].Overrides = ovs[out[i].Key]
	}
	return out, total, nil
}

// ---------------- technologie (agregat) ----------------

type TechAgg struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Count    int      `json:"count"`
	Hosts    int      `json:"hosts"`
	Versions []string `json:"versions"`
	AvgConf  float64  `json:"avg_confidence"`
}

func (a *App) ListTechnologies(ctx context.Context, q string) ([]TechAgg, error) {
	rows, err := a.DB.Query(ctx, `select t.name, max(t.category), count(*), count(distinct t.host_id), coalesce(array_agg(distinct t.version) filter (where t.version<>''),'{}'), avg(t.confidence)
		from technologies t join hosts h on h.id=t.host_id where t.active and h.state<>'INACTIVE' and t.confidence>=0.3 and ($1='' or t.name ilike '%'||$1||'%' or t.category=$1)
		group by t.name order by count(distinct t.host_id) desc, t.name limit 300`, q)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (TechAgg, error) {
		var t TechAgg
		err := r.Scan(&t.Name, &t.Category, &t.Count, &t.Hosts, &t.Versions, &t.AvgConf)
		sort.Slice(t.Versions, func(i, j int) bool { return t.Versions[i] < t.Versions[j] })
		return t, err
	})
}

// ---------------- szczegóły hosta ----------------

type HostDetail struct {
	Host         HostRow                 `json:"host"`
	Identity     json.RawMessage         `json:"identity"`
	Periodicity  json.RawMessage         `json:"periodicity"`
	Misses       int                     `json:"consecutive_misses"`
	TotalSeen    int                     `json:"total_seen"`
	Flap         float64                 `json:"flap_score"`
	HostnameSrc  []map[string]string     `json:"hostname_sources"`
	Services     []ServiceDetail         `json:"services"`
	Overrides    map[string]OverrideView `json:"overrides"`
	OverrideHist []OverrideHistory       `json:"override_history"`
	Notes        []Note                  `json:"notes"`
	Changes      []Change                `json:"changes"`
	Findings     []Finding               `json:"findings"`
	Timeline     []TimelinePoint         `json:"timeline"`
	Heatmap      [7][24]*float64         `json:"heatmap"`
	HostMatches  json.RawMessage         `json:"host_matches"`
}

type ServiceDetail struct {
	ServiceRow
	Techs    json.RawMessage         `json:"techs"`
	CatsFull json.RawMessage         `json:"categories_full"`
	Matches  json.RawMessage         `json:"matches"`
	Web      []WebRow                `json:"web"`
	OvViews  map[string]OverrideView `json:"override_views"`
	Tags     []string                `json:"tags"`
}

type TimelinePoint struct {
	At    time.Time `json:"at"`
	Up    bool      `json:"up"`
	Retry bool      `json:"retry"`
	RunID string    `json:"run_id"`
}

func (a *App) HostDetail(ctx context.Context, ip string) (*HostDetail, error) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return nil, ErrNotFound
	}
	hosts, _, err := a.ListHosts(ctx, "all: ip:"+ip, Page{Limit: 1})
	if err != nil || len(hosts) == 0 {
		return nil, ErrNotFound
	}
	d := &HostDetail{Host: hosts[0]}
	var flap float32
	a.DB.QueryRow(ctx, `select identity, periodicity, consecutive_misses, total_seen, flap_score from hosts where id=$1`, d.Host.ID).Scan(&d.Identity, &d.Periodicity, &d.Misses, &d.TotalSeen, &flap)
	d.Flap = float64(flap)
	rows, _ := a.DB.Query(ctx, `select name, source from host_hostnames where host_id=$1 order by name`, d.Host.ID)
	for rows.Next() {
		var n, s string
		rows.Scan(&n, &s)
		d.HostnameSrc = append(d.HostnameSrc, map[string]string{"name": n, "source": s})
	}
	rows.Close()
	srows, err := a.DB.Query(ctx, `select `+serviceCols+` from services s join hosts h on h.id=s.host_id where h.id=$1 order by s.state='INACTIVE', s.proto, s.port`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	svcs, err := pgx.CollectRows(srows, scanService)
	if err != nil {
		return nil, err
	}
	for _, s := range svcs {
		sd := ServiceDetail{ServiceRow: s}
		a.DB.QueryRow(ctx, `select (select coalesce(jsonb_agg(jsonb_build_object('name',t.name,'version',t.version,'category',t.category,'confidence',round(t.confidence::numeric,2),'evidence',t.evidence)),'[]') from technologies t where t.entity_type='service' and t.entity_id=$1 and t.active),
			(select coalesce(jsonb_agg(jsonb_build_object('category',c.category,'confidence',round(c.confidence::numeric,2),'evidence',c.evidence)),'[]') from classifications c where c.entity_type='service' and c.entity_id=$1 and c.active),
			(select coalesce(jsonb_agg(jsonb_build_object('sig_id',m.sig_id,'evidence',m.evidence,'first_seen',m.first_seen)),'[]') from signature_matches m where m.entity_type='service' and m.entity_id=$1 and m.active)`, s.ID).
			Scan(&sd.Techs, &sd.CatsFull, &sd.Matches)
		wrows, err := a.DB.Query(ctx, `select `+webCols+` from http_endpoints e join services s on s.id=e.service_id join hosts h on h.id=e.host_id where e.service_id=$1 order by e.vhost, e.scheme`, s.ID)
		if err == nil {
			sd.Web, _ = pgx.CollectRows(wrows, scanWeb)
		}
		sd.OvViews = a.Overrides(ctx, "service", s.Key)
		for i := range sd.Web {
			sd.Web[i].Overrides = map[string]any{}
			for f, v := range a.Overrides(ctx, "http", sd.Web[i].Key) {
				sd.Web[i].Overrides[f] = v
			}
		}
		sd.Tags = a.EntityTags(ctx, "service", s.Key)
		d.Services = append(d.Services, sd)
	}
	d.Overrides = a.Overrides(ctx, "host", ip)
	d.OverrideHist = a.OverrideHistory(ctx, "host", ip)
	d.Notes = a.Notes(ctx, "host", ip)
	d.Changes, _ = a.ListChanges(ctx, ChangeFilter{IP: ip, Limit: 100, MinPriority: -1})
	d.Findings, _, _ = a.ListFindings(ctx, FindingFilter{Q: ip + "/", Limit: 200})
	extra, _, _ := a.ListFindings(ctx, FindingFilter{Q: ip, Limit: 200})
	seen := map[string]bool{}
	var fl []Finding
	for _, f := range append(d.Findings, extra...) {
		if strings.SplitN(f.EntityKey, "/", 2)[0] == ip && !seen[f.ID] {
			seen[f.ID] = true
			fl = append(fl, f)
		}
	}
	d.Findings = fl
	trows, _ := a.DB.Query(ctx, `select at, up, retry, coalesce(run_id::text,'') from availability_history where entity_id=$1 order by at desc limit 300`, d.Host.ID)
	var up, tot [7][24]int
	for trows.Next() {
		var p TimelinePoint
		trows.Scan(&p.At, &p.Up, &p.Retry, &p.RunID)
		d.Timeline = append(d.Timeline, p)
		l := p.At.In(warsaw())
		wd := (int(l.Weekday()) + 6) % 7
		tot[wd][l.Hour()]++
		if p.Up {
			up[wd][l.Hour()]++
		}
	}
	trows.Close()
	for i := 0; i < 7; i++ {
		for j := 0; j < 24; j++ {
			if tot[i][j] > 0 {
				v := float64(up[i][j]) / float64(tot[i][j])
				d.Heatmap[i][j] = &v
			}
		}
	}
	a.DB.QueryRow(ctx, `select coalesce(jsonb_agg(jsonb_build_object('sig_id',sig_id,'evidence',evidence)),'[]') from signature_matches where entity_type='host' and entity_id=$1 and active`, d.Host.ID).Scan(&d.HostMatches)
	return d, nil
}

func warsaw() *time.Location {
	l, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		return time.UTC
	}
	return l
}

// RawData – odszyfrowane dane surowe encji (wymaga sensitive:read).
func (a *App) RawData(ctx context.Context, etype, key string) (any, error) {
	switch etype {
	case "http":
		id := a.httpIDByKey(ctx, key)
		if id == "" {
			return nil, ErrNotFound
		}
		r := a.loadHTTPRaw(ctx, id)
		if r == nil {
			return map[string]any{}, nil
		}
		return r, nil
	case "service":
		p := strings.Split(key, "/")
		if len(p) < 3 {
			return nil, ErrNotFound
		}
		var id string
		var ct []byte
		if a.DB.QueryRow(ctx, `select s.id, s.raw_enc from services s join hosts h on h.id=s.host_id where h.ip=$1::inet and s.proto=$2 and s.port=$3`, p[0], p[1], atoi(p[2])).Scan(&id, &ct) != nil {
			return nil, ErrNotFound
		}
		pt, err := a.Keys.Decrypt("services.raw_enc:"+id, ct)
		if err != nil {
			return nil, err
		}
		var v any
		json.Unmarshal(pt, &v)
		return v, nil
	}
	return nil, ErrNotFound
}

// ---------------- zmiany ----------------

type Change struct {
	ID         int64           `json:"id"`
	RunID      string          `json:"run_id"`
	At         time.Time       `json:"at"`
	EntityType string          `json:"entity_type"`
	EntityKey  string          `json:"entity_key"`
	HostIP     string          `json:"host_ip"`
	Type       string          `json:"type"`
	Summary    string          `json:"summary"`
	Diff       json.RawMessage `json:"diff"`
	Priority   int             `json:"priority"`
	AckBy      *string         `json:"acknowledged_by"`
	GroupName  string          `json:"group_name"`
}

type ChangeFilter struct {
	Type        string
	IP          string
	Q           string
	RunID       string
	Since       time.Time
	MinPriority int
	Unacked     bool
	Limit       int
	Offset      int
}

func (a *App) ListChanges(ctx context.Context, f ChangeFilter) ([]Change, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	var types []string
	if f.Type != "" {
		types = strings.Split(f.Type, ",")
	}
	rows, err := a.DB.Query(ctx, `select c.id, coalesce(c.run_id::text,''), c.at, c.entity_type, c.entity_key, coalesce(host(c.host_ip),''), c.change_type, c.summary, c.diff, c.priority, c.acknowledged_by, coalesce(g.name,'')
		from changes c left join scan_runs r on r.id=c.run_id left join target_groups g on g.id=r.group_id
		where ($1::text[] is null or c.change_type = any($1)) and ($2='' or host(c.host_ip)=$2) and ($3='' or c.entity_key ilike '%'||$3||'%' or c.summary ilike '%'||$3||'%')
		and ($4='' or c.run_id::text=$4) and c.at >= $5 and c.priority >= $6 and (not $7 or c.acknowledged_at is null)
		order by c.at desc, c.priority desc limit $8 offset $9`, typesOrNil(types), f.IP, f.Q, f.RunID, f.Since, f.MinPriority, f.Unacked, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Change])
}

func typesOrNil(t []string) any {
	if len(t) == 0 {
		return nil
	}
	return t
}

func (a *App) AckChange(ctx context.Context, actor Actor, ids []int64) error {
	_, err := a.DB.Exec(ctx, `update changes set acknowledged_by=$2, acknowledged_at=now() where id = any($1)`, ids, actor.Name())
	a.Audit(ctx, actor, "changes.ack", "change", fmt.Sprint(len(ids)), nil)
	return err
}

// ---------------- dashboard ----------------

type QueueItem struct {
	Kind      string          `json:"kind"` // change | entity
	Key       string          `json:"key"`
	IP        string          `json:"ip"`
	Title     string          `json:"title"`
	Reason    string          `json:"reason"`
	Priority  int             `json:"priority"`
	At        time.Time       `json:"at"`
	ChangeID  int64           `json:"change_id,omitempty"`
	Type      string          `json:"type,omitempty"`
	Breakdown json.RawMessage `json:"breakdown,omitempty"`
}

type Dashboard struct {
	KPI      map[string]int   `json:"kpi"`
	Delta    map[string]int   `json:"delta"`
	Runs     []*Run           `json:"runs"`
	Queue    []QueueItem      `json:"queue"`
	Trend    []map[string]any `json:"trend"`
	Clusters []Cluster        `json:"clusters"`
	Findings map[string]int   `json:"findings_by_category"`
	Workers  []Worker         `json:"workers"`
	DD       map[string]any   `json:"defectdojo"`
	Kill     KillSwitch       `json:"killswitch"`
}

func (a *App) Dashboard(ctx context.Context) (*Dashboard, error) {
	d := &Dashboard{KPI: map[string]int{}, Delta: map[string]int{}, Findings: map[string]int{}}
	var hosts, svcs, web, flap, periodic, inactive7, certs, open int
	a.DB.QueryRow(ctx, `select (select count(*) from hosts where state<>'INACTIVE'), (select count(*) from services where state<>'INACTIVE'),
		(select count(*) from http_endpoints where state<>'INACTIVE'), (select count(*) from hosts where 'FLAPPING'=any(labels) or exists(select 1 from services s where s.host_id=hosts.id and 'FLAPPING'=any(s.labels))),
		(select count(*) from hosts where exists(select 1 from unnest(labels) l where l like 'PERIODIC%')),
		(select count(*) from changes where change_type in ('HOST_GONE','SERVICE_GONE') and at > now()-interval '7 days'),
		(select count(*) from http_endpoints where state<>'INACTIVE' and tls is not null and (tls->>'days_left')::int < 30),
		(select count(*) from findings where active and status='open')`).Scan(&hosts, &svcs, &web, &flap, &periodic, &inactive7, &certs, &open)
	d.KPI["hosts"], d.KPI["services"], d.KPI["web"], d.KPI["flapping"], d.KPI["periodic"] = hosts, svcs, web, flap, periodic
	d.KPI["gone_7d"], d.KPI["certs_expiring"], d.KPI["findings_open"] = inactive7, certs, open
	// zmiany od ostatniego zakończonego przebiegu skanera
	var lastRun string
	a.DB.QueryRow(ctx, `select id from scan_runs where status='COMPLETED' and source='scanner' order by finished_at desc limit 1`).Scan(&lastRun)
	if lastRun != "" {
		rows, _ := a.DB.Query(ctx, `select change_type, count(*) from changes where run_id=$1 group by change_type`, lastRun)
		for rows.Next() {
			var t string
			var n int
			rows.Scan(&t, &n)
			d.Delta[t] = n
		}
		rows.Close()
		d.Delta["_baseline"] = 0
		var pr int
		a.DB.QueryRow(ctx, `select coalesce(max(priority),0) from changes where run_id=$1`, lastRun).Scan(&pr)
		if pr == 0 && len(d.Delta) > 1 {
			d.Delta["_baseline"] = 1
		}
	}
	runs, _ := a.ListRuns(ctx, RunFilter{Limit: 20, Source: "scanner"})
	for _, r := range runs {
		if r.Status == "RUNNING" || strings.HasPrefix(r.Status, "PAUSED") || (r.FinishedAt != nil && time.Since(*r.FinishedAt) < 30*time.Minute) {
			full, err := a.GetRun(ctx, r.ID)
			if err == nil {
				d.Runs = append(d.Runs, full)
			}
		}
		if len(d.Runs) >= 5 {
			break
		}
	}
	// kolejka „do przejrzenia”: niepotwierdzone zmiany + encje z wysoką oceną i otwartymi znaleziskami
	crow, _ := a.DB.Query(ctx, `select c.id, c.entity_key, coalesce(host(c.host_ip),''), c.change_type, c.summary, c.priority, c.at from changes c
		where c.acknowledged_at is null and c.priority >= 10 and c.at > now()-interval '14 days' order by c.priority desc, c.at desc limit 40`)
	for crow.Next() {
		var q QueueItem
		crow.Scan(&q.ChangeID, &q.Key, &q.IP, &q.Type, &q.Title, &q.Priority, &q.At)
		q.Kind = "change"
		q.Reason = changeLabel(q.Type)
		d.Queue = append(d.Queue, q)
	}
	crow.Close()
	erow, _ := a.DB.Query(ctx, `select x.key, x.ip, x.title, x.score, x.br, x.last_seen from (
		select host(h.ip)||'/tcp/'||s.port||'/'||e.scheme||'/'||coalesce(nullif(e.vhost,''),'-') as key, host(h.ip) as ip,
		  coalesce(nullif(e.title,''), e.url) as title, e.score, e.score_breakdown as br, e.last_seen
		  from http_endpoints e join services s on s.id=e.service_id join hosts h on h.id=e.host_id where e.state<>'INACTIVE' and e.score>=30
		union all select host(h.ip)||'/'||s.proto||'/'||s.port, host(h.ip), trim(s.service_name||' '||s.product||' '||s.version), s.score, s.score_breakdown, s.last_seen
		  from services s join hosts h on h.id=s.host_id where s.state<>'INACTIVE' and s.score>=30
		) x where exists(select 1 from findings f where f.entity_key=x.key and f.active and f.status='open') or x.score>=40
		order by x.score desc limit 40`)
	for erow.Next() {
		var q QueueItem
		var br []byte
		erow.Scan(&q.Key, &q.IP, &q.Title, &q.Priority, &br, &q.At)
		q.Kind = "entity"
		q.Breakdown = br
		var items []ScoreItem
		json.Unmarshal(br, &items)
		var parts []string
		for _, it := range items {
			if it.Points > 0 {
				parts = append(parts, fmt.Sprintf("+%d %s", it.Points, it.Label))
			}
			if len(parts) == 3 {
				break
			}
		}
		q.Reason = strings.Join(parts, ", ")
		d.Queue = append(d.Queue, q)
	}
	erow.Close()
	sort.SliceStable(d.Queue, func(i, j int) bool { return d.Queue[i].Priority > d.Queue[j].Priority })
	if len(d.Queue) > 30 {
		d.Queue = d.Queue[:30]
	}
	trow, _ := a.DB.Query(ctx, `select r.id, coalesce(g.name,''), r.finished_at, r.stats, r.mode from scan_runs r left join target_groups g on g.id=r.group_id
		where r.status='COMPLETED' and r.source='scanner' order by r.finished_at desc limit 20`)
	for trow.Next() {
		var id, g, mode string
		var fin *time.Time
		var st []byte
		trow.Scan(&id, &g, &fin, &st, &mode)
		var m map[string]any
		json.Unmarshal(st, &m)
		d.Trend = append(d.Trend, map[string]any{"run_id": id, "group": g, "finished_at": fin, "stats": m, "mode": mode})
	}
	trow.Close()
	for i, j := 0, len(d.Trend)-1; i < j; i, j = i+1, j-1 {
		d.Trend[i], d.Trend[j] = d.Trend[j], d.Trend[i]
	}
	d.Clusters, _ = a.ListClusters(ctx, 6)
	frow, _ := a.DB.Query(ctx, `select category, count(*) from findings where active and status='open' group by category`)
	for frow.Next() {
		var c string
		var n int
		frow.Scan(&c, &n)
		d.Findings[c] = n
	}
	frow.Close()
	d.Workers, _ = a.ListWorkers(ctx)
	cfg := a.DDConfig(ctx)
	d.DD = map[string]any{"configured": cfg.URL != "" && cfg.HasToken, "last_sync": cfg.LastSync, "last_error": cfg.LastError, "url": cfg.URL}
	d.Kill = a.KillSwitch(ctx)
	return d, nil
}

var changeLabels = map[string]string{
	"HOST_NEW": "nowy host", "HOST_GONE": "host zniknął", "HOST_RETURNED": "host wrócił", "SERVICE_NEW": "nowa usługa", "SERVICE_GONE": "usługa zniknęła",
	"SERVICE_RETURNED": "usługa wróciła", "SERVICE_CHANGED": "zmiana usługi", "HTTP_CHANGED": "zmiana strony WWW", "TLS_CHANGED": "zmiana certyfikatu",
	"IDENTITY_CHANGED": "inne urządzenie pod adresem", "SIGNATURE_MATCH_NEW": "nowe dopasowanie sygnatury", "SIGNATURE_MATCH_GONE": "sygnatura przestała pasować",
	"STATE_FLAPPING": "niestabilna dostępność", "STATE_PERIODIC": "dostępność zależna od pory dnia", "DOMAIN_OUT_OF_SCOPE": "domena poza zakresem",
}

func changeLabel(t string) string {
	if l := changeLabels[t]; l != "" {
		return l
	}
	return strings.ToLower(t)
}

// ---------------- klastry podobnych usług (sekcja 10.2) ----------------

type Cluster struct {
	Key      string          `json:"key"`
	Count    int             `json:"count"`
	Title    string          `json:"title"`
	Server   string          `json:"server"`
	Favicon  string          `json:"favicon"`
	Techs    []string        `json:"techs"`
	MaxScore int             `json:"max_score"`
	Members  []ClusterMember `json:"members,omitempty"`
}

type ClusterMember struct {
	Key      string   `json:"key"`
	IP       string   `json:"ip"`
	URL      string   `json:"url"`
	Versions []string `json:"versions"`
	Outlier  bool     `json:"outlier"`
	Score    int      `json:"score"`
}

func (a *App) ListClusters(ctx context.Context, limit int) ([]Cluster, error) {
	rows, err := a.DB.Query(ctx, `select e.cluster_key, count(*), max(e.title), max(e.server), max(e.favicon_mmh3), max(e.score),
		(select coalesce(array_agg(distinct t.name),'{}') from technologies t join http_endpoints e2 on e2.id=t.entity_id where e2.cluster_key=e.cluster_key and t.active and t.confidence>=0.5)
		from http_endpoints e where e.state<>'INACTIVE' and e.cluster_key<>'' group by e.cluster_key having count(*)>1 order by count(*) desc, max(e.score) desc limit $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Cluster, error) {
		var c Cluster
		err := r.Scan(&c.Key, &c.Count, &c.Title, &c.Server, &c.Favicon, &c.MaxScore, &c.Techs)
		return c, err
	})
}

func (a *App) GetCluster(ctx context.Context, key string) (*Cluster, error) {
	cl, err := a.ListClusters(ctx, 1000)
	if err != nil {
		return nil, err
	}
	var c *Cluster
	for i := range cl {
		if cl[i].Key == key {
			c = &cl[i]
		}
	}
	if c == nil {
		return nil, ErrNotFound
	}
	rows, err := a.DB.Query(ctx, `select host(h.ip)||'/tcp/'||s.port||'/'||e.scheme||'/'||coalesce(nullif(e.vhost,''),'-'), host(h.ip), e.url, e.score,
		(select coalesce(array_agg(t.name||' '||t.version order by t.name),'{}') from technologies t where t.entity_type='http' and t.entity_id=e.id and t.active and t.version<>'')
		from http_endpoints e join services s on s.id=e.service_id join hosts h on h.id=e.host_id where e.cluster_key=$1 and e.state<>'INACTIVE' order by h.ip`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	freq := map[string]int{}
	for rows.Next() {
		var m ClusterMember
		rows.Scan(&m.Key, &m.IP, &m.URL, &m.Score, &m.Versions)
		freq[strings.Join(m.Versions, ",")]++
		c.Members = append(c.Members, m)
	}
	mode, best := "", 0
	for k, n := range freq {
		if n > best {
			mode, best = k, n
		}
	}
	for i := range c.Members {
		c.Members[i].Outlier = len(freq) > 1 && strings.Join(c.Members[i].Versions, ",") != mode
	}
	return c, nil
}

// ---------------- audyt ----------------

type AuditRow struct {
	ID      int64           `json:"id"`
	At      time.Time       `json:"at"`
	Actor   string          `json:"actor"`
	Action  string          `json:"action"`
	Object  string          `json:"object"`
	ObjID   string          `json:"object_id"`
	Details json.RawMessage `json:"details"`
	IP      string          `json:"ip"`
}

func (a *App) ListAudit(ctx context.Context, q string, limit, offset int) ([]AuditRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := a.DB.Query(ctx, `select id, at, actor, action, object_type, object_id, details, ip from audit_log
		where ($1='' or actor ilike '%'||$1||'%' or action ilike '%'||$1||'%' or object_id ilike '%'||$1||'%') order by id desc limit $2 offset $3`, q, limit, offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AuditRow])
}

func keyIP(key string) string { return strings.SplitN(key, "/", 2)[0] }

var _ = obs.Schema
