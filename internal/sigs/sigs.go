// Package sigs: silnik bezpiecznych sygnatur detekcyjnych (sekcja 9 dokumentacji).
// Sygnatury pasywne działają na zapisanych obserwacjach, aktywne dodatkowo deklarują
// jedno lub więcej żądań GET/HEAD wykonywanych przez prober workera.
package sigs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Signature struct {
	ID          string      `yaml:"id" json:"id"`
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Author      string      `yaml:"author,omitempty" json:"author,omitempty"`
	Version     int         `yaml:"version,omitempty" json:"version,omitempty"`
	Enabled     *bool       `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Scope       string      `yaml:"scope" json:"scope"`
	Categories  []string    `yaml:"categories,omitempty" json:"categories,omitempty"`
	Severity    string      `yaml:"severity,omitempty" json:"severity,omitempty"`
	Priority    int         `yaml:"priority,omitempty" json:"priority,omitempty"`
	Confidence  float64     `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Tags        []string    `yaml:"tags,omitempty" json:"tags,omitempty"`
	Technology  *TechSpec   `yaml:"technology,omitempty" json:"technology,omitempty"`
	Request     *Request    `yaml:"request,omitempty" json:"request,omitempty"`
	Requests    []Request   `yaml:"requests,omitempty" json:"requests,omitempty"`
	Match       Cond        `yaml:"match" json:"match"`
	Export      *ExportSpec `yaml:"export,omitempty" json:"export,omitempty"`

	compiled bool
}

type TechSpec struct {
	Name        string   `yaml:"name" json:"name"`
	Category    string   `yaml:"category,omitempty" json:"category,omitempty"`
	VersionFrom *Extract `yaml:"version_from,omitempty" json:"version_from,omitempty"`
}

type Extract struct {
	Part  string `yaml:"part" json:"part"`
	Name  string `yaml:"name,omitempty" json:"name,omitempty"`
	Regex string `yaml:"regex" json:"regex"`
	re    *regexp.Regexp
}

type Request struct {
	Method          string            `yaml:"method,omitempty" json:"method,omitempty"`
	Path            string            `yaml:"path" json:"path"`
	FollowRedirects bool              `yaml:"follow_redirects,omitempty" json:"follow_redirects,omitempty"`
	Headers         map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body            string            `yaml:"body,omitempty" json:"body,omitempty"`
}

type ExportSpec struct {
	DefectDojo bool   `yaml:"defectdojo" json:"defectdojo"`
	Title      string `yaml:"title,omitempty" json:"title,omitempty"`
}

// Cond to warunek: grupa (all/any/not) albo pojedyncza reguła (part/op/value).
type Cond struct {
	All   []Cond `yaml:"all,omitempty" json:"all,omitempty"`
	Any   []Cond `yaml:"any,omitempty" json:"any,omitempty"`
	Not   *Cond  `yaml:"not,omitempty" json:"not,omitempty"`
	Part  string `yaml:"part,omitempty" json:"part,omitempty"`
	Name  string `yaml:"name,omitempty" json:"name,omitempty"`
	Attr  string `yaml:"attr,omitempty" json:"attr,omitempty"`
	Op    string `yaml:"op,omitempty" json:"op,omitempty"`
	Value any    `yaml:"value,omitempty" json:"value,omitempty"`

	vals []string
	re   *regexp.Regexp
}

func (s *Signature) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// Active – sygnatura wymaga żądania wykonanego przez prober.
func (s *Signature) Active() bool { return s.Request != nil || len(s.Requests) > 0 }

// AllRequests zwraca listę żądań (request + requests).
func (s *Signature) AllRequests() []Request {
	var out []Request
	if s.Request != nil {
		out = append(out, *s.Request)
	}
	return append(out, s.Requests...)
}

// ---------------- części i operatory ----------------

var partsByScope = map[string]map[string]bool{
	"http": set("status", "title", "header", "header_names", "cookie_name", "cookie", "body", "body_hash",
		"favicon_mmh3", "final_url", "redirect_location", "redirect_chain", "tech", "tech_version",
		"tls_subject_cn", "tls_san", "tls_issuer", "tls_expired", "tls_days_left", "tls_self_signed", "tls_version",
		"vhost", "scheme", "port", "soft404", "path", "hostname", "cleartext_login", "length", "ip", "headers_raw", "pattern_match", "cookie_insecure_session", "response_ms"),
	"service": set("port", "proto", "service", "product", "version", "extrainfo", "cpe", "banner", "devicetype",
		"tunnel", "tls_subject_cn", "tls_san", "tls_issuer", "tls_expired", "tls_days_left", "tls_self_signed",
		"tls_version", "hostname", "ip"),
	"host": set("hostname", "ptr", "open_ports", "os", "labels", "ip", "devicetype"),
}

var ops = set("equals", "iequals", "contains", "icontains", "regex", "in", "exists", "not_exists",
	"lt", "gt", "between", "version_lt", "version_gte", "starts_with")

func set(v ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range v {
		m[x] = true
	}
	return m
}

// Parts zwraca dozwolone części dla zakresu (do podpowiedzi w edytorze).
func Parts(scope string) []string {
	var out []string
	for p := range partsByScope[scope] {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func Ops() []string {
	var out []string
	for o := range ops {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// ---------------- parsowanie i walidacja ----------------

// ParseAll czyta jeden lub wiele dokumentów YAML (oddzielonych ---) albo JSON.
func ParseAll(src []byte) ([]*Signature, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var out []*Signature
	for {
		var s Signature
		err := dec.Decode(&s)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("YAML: %w", err)
		}
		if s.ID == "" && s.Name == "" && s.Match.empty() {
			continue
		}
		out = append(out, &s)
	}
	if len(out) == 0 {
		return nil, errors.New("brak sygnatur w pliku")
	}
	return out, nil
}

func (c *Cond) empty() bool {
	return len(c.All) == 0 && len(c.Any) == 0 && c.Not == nil && c.Part == ""
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,79}$`)
var payloadChars = []string{"'", "\"", "<", ">", "`", "${", ";", "|", "%00", "\\", "{{", "}}"}

// Validate sprawdza sygnaturę i kompiluje wyrażenia. Zwraca listę czytelnych błędów.
func (s *Signature) Validate() []string {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if !idRe.MatchString(s.ID) {
		add("id: wymagane, tylko [a-z0-9-], 2–80 znaków")
	}
	if strings.TrimSpace(s.Name) == "" {
		add("name: wymagane")
	}
	if s.Scope == "" {
		s.Scope = "http"
	}
	if partsByScope[s.Scope] == nil {
		add("scope: dozwolone http, service, host")
	}
	if s.Severity == "" {
		s.Severity = "info"
	}
	if !set("info", "low", "medium", "high")[s.Severity] {
		add("severity: dozwolone info, low, medium, high")
	}
	if s.Confidence == 0 {
		s.Confidence = 0.8
	}
	if s.Confidence < 0 || s.Confidence > 1 {
		add("confidence: musi być w zakresie 0..1")
	}
	if s.Priority < 0 || s.Priority > 100 {
		add("priority: musi być w zakresie 0..100")
	}
	reqs := s.AllRequests()
	if len(reqs) > 3 {
		add("maksymalnie 3 żądania na sygnaturę")
	}
	if len(reqs) > 0 && s.Scope != "http" {
		add("request: żądania są dozwolone tylko dla scope: http")
	}
	for i, r := range reqs {
		p := fmt.Sprintf("request[%d]", i)
		m := strings.ToUpper(r.Method)
		if m == "" {
			m = "GET"
		}
		if m != "GET" && m != "HEAD" {
			add("%s.method: dozwolone wyłącznie GET i HEAD (bezpieczna detekcja)", p)
		}
		if r.Body != "" {
			add("%s.body: żądania nie mogą mieć treści", p)
		}
		for h := range r.Headers {
			lh := strings.ToLower(h)
			if lh != "accept" && lh != "accept-language" {
				add("%s.headers: dozwolone tylko Accept i Accept-Language (bez uwierzytelniania i cookies)", p)
			}
		}
		if !strings.HasPrefix(r.Path, "/") || strings.HasPrefix(r.Path, "//") {
			add("%s.path: musi zaczynać się od / (bez schematu i hosta)", p)
		}
		if strings.Contains(r.Path, "..") || strings.Contains(r.Path, "://") || len(r.Path) > 512 {
			add("%s.path: niedozwolona ścieżka (.., schemat lub >512 znaków)", p)
		}
		for _, ch := range payloadChars {
			if strings.Contains(r.Path, ch) {
				add("%s.path: zawiera znak typowy dla payloadu (%s)", p, ch)
				break
			}
		}
	}
	if s.Match.empty() {
		add("match: wymagany co najmniej jeden warunek")
	} else {
		s.Match.validate("match", s.Scope, &errs)
	}
	if s.Technology != nil {
		if s.Technology.Name == "" {
			add("technology.name: wymagane")
		}
		if vf := s.Technology.VersionFrom; vf != nil {
			re, err := compileRe(vf.Regex)
			if err != nil {
				add("technology.version_from.regex: %v", err)
			} else if re.NumSubexp() < 1 {
				add("technology.version_from.regex: potrzebna grupa przechwytująca ( )")
			}
			vf.re = re
		}
	}
	if len(errs) == 0 {
		s.compiled = true
	}
	return errs
}

func compileRe(src string) (*regexp.Regexp, error) {
	if len(src) > 2000 {
		return nil, errors.New("wyrażenie dłuższe niż 2000 znaków")
	}
	return regexp.Compile(src) // RE2: liniowy czas, brak ReDoS
}

func (c *Cond) validate(path, scope string, errs *[]string) {
	add := func(f string, a ...any) { *errs = append(*errs, fmt.Sprintf(f, a...)) }
	groups := 0
	if len(c.All) > 0 {
		groups++
	}
	if len(c.Any) > 0 {
		groups++
	}
	if c.Not != nil {
		groups++
	}
	if groups > 0 && c.Part != "" {
		add("%s: warunek nie może jednocześnie mieć part i all/any/not", path)
		return
	}
	for i := range c.All {
		c.All[i].validate(fmt.Sprintf("%s.all[%d]", path, i), scope, errs)
	}
	for i := range c.Any {
		c.Any[i].validate(fmt.Sprintf("%s.any[%d]", path, i), scope, errs)
	}
	if c.Not != nil {
		c.Not.validate(path+".not", scope, errs)
	}
	if groups > 0 {
		return
	}
	if !partsByScope[scope][c.Part] {
		add("%s.part: nieznana część %q dla scope %s", path, c.Part, scope)
	}
	if c.Op == "" {
		c.Op = "equals"
	}
	if !ops[c.Op] {
		add("%s.op: nieznany operator %q", path, c.Op)
	}
	if (c.Part == "header" || c.Part == "cookie") && c.Name == "" && c.Op != "exists" && c.Op != "not_exists" {
		add("%s.name: wymagane dla części %s", path, c.Part)
	}
	c.vals = toStrings(c.Value)
	if c.Op != "exists" && c.Op != "not_exists" && len(c.vals) == 0 {
		add("%s.value: wymagana wartość", path)
	}
	if len(c.vals) == 0 {
		return
	}
	switch c.Op {
	case "regex":
		re, err := compileRe(c.vals[0])
		if err != nil {
			add("%s.value: niepoprawne wyrażenie regularne: %v", path, err)
		}
		c.re = re
	case "between":
		if len(c.vals) != 2 {
			add("%s.value: between wymaga listy [min, max]", path)
		}
	case "lt", "gt":
		if _, err := strconv.ParseFloat(firstOr(c.vals), 64); err != nil {
			add("%s.value: wymagana liczba", path)
		}
	}
}

func firstOr(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func toStrings(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case []string:
		return x
	default:
		return []string{fmt.Sprint(x)}
	}
}

// ---------------- ewaluacja ----------------

// Subject dostarcza wartości części dla jednej encji/odpowiedzi.
type Subject interface {
	Values(part, name, attr string) []string
}

// MapSubject – prosta implementacja: klucz "part" lub "part:name" (name małymi literami).
type MapSubject map[string][]string

func (m MapSubject) Values(part, name, attr string) []string {
	k := part
	if name != "" {
		k += ":" + strings.ToLower(name)
	}
	if attr != "" {
		k += ":" + strings.ToLower(attr)
	}
	return m[k]
}

func (m MapSubject) Add(key string, vals ...string) {
	for _, v := range vals {
		m[key] = append(m[key], v)
	}
}

// Result to wynik dopasowania.
type Result struct {
	Matched  bool     `json:"matched"`
	Evidence []string `json:"evidence,omitempty"`
	Version  string   `json:"version,omitempty"`
	Trace    []Trace  `json:"trace,omitempty"`
}

// Trace – krok ewaluacji (do testowania sygnatur w edytorze).
type Trace struct {
	Rule   string   `json:"rule"`
	OK     bool     `json:"ok"`
	Values []string `json:"values,omitempty"`
}

// Eval ocenia sygnaturę. Gdy trace=true, zwraca też ślad każdej reguły.
func (s *Signature) Eval(sub Subject, trace bool) Result {
	if !s.compiled {
		if errs := s.Validate(); len(errs) > 0 {
			return Result{}
		}
	}
	var r Result
	r.Matched = s.Match.eval(sub, &r, trace)
	if !r.Matched {
		r.Evidence = nil
		return r
	}
	if s.Technology != nil && s.Technology.VersionFrom != nil && s.Technology.VersionFrom.re != nil {
		vf := s.Technology.VersionFrom
		for _, v := range sub.Values(vf.Part, vf.Name, "") {
			if m := vf.re.FindStringSubmatch(v); len(m) > 1 {
				r.Version = m[1]
				break
			}
		}
	}
	sort.Strings(r.Evidence)
	return r
}

func (c *Cond) desc() string {
	p := c.Part
	if c.Name != "" {
		p += "[" + c.Name + "]"
	}
	if c.Attr != "" {
		p += "." + c.Attr
	}
	switch c.Op {
	case "exists", "not_exists":
		return p + " " + c.Op
	}
	return fmt.Sprintf("%s %s %s", p, c.Op, strings.Join(c.vals, "|"))
}

func (c *Cond) eval(sub Subject, r *Result, trace bool) bool {
	switch {
	case len(c.All) > 0:
		for i := range c.All {
			if !c.All[i].eval(sub, r, trace) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		ok := false
		for i := range c.Any {
			if c.Any[i].eval(sub, r, trace) {
				ok = true
				if !trace {
					break
				}
			}
		}
		return ok
	case c.Not != nil:
		var tmp Result
		return !c.Not.eval(sub, &tmp, false)
	}
	vals := sub.Values(c.Part, c.Name, c.Attr)
	ok := c.test(vals)
	if trace {
		shown := vals
		if len(shown) > 3 {
			shown = shown[:3]
		}
		for i := range shown {
			if len(shown[i]) > 120 {
				shown[i] = shown[i][:120] + "…"
			}
		}
		r.Trace = append(r.Trace, Trace{Rule: c.desc(), OK: ok, Values: shown})
	}
	if ok {
		r.Evidence = append(r.Evidence, c.desc())
	}
	return ok
}

func (c *Cond) test(vals []string) bool {
	switch c.Op {
	case "exists":
		return len(vals) > 0 && !(len(vals) == 1 && vals[0] == "")
	case "not_exists":
		return len(vals) == 0 || (len(vals) == 1 && vals[0] == "")
	}
	for _, v := range vals {
		if c.testOne(v) {
			return true
		}
	}
	return false
}

func (c *Cond) testOne(v string) bool {
	switch c.Op {
	case "equals":
		return v == c.vals[0]
	case "iequals":
		return strings.EqualFold(v, c.vals[0])
	case "contains":
		return strings.Contains(v, c.vals[0])
	case "icontains":
		return strings.Contains(strings.ToLower(v), strings.ToLower(c.vals[0]))
	case "starts_with":
		return strings.HasPrefix(v, c.vals[0])
	case "regex":
		return c.re != nil && c.re.MatchString(v)
	case "in":
		for _, w := range c.vals {
			if strings.EqualFold(v, w) {
				return true
			}
		}
		return false
	case "lt", "gt", "between":
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return false
		}
		a, _ := strconv.ParseFloat(c.vals[0], 64)
		switch c.Op {
		case "lt":
			return f < a
		case "gt":
			return f > a
		default:
			b, _ := strconv.ParseFloat(c.vals[1], 64)
			return f >= a && f <= b
		}
	case "version_lt":
		return v != "" && CompareVersions(v, c.vals[0]) < 0
	case "version_gte":
		return v != "" && CompareVersions(v, c.vals[0]) >= 0
	}
	return false
}

var numRe = regexp.MustCompile(`\d+`)

// CompareVersions porównuje wersje „luźno” (segmenty liczbowe): 5.6.40 < 7.4 < 8.1.2.
func CompareVersions(a, b string) int {
	as, bs := numRe.FindAllString(a, -1), numRe.FindAllString(b, -1)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
