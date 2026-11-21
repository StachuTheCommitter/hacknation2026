// Package obs: kanoniczny schemat obserwacji (asi.observation/v1), walidacja i pola stabilne.
// Ten sam schemat produkuje worker, formularz, import CSV/JSON i adaptery.
package obs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const Schema = "asi.observation/v1"

type Observation struct {
	Schema     string         `json:"schema,omitempty"`
	ObservedAt time.Time      `json:"observed_at"`
	Source     string         `json:"source,omitempty"`
	Host       Host           `json:"host"`
	Services   []Service      `json:"services,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	Note       string         `json:"note,omitempty"`
	Retry      bool           `json:"recovered_on_retry,omitempty"`
	Light      bool           `json:"light,omitempty"` // tryb szybki: tylko lekki pomiar
	Extra      map[string]any `json:"extra,omitempty"`
}

type Host struct {
	IP           string     `json:"ip"`
	Up           *bool      `json:"up,omitempty"`
	UpReason     string     `json:"up_reason,omitempty"`
	Hostnames    []Hostname `json:"hostnames,omitempty"`
	SSHHostkeyFP string     `json:"ssh_hostkey_fp,omitempty"`
	OS           string     `json:"os,omitempty"`
	DeviceType   string     `json:"devicetype,omitempty"`
	MAC          string     `json:"mac,omitempty"`
}

func (h Host) IsUp() bool { return h.Up == nil || *h.Up }

type Hostname struct {
	Name   string `json:"name"`
	Source string `json:"source,omitempty"`
}

// UnmarshalJSON pozwala podać nazwy jako ["a","b"] albo [{"name":"a"}].
func (h *Hostname) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		h.Name = s
		return nil
	}
	type alias Hostname
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*h = Hostname(a)
	return nil
}

type NmapInfo struct {
	Method string `json:"method,omitempty"`
	Conf   int    `json:"conf,omitempty"`
}

type Service struct {
	Proto      string            `json:"proto"`
	Port       int               `json:"port"`
	State      string            `json:"state,omitempty"`
	Service    string            `json:"service,omitempty"`
	Product    string            `json:"product,omitempty"`
	Version    string            `json:"version,omitempty"`
	ExtraInfo  string            `json:"extrainfo,omitempty"`
	DeviceType string            `json:"devicetype,omitempty"`
	OSType     string            `json:"ostype,omitempty"`
	Tunnel     string            `json:"tunnel,omitempty"`
	CPE        []string          `json:"cpe,omitempty"`
	Banner     string            `json:"banner,omitempty"`
	Nmap       *NmapInfo         `json:"nmap,omitempty"`
	TLS        *TLS              `json:"tls,omitempty"`
	HTTP       []HTTP            `json:"http,omitempty"`
	Scripts    map[string]string `json:"scripts,omitempty"`
	Tech       []Tech            `json:"tech,omitempty"`
	Light      bool              `json:"light,omitempty"` // tryb szybki: bez nmap -sV, pola usługi przenoszone z poprzedniego pomiaru
}

func (s Service) IsOpen() bool { return s.State == "" || s.State == "open" }

type TLS struct {
	Version       string    `json:"version,omitempty"`
	Cipher        string    `json:"cipher,omitempty"`
	SubjectCN     string    `json:"subject_cn,omitempty"`
	SAN           []string  `json:"san,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	NotAfter      time.Time `json:"not_after,omitempty"`
	SelfSigned    bool      `json:"self_signed,omitempty"`
	Trusted       bool      `json:"trusted,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	KeyBits       int       `json:"key_bits,omitempty"`
	KeyType       string    `json:"key_type,omitempty"`
	HostnameMatch *bool     `json:"hostname_match,omitempty"`
}

func (t *TLS) Expired(now time.Time) bool {
	return t != nil && !t.NotAfter.IsZero() && now.After(t.NotAfter)
}

func (t *TLS) DaysLeft(now time.Time) int {
	if t == nil || t.NotAfter.IsZero() {
		return 0
	}
	return int(t.NotAfter.Sub(now).Hours() / 24)
}

type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httponly"`
	SameSite string `json:"samesite,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
}

type Redirect struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

type Tech struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Category   string   `json:"category,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Confidence float64  `json:"confidence,omitempty"`
	Source     string   `json:"source,omitempty"`
}

// Headers akceptuje {"A":"x"} oraz {"A":["x","y"]}; trzyma kanoniczne nazwy.
type Headers map[string][]string

func (h *Headers) UnmarshalJSON(b []byte) error {
	var multi map[string][]string
	if err := json.Unmarshal(b, &multi); err == nil {
		*h = canon(multi)
		return nil
	}
	var single map[string]string
	if err := json.Unmarshal(b, &single); err != nil {
		return err
	}
	m := map[string][]string{}
	for k, v := range single {
		m[k] = []string{v}
	}
	*h = canon(m)
	return nil
}

func canon(m map[string][]string) Headers {
	out := Headers{}
	for k, v := range m {
		ck := http.CanonicalHeaderKey(strings.ReplaceAll(k, "_", "-"))
		out[ck] = append(out[ck], v...)
	}
	return out
}

func (h Headers) Get(k string) string {
	v := h[http.CanonicalHeaderKey(k)]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func (h Headers) Names() []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, strings.ToLower(k))
	}
	sort.Strings(out)
	return out
}

type PathResult struct {
	Path         string  `json:"path"`
	Status       int     `json:"status"`
	Length       int     `json:"length"`
	Title        string  `json:"title,omitempty"`
	Soft404      bool    `json:"soft404,omitempty"`
	Headers      Headers `json:"headers,omitempty"`
	Body         string  `json:"body,omitempty"`
	PatternMatch *bool   `json:"pattern_match,omitempty"`
	Location     string  `json:"location,omitempty"`
}

type Baseline struct {
	Status int    `json:"status"`
	Length int    `json:"length"`
	Title  string `json:"title,omitempty"`
	Hash   string `json:"hash,omitempty"`
}

type HTTP struct {
	Vhost          string       `json:"vhost,omitempty"`
	Scheme         string       `json:"scheme"`
	URL            string       `json:"url,omitempty"`
	Status         int          `json:"status"`
	Title          string       `json:"title,omitempty"`
	Headers        Headers      `json:"headers,omitempty"`
	Cookies        []Cookie     `json:"cookies,omitempty"`
	RedirectChain  []Redirect   `json:"redirect_chain,omitempty"`
	FinalURL       string       `json:"final_url,omitempty"`
	FaviconMMH3    string       `json:"favicon_mmh3,omitempty"`
	BodySHA256     string       `json:"body_sha256,omitempty"`
	BodySnippet    string       `json:"body_snippet,omitempty"`
	Body           string       `json:"body,omitempty"` // tylko w transporcie z workera (do sygnatur), nie zapisywane jawnie
	Tech           []Tech       `json:"tech,omitempty"`
	Paths          []PathResult `json:"paths,omitempty"`
	Soft404        *Baseline    `json:"soft404_baseline,omitempty"`
	CleartextLogin bool         `json:"cleartext_login,omitempty"`
	ResponseMs     int          `json:"response_ms,omitempty"`
	TLS            *TLS         `json:"tls,omitempty"`
	Light          bool         `json:"light,omitempty"` // tryb szybki: ścieżki i favicona pominięte
}

// File to plik importu / eksportu.
type File struct {
	Schema       string        `json:"schema"`
	GeneratedAt  time.Time     `json:"generated_at,omitempty"`
	Run          *RunInfo      `json:"run,omitempty"`
	Observations []Observation `json:"observations"`
}

type RunInfo struct {
	ID        string    `json:"id,omitempty"`
	Group     string    `json:"group,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// ---------------- walidacja i normalizacja ----------------

type FieldError struct {
	Path string `json:"path"`
	Msg  string `json:"message"`
}

func (e FieldError) Error() string { return e.Path + ": " + e.Msg }

var protoOK = map[string]bool{"tcp": true, "udp": true}

// Normalize uzupełnia wartości domyślne i zwraca listę błędów walidacji.
func Normalize(o *Observation, prefix string) []FieldError {
	var errs []FieldError
	add := func(p, m string) { errs = append(errs, FieldError{prefix + p, m}) }
	if o.Schema != "" && o.Schema != Schema {
		add("schema", "nieobsługiwany schemat "+o.Schema)
	}
	o.Schema = Schema
	if o.ObservedAt.IsZero() {
		o.ObservedAt = time.Now().UTC()
	}
	a, err := netip.ParseAddr(strings.TrimSpace(o.Host.IP))
	if err != nil {
		add("host.ip", "niepoprawny adres IP")
	} else {
		o.Host.IP = a.Unmap().String()
	}
	for i := range o.Host.Hostnames {
		o.Host.Hostnames[i].Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o.Host.Hostnames[i].Name), "."))
		if o.Host.Hostnames[i].Source == "" {
			o.Host.Hostnames[i].Source = "manual"
		}
	}
	seen := map[string]bool{}
	for i := range o.Services {
		s := &o.Services[i]
		p := fmt.Sprintf("services[%d].", i)
		s.Proto = strings.ToLower(s.Proto)
		if s.Proto == "" {
			s.Proto = "tcp"
		}
		if !protoOK[s.Proto] {
			add(p+"proto", "dozwolone: tcp, udp")
		}
		if s.Port < 1 || s.Port > 65535 {
			add(p+"port", "musi być w zakresie 1..65535")
		}
		k := fmt.Sprintf("%s/%d", s.Proto, s.Port)
		if seen[k] {
			add(p+"port", "zduplikowana usługa "+k)
		}
		seen[k] = true
		if s.State == "" {
			s.State = "open"
		}
		if s.State != "open" && s.State != "closed" && s.State != "filtered" {
			add(p+"state", "dozwolone: open, closed, filtered")
		}
		for j := range s.HTTP {
			h := &s.HTTP[j]
			h.Scheme = strings.ToLower(h.Scheme)
			if h.Scheme == "" {
				h.Scheme = "http"
				if s.Tunnel == "ssl" || s.Port == 443 || s.Port == 8443 {
					h.Scheme = "https"
				}
			}
			if h.Scheme != "http" && h.Scheme != "https" {
				add(fmt.Sprintf("%shttp[%d].scheme", p, j), "dozwolone: http, https")
			}
			h.Vhost = strings.ToLower(strings.TrimSpace(h.Vhost))
			if h.URL == "" {
				host := o.Host.IP
				if h.Vhost != "" {
					host = h.Vhost
				}
				h.URL = fmt.Sprintf("%s://%s:%d/", h.Scheme, host, s.Port)
			}
		}
	}
	return errs
}

// ---------------- klucze naturalne ----------------

func HostKey(ip string) string { return ip }

func ServiceKey(ip, proto string, port int) string { return fmt.Sprintf("%s/%s/%d", ip, proto, port) }

func HTTPKey(ip string, port int, scheme, vhost string) string {
	if vhost == "" {
		vhost = "-"
	}
	return fmt.Sprintf("%s/tcp/%d/%s/%s", ip, port, scheme, vhost)
}

// ---------------- pola stabilne (sekcja 6.3) ----------------

var (
	digitsRe = regexp.MustCompile(`\d+`)
	spaceRe  = regexp.MustCompile(`\s+`)
)

// NormTitle usuwa szum z tytułu (białe znaki, wielkość liter).
func NormTitle(t string) string {
	return strings.TrimSpace(spaceRe.ReplaceAllString(strings.ToLower(t), " "))
}

// NormBanner usuwa liczby i daty z banera.
func NormBanner(b string) string {
	b = digitsRe.ReplaceAllString(b, "#")
	return strings.TrimSpace(spaceRe.ReplaceAllString(b, " "))
}

func StableURL(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

// HostStable – pola stabilne hosta.
func HostStable(h Host, openPorts []string) map[string]any {
	names := make([]string, 0, len(h.Hostnames))
	for _, n := range h.Hostnames {
		names = append(names, n.Name)
	}
	sort.Strings(names)
	sort.Strings(openPorts)
	_ = names // nazwy hostów śledzone osobno (host_hostnames) – źródła PTR/DNS/SAN różnią się między pomiarami
	return map[string]any{
		"up": h.IsUp(), "open_ports": openPorts, "ssh_hostkey": h.SSHHostkeyFP,
	}
}

// ServiceStable – pola stabilne usługi.
func ServiceStable(s Service) map[string]any {
	cpe := append([]string(nil), s.CPE...)
	sort.Strings(cpe)
	m := map[string]any{
		"state": s.State, "service": s.Service, "product": s.Product, "version": s.Version,
		"extrainfo": s.ExtraInfo, "tunnel": s.Tunnel, "cpe": cpe, "banner": NormBanner(s.Banner),
	}
	if s.TLS != nil {
		m["tls_sha256"] = s.TLS.SHA256
	}
	return m
}

// HTTPStable – pola stabilne endpointu HTTP.
func HTTPStable(h HTTP, techs []string) map[string]any {
	var cookies []string
	for _, c := range h.Cookies {
		cookies = append(cookies, fmt.Sprintf("%s;s=%t;h=%t;ss=%s", c.Name, c.Secure, c.HTTPOnly, strings.ToLower(c.SameSite)))
	}
	sort.Strings(cookies)
	cookies = dedupe(cookies)
	sort.Strings(techs)
	m := map[string]any{
		"status": h.Status, "title": NormTitle(h.Title), "server": h.Headers.Get("Server"),
		"powered_by": h.Headers.Get("X-Powered-By"), "header_names": stableHeaderNames(h.Headers),
		"cookies": cookies, "final_url": StableURL(h.FinalURL), "favicon": h.FaviconMMH3, "tech": techs,
	}
	if h.TLS != nil {
		m["tls_sha256"] = h.TLS.SHA256
		m["tls_cn"] = h.TLS.SubjectCN
	}
	return m
}

// zmienne nagłówki, które nie wchodzą do porównań
var volatileHeaders = map[string]bool{
	"date": true, "expires": true, "age": true, "etag": true, "last-modified": true, "x-request-id": true,
	"cf-ray": true, "set-cookie": true, "content-length": true, "x-runtime": true, "x-amz-request-id": true,
	"report-to": true, "nel": true, "x-debug-token-link": true, "keep-alive": true, "connection": true,
}

func stableHeaderNames(h Headers) []string {
	var out []string
	for _, n := range h.Names() {
		if !volatileHeaders[n] {
			out = append(out, n)
		}
	}
	return out
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Canonical zwraca kanoniczny JSON mapy (klucze posortowane przez encoding/json).
func Canonical(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}
