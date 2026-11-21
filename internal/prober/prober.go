// Package prober: natywny fingerprinting HTTP/HTTPS (Etap 4).
// Ten sam silnik wykrywania technologii co httpx -td (wappalyzergo), ale z pełną kontrolą nad
// vhostami (Host + SNI), łańcuchem przekierowań, cookies, kontrolą soft-404 i ścieżkami sygnatur.
// Wyłącznie GET/HEAD, bez uwierzytelniania, z limitem tempa i jednym połączeniem na host naraz.
package prober

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/time/rate"

	"asi/internal/obs"
)

const maxBody = 256 * 1024

type Prober struct {
	UA        string
	Timeout   time.Duration
	Limiter   *rate.Limiter
	Paths     []string
	Sensitive map[string]*regexp.Regexp
	wapp      *wappalyzer.Wappalyze
}

var (
	wappOnce sync.Once
	wappInst *wappalyzer.Wappalyze
	wappErr  error
)

// New tworzy prober z limitem rps (wspólnym dla wszystkich hostów zadania).
func New(ua string, timeout time.Duration, rps int, paths []string, sensitive map[string]string) (*Prober, error) {
	wappOnce.Do(func() { wappInst, wappErr = wappalyzer.New() })
	if wappErr != nil {
		return nil, wappErr
	}
	if rps <= 0 {
		rps = 1
	}
	p := &Prober{UA: ua, Timeout: timeout, Limiter: rate.NewLimiter(rate.Limit(rps), max(1, rps/2)), Paths: paths, wapp: wappInst, Sensitive: map[string]*regexp.Regexp{}}
	for path, re := range sensitive {
		p.Sensitive[path] = regexp.MustCompile(re)
	}
	return p, nil
}

type target struct {
	ip     string
	port   int
	scheme string
	vhost  string
}

func (t target) host() string {
	if t.vhost != "" {
		return t.vhost
	}
	if strings.Contains(t.ip, ":") {
		return "[" + t.ip + "]"
	}
	return t.ip
}

func (t target) base() string {
	h := t.host()
	if (t.scheme == "http" && t.port != 80) || (t.scheme == "https" && t.port != 443) {
		h += ":" + strconv.Itoa(t.port)
	}
	return t.scheme + "://" + h
}

// client łączy się zawsze z ip:port (niezależnie od DNS), SNI = vhost.
func (p *Prober) client(t target) *http.Client {
	dialer := &net.Dialer{Timeout: p.Timeout}
	addr := net.JoinHostPort(t.ip, strconv.Itoa(t.port))
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: t.vhost, MinVersion: tls.VersionTLS10,
			CipherSuites: nil},
		TLSHandshakeTimeout:   p.Timeout,
		ResponseHeaderTimeout: p.Timeout,
		DisableKeepAlives:     true,
		MaxConnsPerHost:       1,
		ForceAttemptHTTP2:     false,
	}
	return &http.Client{Transport: tr, Timeout: p.Timeout * 2, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type response struct {
	status  int
	headers http.Header
	body    []byte
	tls     *tls.ConnectionState
	ms      int
	loc     string
}

func (p *Prober) get(ctx context.Context, cl *http.Client, t target, path string) (*response, error) {
	if err := p.Limiter.Wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.base()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Host = t.host()
	req.Header.Set("User-Agent", p.UA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return &response{status: resp.StatusCode, headers: resp.Header, body: body, tls: resp.TLS, ms: int(time.Since(start).Milliseconds()), loc: resp.Header.Get("Location")}, nil
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var spaceRe = regexp.MustCompile(`\s+`)
var iconRe = regexp.MustCompile(`(?is)<link[^>]+rel=["']?(?:shortcut )?icon["']?[^>]*>`)
var hrefRe = regexp.MustCompile(`(?is)href=["']?([^"' >]+)`)
var passwordRe = regexp.MustCompile(`(?i)<input[^>]+type=["']?password`)
var digitsRe = regexp.MustCompile(`[0-9]+`)

func title(b []byte) string {
	m := titleRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	t := html.UnescapeString(spaceRe.ReplaceAllString(string(m[1]), " "))
	t = strings.TrimSpace(t)
	if len(t) > 300 {
		t = t[:300]
	}
	return t
}

func normHash(b []byte) string {
	h := sha256.Sum256(digitsRe.ReplaceAll(b, nil))
	return hex.EncodeToString(h[:8])
}

// Detect ustala schemat portu. Dla typowych portów HTTPS najpierw TLS; dla pozostałych najpierw zwykłe HTTP –
// niektóre serwery (np. Traefik) przyjmują TLS na każdym porcie i zwracają wtedy domyślny certyfikat i 404.
func (p *Prober) Detect(ctx context.Context, ip string, port int, hintTLS bool) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	tryTLS := func() bool {
		d := &net.Dialer{Timeout: p.Timeout}
		c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	tryHTTP := func() (ok, wantsTLS bool) {
		d := &net.Dialer{Timeout: p.Timeout}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return false, false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(p.Timeout))
		fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", ip, p.UA)
		buf := make([]byte, 1024)
		n, _ := io.ReadAtLeast(c, buf, 12)
		resp := string(buf[:n])
		if !strings.HasPrefix(resp, "HTTP/") {
			return false, n > 0 && n < 8 // krótka binarna odpowiedź → zwykle alert TLS
		}
		l := strings.ToLower(resp)
		return true, strings.Contains(l, " 400 ") && (strings.Contains(l, "https") || strings.Contains(l, "tls") || strings.Contains(l, "ssl"))
	}
	if hintTLS || port == 443 || port == 8443 || port == 9443 {
		if tryTLS() {
			return "https"
		}
		return "http"
	}
	if ok, wantsTLS := tryHTTP(); ok && !wantsTLS {
		return "http"
	}
	if tryTLS() {
		return "https"
	}
	return "http"
}

// Probe zbiera informacje o jednym endpoincie (scheme + vhost).
func (p *Prober) Probe(ctx context.Context, ip string, port int, scheme, vhost string, light bool, extraPaths []string) (*obs.HTTP, error) {
	t := target{ip: ip, port: port, scheme: scheme, vhost: vhost}
	cl := p.client(t)
	r, err := p.get(ctx, cl, t, "/")
	if err != nil {
		return nil, err
	}
	h := &obs.HTTP{Scheme: scheme, Vhost: vhost, URL: t.base() + "/", ResponseMs: r.ms}
	// przekierowania (tylko w obrębie tego samego hosta)
	cur := t
	for i := 0; i < 5 && r.status >= 300 && r.status < 400 && r.loc != ""; i++ {
		h.RedirectChain = append(h.RedirectChain, obs.Redirect{URL: cur.base() + "/", Status: r.status, Location: r.loc})
		u, err := url.Parse(r.loc)
		if err != nil {
			break
		}
		next := cur
		if u.IsAbs() {
			hn := u.Hostname()
			if hn != t.ip && hn != t.vhost {
				break // poza endpointem – zapisujemy tylko Location
			}
			next.scheme = u.Scheme
			if ps := u.Port(); ps != "" {
				next.port, _ = strconv.Atoi(ps)
			} else if u.Scheme == "https" {
				next.port = 443
			} else {
				next.port = 80
			}
		}
		path := u.RequestURI()
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		ncl := p.client(next)
		nr, err := p.get(ctx, ncl, next, path)
		if err != nil {
			break
		}
		r, cur = nr, next
		h.FinalURL = next.base() + path
	}
	if h.FinalURL == "" {
		h.FinalURL = h.URL
	}
	h.Status = r.status
	h.Headers = obs.Headers(r.headers.Clone())
	h.Title = title(r.body)
	sum := sha256.Sum256(r.body)
	h.BodySHA256 = hex.EncodeToString(sum[:])
	h.Body = string(r.body)
	for _, c := range (&http.Response{Header: r.headers}).Cookies() {
		ss := ""
		switch c.SameSite {
		case http.SameSiteLaxMode:
			ss = "Lax"
		case http.SameSiteStrictMode:
			ss = "Strict"
		case http.SameSiteNoneMode:
			ss = "None"
		}
		h.Cookies = append(h.Cookies, obs.Cookie{Name: c.Name, Value: c.Value, Secure: c.Secure, HTTPOnly: c.HttpOnly, SameSite: ss, Domain: c.Domain, Path: c.Path})
	}
	if r.tls != nil {
		h.TLS = tlsInfo(r.tls, vhost, ip)
	} else if scheme == "https" {
		h.TLS = p.grabTLS(ip, port, vhost)
	}
	h.CleartextLogin = cur.scheme == "http" && passwordRe.Match(r.body)
	// technologie (wappalyzergo)
	for k, info := range p.wapp.FingerprintWithInfo(r.headers, r.body) {
		name, ver, _ := strings.Cut(k, ":")
		h.Tech = append(h.Tech, obs.Tech{Name: name, Version: ver, Categories: info.Categories, Source: "wappalyzer", Confidence: 0.7})
	}
	if light {
		h.Light = true
		return h, nil
	}
	// favicona
	h.FaviconMMH3 = p.favicon(ctx, cl, cur, r.body)
	// baza soft-404
	base, err := p.get(ctx, cl, cur, "/asi-nx-"+randToken())
	if err == nil {
		h.Soft404 = &obs.Baseline{Status: base.status, Length: len(base.body), Title: title(base.body), Hash: normHash(base.body)}
	}
	seen := map[string]bool{"/": true}
	for _, path := range append(append([]string{}, p.Paths...), extraPaths...) {
		if seen[path] || ctx.Err() != nil {
			continue
		}
		seen[path] = true
		pr, err := p.get(ctx, cl, cur, path)
		if err != nil {
			continue
		}
		res := obs.PathResult{Path: path, Status: pr.status, Length: len(pr.body), Title: title(pr.body), Location: pr.loc, Headers: obs.Headers(pr.headers.Clone())}
		res.Soft404 = isSoft404(h.Soft404, pr)
		if re, ok := p.Sensitive[path]; ok {
			m := pr.status == 200 && !res.Soft404 && re.Match(pr.body)
			res.PatternMatch = &m // treść ścieżek wrażliwych nie opuszcza workera
		} else if !res.Soft404 {
			b := pr.body
			if len(b) > 32*1024 {
				b = b[:32*1024]
			}
			res.Body = string(b)
		}
		h.Paths = append(h.Paths, res)
	}
	return h, nil
}

// isSoft404 – odpowiedź podobna do strony nieistniejącej (SPA, catch-all).
func isSoft404(b *obs.Baseline, r *response) bool {
	if b == nil {
		return false
	}
	if r.status == 404 || r.status == 410 {
		return true
	}
	if r.status != b.Status {
		return false
	}
	if normHash(r.body) == b.Hash {
		return true
	}
	l1, l2 := float64(len(r.body)), float64(b.Length)
	similarLen := l2 > 0 && l1/l2 > 0.9 && l1/l2 < 1.1
	return similarLen && title(r.body) == b.Title
}

func (p *Prober) favicon(ctx context.Context, cl *http.Client, t target, body []byte) string {
	path := "/favicon.ico"
	if tag := iconRe.Find(body); tag != nil {
		if m := hrefRe.FindSubmatch(tag); m != nil {
			href := html.UnescapeString(string(m[1]))
			if u, err := url.Parse(href); err == nil && !u.IsAbs() && !strings.HasPrefix(href, "data:") {
				if strings.HasPrefix(u.Path, "/") {
					path = u.Path
				} else {
					path = "/" + u.Path
				}
			}
		}
	}
	r, err := p.get(ctx, cl, t, path)
	if err != nil || r.status != 200 || len(r.body) == 0 || bytes.Contains(r.body[:min(len(r.body), 200)], []byte("<html")) {
		return ""
	}
	return strconv.Itoa(int(int32(murmur3(shodanBase64(r.body)))))
}

// shodanBase64 – base64 z łamaniem linii co 76 znaków (zgodnie z base64.encodebytes w Pythonie).
func shodanBase64(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out bytes.Buffer
	for i := 0; i < len(enc); i += 76 {
		out.WriteString(enc[i:min(i+76, len(enc))])
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// murmur3 – MurmurHash3 x86_32, seed 0.
func murmur3(data []byte) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
		h = h<<13 | h>>19
		h = h*5 + 0xe6546b64
	}
	tail := data[n*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

func randToken() string {
	b := make([]byte, 6)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}

func (p *Prober) grabTLS(ip string, port int, vhost string) *obs.TLS {
	d := &net.Dialer{Timeout: p.Timeout}
	c, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true, ServerName: vhost})
	if err != nil {
		return nil
	}
	defer c.Close()
	st := c.ConnectionState()
	return tlsInfo(&st, vhost, ip)
}

var tlsNames = map[uint16]string{tls.VersionTLS10: "TLS1.0", tls.VersionTLS11: "TLS1.1", tls.VersionTLS12: "TLS1.2", tls.VersionTLS13: "TLS1.3"}

func tlsInfo(st *tls.ConnectionState, vhost, ip string) *obs.TLS {
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	c := st.PeerCertificates[0]
	t := &obs.TLS{Version: tlsNames[st.Version], Cipher: tls.CipherSuiteName(st.CipherSuite), SubjectCN: c.Subject.CommonName, SAN: c.DNSNames,
		Issuer: issuerString(c), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC()}
	sum := sha256.Sum256(c.Raw)
	t.SHA256 = hex.EncodeToString(sum[:])
	switch k := c.PublicKey.(type) {
	case interface{ Size() int }:
		t.KeyBits = k.Size() * 8
		t.KeyType = "RSA"
	}
	if c.PublicKeyAlgorithm == x509.ECDSA {
		t.KeyType = "ECDSA"
	}
	t.SelfSigned = bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
	inter := x509.NewCertPool()
	for _, ic := range st.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	name := vhost
	if name == "" {
		name = ip
	}
	_, err := c.Verify(x509.VerifyOptions{Intermediates: inter, DNSName: name})
	t.Trusted = err == nil
	m := c.VerifyHostname(name) == nil
	t.HostnameMatch = &m
	return t
}

func issuerString(c *x509.Certificate) string {
	var parts []string
	if c.Issuer.CommonName != "" {
		parts = append(parts, "CN="+c.Issuer.CommonName)
	}
	for _, o := range c.Issuer.Organization {
		parts = append(parts, "O="+o)
	}
	if len(parts) == 0 {
		return c.Issuer.String()
	}
	return strings.Join(parts, ", ")
}

// NonHTTP – usługi rozpoznane przez nmap jako nie-HTTP (nie sondujemy ich protokołem HTTP).
var NonHTTP = map[string]bool{"ssh": true, "ftp": true, "smtp": true, "mysql": true, "postgresql": true, "redis": true, "ms-wbt-server": true, "telnet": true,
	"domain": true, "microsoft-ds": true, "netbios-ssn": true, "msrpc": true, "ldap": true, "imap": true, "pop3": true, "vnc": true, "mongodb": true,
	"jetdirect": true, "memcached": true, "rtsp": true, "smtps": true, "imaps": true, "pop3s": true, "ms-sql-s": true, "oracle-tns": true, "rpcbind": true,
	"nfs": true, "snmp": true, "ntp": true, "sip": true, "mqtt": true, "amqp": true, "ldaps": true, "kerberos-sec": true, "winrm": false}

var ErrNotHTTP = errors.New("nie HTTP")

var _ = fmt.Sprint
