// labweb – lekki emulator usług do laboratorium ASI. Profil YAML opisuje listenery HTTP/HTTPS
// (tytuł, nagłówki, cookies, favicona, ścieżki, vhosty, catch-all SPA, certyfikat ważny / wygasły)
// oraz banery TCP (telnet, RTSP, porty „ciche”). Opcjonalnie symuluje niestabilność (FLAP_PERIOD).
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"hash/fnv"
	"image"
	"image/color"
	"image/png"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Profile struct {
	Name string     `yaml:"name"`
	HTTP []Listener `yaml:"http"`
	TCP  []TCP      `yaml:"tcp"`
}

type Listener struct {
	Port   int             `yaml:"port"`
	TLS    string          `yaml:"tls"` // "", self_signed, expired
	CN     string          `yaml:"cn"`
	Site   Site            `yaml:"site"`
	Vhosts map[string]Site `yaml:"vhosts"`
}

type Site struct {
	Status   int               `yaml:"status"`
	Title    string            `yaml:"title"`
	Headers  map[string]string `yaml:"headers"`
	Cookies  []Cookie          `yaml:"cookies"`
	Body     string            `yaml:"body"`
	Favicon  string            `yaml:"favicon"` // ziarno koloru favicony; puste = brak
	CatchAll bool              `yaml:"catch_all"`
	Routes   map[string]Route  `yaml:"routes"`
	Redirect string            `yaml:"redirect"`
}

type Route struct {
	Status  int               `yaml:"status"`
	Title   string            `yaml:"title"`
	Body    string            `yaml:"body"`
	Headers map[string]string `yaml:"headers"`
}

type Cookie struct {
	Name     string `yaml:"name"`
	Value    string `yaml:"value"`
	Secure   bool   `yaml:"secure"`
	HTTPOnly bool   `yaml:"httponly"`
}

type TCP struct {
	Port   int    `yaml:"port"`
	Kind   string `yaml:"kind"` // banner | rtsp | silent
	Banner string `yaml:"banner"`
}

func main() {
	path := os.Getenv("LABWEB_PROFILE")
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("profil: %v", err)
	}
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		log.Fatalf("profil: %v", err)
	}
	flap, _ := strconv.Atoi(os.Getenv("FLAP_PERIOD"))
	var wg sync.WaitGroup
	for _, l := range p.HTTP {
		wg.Add(1)
		go func(l Listener) { defer wg.Done(); serveHTTP(p.Name, l, flap) }(l)
	}
	for _, t := range p.TCP {
		wg.Add(1)
		go func(t TCP) { defer wg.Done(); serveTCP(t) }(t)
	}
	log.Printf("labweb %s: %d HTTP, %d TCP", p.Name, len(p.HTTP), len(p.TCP))
	wg.Wait()
}

func page(s Site, title, body string) string {
	if title == "" {
		title = s.Title
	}
	if body == "" {
		body = s.Body
	}
	if strings.Contains(strings.ToLower(body), "<html") {
		return body
	}
	icon := ""
	if s.Favicon != "" {
		icon = `<link rel="icon" href="/favicon.ico">`
	}
	return fmt.Sprintf("<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>%s</title>%s</head>\n<body>\n%s\n</body></html>\n", title, icon, body)
}

func handler(name string, l Listener) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := l.Site
		host := strings.ToLower(strings.Split(r.Host, ":")[0])
		if v, ok := l.Vhosts[host]; ok {
			s = v
		}
		for k, v := range s.Headers {
			w.Header().Set(k, v)
		}
		if r.URL.Path == "/favicon.ico" && s.Favicon != "" {
			w.Header().Set("Content-Type", "image/png")
			w.Write(favicon(s.Favicon))
			return
		}
		if rt, ok := s.Routes[r.URL.Path]; ok {
			for k, v := range rt.Headers {
				w.Header().Set(k, v)
			}
			st := rt.Status
			if st == 0 {
				st = 200
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if strings.HasSuffix(r.URL.Path, ".txt") || strings.HasPrefix(r.URL.Path, "/.") || strings.HasSuffix(r.URL.Path, "/health") {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(st)
				fmt.Fprint(w, rt.Body)
				return
			}
			w.WriteHeader(st)
			fmt.Fprint(w, page(s, rt.Title, rt.Body))
			return
		}
		if r.URL.Path != "/" && !s.CatchAll {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(404)
			fmt.Fprint(w, page(s, "404 Not Found", "<h1>Not Found</h1>"))
			return
		}
		if s.Redirect != "" && r.URL.Path == "/" {
			http.Redirect(w, r, s.Redirect, http.StatusFound)
			return
		}
		for _, c := range s.Cookies {
			val := c.Value
			if val == "" {
				val = randHex(16)
			}
			http.SetCookie(w, &http.Cookie{Name: c.Name, Value: val, Path: "/", Secure: c.Secure, HttpOnly: c.HTTPOnly})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		st := s.Status
		if st == 0 {
			st = 200
		}
		w.WriteHeader(st)
		fmt.Fprint(w, page(s, "", ""))
	})
}

func serveHTTP(name string, l Listener, flap int) {
	srv := &http.Server{Handler: handler(name, l), ReadHeaderTimeout: 10 * time.Second}
	addr := ":" + strconv.Itoa(l.Port)
	listen := func() (net.Listener, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		if l.TLS != "" {
			cert := makeCert(l.CN, l.TLS == "expired")
			ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10})
		}
		return ln, nil
	}
	for {
		ln, err := listen()
		if err != nil {
			log.Printf("listen %s: %v", addr, err)
			time.Sleep(2 * time.Second)
			continue
		}
		if flap <= 0 {
			log.Fatal(srv.Serve(ln))
		}
		// tryb niestabilny: port na zmianę otwarty i zamknięty
		go srv.Serve(ln)
		time.Sleep(time.Duration(flap) * time.Second)
		ln.Close()
		log.Printf("flap: port %d zamknięty na %ds", l.Port, flap)
		time.Sleep(time.Duration(flap) * time.Second)
	}
}

func serveTCP(t TCP) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(t.Port))
	if err != nil {
		log.Printf("tcp %d: %v", t.Port, err)
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			switch t.Kind {
			case "banner":
				c.Write([]byte(strings.ReplaceAll(t.Banner, `\r\n`, "\r\n")))
				buf := make([]byte, 512)
				c.Read(buf)
			case "rtsp":
				rd := bufio.NewReader(c)
				for {
					line, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) == "" {
						fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: %s\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n", t.Banner)
						return
					}
				}
			default: // silent – przyjmuje połączenie i czyta
				buf := make([]byte, 1024)
				c.Read(buf)
			}
		}(c)
	}
}

// ---------------- favicona i certyfikat ----------------

func favicon(seed string) []byte {
	h := fnv.New32a()
	h.Write([]byte(seed))
	v := h.Sum32()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	c := color.RGBA{uint8(v), uint8(v >> 8), uint8(v >> 16), 255}
	for x := 0; x < 16; x++ {
		for y := 0; y < 16; y++ {
			if (x-8)*(x-8)+(y-8)*(y-8) < 49 {
				img.Set(x, y, c)
			}
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func makeCert(cn string, expired bool) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	nb, na := time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0)
	if expired {
		nb, na = time.Now().AddDate(-2, 0, 0), time.Now().AddDate(0, -1, 0)
	}
	if cn == "" {
		cn = "localhost"
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"ASI Lab"}}, NotBefore: nb, NotAfter: na,
		DNSNames: []string{cn}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
