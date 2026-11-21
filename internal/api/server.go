// Package api: REST API (/api/v1), API workerów (/worker/v1), SSE i serwowanie UI.
// Każda trasa deklaruje wymagane uprawnienie – test RBAC sprawdza kompletność tablicy tras.
package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"asi/internal/core"
	"asi/internal/rbac"
)

type Ctx struct {
	W     http.ResponseWriter
	R     *http.Request
	Actor *core.Actor
}

func (c *Ctx) Param(k string) string { return chi.URLParam(c.R, k) }
func (c *Ctx) Query(k string) string { return c.R.URL.Query().Get(k) }
func (c *Ctx) QueryInt(k string, def int) int {
	if v, err := strconv.Atoi(c.Query(k)); err == nil {
		return v
	}
	return def
}

// Bind dekoduje JSON z limitem rozmiaru.
func (c *Ctx) Bind(v any) error {
	dec := json.NewDecoder(io.LimitReader(c.R.Body, 4<<20))
	if err := dec.Decode(v); err != nil {
		return core.Invalid("niepoprawny JSON: "+err.Error(), nil)
	}
	return nil
}

type Handler func(c *Ctx) (any, error)

// Route – wpis w tablicy tras (metoda, ścieżka, wymagane uprawnienie).
type Route struct {
	Method string
	Path   string
	Perm   string
	h      Handler
	raw    bool
}

type Server struct {
	App    *core.App
	Routes []Route
	UI     fs.FS
	mux    *chi.Mux

	loginMu      sync.Mutex
	loginLimiter map[string]*rate.Limiter
}

func New(app *core.App, ui fs.FS) *Server {
	s := &Server{App: app, UI: ui, loginLimiter: map[string]*rate.Limiter{}}
	s.routes()
	s.mux = chi.NewRouter()
	s.mux.Use(securityHeaders)
	for _, rt := range s.Routes {
		rt := rt
		s.mux.Method(rt.Method, rt.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(rt, w, r) }))
	}
	s.workerRoutes(s.mux)
	s.mux.NotFound(s.serveUI)
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) add(method, path, perm string, h Handler) {
	s.Routes = append(s.Routes, Route{Method: method, Path: "/api/v1" + path, Perm: perm, h: h})
}

func (s *Server) addRaw(method, path, perm string, h Handler) {
	s.Routes = append(s.Routes, Route{Method: method, Path: "/api/v1" + path, Perm: perm, h: h, raw: true})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const sessionCookie = "asi_session"
const csrfCookie = "asi_csrf"

func (s *Server) serve(rt Route, w http.ResponseWriter, r *http.Request) {
	ctx := &Ctx{W: w, R: r}
	if rt.Perm != rbac.Public {
		tok := ""
		if c, err := r.Cookie(sessionCookie); err == nil {
			tok = c.Value
		}
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead
		actor, err := s.App.SessionActor(r.Context(), tok, r.Header.Get("X-CSRF-Token"), mutating, clientIP(r))
		if err != nil {
			if err.Error() == "csrf" {
				writeErr(w, http.StatusForbidden, "csrf", "brak lub niepoprawny token CSRF", nil)
				return
			}
			writeErr(w, http.StatusUnauthorized, "unauthorized", "zaloguj się ponownie", nil)
			return
		}
		if rt.Perm != rbac.Authenticated && !actor.Can(rt.Perm) {
			s.App.Audit(r.Context(), *actor, "rbac.denied", "route", rt.Method+" "+rt.Path, map[string]any{"required": rt.Perm})
			writeErr(w, http.StatusForbidden, "forbidden", "brak uprawnienia: "+rt.Perm, map[string]string{"required": rt.Perm})
			return
		}
		ctx.Actor = actor
	}
	res, err := rt.h(ctx)
	if err != nil {
		var inv *core.InvalidError
		switch {
		case errors.As(err, &inv):
			writeErr(w, http.StatusBadRequest, "invalid", inv.Msg, inv.Details)
		case errors.Is(err, core.ErrNotFound):
			writeErr(w, http.StatusNotFound, "not_found", "nie znaleziono", nil)
		case errors.Is(err, core.ErrAuth), errors.Is(err, core.ErrLocked):
			writeErr(w, http.StatusUnauthorized, "unauthorized", err.Error(), nil)
		case errors.Is(err, errTooMany):
			writeErr(w, http.StatusTooManyRequests, "rate_limited", err.Error(), nil)
		default:
			slog.Error("api", "path", r.URL.Path, "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "błąd serwera", nil)
		}
		return
	}
	if rt.raw || res == nil {
		if res == nil && !rt.raw {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	writeJSON(w, r, http.StatusOK, res)
}

func writeJSON(w http.ResponseWriter, r *http.Request, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	var out io.Writer = w
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		out = gz
	}
	w.WriteHeader(code)
	json.NewEncoder(out).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, kind, msg string, details any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": kind, "message": msg, "details": details}})
}

var errTooMany = errors.New("zbyt wiele prób logowania – spróbuj za chwilę")

func (s *Server) allowLogin(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	l := s.loginLimiter[ip]
	if l == nil {
		l = rate.NewLimiter(rate.Every(6*time.Second), 10)
		s.loginLimiter[ip] = l
	}
	return l.Allow()
}

func (s *Server) setSessionCookies(w http.ResponseWriter, sess *core.Session) {
	secure := s.App.Cfg.SecureCookies || strings.HasPrefix(s.App.Cfg.BaseURL, "https")
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sess.Token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: sess.CSRF, Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
}

// ---------------- SSE ----------------

func (s *Server) events(c *Ctx) (any, error) {
	w, r := c.W, c.R
	fl, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming nieobsługiwany")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := s.App.Events.Subscribe()
	defer s.App.Events.Unsubscribe(ch)
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	fmt.Fprint(w, ": ok\n\n")
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return nil, nil
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case ev := <-ch:
			b, _ := json.Marshal(ev.Data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, b)
			fl.Flush()
		}
	}
}

// ---------------- UI ----------------

func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/worker/") {
		writeErr(w, http.StatusNotFound, "not_found", "nieznany endpoint", nil)
		return
	}
	if s.UI == nil {
		http.Error(w, "UI nie zostało zbudowane", http.StatusNotFound)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p != "" {
		if f, err := s.UI.Open(p); err == nil {
			st, _ := f.Stat()
			f.Close()
			if st != nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.FileServer(http.FS(s.UI)).ServeHTTP(w, r)
				return
			}
		}
	}
	// SPA: wszystkie pozostałe ścieżki → index.html
	b, err := fs.ReadFile(s.UI, "index.html")
	if err != nil {
		http.Error(w, "UI nie zostało zbudowane", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}

// Run uruchamia serwer HTTP z łagodnym zamknięciem.
func (s *Server) Run(ctx context.Context, addr, cert, key string) error {
	srv := &http.Server{Addr: addr, Handler: s.mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sh)
	}()
	slog.Info("ASI nasłuchuje", "addr", addr)
	var err error
	if cert != "" && key != "" {
		err = srv.ListenAndServeTLS(cert, key)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
