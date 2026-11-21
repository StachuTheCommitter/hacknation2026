package api

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"asi/internal/model"
)

// workerAuthCache – unikamy liczenia argon2id przy każdym heartbeat.
type workerAuthCache struct {
	mu sync.Mutex
	m  map[string]workerAuth
}

type workerAuth struct {
	id  string
	exp time.Time
}

var wcache = &workerAuthCache{m: map[string]workerAuth{}}

func (s *Server) workerID(r *http.Request) (string, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	name := r.Header.Get("X-Worker-Name")
	if tok == "" {
		return "", false
	}
	k := name + "|" + tok
	wcache.mu.Lock()
	if a, ok := wcache.m[k]; ok && time.Now().Before(a.exp) {
		wcache.mu.Unlock()
		return a.id, true
	}
	wcache.mu.Unlock()
	id, err := s.App.AuthWorker(r.Context(), name, tok)
	if err != nil {
		return "", false
	}
	wcache.mu.Lock()
	wcache.m[k] = workerAuth{id, time.Now().Add(5 * time.Minute)}
	wcache.mu.Unlock()
	return id, true
}

func (s *Server) workerRoutes(r chi.Router) {
	r.Route("/worker/v1", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				id, ok := s.workerID(req)
				if !ok {
					writeErr(w, http.StatusUnauthorized, "unauthorized", "niepoprawny token workera", nil)
					return
				}
				req.Header.Set("X-Worker-ID", id)
				next.ServeHTTP(w, req)
			})
		})
		r.Post("/hello", func(w http.ResponseWriter, req *http.Request) {
			var h model.Hello
			json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&h)
			s.App.WorkerHello(req.Context(), req.Header.Get("X-Worker-ID"), h)
			writeJSON(w, req, 200, map[string]any{"ok": true, "server_time": time.Now()})
		})
		r.Post("/lease", func(w http.ResponseWriter, req *http.Request) {
			l, err := s.App.Lease(req.Context(), req.Header.Get("X-Worker-ID"))
			if err != nil {
				writeErr(w, 500, "internal", err.Error(), nil)
				return
			}
			if l == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeJSON(w, req, 200, l)
		})
		r.Post("/tasks/{id}/heartbeat", func(w http.ResponseWriter, req *http.Request) {
			writeJSON(w, req, 200, s.App.Heartbeat(req.Context(), req.Header.Get("X-Worker-ID"), chi.URLParam(req, "id")))
		})
		r.Post("/tasks/{id}/abort", func(w http.ResponseWriter, req *http.Request) {
			s.App.Abort(req.Context(), req.Header.Get("X-Worker-ID"), chi.URLParam(req, "id"))
			w.WriteHeader(http.StatusNoContent)
		})
		r.Post("/tasks/{id}/fail", func(w http.ResponseWriter, req *http.Request) {
			var in struct {
				Error     string `json:"error"`
				Retryable bool   `json:"retryable"`
			}
			json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in)
			s.App.Fail(req.Context(), req.Header.Get("X-Worker-ID"), chi.URLParam(req, "id"), in.Error, in.Retryable)
			w.WriteHeader(http.StatusNoContent)
		})
		r.Post("/tasks/{id}/complete", func(w http.ResponseWriter, req *http.Request) {
			var body io.Reader = io.LimitReader(req.Body, 256<<20)
			if req.Header.Get("Content-Encoding") == "gzip" {
				gz, err := gzip.NewReader(body)
				if err != nil {
					writeErr(w, 400, "invalid", "gzip", nil)
					return
				}
				defer gz.Close()
				body = gz
			}
			var res model.Result
			if err := json.NewDecoder(body).Decode(&res); err != nil {
				writeErr(w, 400, "invalid", err.Error(), nil)
				return
			}
			if err := s.App.Complete(req.Context(), req.Header.Get("X-Worker-ID"), chi.URLParam(req, "id"), &res); err != nil {
				writeErr(w, 409, "conflict", err.Error(), nil)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	})
}
