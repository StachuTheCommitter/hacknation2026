// Package worker: proces skanujący. Pobiera zadania z control plane (lease), uruchamia narzędzia
// w granicach przydzielonego budżetu, wysyła heartbeat (anulowanie przy końcu okna / kill switch)
// i odsyła wyniki w schemacie kanonicznym. Nie ma dostępu do bazy ani klucza szyfrowania.
package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"asi/internal/config"
	"asi/internal/model"
	"asi/internal/netx"
)

type Worker struct {
	cfg        config.Config
	http       *http.Client
	tools      map[string]string
	caps       map[string]bool
	warn       []string
	privileged bool
}

func New(cfg config.Config) *Worker {
	return &Worker{cfg: cfg, http: &http.Client{Timeout: 60 * time.Second}, tools: map[string]string{}, caps: map[string]bool{}}
}

func (w *Worker) call(ctx context.Context, path string, body any, out any) (int, error) {
	var rdr io.Reader
	gz := false
	if body != nil {
		b, _ := json.Marshal(body)
		if len(b) > 64*1024 {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			zw.Write(b)
			zw.Close()
			rdr, gz = &buf, true
		} else {
			rdr = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.ServerURL+"/worker/v1"+path, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.WorkerToken)
	req.Header.Set("X-Worker-Name", w.cfg.WorkerName)
	req.Header.Set("Content-Type", "application/json")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && resp.StatusCode == 200 {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

// detect sprawdza narzędzia i uprawnienia (SYN scan wymaga NET_RAW).
func (w *Worker) detect() {
	for name, args := range map[string][]string{"nmap": {"--version"}, "naabu": {"-version"}, "nuclei": {"-version"}} {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil && len(out) == 0 {
			continue
		}
		line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(strings.ToLower(l), "version") {
				line = strings.TrimSpace(l)
				break
			}
		}
		w.tools[name] = line
	}
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		c.Close()
		w.privileged = true
	}
	w.caps["syn"] = w.privileged
	w.caps["icmp"] = w.privileged
	w.caps["naabu"] = w.tools["naabu"] != ""
	w.caps["nmap"] = w.tools["nmap"] != ""
	w.caps["nuclei"] = w.tools["nuclei"] != ""
	if !w.privileged {
		w.warn = append(w.warn, "brak uprawnień NET_RAW – skan w trybie TCP connect (wolniejszy, inna charakterystyka ruchu); dodaj cap_add: [NET_RAW, NET_ADMIN]")
	}
	if w.tools["nmap"] == "" {
		w.warn = append(w.warn, "brak nmap – discovery i identyfikacja usług niedostępne")
	}
	if w.tools["naabu"] == "" {
		w.warn = append(w.warn, "brak naabu – skan portów wykonywany przez nmap")
	}
}

// Run – główna pętla workera.
func (w *Worker) Run(ctx context.Context) error {
	if w.cfg.WorkerToken == "" {
		return errors.New("brak ASI_WORKER_TOKEN")
	}
	w.detect()
	slog.Info("worker startuje", "name", w.cfg.WorkerName, "server", w.cfg.ServerURL, "tools", w.tools, "privileged", w.privileged)
	for {
		_, err := w.call(ctx, "/hello", model.Hello{Name: w.cfg.WorkerName, Version: "1.0", Capabilities: w.caps, Tools: w.tools, Warnings: w.warn}, nil)
		if err == nil {
			break
		}
		slog.Warn("serwer niedostępny, ponawiam", "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
		}
	}
	idle := time.Second
	for ctx.Err() == nil {
		var lease model.Lease
		code, err := w.call(ctx, "/lease", map[string]any{}, &lease)
		if err != nil || code == http.StatusNoContent {
			if err != nil {
				slog.Warn("lease", "err", err)
			}
			jitter := time.Duration(rand.IntN(800)) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(idle + jitter):
			}
			idle = min(idle*2, 4*time.Second)
			continue
		}
		idle = time.Second
		w.execute(ctx, &lease)
	}
	return nil
}

func (w *Worker) execute(parent context.Context, l *model.Lease) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	cancelled := false
	done := make(chan struct{})
	go func() { // heartbeat co 5 s
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				var rep model.HeartbeatReply
				if _, err := w.call(parent, "/tasks/"+l.TaskID+"/heartbeat", nil, &rep); err == nil && rep.Command == "cancel" {
					slog.Info("serwer anulował zadanie (okno czasowe / pauza / kill switch)", "task", l.TaskID)
					cancelled = true
					cancel()
					return
				}
			}
		}
	}()
	start := time.Now()
	slog.Info("zadanie", "kind", l.Kind, "task", l.TaskID, "rate_pps", l.RatePPS, "http_rps", l.HTTPRPS)
	scope := netx.NewScope(l.Scope, l.Exclusions)
	var res *model.Result
	var err error
	switch l.Kind {
	case model.TaskSweep:
		res, err = w.sweep(ctx, l, scope)
	case model.TaskRetry:
		res, err = w.retry(ctx, l, scope)
	case model.TaskProbe:
		res, err = w.probe(ctx, l, scope)
	case model.TaskDNS:
		res, err = w.dns(ctx, l)
	default:
		err = fmt.Errorf("nieznany rodzaj zadania %s", l.Kind)
	}
	close(done)
	switch {
	case cancelled || errors.Is(ctx.Err(), context.Canceled):
		w.call(parent, "/tasks/"+l.TaskID+"/abort", nil, nil)
	case err != nil:
		slog.Error("zadanie nieudane", "task", l.TaskID, "err", err)
		w.call(parent, "/tasks/"+l.TaskID+"/fail", map[string]any{"error": err.Error(), "retryable": true}, nil)
	default:
		if res.Stats == nil {
			res.Stats = map[string]any{}
		}
		res.Stats["duration_sec"] = time.Since(start).Seconds()
		res.Warnings = append(res.Warnings, w.warn...)
		if _, err := w.call(parent, "/tasks/"+l.TaskID+"/complete", res, nil); err != nil {
			slog.Error("wysyłka wyniku", "task", l.TaskID, "err", err)
		}
		slog.Info("zadanie zakończone", "task", l.TaskID, "sec", int(time.Since(start).Seconds()), "hosts", len(res.Hosts), "observations", len(res.Observations))
	}
}

// run uruchamia narzędzie w osobnej grupie procesów; przy anulowaniu SIGTERM, po 3 s SIGKILL.
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	select {
	case err := <-waitCh:
		if err != nil && stdout.Len() == 0 {
			return nil, fmt.Errorf("%s: %v: %s", name, err, tail(stderr.String(), 400))
		}
		return stdout.Bytes(), nil
	case <-ctx.Done():
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-waitCh:
		case <-time.After(3 * time.Second):
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-waitCh
		}
		return nil, ctx.Err()
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func tempFile(lines []string) (string, func(), error) {
	f, err := os.CreateTemp("", "asi-*.txt")
	if err != nil {
		return "", nil, err
	}
	f.WriteString(strings.Join(lines, "\n") + "\n")
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}
