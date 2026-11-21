// asi – Attack Surface Intelligence: control plane, worker i narzędzia administracyjne w jednej binarce.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"asi/internal/api"
	"asi/internal/config"
	"asi/internal/core"
	"asi/internal/crypto"
	"asi/internal/obs"
	"asi/internal/worker"
	"asi/web"
)

const usage = `asi – Attack Surface Intelligence

Użycie:
  asi server          uruchamia control plane (API, UI, scheduler)
  asi worker          uruchamia worker skanujący
  asi migrate         stosuje migracje bazy
  asi keygen          generuje klucz główny (ASI_MASTER_KEY)
  asi rotate-keys     tworzy nowy klucz danych i przeszyfrowuje rekordy
  asi seed-history    wgrywa syntetyczną historię 14 dni (demo: flapping, okresowość) przez pipeline importu
  asi eval REF CAND   porównuje przebieg kandydujący z referencyjnym (precision / recall)
  asi healthcheck     sprawdza, czy serwer odpowiada
`

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level()})))
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg := config.Load()
	var err error
	switch os.Args[1] {
	case "server":
		err = server(ctx, cfg)
	case "worker":
		err = worker.New(cfg).Run(ctx)
	case "migrate":
		_, err = core.New(ctx, cfg)
	case "keygen":
		fmt.Println("ASI_MASTER_KEY=" + crypto.NewMasterKey())
	case "rotate-keys":
		var app *core.App
		if app, err = core.New(ctx, cfg); err == nil {
			var n int
			n, err = app.RotateDataKey(ctx, core.System)
			fmt.Printf("przeszyfrowano %d rekordów\n", n)
		}
	case "seed-history":
		err = seedHistory(ctx, cfg)
	case "eval":
		if len(os.Args) < 4 {
			err = fmt.Errorf("użycie: asi eval <ref_run_id> <cand_run_id>")
			break
		}
		var app *core.App
		if app, err = core.New(ctx, cfg); err == nil {
			var ms []core.Metric
			if ms, err = app.Evaluate(ctx, os.Args[2], os.Args[3]); err == nil {
				for _, m := range ms {
					fmt.Printf("%-32s P=%.2f R=%.2f F1=%.2f (TP %d, FP %d, FN %d)\n", m.Name, m.Precision, m.Recall, m.F1, m.TP, m.FP, m.FN)
				}
			}
		}
	case "healthcheck":
		addr := cfg.Listen
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		resp, e := http.Get("http://" + addr + "/healthz")
		if e != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		slog.Error("błąd", "err", err)
		os.Exit(1)
	}
}

func level() slog.Level {
	if os.Getenv("ASI_LOG_LEVEL") == "debug" {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func server(ctx context.Context, cfg config.Config) error {
	app, err := core.New(ctx, cfg)
	if err != nil {
		return err
	}
	srv := api.New(app, web.UI())
	go app.RunScheduler(ctx)
	h := srv.Handler()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("/", h)
	hs := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(c)
	}()
	slog.Info("ASI control plane", "listen", cfg.Listen, "demo_mode", cfg.DemoMode)
	if cfg.TLSCert != "" {
		err = hs.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = hs.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// seedHistory – syntetyczna historia 14 dni (co 3 h) wgrywana zwykłym pipeline'em importu JSON.
func seedHistory(ctx context.Context, cfg config.Config) error {
	app, err := core.New(ctx, cfg)
	if err != nil {
		return err
	}
	var n int
	app.DB.QueryRow(ctx, `select count(*) from scan_runs where note like 'historia syntetyczna%'`).Scan(&n)
	if n > 0 {
		fmt.Println("historia już wgrana – pomijam")
		return nil
	}
	loc, _ := time.LoadLocation("Europe/Warsaw")
	rng := rand.New(rand.NewPCG(7, 11))
	start := time.Now().In(loc).Add(-14 * 24 * time.Hour).Truncate(time.Hour)
	type host struct {
		ip, name, title string
		port            int
		up              func(t time.Time) bool
	}
	hosts := []host{
		{"10.77.9.21", "lab-pc-21.lab.local", "Stacja laboratoryjna 21", 3389, func(t time.Time) bool {
			wd := t.Weekday() != time.Saturday && t.Weekday() != time.Sunday
			return wd && t.Hour() >= 8 && t.Hour() < 18
		}},
		{"10.77.9.22", "lab-pc-22.lab.local", "Stacja laboratoryjna 22", 3389, func(t time.Time) bool {
			return t.Hour() >= 7 && t.Hour() < 19
		}},
		{"10.77.9.31", "czujnik-31.lab.local", "Czujnik środowiskowy", 80, func(t time.Time) bool { return rng.Float64() < 0.55 }},
		{"10.77.9.40", "gosc-40.lab.local", "Laptop gościa", 445, func(t time.Time) bool { return false }},
	}
	actor := core.Actor{Email: "seed-history"}
	runs := 0
	for t := start; t.Before(time.Now().Add(-3 * time.Hour)); t = t.Add(3 * time.Hour) {
		var list []obs.Observation
		for i, h := range hosts {
			up := h.up(t)
			if i == 3 { // host efemeryczny: widziany tylko raz, 10 dni temu
				up = t.Sub(start) >= 4*24*time.Hour && t.Sub(start) < 4*24*time.Hour+3*time.Hour
				if t.Sub(start) < 4*24*time.Hour {
					continue
				}
			}
			upv := up
			state := "open"
			if !up {
				state = "closed"
			}
			o := obs.Observation{ObservedAt: t.UTC(), Source: "json_import", Host: obs.Host{IP: h.ip, Up: &upv, Hostnames: []obs.Hostname{{Name: h.name, Source: "dns"}}},
				Services: []obs.Service{{Proto: "tcp", Port: h.port, State: state, Service: map[int]string{3389: "ms-wbt-server", 80: "http", 445: "microsoft-ds"}[h.port]}}}
			if h.port == 80 && up {
				o.Services[0].HTTP = []obs.HTTP{{Scheme: "http", Status: 200, Title: h.title, Headers: obs.Headers{"Server": {"lwIP/2.1"}}}}
			}
			list = append(list, o)
		}
		b, _ := json.Marshal(obs.File{Schema: "asi.export/v1", Run: &obs.RunInfo{StartedAt: t.UTC(), Group: "Lab – usługi"}, Observations: list})
		if _, err := app.ImportObservations(ctx, actor, b, "historia syntetyczna "+t.Format("2006-01-02 15:04"), "", "", false); err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
		runs++
	}
	fmt.Printf("wgrano %d syntetycznych przebiegów\n", runs)
	return nil
}
