// Package config: konfiguracja ze zmiennych środowiskowych (sekcja 19).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL       string
	MasterKey         string
	Listen            string
	BaseURL           string
	TLSCert, TLSKey   string
	TZ                string
	BootstrapEmail    string
	BootstrapPassword string
	SeedDemoUsers     bool
	SeedDemoLab       bool
	DemoMode          bool
	GlobalMaxPPS      int
	ScannerContact    string
	DDURL, DDToken    string
	WorkerTokens      string
	SecureCookies     bool

	// worker
	ServerURL   string
	WorkerToken string
	WorkerName  string
	MaxNmap     int
	Slots       int
	Vantage     string
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(env(k, "")); err == nil {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if v, err := strconv.ParseBool(env(k, "")); err == nil {
		return v
	}
	return def
}

func Load() Config {
	c := Config{
		DatabaseURL:       env("ASI_DATABASE_URL", "postgres://asi:asi@localhost:5432/asi?sslmode=disable"),
		MasterKey:         env("ASI_MASTER_KEY", ""),
		Listen:            env("ASI_LISTEN", ":8080"),
		BaseURL:           env("ASI_BASE_URL", "http://localhost:8080"),
		TLSCert:           env("ASI_TLS_CERT", ""),
		TLSKey:            env("ASI_TLS_KEY", ""),
		TZ:                env("ASI_TZ", "Europe/Warsaw"),
		BootstrapEmail:    env("ASI_BOOTSTRAP_ADMIN_EMAIL", ""),
		BootstrapPassword: env("ASI_BOOTSTRAP_ADMIN_PASSWORD", ""),
		SeedDemoUsers:     envBool("ASI_SEED_DEMO_USERS", false),
		SeedDemoLab:       envBool("ASI_SEED_DEMO_LAB", false),
		DemoMode:          envBool("ASI_DEMO_MODE", false),
		GlobalMaxPPS:      envInt("ASI_GLOBAL_MAX_PPS", 2000),
		ScannerContact:    env("ASI_SCANNER_CONTACT", "cbi@agh.edu.pl"),
		DDURL:             strings.TrimRight(env("ASI_DD_URL", ""), "/"),
		DDToken:           env("ASI_DD_TOKEN", ""),
		WorkerTokens:      env("ASI_WORKER_BOOTSTRAP_TOKENS", ""),
		SecureCookies:     envBool("ASI_SECURE_COOKIES", false),
		ServerURL:         strings.TrimRight(env("ASI_SERVER_URL", "http://localhost:8080"), "/"),
		WorkerToken:       env("ASI_WORKER_TOKEN", ""),
		WorkerName:        env("ASI_WORKER_NAME", ""),
		MaxNmap:           envInt("ASI_WORKER_MAX_NMAP", 4),
		Slots:             envInt("ASI_WORKER_SLOTS", 4),
		Vantage:           env("ASI_WORKER_VANTAGE", ""),
	}
	if f := env("ASI_MASTER_KEY_FILE", ""); f != "" && c.MasterKey == "" {
		if b, err := os.ReadFile(f); err == nil {
			c.MasterKey = strings.TrimSpace(string(b))
		}
	}
	if f := env("ASI_DD_TOKEN_FILE", ""); f != "" && c.DDToken == "" {
		if b, err := os.ReadFile(f); err == nil {
			c.DDToken = strings.TrimSpace(string(b))
		}
	}
	if c.WorkerName == "" {
		h, _ := os.Hostname()
		c.WorkerName = "worker-" + h
	}
	return c
}

// Thresholds – progi zależne od trybu demo (sekcja 19.2).
type Thresholds struct {
	K, KEphemeral       int
	InactiveAfter       time.Duration
	InactiveAfterEphem  time.Duration
	RetryDelays         []time.Duration
	FlapWindow, FlapMin int
	TaskTarget          time.Duration
	DDSyncEvery         time.Duration
	LeaseTTL            time.Duration
}

func (c Config) Thresholds() Thresholds {
	if c.DemoMode {
		return Thresholds{K: 2, KEphemeral: 1, InactiveAfter: 0, InactiveAfterEphem: 0,
			RetryDelays: []time.Duration{20 * time.Second, 60 * time.Second}, FlapWindow: 5, FlapMin: 3,
			TaskTarget: 15 * time.Second, DDSyncEvery: time.Minute, LeaseTTL: 60 * time.Second}
	}
	return Thresholds{K: 3, KEphemeral: 1, InactiveAfter: 72 * time.Hour, InactiveAfterEphem: 24 * time.Hour,
		RetryDelays: []time.Duration{2 * time.Minute, 10 * time.Minute}, FlapWindow: 10, FlapMin: 4,
		TaskTarget: 60 * time.Second, DDSyncEvery: 15 * time.Minute, LeaseTTL: 60 * time.Second}
}

func (c Config) UserAgent() string {
	return fmt.Sprintf("ASI-Scanner/1.0 (AGH CBI; +%s)", c.ScannerContact)
}
