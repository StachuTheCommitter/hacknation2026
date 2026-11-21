// Package model: typy współdzielone przez serwer i workera (profile, zadania, wyniki).
package model

import (
	"time"

	"asi/internal/netx"
	"asi/internal/obs"
)

// Profile – parametry techniczne skanu (sekcja 4).
type Profile struct {
	TCPPorts           string   `json:"tcp_ports"`
	UDPPorts           string   `json:"udp_ports"`
	DiscoveryEngine    string   `json:"discovery_engine"`  // nmap | naabu | none
	DiscoveryTCPSyn    string   `json:"discovery_tcp_syn"` // porty sond SYN
	DiscoveryTCPAck    string   `json:"discovery_tcp_ack"`
	DiscoveryICMP      bool     `json:"discovery_icmp"`
	PortscanEngine     string   `json:"portscan_engine"` // naabu | nmap
	PortscanScope      string   `json:"portscan_scope"`  // alive | all
	NmapIntensity      int      `json:"nmap_intensity"`
	NmapScripts        []string `json:"nmap_scripts"`
	HTTPEnabled        bool     `json:"http_enabled"`
	ProberPaths        []string `json:"prober_paths"`
	ActiveSignatures   bool     `json:"active_signatures"`
	Nuclei             bool     `json:"nuclei"`
	Retries            int      `json:"retries"`
	HostTimeoutSec     int      `json:"host_timeout_sec"`
	HTTPTimeoutSec     int      `json:"http_timeout_sec"`
	RetryDelaysSec     []int    `json:"retry_delays_sec"`
	ResolvePTR         bool     `json:"resolve_ptr"`
	SkipEdgeAddresses  bool     `json:"skip_edge_addresses"`
	MaxProbeHostsBatch int      `json:"max_probe_hosts_batch"`
}

// AllowedNmapScripts – allowlista skryptów (sekcja 2.3).
var AllowedNmapScripts = map[string]bool{"banner": true, "ssl-cert": true, "ssh-hostkey": true, "http-title": true}

// DefaultProberPaths – ścieżki sprawdzane metodą GET (bez logowania, bez payloadów).
var DefaultProberPaths = []string{
	"/robots.txt", "/.well-known/security.txt", "/admin", "/administrator/", "/login", "/user/login",
	"/wp-login.php", "/phpmyadmin/", "/manager/html", "/server-status", "/version", "/api",
	"/swagger-ui/", "/actuator/health", "/_profiler", "/.git/HEAD", "/.env",
}

// SensitivePaths – odpowiedź nie jest zapisywana, tylko flaga dopasowania wzorca.
var SensitivePaths = map[string]string{
	"/.git/HEAD": `^ref: refs/`,
	"/.env":      `(?m)^[A-Z][A-Z0-9_]{2,}=`,
}

func DefaultProfile() Profile {
	return Profile{
		TCPPorts: "top-1000", UDPPorts: "", DiscoveryEngine: "nmap",
		DiscoveryTCPSyn: "21,22,23,25,80,135,139,443,445,3389,8080,8443", DiscoveryTCPAck: "80,443", DiscoveryICMP: true,
		PortscanEngine: "naabu", PortscanScope: "alive", NmapIntensity: 7,
		NmapScripts: []string{"banner", "ssl-cert", "ssh-hostkey"}, HTTPEnabled: true,
		ProberPaths: DefaultProberPaths, ActiveSignatures: true, Retries: 2,
		HostTimeoutSec: 300, HTTPTimeoutSec: 8, RetryDelaysSec: []int{120, 600}, ResolvePTR: true,
		SkipEdgeAddresses: false, MaxProbeHostsBatch: 16,
	}
}

// Fill uzupełnia brakujące pola wartościami domyślnymi.
func (p *Profile) Fill() {
	d := DefaultProfile()
	if p.TCPPorts == "" {
		p.TCPPorts = d.TCPPorts
	}
	if p.DiscoveryEngine == "" {
		p.DiscoveryEngine = d.DiscoveryEngine
	}
	if p.DiscoveryTCPSyn == "" {
		p.DiscoveryTCPSyn = d.DiscoveryTCPSyn
	}
	if p.PortscanEngine == "" {
		p.PortscanEngine = d.PortscanEngine
	}
	if p.PortscanScope == "" {
		p.PortscanScope = d.PortscanScope
	}
	if p.NmapIntensity <= 0 || p.NmapIntensity > 9 {
		p.NmapIntensity = d.NmapIntensity
	}
	if p.Retries < 0 || p.Retries > 5 {
		p.Retries = d.Retries
	}
	if p.HostTimeoutSec <= 0 {
		p.HostTimeoutSec = d.HostTimeoutSec
	}
	if p.HTTPTimeoutSec <= 0 {
		p.HTTPTimeoutSec = d.HTTPTimeoutSec
	}
	if len(p.RetryDelaysSec) == 0 {
		p.RetryDelaysSec = d.RetryDelaysSec
	}
	if p.MaxProbeHostsBatch <= 0 {
		p.MaxProbeHostsBatch = d.MaxProbeHostsBatch
	}
	var scripts []string
	for _, s := range p.NmapScripts {
		if AllowedNmapScripts[s] {
			scripts = append(scripts, s)
		}
	}
	p.NmapScripts = scripts
}

// ---------------- zadania ----------------

const (
	TaskDNS   = "dns"
	TaskSweep = "sweep"
	TaskProbe = "probe"
	TaskRetry = "retry"
)

// Lease – zadanie przekazane workerowi.
type Lease struct {
	TaskID     string    `json:"task_id"`
	RunID      string    `json:"run_id"`
	Kind       string    `json:"kind"`
	Mode       string    `json:"mode"`
	RatePPS    int       `json:"rate_pps"`
	HTTPRPS    int       `json:"http_rps"`
	Profile    Profile   `json:"profile"`
	Payload    Payload   `json:"payload"`
	Scope      []string  `json:"scope"`
	Exclusions []string  `json:"exclusions"`
	UserAgent  string    `json:"user_agent"`
	Deadline   time.Time `json:"deadline"`
	Paths      []string  `json:"paths,omitempty"` // ścieżki z sygnatur aktywnych
}

// Payload – treść zadania zależna od rodzaju.
type Payload struct {
	Ranges  []netx.Range `json:"ranges,omitempty"`
	IPs     []string     `json:"ips,omitempty"`
	Domains []string     `json:"domains,omitempty"`
	Hosts   []ProbeHost  `json:"hosts,omitempty"`
	Ports   string       `json:"ports,omitempty"` // nadpisanie listy portów (liveness / retry)
	Retry   int          `json:"retry,omitempty"`
}

type ProbeHost struct {
	IP        string      `json:"ip"`
	Hostnames []string    `json:"hostnames,omitempty"`
	Ports     []ProbePort `json:"ports"`
}

type ProbePort struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	Known bool   `json:"known,omitempty"` // tryb szybki: znana usługa → lekki pomiar
	// znany odcisk endpointów HTTP (vhost → stable_fp) do wykrywania podmiany usługi
	Service string `json:"service,omitempty"`
}

// ---------------- wyniki ----------------

type SweepHost struct {
	IP     string    `json:"ip"`
	Up     bool      `json:"up"`
	Reason string    `json:"reason,omitempty"`
	MAC    string    `json:"mac,omitempty"`
	PTR    string    `json:"ptr,omitempty"`
	Ports  []PortHit `json:"ports,omitempty"`
}

type PortHit struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

type Coverage struct {
	Ranges   []netx.Range `json:"ranges,omitempty"`
	IPs      []string     `json:"ips,omitempty"`
	TCPPorts string       `json:"tcp_ports"`
	UDPPorts string       `json:"udp_ports"`
	Stages   []string     `json:"stages"`
}

type DNSRecord struct {
	Name  string   `json:"name"`
	IPs   []string `json:"ips"`
	CNAME string   `json:"cname,omitempty"`
	Error string   `json:"error,omitempty"`
}

// Result – wynik zadania odsyłany przez workera.
type Result struct {
	Hosts        []SweepHost       `json:"hosts,omitempty"`
	Observations []obs.Observation `json:"observations,omitempty"`
	DNS          []DNSRecord       `json:"dns,omitempty"`
	Coverage     Coverage          `json:"coverage"`
	Stats        map[string]any    `json:"stats,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
}

// HeartbeatReply – polecenie dla workera.
type HeartbeatReply struct {
	Command string `json:"command"` // continue | cancel | throttle
	RatePPS int    `json:"rate_pps,omitempty"`
}

type Hello struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Capabilities map[string]bool   `json:"capabilities"`
	Tools        map[string]string `json:"tools"`
	Warnings     []string          `json:"warnings,omitempty"`
}
