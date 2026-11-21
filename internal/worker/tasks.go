package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"asi/internal/model"
	"asi/internal/netx"
	"asi/internal/nmapxml"
	"asi/internal/obs"
	"asi/internal/prober"
)

// ---------------- sweep: discovery + skan portów ----------------

func (w *Worker) sweep(ctx context.Context, l *model.Lease, scope netx.Scope) (*model.Result, error) {
	p := l.Profile
	var ips []string
	dropped := 0
	netx.Expand(l.Payload.Ranges, p.SkipEdgeAddresses, func(a netip.Addr) {
		if s := a.String(); scope.Allowed(s) {
			ips = append(ips, s)
		} else {
			dropped++
		}
	})
	for _, ip := range l.Payload.IPs {
		if scope.Allowed(ip) {
			ips = append(ips, ip)
		} else {
			dropped++
		}
	}
	res := &model.Result{Coverage: model.Coverage{Ranges: l.Payload.Ranges, IPs: l.Payload.IPs, TCPPorts: p.TCPPorts, UDPPorts: p.UDPPorts, Stages: []string{"discovery", "portscan"}},
		Stats: map[string]any{"addresses": len(ips), "dropped_by_scope": dropped}}
	if l.Payload.Ports != "" {
		res.Coverage.TCPPorts = l.Payload.Ports
	}
	if len(ips) == 0 {
		return res, nil
	}
	hosts := map[string]*model.SweepHost{}
	var alive []string
	t0 := time.Now()
	if p.DiscoveryEngine != "none" {
		up, err := w.discover(ctx, ips, p, l.RatePPS, l.Exclusions)
		if err != nil {
			return nil, err
		}
		for _, h := range up {
			hh := h
			hosts[h.IP] = &hh
			alive = append(alive, h.IP)
		}
	}
	res.Stats["discovery_sec"] = time.Since(t0).Seconds()
	targets := alive
	if p.PortscanScope == "all" || p.DiscoveryEngine == "none" {
		targets = ips
	}
	t1 := time.Now()
	ports := res.Coverage.TCPPorts
	if len(targets) > 0 {
		open, err := w.portscan(ctx, targets, ports, p, l.RatePPS, l.Exclusions)
		if err != nil {
			return nil, err
		}
		for ip, ps := range open {
			h := hosts[ip]
			if h == nil {
				h = &model.SweepHost{IP: ip, Up: true, Reason: "open-port"}
				hosts[ip] = h
			}
			h.Ports = append(h.Ports, ps...)
		}
		if p.UDPPorts != "" && len(alive) > 0 {
			udp, err := w.udpscan(ctx, alive, p.UDPPorts, l.RatePPS)
			if err == nil {
				for ip, ps := range udp {
					if h := hosts[ip]; h != nil {
						h.Ports = append(h.Ports, ps...)
					}
				}
			}
		}
	}
	res.Stats["portscan_sec"] = time.Since(t1).Seconds()
	if p.ResolvePTR {
		w.resolvePTR(ctx, hosts)
	}
	for _, h := range hosts {
		sort.Slice(h.Ports, func(i, j int) bool { return h.Ports[i].Port < h.Ports[j].Port })
		res.Hosts = append(res.Hosts, *h)
	}
	res.Stats["alive"] = len(hosts)
	return res, nil
}

func (w *Worker) discover(ctx context.Context, ips []string, p model.Profile, rate int, excl []string) ([]model.SweepHost, error) {
	if p.DiscoveryEngine == "naabu" && w.tools["naabu"] != "" {
		return w.discoverNaabu(ctx, ips, p, rate)
	}
	if w.tools["nmap"] == "" {
		return nil, fmt.Errorf("brak nmap do wykrywania hostów")
	}
	file, cleanup, err := tempFile(ips)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	args := []string{"-sn", "-n", "--max-retries", "1", "--min-hostgroup", "256", "--max-rate", strconv.Itoa(max(rate, 10)), "-iL", file, "-oX", "-"}
	if p.DiscoveryICMP {
		args = append(args, "-PE", "-PP")
	}
	if p.DiscoveryTCPSyn != "" {
		args = append(args, "-PS"+p.DiscoveryTCPSyn)
	}
	if p.DiscoveryTCPAck != "" && w.privileged {
		args = append(args, "-PA"+p.DiscoveryTCPAck)
	}
	if ef, c2, err := tempFile(excl); err == nil && len(excl) > 0 {
		defer c2()
		args = append(args, "--excludefile", ef)
	}
	out, err := run(ctx, "nmap", args...)
	if err != nil {
		return nil, err
	}
	nr, err := nmapxml.Parse(bytes.NewReader(out))
	if err != nil {
		return nil, fmt.Errorf("nmap -sn: %w", err)
	}
	var up []model.SweepHost
	for _, h := range nr.Hosts {
		if h.Status.State != "up" {
			continue
		}
		ip, mac := h.IP()
		up = append(up, model.SweepHost{IP: ip, Up: true, Reason: h.Status.Reason, MAC: mac})
	}
	return up, nil
}

func (w *Worker) discoverNaabu(ctx context.Context, ips []string, p model.Profile, rate int) ([]model.SweepHost, error) {
	file, cleanup, err := tempFile(ips)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	args := []string{"-list", file, "-sn", "-rate", strconv.Itoa(max(rate, 10)), "-silent", "-json"}
	if p.DiscoveryICMP {
		args = append(args, "-pe", "-pp")
	}
	if p.DiscoveryTCPSyn != "" {
		args = append(args, "-ps", p.DiscoveryTCPSyn)
	}
	if w.privileged {
		args = append(args, "-arp")
	}
	out, err := run(ctx, "naabu", args...)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var up []model.SweepHost
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		ip := fmt.Sprint(m["ip"])
		if ip == "" || ip == "<nil>" {
			ip = fmt.Sprint(m["host"])
		}
		if !seen[ip] {
			seen[ip] = true
			up = append(up, model.SweepHost{IP: ip, Up: true, Reason: "naabu-discovery"})
		}
	}
	return up, nil
}

// portscan – naabu (SYN, szybki) albo nmap jako zapasowy silnik.
func (w *Worker) portscan(ctx context.Context, targets []string, ports string, p model.Profile, rate int, excl []string) (map[string][]model.PortHit, error) {
	ps, err := netx.ParsePorts(ports)
	if err != nil || len(ps) == 0 {
		return nil, fmt.Errorf("niepoprawna lista portów %q", ports)
	}
	spec := netx.FormatPorts(ps)
	file, cleanup, err := tempFile(targets)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	open := map[string][]model.PortHit{}
	if p.PortscanEngine == "naabu" && w.tools["naabu"] != "" {
		scanType := "c"
		if w.privileged {
			scanType = "s"
		}
		args := []string{"-list", file, "-p", spec, "-rate", strconv.Itoa(max(rate, 10)), "-c", "25", "-retries", strconv.Itoa(max(p.Retries, 1)),
			"-timeout", "1000", "-scan-type", scanType, "-Pn", "-json", "-silent", "-disable-update-check"}
		if ef, c2, err := tempFile(excl); err == nil && len(excl) > 0 {
			defer c2()
			args = append(args, "-exclude-file", ef)
		}
		out, err := run(ctx, "naabu", args...)
		if err == nil {
			sc := bufio.NewScanner(bytes.NewReader(out))
			seen := map[string]bool{}
			for sc.Scan() {
				var m struct {
					IP       string `json:"ip"`
					Host     string `json:"host"`
					Port     any    `json:"port"`
					Protocol string `json:"protocol"`
				}
				if json.Unmarshal(sc.Bytes(), &m) != nil {
					continue
				}
				ip := m.IP
				if ip == "" {
					ip = m.Host
				}
				port := 0
				switch v := m.Port.(type) {
				case float64:
					port = int(v)
				case map[string]any:
					if f, ok := v["Port"].(float64); ok {
						port = int(f)
					}
				}
				k := ip + ":" + strconv.Itoa(port)
				if port > 0 && !seen[k] {
					seen[k] = true
					open[ip] = append(open[ip], model.PortHit{Proto: "tcp", Port: port})
				}
			}
			return open, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		slog.Warn("naabu nie powiódł się, używam nmap", "err", err)
	}
	scan := "-sT"
	if w.privileged {
		scan = "-sS"
	}
	args := []string{scan, "-Pn", "-n", "-p", spec, "--open", "--max-rate", strconv.Itoa(max(rate, 10)), "--max-retries", strconv.Itoa(max(p.Retries, 1)),
		"--min-hostgroup", "64", "-iL", file, "-oX", "-"}
	out, err := run(ctx, "nmap", args...)
	if err != nil {
		return nil, err
	}
	nr, err := nmapxml.Parse(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	for _, h := range nr.Hosts {
		ip, _ := h.IP()
		for _, pt := range h.Ports {
			if pt.State.State == "open" {
				open[ip] = append(open[ip], model.PortHit{Proto: pt.Protocol, Port: pt.PortID})
			}
		}
	}
	return open, nil
}

func (w *Worker) udpscan(ctx context.Context, hosts []string, ports string, rate int) (map[string][]model.PortHit, error) {
	if !w.privileged {
		return nil, fmt.Errorf("skan UDP wymaga uprawnień NET_RAW")
	}
	file, cleanup, err := tempFile(hosts)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	out, err := run(ctx, "nmap", "-sU", "-sV", "--version-intensity", "2", "-n", "-Pn", "-p", "U:"+ports, "--max-rate", strconv.Itoa(max(rate/4, 10)),
		"--max-retries", "1", "--host-timeout", "3m", "-iL", file, "-oX", "-")
	if err != nil {
		return nil, err
	}
	nr, err := nmapxml.Parse(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	res := map[string][]model.PortHit{}
	for _, h := range nr.Hosts {
		ip, _ := h.IP()
		for _, pt := range h.Ports {
			if pt.State.State == "open" {
				res[ip] = append(res[ip], model.PortHit{Proto: "udp", Port: pt.PortID})
			}
		}
	}
	return res, nil
}

func (w *Worker) resolvePTR(ctx context.Context, hosts map[string]*model.SweepHost) {
	var mu sync.Mutex
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	r := &net.Resolver{}
	for ip, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string, h *model.SweepHost) {
			defer wg.Done()
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			names, err := r.LookupAddr(c, ip)
			if err == nil && len(names) > 0 {
				mu.Lock()
				h.PTR = strings.TrimSuffix(strings.ToLower(names[0]), ".")
				mu.Unlock()
			}
		}(ip, h)
	}
	wg.Wait()
}

// ---------------- retry: ponowny pomiar znanych encji ----------------

func (w *Worker) retry(ctx context.Context, l *model.Lease, scope netx.Scope) (*model.Result, error) {
	res := &model.Result{Coverage: model.Coverage{Stages: []string{"retry"}}, Stats: map[string]any{"retry": l.Payload.Retry}}
	var ips []string
	portsBy := map[string][]model.ProbePort{}
	for _, h := range l.Payload.Hosts {
		if scope.Allowed(h.IP) {
			ips = append(ips, h.IP)
			portsBy[h.IP] = h.Ports
		}
	}
	if len(ips) == 0 {
		return res, nil
	}
	prof := l.Profile
	prof.Retries = 2
	up, err := w.discover(ctx, ips, prof, l.RatePPS, l.Exclusions)
	if err != nil {
		return nil, err
	}
	hosts := map[string]*model.SweepHost{}
	for _, h := range up {
		hh := h
		hosts[h.IP] = &hh
	}
	// porty: grupujemy hosty o tym samym zestawie znanych portów
	groups := map[string][]string{}
	for ip, ps := range portsBy {
		var tcp []int
		for _, p := range ps {
			if p.Proto == "tcp" {
				tcp = append(tcp, p.Port)
			}
		}
		if len(tcp) > 0 {
			k := netx.FormatPorts(tcp)
			groups[k] = append(groups[k], ip)
		}
	}
	for spec, ips := range groups {
		open, err := w.portscan(ctx, ips, spec, prof, l.RatePPS, l.Exclusions)
		if err != nil {
			return nil, err
		}
		for ip, ps := range open {
			h := hosts[ip]
			if h == nil {
				h = &model.SweepHost{IP: ip, Up: true, Reason: "open-port"}
				hosts[ip] = h
			}
			h.Ports = append(h.Ports, ps...)
		}
	}
	for _, h := range hosts {
		res.Hosts = append(res.Hosts, *h)
	}
	return res, nil
}

// ---------------- dns ----------------

func (w *Worker) dns(ctx context.Context, l *model.Lease) (*model.Result, error) {
	res := &model.Result{}
	r := &net.Resolver{}
	for _, d := range l.Payload.Domains {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		rec := model.DNSRecord{Name: d}
		addrs, err := r.LookupHost(c, d)
		if err != nil {
			rec.Error = err.Error()
		}
		for _, a := range addrs {
			if ip, err := netip.ParseAddr(a); err == nil {
				rec.IPs = append(rec.IPs, ip.Unmap().String())
			}
		}
		if cn, err := r.LookupCNAME(c, d); err == nil && strings.TrimSuffix(cn, ".") != d {
			rec.CNAME = strings.TrimSuffix(cn, ".")
		}
		cancel()
		res.DNS = append(res.DNS, rec)
	}
	return res, nil
}

// ---------------- probe: identyfikacja usług + HTTP ----------------

func (w *Worker) probe(ctx context.Context, l *model.Lease, scope netx.Scope) (*model.Result, error) {
	p := l.Profile
	res := &model.Result{Coverage: model.Coverage{Stages: []string{"probe"}}, Stats: map[string]any{}}
	type hostWork struct {
		h        model.ProbeHost
		services map[string]*obs.Service
		sshFP    string
		dev      string
	}
	var work []*hostWork
	byIP := map[string]*hostWork{}
	for _, h := range l.Payload.Hosts {
		if !scope.Allowed(h.IP) {
			continue
		}
		hw := &hostWork{h: h, services: map[string]*obs.Service{}}
		work = append(work, hw)
		byIP[h.IP] = hw
		for _, pp := range h.Ports {
			s := &obs.Service{Proto: pp.Proto, Port: pp.Port, State: "open"}
			if pp.Known && l.Mode == "differential" {
				s.Light = true
			}
			hw.services[fmt.Sprintf("%s/%d", pp.Proto, pp.Port)] = s
		}
	}
	// Etap 3: nmap -sV – hosty o identycznym zestawie (nieznanych) portów w jednym wywołaniu
	groups := map[string][]string{}
	for _, hw := range work {
		var tcp, udp []int
		for _, pp := range hw.h.Ports {
			if pp.Known && l.Mode == "differential" {
				continue
			}
			if pp.Proto == "udp" {
				udp = append(udp, pp.Port)
			} else {
				tcp = append(tcp, pp.Port)
			}
		}
		if len(tcp)+len(udp) == 0 {
			continue
		}
		spec := ""
		if len(tcp) > 0 {
			spec = "T:" + netx.FormatPorts(tcp)
		}
		if len(udp) > 0 {
			if spec != "" {
				spec += ","
			}
			spec += "U:" + netx.FormatPorts(udp)
		}
		groups[spec] = append(groups[spec], hw.h.IP)
	}
	// Etapy 3 i 4 równolegle: nmap -sV (bywa wolny na nietypowych usługach) i fingerprinting HTTP.
	// HTTP sonduje wszystkie otwarte porty TCP; wyniki dla portów, które nmap rozpozna jako nie-HTTP, są odrzucane.
	httpBy := map[string][]obs.HTTP{}
	schemeBy := map[string]string{}
	var httpMu sync.Mutex
	var phase sync.WaitGroup
	var nmapErr, httpErr error
	phase.Add(2)
	go func() {
		defer phase.Done()
		t0 := time.Now()
		if w.tools["nmap"] != "" && len(groups) > 0 {
			sem := make(chan struct{}, max(w.cfg.MaxNmap, 1))
			var mu sync.Mutex
			var wg sync.WaitGroup
			var firstErr error
			rate := max(l.RatePPS/max(len(groups), 1), 20)
			for spec, ips := range groups {
				wg.Add(1)
				sem <- struct{}{}
				go func(spec string, ips []string) {
					defer wg.Done()
					defer func() { <-sem }()
					if strings.Contains(spec, "U:") && !w.privileged {
						spec = strings.TrimSuffix(strings.SplitN(spec, "U:", 2)[0], ",") // UDP wymaga NET_RAW
					}
					if spec == "" {
						return
					}
					args := []string{"-sV", "--version-intensity", strconv.Itoa(p.NmapIntensity), "-Pn", "-n", "-p", spec,
						"--max-rate", strconv.Itoa(rate), "--max-retries", "2", "--host-timeout", fmt.Sprintf("%ds", p.HostTimeoutSec), "-oX", "-"}
					if w.privileged {
						args = append(args, "-sS")
						if strings.Contains(spec, "U:") {
							args = append(args, "-sU")
						}
					} else {
						args = append(args, "-sT")
					}
					var scripts []string
					for _, s := range p.NmapScripts {
						if model.AllowedNmapScripts[s] {
							scripts = append(scripts, s)
						}
					}
					if len(scripts) > 0 {
						args = append(args, "--script", strings.Join(scripts, ","), "--script-timeout", "15s")
					}
					args = append(args, ips...)
					out, err := run(ctx, "nmap", args...)
					if err != nil {
						mu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						mu.Unlock()
						return
					}
					nr, err := nmapxml.Parse(bytes.NewReader(out))
					if err != nil {
						return
					}
					mu.Lock()
					defer mu.Unlock()
					for _, h := range nr.Hosts {
						ip, _ := h.IP()
						hw := byIP[ip]
						if hw == nil {
							continue
						}
						for _, pt := range h.Ports {
							k := fmt.Sprintf("%s/%d", pt.Protocol, pt.PortID)
							if pt.State.State != "open" {
								if s := hw.services[k]; s != nil && pt.State.State == "closed" {
									s.State = "closed"
								}
								continue
							}
							s := nmapxml.ServiceFromPort(pt)
							if fp := s.Scripts["ssh-hostkey-fp"]; fp != "" {
								hw.sshFP = fp
							}
							if s.DeviceType != "" {
								hw.dev = s.DeviceType
							}
							cp := s
							hw.services[k] = &cp
						}
					}
				}(spec, ips)
			}
			wg.Wait()
			if firstErr != nil && ctx.Err() != nil {
				nmapErr = ctx.Err()
				return
			}
			if firstErr != nil {
				res.Warnings = append(res.Warnings, "nmap -sV: "+firstErr.Error())
			}
		}
		httpMu.Lock()
		res.Stats["nmap_sec"] = time.Since(t0).Seconds()
		httpMu.Unlock()
	}()
	go func() {
		defer phase.Done()
		t1 := time.Now()
		if !p.HTTPEnabled {
			return
		}
		pr, err := prober.New(l.UserAgent, time.Duration(p.HTTPTimeoutSec)*time.Second, max(l.HTTPRPS, 1), append([]string{}, p.ProberPaths...), model.SensitivePaths)
		if err != nil {
			httpErr = err
			return
		}
		sem := make(chan struct{}, 8)
		var wg sync.WaitGroup
		for _, hw := range work {
			wg.Add(1)
			sem <- struct{}{}
			go func(hw *hostWork) {
				defer wg.Done()
				defer func() { <-sem }()
				vhosts := append([]string{""}, hw.h.Hostnames...)
				if len(vhosts) > 6 {
					vhosts = vhosts[:6]
				}
				for _, pp := range hw.h.Ports {
					if ctx.Err() != nil || pp.Proto != "tcp" {
						continue
					}
					light := pp.Known && l.Mode == "differential"
					scheme := pr.Detect(ctx, hw.h.IP, pp.Port, false)
					var results []obs.HTTP
					for i, vh := range vhosts {
						h, err := pr.Probe(ctx, hw.h.IP, pp.Port, scheme, vh, light, extraPaths(l))
						if err != nil {
							if i == 0 {
								break // port nie mówi HTTP – nie próbujemy vhostów
							}
							continue
						}
						results = append(results, *h)
					}
					k := fmt.Sprintf("%s|tcp/%d", hw.h.IP, pp.Port)
					httpMu.Lock()
					httpBy[k], schemeBy[k] = results, scheme
					httpMu.Unlock()
				}
			}(hw)
		}
		wg.Wait()
		httpMu.Lock()
		res.Stats["http_sec"] = time.Since(t1).Seconds()
		httpMu.Unlock()
	}()
	phase.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if nmapErr != nil {
		return nil, nmapErr
	}
	if httpErr != nil {
		return nil, httpErr
	}
	for _, hw := range work {
		for k, s := range hw.services {
			hk := hw.h.IP + "|" + k
			results := httpBy[hk]
			if len(results) == 0 || s.Proto != "tcp" || s.State != "open" {
				continue
			}
			if prober.NonHTTP[s.Service] && s.Nmap != nil && s.Nmap.Method == "probed" {
				continue // nmap pewnie rozpoznał usługę nie-HTTP
			}
			s.HTTP = results
			if s.Service == "" || s.Service == "tcpwrapped" || strings.HasSuffix(s.Service, "?") || s.Nmap == nil || s.Nmap.Method == "table" {
				if s.Service == "" || s.Nmap == nil || s.Nmap.Method == "table" {
					s.Service = schemeBy[hk]
				}
			}
		}
	}
	up := true
	for _, hw := range work {
		o := obs.Observation{Schema: obs.Schema, ObservedAt: time.Now().UTC(), Source: "scanner", Host: obs.Host{IP: hw.h.IP, Up: &up, SSHHostkeyFP: hw.sshFP, DeviceType: hw.dev}}
		for _, hn := range hw.h.Hostnames {
			o.Host.Hostnames = append(o.Host.Hostnames, obs.Hostname{Name: hn, Source: "dns"})
		}
		for _, s := range sortedServices(hw.services) {
			o.Services = append(o.Services, *s)
		}
		res.Observations = append(res.Observations, o)
	}
	return res, nil
}

func extraPaths(l *model.Lease) []string {
	if !l.Profile.ActiveSignatures {
		return nil
	}
	return l.Paths
}

func sortedServices(m map[string]*obs.Service) []*obs.Service {
	out := make([]*obs.Service, 0, len(m))
	for _, s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}
