// Package nmapxml: parser wyjścia XML nmapa do schematu kanonicznego (worker i import plików).
package nmapxml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"strconv"
	"strings"
	"time"

	"asi/internal/obs"
)

type Run struct {
	XMLName xml.Name `xml:"nmaprun"`
	Start   int64    `xml:"start,attr"`
	Args    string   `xml:"args,attr"`
	Version string   `xml:"version,attr"`
	Hosts   []Host   `xml:"host"`
	Stats   struct {
		Finished struct {
			Elapsed float64 `xml:"elapsed,attr"`
		} `xml:"finished"`
		Hosts struct {
			Up   int `xml:"up,attr"`
			Down int `xml:"down,attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}

type Host struct {
	StartTime int64 `xml:"starttime,attr"`
	Status    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []Port `xml:"ports>port"`
	OS    struct {
		Matches []struct {
			Name     string `xml:"name,attr"`
			Accuracy int    `xml:"accuracy,attr"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

type Port struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"state"`
	Service struct {
		Name       string   `xml:"name,attr"`
		Product    string   `xml:"product,attr"`
		Version    string   `xml:"version,attr"`
		ExtraInfo  string   `xml:"extrainfo,attr"`
		OSType     string   `xml:"ostype,attr"`
		DeviceType string   `xml:"devicetype,attr"`
		Tunnel     string   `xml:"tunnel,attr"`
		Method     string   `xml:"method,attr"`
		Conf       int      `xml:"conf,attr"`
		CPE        []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []Script `xml:"script"`
}

type Script struct {
	ID     string  `xml:"id,attr"`
	Output string  `xml:"output,attr"`
	Elems  []Elem  `xml:"elem"`
	Tables []Table `xml:"table"`
}

type Table struct {
	Key    string  `xml:"key,attr"`
	Elems  []Elem  `xml:"elem"`
	Tables []Table `xml:"table"`
}

type Elem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

func Parse(r io.Reader) (*Run, error) {
	var run Run
	dec := xml.NewDecoder(r)
	dec.Strict = false
	if err := dec.Decode(&run); err != nil {
		return nil, err
	}
	return &run, nil
}

// IP zwraca adres IPv4/IPv6 hosta i MAC (jeśli jest).
func (h Host) IP() (ip, mac string) {
	for _, a := range h.Addresses {
		switch a.AddrType {
		case "ipv4", "ipv6":
			if ip == "" {
				ip = a.Addr
			}
		case "mac":
			mac = a.Addr
		}
	}
	return
}

// ToObservations konwertuje wynik nmapa do obserwacji kanonicznych.
func (run *Run) ToObservations(source string) []obs.Observation {
	var out []obs.Observation
	for _, h := range run.Hosts {
		ip, mac := h.IP()
		if ip == "" {
			continue
		}
		up := h.Status.State == "up" || h.Status.State == ""
		ts := time.Now().UTC()
		if h.StartTime > 0 {
			ts = time.Unix(h.StartTime, 0).UTC()
		} else if run.Start > 0 {
			ts = time.Unix(run.Start, 0).UTC()
		}
		o := obs.Observation{Schema: obs.Schema, ObservedAt: ts, Source: source, Host: obs.Host{IP: ip, Up: &up, UpReason: h.Status.Reason, MAC: mac}}
		for _, hn := range h.Hostnames {
			src := "dns"
			if hn.Type == "PTR" {
				src = "ptr"
			}
			o.Host.Hostnames = append(o.Host.Hostnames, obs.Hostname{Name: strings.ToLower(hn.Name), Source: src})
		}
		if len(h.OS.Matches) > 0 && h.OS.Matches[0].Accuracy >= 85 {
			o.Host.OS = h.OS.Matches[0].Name
		}
		for _, p := range h.Ports {
			if p.State.State != "open" && p.State.State != "open|filtered" {
				continue
			}
			if p.State.State == "open|filtered" && p.Service.Method != "probed" {
				continue // UDP bez odpowiedzi – nie traktujemy jako otwarty
			}
			s := ServiceFromPort(p)
			if s.DeviceType != "" && o.Host.DeviceType == "" {
				o.Host.DeviceType = s.DeviceType
			}
			if fp := s.Scripts["ssh-hostkey-fp"]; fp != "" {
				o.Host.SSHHostkeyFP = fp
			}
			o.Services = append(o.Services, s)
		}
		out = append(out, o)
	}
	return out
}

// ServiceFromPort – pojedynczy port nmapa → usługa kanoniczna.
func ServiceFromPort(p Port) obs.Service {
	s := obs.Service{
		Proto: p.Protocol, Port: p.PortID, State: "open", Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version,
		ExtraInfo: p.Service.ExtraInfo, DeviceType: p.Service.DeviceType, OSType: p.Service.OSType, Tunnel: p.Service.Tunnel, CPE: p.Service.CPE,
	}
	if p.Service.Method != "" {
		s.Nmap = &obs.NmapInfo{Method: p.Service.Method, Conf: p.Service.Conf}
	}
	for _, sc := range p.Scripts {
		if s.Scripts == nil {
			s.Scripts = map[string]string{}
		}
		switch sc.ID {
		case "banner":
			s.Banner = sc.Output
		case "ssl-cert":
			s.TLS = parseSSLCert(sc)
		case "ssh-hostkey":
			// odcisk tożsamości urządzenia: hash posortowanych kluczy
			var keys []string
			for _, t := range sc.Tables {
				for _, e := range t.Elems {
					if e.Key == "fingerprint" {
						keys = append(keys, e.Value)
					}
				}
			}
			if len(keys) > 0 {
				h := sha256.Sum256([]byte(strings.Join(keys, ",")))
				s.Scripts["ssh-hostkey-fp"] = hex.EncodeToString(h[:8])
			}
		}
		s.Scripts[sc.ID] = truncate(sc.Output, 4000)
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func parseSSLCert(sc Script) *obs.TLS {
	t := &obs.TLS{}
	get := func(tables []Table, key string) []Elem {
		for _, tb := range tables {
			if tb.Key == key {
				return tb.Elems
			}
		}
		return nil
	}
	for _, e := range get(sc.Tables, "subject") {
		if e.Key == "commonName" {
			t.SubjectCN = e.Value
		}
	}
	var issuerParts []string
	for _, e := range get(sc.Tables, "issuer") {
		issuerParts = append(issuerParts, e.Key+"="+e.Value)
	}
	t.Issuer = strings.Join(issuerParts, ", ")
	for _, e := range get(sc.Tables, "validity") {
		tm, err := time.Parse("2006-01-02T15:04:05", strings.TrimSuffix(e.Value, "Z")[:min(19, len(strings.TrimSuffix(e.Value, "Z")))])
		if err != nil {
			continue
		}
		switch e.Key {
		case "notBefore":
			t.NotBefore = tm
		case "notAfter":
			t.NotAfter = tm
		}
	}
	for _, e := range get(sc.Tables, "pubkey") {
		switch e.Key {
		case "bits":
			t.KeyBits, _ = strconv.Atoi(e.Value)
		case "type":
			t.KeyType = e.Value
		}
	}
	for _, e := range sc.Elems {
		switch e.Key {
		case "sha256":
			t.SHA256 = e.Value
		case "sig_algo":
		}
	}
	for _, tb := range sc.Tables {
		if tb.Key == "extensions" {
			for _, ext := range tb.Tables {
				var name, value string
				for _, e := range ext.Elems {
					switch e.Key {
					case "name":
						name = e.Value
					case "value":
						value = e.Value
					}
				}
				if name == "X509v3 Subject Alternative Name" {
					for _, part := range strings.Split(value, ",") {
						part = strings.TrimSpace(part)
						if strings.HasPrefix(part, "DNS:") {
							t.SAN = append(t.SAN, strings.TrimPrefix(part, "DNS:"))
						}
					}
				}
			}
		}
	}
	t.SelfSigned = issuerParts != nil && t.SubjectCN != "" && strings.Contains(t.Issuer, "commonName="+t.SubjectCN)
	return t
}
