package core

import (
	"context"
	"sort"
	"strings"
)

// Metric – precision / recall / F1 dla jednego wymiaru.
type Metric struct {
	Name      string   `json:"name"`
	TP        int      `json:"tp"`
	FP        int      `json:"fp"`
	FN        int      `json:"fn"`
	Precision float64  `json:"precision"`
	Recall    float64  `json:"recall"`
	F1        float64  `json:"f1"`
	Missing   []string `json:"missing,omitempty"`
	Extra     []string `json:"extra,omitempty"`
}

func metric(name string, ref, cand map[string]bool) Metric {
	m := Metric{Name: name}
	for k := range cand {
		if ref[k] {
			m.TP++
		} else {
			m.FP++
			m.Extra = append(m.Extra, k)
		}
	}
	for k := range ref {
		if !cand[k] {
			m.FN++
			m.Missing = append(m.Missing, k)
		}
	}
	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	sort.Strings(m.Missing)
	sort.Strings(m.Extra)
	if len(m.Missing) > 50 {
		m.Missing = m.Missing[:50]
	}
	if len(m.Extra) > 50 {
		m.Extra = m.Extra[:50]
	}
	return m
}

// Evaluate porównuje przebieg kandydujący z przebiegiem referencyjnym (np. zaimportowanymi wynikami organizatorów).
func (a *App) Evaluate(ctx context.Context, refID, candID string) ([]Metric, error) {
	if _, err := a.GetRun(ctx, refID); err != nil {
		return nil, err
	}
	if _, err := a.GetRun(ctx, candID); err != nil {
		return nil, err
	}
	ref, cand := a.evalSets(ctx, refID), a.evalSets(ctx, candID)
	// porównujemy tylko adresy obecne w referencji (referencja może obejmować część infrastruktury)
	refIPs := ref["hosts"]
	for dim, set := range cand {
		for k := range set {
			if !refIPs[strings.SplitN(k, "/", 2)[0]] && dim != "hosts" {
				delete(set, k)
			}
		}
	}
	var out []Metric
	for _, d := range []struct{ key, label string }{{"hosts", "Aktywne hosty"}, {"ports", "Otwarte porty (ip/proto/port)"},
		{"services", "Nazwy usług"}, {"products", "Produkty"}, {"tech", "Technologie WWW"}, {"cats", "Kategorie"}} {
		out = append(out, metric(d.label, ref[d.key], cand[d.key]))
	}
	return out, nil
}

func (a *App) evalSets(ctx context.Context, runID string) map[string]map[string]bool {
	s := map[string]map[string]bool{"hosts": {}, "ports": {}, "services": {}, "products": {}, "tech": {}, "cats": {}}
	snap := a.snapshot(ctx, runID)
	for k, x := range snap {
		if !x.up {
			continue
		}
		p := strings.Split(k, "/")
		switch x.etype {
		case "host":
			s["hosts"][k] = true
		case "service":
			s["ports"][k] = true
			if v, _ := x.stable["service"].(string); v != "" {
				s["services"][k+"="+normSvc(v)] = true
			}
			if v, _ := x.stable["product"].(string); v != "" {
				s["products"][k+"="+strings.ToLower(v)] = true
			}
		case "http":
			if techs, ok := x.stable["tech"].([]any); ok {
				for _, t := range techs {
					name := strings.ToLower(strings.SplitN(t.(string), ":", 2)[0])
					s["tech"][p[0]+"/"+p[2]+"="+name] = true
				}
			}
		}
	}
	rows, _ := a.DB.Query(ctx, `select distinct host(h.ip), c.category from classifications c join hosts h on h.id=c.host_id
		where c.active and c.confidence>=0.45 and h.ip in (select split_part(entity_key,'/',1)::inet from observations where run_id=$1 and entity_type='host')`, runID)
	for rows.Next() {
		var ip, c string
		rows.Scan(&ip, &c)
		s["cats"][ip+"="+c] = true
	}
	rows.Close()
	return s
}

func normSvc(s string) string {
	s = strings.ToLower(strings.TrimPrefix(s, "ssl/"))
	switch s {
	case "https", "http-alt", "http-proxy", "https-alt":
		return "http"
	}
	return s
}
