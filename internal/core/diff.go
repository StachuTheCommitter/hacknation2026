package core

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"asi/internal/netx"
)

// RunDiffItem – różnica jednej encji między przebiegami.
type RunDiffItem struct {
	Kind       string      `json:"kind"` // ADDED | REMOVED | CHANGED
	EntityType string      `json:"entity_type"`
	Key        string      `json:"key"`
	IP         string      `json:"ip"`
	Fields     []FieldDiff `json:"fields,omitempty"`
	Summary    string      `json:"summary"`
}

type RunDiff struct {
	A, B        *Run           `json:"-"`
	RunA        map[string]any `json:"run_a"`
	RunB        map[string]any `json:"run_b"`
	CommonAddrs uint64         `json:"common_addresses"`
	OnlyA       uint64         `json:"only_a_addresses"`
	OnlyBAddrs  uint64         `json:"only_b_addresses"`
	CommonTCP   int            `json:"common_tcp_ports"`
	Items       []RunDiffItem  `json:"items"`
	Counts      map[string]int `json:"counts"`
	Note        string         `json:"note,omitempty"`
}

type snap struct {
	etype  string
	up     bool
	stable map[string]any
	fp     string
}

// snapshot – najnowsza obserwacja każdej encji w przebiegu (pełna, jeśli była).
func (a *App) snapshot(ctx context.Context, runID string) map[string]snap {
	m := map[string]snap{}
	rows, err := a.DB.Query(ctx, `select distinct on (entity_key) entity_key, entity_type, up, stable, stable_fp from observations where run_id=$1
		order by entity_key, (stable_fp<>'') desc, observed_at desc, id desc`, runID)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var s snap
		var raw []byte
		rows.Scan(&k, &s.etype, &s.up, &raw, &s.fp)
		json.Unmarshal(raw, &s.stable)
		m[k] = s
	}
	return m
}

// DiffRuns porównuje dwa przebiegi wyłącznie na wspólnym pokryciu (sekcja 6.2).
func (a *App) DiffRuns(ctx context.Context, idA, idB string) (*RunDiff, error) {
	ra, err := a.GetRun(ctx, idA)
	if err != nil {
		return nil, err
	}
	rb, err := a.GetRun(ctx, idB)
	if err != nil {
		return nil, err
	}
	if ra.CreatedAt.After(rb.CreatedAt) {
		ra, rb = rb, ra
	}
	ca, cb := a.runCoverage(ctx, ra.ID), a.runCoverage(ctx, rb.ID)
	d := &RunDiff{Counts: map[string]int{"ADDED": 0, "REMOVED": 0, "CHANGED": 0}}
	brief := func(r *Run) map[string]any {
		return map[string]any{"id": r.ID, "group": r.GroupName, "mode": r.Mode, "status": r.Status, "created_at": r.CreatedAt, "finished_at": r.FinishedAt, "source": r.Source}
	}
	d.RunA, d.RunB = brief(ra), brief(rb)
	common := netx.Intersect(ca.Ranges, cb.Ranges)
	d.CommonAddrs = netx.Total(common)
	d.OnlyA = netx.Total(ca.Ranges) - d.CommonAddrs
	d.OnlyBAddrs = netx.Total(cb.Ranges) - d.CommonAddrs
	for p := range ca.TCP {
		if cb.TCP[p] {
			d.CommonTCP++
		}
	}
	both := func(key string) bool { return ca.Covers(key) && cb.Covers(key) }
	sa, sb := a.snapshot(ctx, ra.ID), a.snapshot(ctx, rb.ID)
	keys := map[string]bool{}
	for k, s := range sa {
		if s.up {
			keys[k] = true
		}
	}
	for k, s := range sb {
		if s.up {
			keys[k] = true
		}
	}
	for _, k := range sortedKeys(keys) {
		if !both(k) {
			continue
		}
		x, okA := sa[k]
		y, okB := sb[k]
		upA, upB := okA && x.up, okB && y.up
		etype := x.etype
		if etype == "" {
			etype = y.etype
		}
		item := RunDiffItem{EntityType: etype, Key: k, IP: keyIP(k)}
		switch {
		case upA && !upB:
			item.Kind, item.Summary = "REMOVED", "brak odpowiedzi w przebiegu B"
		case !upA && upB:
			item.Kind, item.Summary = "ADDED", "pojawiło się w przebiegu B"
		case x.fp != "" && y.fp != "" && x.fp != y.fp:
			f := diffStable(x.stable, y.stable)
			if etype == "host" {
				// zmiana zestawu portów hosta jest raportowana na poziomie usług
				var keep []FieldDiff
				for _, fd := range f {
					if fd.Field != "open_ports" {
						keep = append(keep, fd)
					}
				}
				f = keep
			}
			if len(f) == 0 {
				continue
			}
			item.Kind, item.Fields = "CHANGED", f
			item.Summary = "zmienione pola: " + fieldList(f)
		default:
			continue
		}
		d.Counts[item.Kind]++
		d.Items = append(d.Items, item)
	}
	sort.SliceStable(d.Items, func(i, j int) bool {
		if d.Items[i].IP != d.Items[j].IP {
			return ipLess(d.Items[i].IP, d.Items[j].IP)
		}
		return d.Items[i].Key < d.Items[j].Key
	})
	if d.OnlyA > 0 || d.OnlyBAddrs > 0 {
		d.Note = "Część adresów została przeskanowana tylko w jednym z przebiegów – nie są one porównywane (brak fałszywych „zniknięć”)."
	}
	if d.Items == nil {
		d.Items = []RunDiffItem{}
	}
	return d, nil
}

func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) == 4 && len(pb) == 4 {
		for i := 0; i < 4; i++ {
			x, y := atoi(pa[i]), atoi(pb[i])
			if x != y {
				return x < y
			}
		}
		return false
	}
	return a < b
}

var _ = time.Now
