package sigs

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Adapter podzbioru szablonów nuclei (http: word / regex / status / dsl z mmh3 favicony).
// Pozwala wykorzystać istniejące szablony detekcyjne bez uruchamiania nuclei.

type nucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string `yaml:"name"`
		Author      any    `yaml:"author"`
		Severity    string `yaml:"severity"`
		Description string `yaml:"description"`
		Tags        any    `yaml:"tags"`
	} `yaml:"info"`
	HTTP     []nucleiRequest `yaml:"http"`
	Requests []nucleiRequest `yaml:"requests"`
}

type nucleiRequest struct {
	Method            string          `yaml:"method"`
	Path              []string        `yaml:"path"`
	MatchersCondition string          `yaml:"matchers-condition"`
	Matchers          []nucleiMatcher `yaml:"matchers"`
	Redirects         bool            `yaml:"redirects"`
}

type nucleiMatcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Status          []int    `yaml:"status"`
	DSL             []string `yaml:"dsl"`
	Condition       string   `yaml:"condition"`
	Negative        bool     `yaml:"negative"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
}

// LooksLikeNuclei – heurystyka rozpoznania szablonu nuclei.
func LooksLikeNuclei(b []byte) bool {
	return bytes.Contains(b, []byte("{{BaseURL}}")) || (bytes.Contains(b, []byte("\ninfo:")) && (bytes.Contains(b, []byte("\nhttp:")) || bytes.Contains(b, []byte("\nrequests:"))))
}

var mmh3DSL = regexp.MustCompile(`"?(-?\d+)"?\s*==\s*mmh3\(base64_py\(body\)\)|mmh3\(base64_py\(body\)\)\s*==\s*"?(-?\d+)"?`)

// FromNuclei konwertuje szablon(y) nuclei do formatu ASI.
func FromNuclei(src []byte) ([]*Signature, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var out []*Signature
	for {
		var t nucleiTemplate
		if err := dec.Decode(&t); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("nuclei YAML: %w", err)
		}
		if t.ID == "" {
			continue
		}
		s, err := convertNuclei(t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.ID, err)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("brak szablonów nuclei")
	}
	return out, nil
}

func convertNuclei(t nucleiTemplate) (*Signature, error) {
	reqs := append(t.HTTP, t.Requests...)
	if len(reqs) != 1 {
		return nil, errors.New("obsługiwany jest dokładnie jeden blok http")
	}
	r := reqs[0]
	if len(r.Path) != 1 {
		return nil, errors.New("obsługiwana jest dokładnie jedna ścieżka")
	}
	path := strings.TrimPrefix(r.Path[0], "{{BaseURL}}")
	if path == "" {
		path = "/"
	}
	if strings.Contains(path, "{{") {
		return nil, errors.New("zmienne w ścieżce nie są obsługiwane")
	}
	sev := strings.ToLower(t.Info.Severity)
	if sev == "" || sev == "unknown" || sev == "critical" {
		sev = map[string]string{"critical": "high"}[sev]
		if sev == "" {
			sev = "info"
		}
	}
	tags := toStrings(t.Info.Tags)
	if len(tags) == 1 {
		tags = strings.Split(tags[0], ",")
	}
	s := &Signature{
		ID: "nuclei-" + strings.ToLower(t.ID), Name: t.Info.Name, Description: t.Info.Description, Scope: "http",
		Severity: sev, Confidence: 0.75, Priority: 20, Tags: tags, Version: 1,
		Request: &Request{Method: strings.ToUpper(r.Method), Path: path, FollowRedirects: r.Redirects},
	}
	for _, tg := range tags {
		switch strings.TrimSpace(tg) {
		case "panel":
			s.Categories = append(s.Categories, "admin_panel")
		case "tech":
			s.Categories = append(s.Categories, "technology")
		case "iot":
			s.Categories = append(s.Categories, "iot")
		}
	}
	var conds []Cond
	for _, m := range r.Matchers {
		c, err := convertMatcher(m)
		if err != nil {
			return nil, err
		}
		if m.Negative {
			c = Cond{Not: &c}
		}
		conds = append(conds, c)
	}
	if len(conds) == 0 {
		return nil, errors.New("brak matcherów")
	}
	if strings.EqualFold(r.MatchersCondition, "and") {
		s.Match = Cond{All: conds}
	} else {
		s.Match = Cond{Any: conds}
	}
	return s, nil
}

func nucleiPart(p string) string {
	switch p {
	case "header", "headers":
		return "headers_raw"
	case "", "body", "response", "all":
		return "body"
	}
	return "body"
}

func convertMatcher(m nucleiMatcher) (Cond, error) {
	group := func(cs []Cond) Cond {
		if strings.EqualFold(m.Condition, "and") {
			return Cond{All: cs}
		}
		return Cond{Any: cs}
	}
	switch m.Type {
	case "status":
		vals := make([]any, 0, len(m.Status))
		for _, s := range m.Status {
			vals = append(vals, s)
		}
		return Cond{Part: "status", Op: "in", Value: vals}, nil
	case "word":
		op := "contains"
		if m.CaseInsensitive {
			op = "icontains"
		}
		var cs []Cond
		for _, w := range m.Words {
			cs = append(cs, Cond{Part: nucleiPart(m.Part), Op: op, Value: w})
		}
		return group(cs), nil
	case "regex":
		var cs []Cond
		for _, re := range m.Regex {
			cs = append(cs, Cond{Part: nucleiPart(m.Part), Op: "regex", Value: re})
		}
		return group(cs), nil
	case "dsl":
		var cs []Cond
		for _, d := range m.DSL {
			mm := mmh3DSL.FindStringSubmatch(d)
			if mm == nil {
				return Cond{}, fmt.Errorf("nieobsługiwane wyrażenie dsl: %s", d)
			}
			h := mm[1]
			if h == "" {
				h = mm[2]
			}
			cs = append(cs, Cond{Part: "favicon_mmh3", Op: "equals", Value: h})
		}
		return group(cs), nil
	}
	return Cond{}, fmt.Errorf("nieobsługiwany typ matchera %q", m.Type)
}
