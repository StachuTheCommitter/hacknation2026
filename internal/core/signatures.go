package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"asi/internal/sigs"
	"asi/signatures"
)

// SigStore trzyma skompilowane, włączone sygnatury w pamięci.
type SigStore struct {
	app  *App
	mu   sync.RWMutex
	list []*sigs.Signature
}

func (s *SigStore) Reload(ctx context.Context) error {
	rows, err := s.app.DB.Query(ctx, `select source_text from signatures where enabled order by sig_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var list []*sigs.Signature
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			return err
		}
		parsed, err := sigs.ParseAll([]byte(src))
		if err != nil || len(parsed) == 0 {
			continue
		}
		sg := parsed[0]
		if len(sg.Validate()) == 0 && sg.IsEnabled() {
			list = append(list, sg)
		}
	}
	s.mu.Lock()
	s.list = list
	s.mu.Unlock()
	return rows.Err()
}

func (s *SigStore) All() []*sigs.Signature {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.list
}

// ActivePaths – unikalne ścieżki żądań sygnatur aktywnych (dla probera).
func (s *SigStore) ActivePaths() []string {
	m := map[string]bool{}
	for _, sg := range s.All() {
		for _, r := range sg.AllRequests() {
			m[r.Path] = true
		}
	}
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// SignatureRow – widok sygnatury dla API.
type SignatureRow struct {
	ID         string   `json:"id"`
	SigID      string   `json:"sig_id"`
	Name       string   `json:"name"`
	Version    int      `json:"version"`
	Kind       string   `json:"kind"`
	Scope      string   `json:"scope"`
	Enabled    bool     `json:"enabled"`
	Origin     string   `json:"origin"`
	Source     string   `json:"source"`
	Categories []string `json:"categories"`
	Severity   string   `json:"severity"`
	Priority   int      `json:"priority"`
	Matches    int      `json:"matches"`
	UpdatedAt  string   `json:"updated_at"`
	CreatedBy  string   `json:"created_by"`
}

func (a *App) ListSignatures(ctx context.Context) ([]SignatureRow, error) {
	rows, err := a.DB.Query(ctx, `select s.id, s.sig_id, s.name, s.version, s.kind, s.scope, s.enabled, s.origin, s.source_text,
		coalesce(s.definition->'categories','[]'::jsonb), coalesce(s.definition->>'severity','info'), coalesce((s.definition->>'priority')::int,0),
		(select count(*) from signature_matches m where m.sig_id=s.sig_id and m.active), to_char(s.updated_at,'YYYY-MM-DD HH24:MI'), s.created_by
		from signatures s order by s.origin desc, s.sig_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SignatureRow, error) {
		var x SignatureRow
		var cats []string
		err := r.Scan(&x.ID, &x.SigID, &x.Name, &x.Version, &x.Kind, &x.Scope, &x.Enabled, &x.Origin, &x.Source, &cats, &x.Severity, &x.Priority, &x.Matches, &x.UpdatedAt, &x.CreatedBy)
		x.Categories = cats
		return x, err
	})
}

// ParseSignature parsuje i waliduje pojedynczą sygnaturę (z adapterami formatów).
func ParseSignature(src string) (*sigs.Signature, []string) {
	list, err := ParseSignatures(src)
	if err != nil {
		return nil, []string{err.Error()}
	}
	if len(list) != 1 {
		return nil, []string{fmt.Sprintf("oczekiwano jednej sygnatury, znaleziono %d", len(list))}
	}
	sg := list[0]
	if errs := sg.Validate(); len(errs) > 0 {
		return sg, errs
	}
	return sg, nil
}

// ParseSignatures rozpoznaje format (ASI YAML/JSON lub szablon nuclei) i zwraca sygnatury.
func ParseSignatures(src string) ([]*sigs.Signature, error) {
	if sigs.LooksLikeNuclei([]byte(src)) {
		return sigs.FromNuclei([]byte(src))
	}
	return sigs.ParseAll([]byte(src))
}

func canonicalSource(sg *sigs.Signature, original string) string {
	if strings.TrimSpace(original) != "" && !sigs.LooksLikeNuclei([]byte(original)) {
		return strings.TrimSpace(original) + "\n"
	}
	b, _ := yaml.Marshal(sg)
	return string(b)
}

func kindOf(sg *sigs.Signature) string {
	if sg.Active() {
		return "active"
	}
	return "passive"
}

// SaveSignature tworzy lub aktualizuje sygnaturę (nowa wersja przy każdej edycji).
func (a *App) SaveSignature(ctx context.Context, actor Actor, src, origin string, create bool) (*SignatureRow, error) {
	sg, errs := ParseSignature(src)
	if len(errs) > 0 {
		return nil, Invalid("sygnatura niepoprawna", errs)
	}
	text := canonicalSource(sg, src)
	var exists bool
	var version int
	_ = a.DB.QueryRow(ctx, `select true, version from signatures where sig_id=$1`, sg.ID).Scan(&exists, &version)
	if create && exists {
		return nil, Invalid("sygnatura o tym id już istnieje", []string{"id: " + sg.ID})
	}
	if !create && !exists {
		return nil, ErrNotFound
	}
	if origin == "" {
		origin = "user"
	}
	enabled := sg.IsEnabled()
	if exists {
		version++
		_, err := a.DB.Exec(ctx, `update signatures set version=$2, kind=$3, scope=$4, name=$5, definition=$6, source_text=$7, enabled=$8, updated_at=now(),
			origin=case when origin='builtin' and $9<>'builtin' then 'builtin-modified' else origin end where sig_id=$1`,
			sg.ID, version, kindOf(sg), sg.Scope, sg.Name, jsonb(sg), text, enabled, origin)
		if err != nil {
			return nil, err
		}
	} else {
		version = 1
		_, err := a.DB.Exec(ctx, `insert into signatures(sig_id,version,kind,scope,name,definition,source_text,enabled,origin,created_by) values($1,1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			sg.ID, kindOf(sg), sg.Scope, sg.Name, jsonb(sg), text, enabled, origin, actor.Name())
		if err != nil {
			return nil, err
		}
	}
	a.DB.Exec(ctx, `insert into signature_history(sig_id,version,source_text,changed_by) values($1,$2,$3,$4)`, sg.ID, version, text, actor.Name())
	if err := a.Sigs.Reload(ctx); err != nil {
		return nil, err
	}
	a.Audit(ctx, actor, map[bool]string{true: "signature.create", false: "signature.update"}[create], "signature", sg.ID, map[string]any{"version": version})
	return a.GetSignature(ctx, sg.ID)
}

func (a *App) GetSignature(ctx context.Context, sigID string) (*SignatureRow, error) {
	list, err := a.ListSignatures(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range list {
		if s.SigID == sigID || s.ID == sigID {
			return &s, nil
		}
	}
	return nil, ErrNotFound
}

func (a *App) SetSignatureEnabled(ctx context.Context, actor Actor, sigID string, enabled bool) error {
	ct, err := a.DB.Exec(ctx, `update signatures set enabled=$2, updated_at=now() where sig_id=$1`, sigID, enabled)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	if !enabled {
		a.DB.Exec(ctx, `update signature_matches set active=false where sig_id=$1`, sigID)
	}
	a.Audit(ctx, actor, "signature.toggle", "signature", sigID, map[string]any{"enabled": enabled})
	return a.Sigs.Reload(ctx)
}

func (a *App) DeleteSignature(ctx context.Context, actor Actor, sigID string) error {
	ct, err := a.DB.Exec(ctx, `delete from signatures where sig_id=$1`, sigID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.DB.Exec(ctx, `delete from signature_matches where sig_id=$1`, sigID)
	a.Audit(ctx, actor, "signature.delete", "signature", sigID, nil)
	return a.Sigs.Reload(ctx)
}

// ImportSignatures importuje wiele sygnatur (YAML multi-doc, JSON, nuclei).
func (a *App) ImportSignatures(ctx context.Context, actor Actor, src string) (map[string]any, error) {
	list, err := ParseSignatures(src)
	if err != nil {
		return nil, Invalid(err.Error(), nil)
	}
	created, updated := 0, 0
	var errs []string
	for _, sg := range list {
		b, _ := yaml.Marshal(sg)
		var exists bool
		a.DB.QueryRow(ctx, `select true from signatures where sig_id=$1`, sg.ID).Scan(&exists)
		if _, err := a.SaveSignature(ctx, actor, string(b), "imported", !exists); err != nil {
			var ie *InvalidError
			if errors.As(err, &ie) {
				errs = append(errs, fmt.Sprintf("%s: %v", sg.ID, ie.Details))
			} else {
				errs = append(errs, fmt.Sprintf("%s: %v", sg.ID, err))
			}
			continue
		}
		if exists {
			updated++
		} else {
			created++
		}
	}
	return map[string]any{"created": created, "updated": updated, "errors": errs}, nil
}

// loadBuiltinSignatures wczytuje pakiet wbudowany (aktualizuje niezmodyfikowane przez użytkownika).
func (a *App) loadBuiltinSignatures(ctx context.Context) error {
	files, err := signatures.Builtin.ReadDir("builtin")
	if err != nil {
		return err
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		b, _ := signatures.Builtin.ReadFile("builtin/" + f.Name())
		list, err := sigs.ParseAll(b)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name(), err)
		}
		for _, sg := range list {
			if errs := sg.Validate(); len(errs) > 0 {
				return fmt.Errorf("%s/%s: %v", f.Name(), sg.ID, errs)
			}
			out, _ := yaml.Marshal(sg)
			var origin string
			var ver int
			err := a.DB.QueryRow(ctx, `select origin, version from signatures where sig_id=$1`, sg.ID).Scan(&origin, &ver)
			if errors.Is(err, pgx.ErrNoRows) {
				_, err = a.DB.Exec(ctx, `insert into signatures(sig_id,version,kind,scope,name,definition,source_text,enabled,origin,created_by) values($1,$2,$3,$4,$5,$6,$7,$8,'builtin','system')`,
					sg.ID, max(sg.Version, 1), kindOf(sg), sg.Scope, sg.Name, jsonb(sg), string(out), sg.IsEnabled())
				if err != nil {
					return err
				}
				continue
			}
			if origin == "builtin" && sg.Version > ver {
				a.DB.Exec(ctx, `update signatures set version=$2, kind=$3, scope=$4, name=$5, definition=$6, source_text=$7, updated_at=now() where sig_id=$1`,
					sg.ID, sg.Version, kindOf(sg), sg.Scope, sg.Name, jsonb(sg), string(out))
			}
		}
	}
	return nil
}
