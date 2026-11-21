package api

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"asi/internal/rbac"
)

// Każda trasa API musi deklarować uprawnienie, a trasy modyfikujące nie mogą być publiczne.
func TestRoutesDeclarePermissions(t *testing.T) {
	s := &Server{}
	s.routes()
	if len(s.Routes) < 80 {
		t.Fatalf("za mało tras: %d", len(s.Routes))
	}
	for _, r := range s.Routes {
		switch {
		case r.Perm == "":
			t.Errorf("%s %s: brak uprawnienia", r.Method, r.Path)
		case r.Perm == rbac.Public && r.Path != "/api/v1/auth/login":
			t.Errorf("%s %s: publiczna trasa", r.Method, r.Path)
		case r.Perm != rbac.Public && r.Perm != rbac.Authenticated && !rbac.Known(r.Perm):
			t.Errorf("%s %s: nieznane uprawnienie %s", r.Method, r.Path, r.Perm)
		}
	}
}

// Macierz RBAC: trasa × rola domyślna. ASI_WRITE_RBAC=1 zapisuje ją do docs/RBAC.md.
func TestRBACMatrix(t *testing.T) {
	s := &Server{}
	s.routes()
	roles := map[string]map[string]bool{}
	for _, d := range rbac.Defaults {
		roles[d.Name] = map[string]bool{}
		for _, p := range d.Perms {
			roles[d.Name][p] = true
		}
	}
	allowed := func(role, perm string) bool { return perm == rbac.Public || perm == rbac.Authenticated || roles[role][perm] }
	// POST-y tylko obliczeniowe (bez zmiany stanu): walidacja, estymacja, test sygnatury, ocena trafności
	readOnly := map[string]bool{"/api/v1/targets/validate": true, "/api/v1/estimate": true, "/api/v1/eval": true,
		"/api/v1/signatures/validate": true, "/api/v1/signatures/test": true}
	// kontrola wymagań: VIEWER nie modyfikuje niczego poza sesją; MODIFIER nie tworzy i nie usuwa
	for _, r := range s.Routes {
		if r.Method != http.MethodGet && !readOnly[r.Path] && allowed(rbac.RoleViewer, r.Perm) && !strings.HasPrefix(r.Path, "/api/v1/auth/") && r.Perm != rbac.Authenticated {
			t.Errorf("VIEWER może wywołać %s %s", r.Method, r.Path)
		}
		if allowed(rbac.RoleModifier, r.Perm) && (strings.HasSuffix(r.Perm, ":create") || strings.HasSuffix(r.Perm, ":delete") || r.Perm == "scans:start") {
			t.Errorf("MODIFIER może tworzyć/usuwać: %s %s", r.Method, r.Path)
		}
	}
	if os.Getenv("ASI_WRITE_RBAC") == "" {
		return
	}
	var b strings.Builder
	b.WriteString("# Macierz RBAC – trasy API × role domyślne\n\nWygenerowane testem `TestRBACMatrix` (`ASI_WRITE_RBAC=1 go test ./internal/api -run RBACMatrix`).\n\n")
	b.WriteString("| Metoda | Ścieżka | Uprawnienie | ADMIN | EDITOR | MODIFIER | VIEWER |\n|---|---|---|:-:|:-:|:-:|:-:|\n")
	rs := append([]Route(nil), s.Routes...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].Path+rs[i].Method < rs[j].Path+rs[j].Method })
	mark := func(ok bool) string {
		if ok {
			return "✔"
		}
		return "403"
	}
	for _, r := range rs {
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | %s | %s |\n", r.Method, strings.TrimPrefix(r.Path, "/api/v1"), r.Perm,
			mark(allowed(rbac.RoleAdmin, r.Perm)), mark(allowed(rbac.RoleEditor, r.Perm)), mark(allowed(rbac.RoleModifier, r.Perm)), mark(allowed(rbac.RoleViewer, r.Perm)))
	}
	if err := os.WriteFile("../../docs/RBAC.md", []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
