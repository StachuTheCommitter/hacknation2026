// Package rbac: katalog uprawnień i role domyślne (wymagania 12–13).
package rbac

import "sort"

// Permission to nazwane uprawnienie.
type Permission struct {
	Name  string `json:"name"`
	Group string `json:"group"`
	Label string `json:"label"`
}

// Catalog – pełna lista uprawnień w systemie.
var Catalog = []Permission{
	{"users:manage", "Administracja", "Zarządzanie użytkownikami"},
	{"roles:manage", "Administracja", "Tworzenie i edycja ról"},
	{"settings:manage", "Administracja", "Ustawienia, scope, DefectDojo, klucze, workery"},
	{"audit:read", "Administracja", "Podgląd dziennika audytu"},
	{"killswitch:use", "Administracja", "Wyłącznik awaryjny skanów"},

	{"targets:read", "Cele", "Podgląd celów i grup"},
	{"targets:create", "Cele", "Dodawanie celów i grup"},
	{"targets:update", "Cele", "Edycja celów i grup"},
	{"targets:delete", "Cele", "Usuwanie celów i grup"},

	{"config:read", "Konfiguracja", "Podgląd profili, harmonogramów, okien"},
	{"config:create", "Konfiguracja", "Tworzenie profili, harmonogramów, okien"},
	{"config:update", "Konfiguracja", "Edycja profili, harmonogramów, okien"},
	{"config:delete", "Konfiguracja", "Usuwanie profili, harmonogramów, okien"},

	{"scans:read", "Skany", "Podgląd przebiegów"},
	{"scans:start", "Skany", "Uruchamianie przebiegów"},
	{"scans:control", "Skany", "Pauza, wznowienie, anulowanie przebiegu"},
	{"scans:delete", "Skany", "Usuwanie przebiegów"},

	{"results:read", "Wyniki", "Podgląd inwentarza, zmian, diffów"},
	{"results:create", "Wyniki", "Dodawanie obserwacji (formularz, import)"},
	{"results:update", "Wyniki", "Nadpisania, tagi, notatki, wyciszenia"},
	{"results:delete", "Wyniki", "Usuwanie danych z importu i formularza"},
	{"sensitive:read", "Wyniki", "Odsłanianie danych wrażliwych"},
	{"export:use", "Wyniki", "Eksport JSON/CSV"},

	{"signatures:read", "Sygnatury", "Podgląd sygnatur"},
	{"signatures:create", "Sygnatury", "Tworzenie i import sygnatur"},
	{"signatures:update", "Sygnatury", "Edycja sygnatur, retro-hunting"},
	{"signatures:delete", "Sygnatury", "Usuwanie sygnatur"},

	{"defectdojo:push", "DefectDojo", "Wysyłanie znalezisk"},
	{"defectdojo:triage", "DefectDojo", "Oznaczanie FP / risk accepted, synchronizacja"},
}

// Public oznacza trasę dostępną bez logowania; Authenticated – dla każdego zalogowanego.
const (
	Public        = "@public"
	Authenticated = "@auth"
)

func Known(p string) bool {
	for _, c := range Catalog {
		if c.Name == p {
			return true
		}
	}
	return false
}

// Role systemowe.
const (
	RoleAdmin    = "ADMIN"
	RoleEditor   = "EDITOR"
	RoleModifier = "MODIFIER"
	RoleViewer   = "VIEWER"
)

type DefaultRole struct {
	Name        string
	Description string
	Perms       []string
}

func all() []string {
	out := make([]string, 0, len(Catalog))
	for _, c := range Catalog {
		out = append(out, c.Name)
	}
	return out
}

var reads = []string{"targets:read", "config:read", "scans:read", "results:read", "signatures:read", "export:use"}

func with(base []string, extra ...string) []string {
	m := map[string]bool{}
	for _, p := range append(append([]string{}, base...), extra...) {
		m[p] = true
	}
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Defaults – cztery role wymagane przez treść zadania.
var Defaults = []DefaultRole{
	{RoleAdmin, "Administracja – pełny dostęp", all()},
	{RoleEditor, "Dodawanie, usuwanie, modyfikacja", with(reads,
		"killswitch:use",
		"targets:create", "targets:update", "targets:delete",
		"config:create", "config:update", "config:delete",
		"scans:start", "scans:control", "scans:delete",
		"results:create", "results:update", "results:delete", "sensitive:read",
		"signatures:create", "signatures:update", "signatures:delete",
		"defectdojo:push", "defectdojo:triage")},
	{RoleModifier, "Modyfikacja i odczyt", with(reads,
		"targets:update", "config:update", "signatures:update",
		"scans:control", "results:update", "sensitive:read", "defectdojo:triage")},
	{RoleViewer, "Odczyt", with(reads)},
}
