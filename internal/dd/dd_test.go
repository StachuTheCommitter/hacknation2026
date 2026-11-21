package dd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Atrapa API v2: sprawdza nagłówek tokenu, pola multipart importu/reimportu i paginację findings.
func TestClientAgainstMock(t *testing.T) {
	var lastPath string
	var lastFields map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token secret" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/api/v2/import-scan/" || r.URL.Path == "/api/v2/reimport-scan/":
			r.ParseMultipartForm(1 << 20)
			lastPath = r.URL.Path
			lastFields = map[string]string{}
			for k, v := range r.MultipartForm.Value {
				lastFields[k] = v[0]
			}
			f, _, _ := r.FormFile("file")
			b, _ := io.ReadAll(f)
			var doc struct{ Findings []Finding }
			if json.Unmarshal(b, &doc) != nil || len(doc.Findings) != 1 {
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"test": 42})
		case r.URL.Path == "/api/v2/findings/" && r.URL.Query().Get("offset") == "":
			json.NewEncoder(w).Encode(map[string]any{"next": "http://x/api/v2/findings/?test=42&offset=1", "results": []any{map[string]any{"id": 1, "unique_id_from_tool": "asi:a", "false_p": true}}})
		case r.URL.Path == "/api/v2/findings/":
			json.NewEncoder(w).Encode(map[string]any{"next": nil, "results": []any{map[string]any{"id": 2, "unique_id_from_tool": "asi:b", "active": true}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "secret", false)
	f := []byte(`{"findings":[{"title":"t","severity":"Info","description":"d","unique_id_from_tool":"asi:a"}]}`)
	id, _, err := c.Import(context.Background(), ImportParams{ScanType: "Generic Findings Import", Product: "ASI", ProductType: "ASI", Engagement: "E", TestTitle: "T", FileName: "f.json", File: f})
	if err != nil || id != 42 || lastPath != "/api/v2/import-scan/" || lastFields["auto_create_context"] != "true" {
		t.Fatalf("import: %v %d %s %v", err, id, lastPath, lastFields)
	}
	if _, _, err := c.Import(context.Background(), ImportParams{ScanType: "Generic Findings Import", TestID: 42, CloseOld: true, FileName: "f.json", File: f}); err != nil ||
		lastPath != "/api/v2/reimport-scan/" || lastFields["test"] != "42" || lastFields["close_old_findings"] != "true" {
		t.Fatalf("reimport: %v %s %v", err, lastPath, lastFields)
	}
	list, err := c.Findings(context.Background(), 42)
	if err != nil || len(list) != 2 || list[0].Status() != "false_positive" || list[1].Status() != "open" {
		t.Fatalf("findings: %v %+v", err, list)
	}
	bad := New(srv.URL, "zly", false)
	if _, _, err := bad.Import(context.Background(), ImportParams{File: f}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatal("brak błędu przy złym tokenie")
	}
}
