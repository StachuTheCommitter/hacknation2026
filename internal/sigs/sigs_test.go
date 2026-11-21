package sigs

import (
	"io/fs"
	"strings"
	"testing"

	"asi/signatures"
)

func TestBuiltinPackValid(t *testing.T) {
	files, _ := fs.Glob(signatures.Builtin, "builtin/*.yaml")
	if len(files) == 0 {
		t.Fatal("brak plików")
	}
	ids := map[string]bool{}
	n := 0
	for _, f := range files {
		b, _ := signatures.Builtin.ReadFile(f)
		list, err := ParseAll(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, s := range list {
			if errs := s.Validate(); len(errs) > 0 {
				t.Errorf("%s %s: %v", f, s.ID, errs)
			}
			if ids[s.ID] {
				t.Errorf("duplikat id %s", s.ID)
			}
			ids[s.ID] = true
			n++
		}
	}
	t.Logf("%d sygnatur", n)
}

func TestEvalAndUnsafe(t *testing.T) {
	src := `
id: t-wp
name: test
scope: http
technology:
  name: WordPress
  version_from: {part: body, regex: 'WordPress ([0-9.]+)'}
match:
  all:
    - {part: status, op: in, value: [200]}
    - any:
        - {part: header, name: X-Generator, op: icontains, value: wordpress}
        - {part: body, op: regex, value: 'content="WordPress'}
`
	list, err := ParseAll([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	s := list[0]
	if errs := s.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	sub := MapSubject{"status": {"200"}, "body": {`<meta name="generator" content="WordPress 6.4.2">`}}
	r := s.Eval(sub, true)
	if !r.Matched || r.Version != "6.4.2" {
		t.Fatalf("oczekiwano dopasowania 6.4.2: %+v", r)
	}
	sub["status"] = []string{"404"}
	if s.Eval(sub, false).Matched {
		t.Fatal("nie powinno pasować")
	}
	bad := `
id: bad-one
name: bad
scope: http
request: {method: POST, path: "/login?user=admin'--", body: "x=1", headers: {Cookie: a}}
match: {part: status, op: equals, value: 200}
`
	l2, _ := ParseAll([]byte(bad))
	errs := l2[0].Validate()
	joined := strings.Join(errs, "\n")
	for _, want := range []string{"GET i HEAD", "treści", "Accept", "payload"} {
		if !strings.Contains(joined, want) {
			t.Errorf("brak błędu %q w %v", want, errs)
		}
	}
}

func TestVersions(t *testing.T) {
	if CompareVersions("5.6.40", "8.1") >= 0 || CompareVersions("8.2.1", "8.1") <= 0 || CompareVersions("7.4", "7.4.0") != 0 {
		t.Fatal("porównanie wersji")
	}
}

func TestNuclei(t *testing.T) {
	src := `id: grafana-detect
info:
  name: Grafana Login Panel
  severity: info
  tags: panel,grafana
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    matchers-condition: and
    matchers:
      - type: word
        words: ["<title>Grafana</title>"]
      - type: status
        status: [200]
`
	if !LooksLikeNuclei([]byte(src)) {
		t.Fatal("nie rozpoznano")
	}
	l, err := FromNuclei([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if errs := l[0].Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if l[0].Request.Path != "/login" || l[0].Categories[0] != "admin_panel" {
		t.Fatalf("%+v", l[0])
	}
}
