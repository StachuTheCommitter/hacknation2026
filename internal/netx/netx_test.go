package netx

import "testing"

func TestParseTarget(t *testing.T) {
	ok := map[string]string{"10.0.0.1": "ip", "10.0.0.0/24": "cidr", "10.0.0.1-10.0.0.50": "range", "10.0.0.1-50": "range", "portal.lab.local": "domain", "2001:db8::1": "ip"}
	for in, kind := range ok {
		tg, err := ParseTarget(in)
		if err != nil || tg.Kind != kind {
			t.Errorf("%s: %v %v", in, tg.Kind, err)
		}
	}
	for _, bad := range []string{"10.0.0.0/8", "10.0.0.300", "foo bar", "10.0.0.9-10.0.0.1", ""} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q powinno być odrzucone", bad)
		}
	}
	tg, _ := ParseTarget("10.0.0.0/24")
	if Total(tg.Ranges) != 256 {
		t.Fatal("rozmiar /24")
	}
}

func TestCursorTake(t *testing.T) {
	rs := Merge([]Range{PrefixRange(mustPrefix("10.0.0.0/30")), PrefixRange(mustPrefix("10.0.1.0/30"))})
	c := Cursor{}
	var got uint64
	for Remaining(rs, c) > 0 {
		chunk, next := Take(rs, c, 3)
		got += Total(chunk)
		c = next
	}
	if got != 8 {
		t.Fatalf("pobrano %d adresów, oczekiwano 8", got)
	}
}

func TestScope(t *testing.T) {
	s := NewScope([]string{"10.77.0.0/16"}, []string{"10.77.250.0/24", "10.77.0.1"})
	if !s.Allowed("10.77.1.10") || s.Allowed("10.77.250.5") || s.Allowed("10.77.0.1") || s.Allowed("8.8.8.8") {
		t.Fatal("scope")
	}
	in, dropped := s.Clip([]Range{PrefixRange(mustPrefix("10.77.250.0/23"))})
	if Total(in) != 256 || dropped != 256 {
		t.Fatalf("clip: %d %d", Total(in), dropped)
	}
}

func TestPorts(t *testing.T) {
	ps, err := ParsePorts("22,80,8000-8002,top-100")
	if err != nil || len(ps) < 100 {
		t.Fatal(err, len(ps))
	}
	if FormatPorts([]int{1, 2, 3, 5, 7, 8}) != "1-3,5,7-8" {
		t.Fatal(FormatPorts([]int{1, 2, 3, 5, 7, 8}))
	}
	if top, _ := ParsePorts("top-1000"); len(top) != 1000 {
		t.Fatalf("top-1000 ma %d portów", len(top))
	}
}
