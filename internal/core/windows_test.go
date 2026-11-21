package core

import (
	"testing"
	"time"
)

func TestEvalWindowsMidnight(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	ws := []Window{{DaysMask: 127, StartMin: 22 * 60, EndMin: 6 * 60, Kind: "full", RateFactor: 1}}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 18, h, m, 0, 0, loc) }
	if st := EvalWindows(ws, loc, false, at(23, 0)); !st.Open || st.Remaining != 7*3600 {
		t.Fatalf("23:00 powinno być w oknie (zostało 7 h): %+v", st)
	}
	if st := EvalWindows(ws, loc, false, at(3, 0)); !st.Open {
		t.Fatal("03:00 – okno z poprzedniego dnia")
	}
	st := EvalWindows(ws, loc, false, at(12, 0))
	if st.Open || st.NextOpen == nil || st.NextOpen.In(loc).Hour() != 22 {
		t.Fatalf("12:00 poza oknem, następne o 22:00: %+v", st)
	}
	// okno dzienne o niskim tempie + nocne pełne
	ws = append(ws, Window{DaysMask: 0b11111, StartMin: 8 * 60, EndMin: 16 * 60, Kind: "low_impact", RateFactor: 0.1})
	if st := EvalWindows(ws, loc, false, at(10, 0)); !st.Open || st.Kind != "low_impact" || st.RateFactor != 0.1 {
		t.Fatalf("10:00 w środę – okno niskiego tempa: %+v", st)
	}
	if st := EvalWindows(nil, loc, true, at(10, 0)); !st.Open || st.Remaining != -1 {
		t.Fatal("brak okien + always_allowed")
	}
}

func TestNoisyOR(t *testing.T) {
	if c := NoisyOR([]float64{0.8, 0.75}); c < 0.94 || c > 0.96 {
		t.Fatalf("noisy-OR 0.8,0.75 = %.3f", c)
	}
	if NoisyOR(nil) != 0 {
		t.Fatal("brak dowodów = 0")
	}
}

func TestDiffStable(t *testing.T) {
	d := diffStable(map[string]any{"title": "a", "tech": []string{"x"}, "server": ""}, map[string]any{"title": "b", "tech": []any{"x"}})
	if len(d) != 1 || d[0].Field != "title" {
		t.Fatalf("%+v", d)
	}
}
