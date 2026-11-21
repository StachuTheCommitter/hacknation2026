package prober

import "testing"

// Wektory referencyjne MurmurHash3 x86_32 (seed 0).
func TestMurmur3(t *testing.T) {
	cases := map[string]uint32{"": 0, "hello": 0x248bfa47, "The quick brown fox jumps over the lazy dog": 0x2e4ff723}
	for in, want := range cases {
		if got := murmur3([]byte(in)); got != want {
			t.Errorf("murmur3(%q)=%x, oczekiwano %x", in, got, want)
		}
	}
}
