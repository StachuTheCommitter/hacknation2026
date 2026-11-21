package crypto

import (
	"bytes"
	"testing"
)

func TestEnvelope(t *testing.T) {
	k := NewKeyring(Random(32))
	w, _ := k.Wrap(1, Random(32))
	if err := k.AddWrapped(1, "data", w, true); err != nil {
		t.Fatal(err)
	}
	hw, _ := k.Wrap(2, Random(32))
	k.AddWrapped(2, "hmac", hw, true)
	ct, err := k.Encrypt("t.c:1", []byte("tajne"))
	if err != nil {
		t.Fatal(err)
	}
	ct2, _ := k.Encrypt("t.c:1", []byte("tajne"))
	if bytes.Equal(ct, ct2) {
		t.Fatal("nonce musi być losowy przy każdym szyfrowaniu")
	}
	if pt, err := k.Decrypt("t.c:1", ct); err != nil || string(pt) != "tajne" {
		t.Fatal("odszyfrowanie", err)
	}
	if _, err := k.Decrypt("t.c:2", ct); err == nil {
		t.Fatal("szyfrogram przeniesiony do innego wiersza (inne AAD) musi zostać odrzucony")
	}
	if KeyID(ct) != 1 {
		t.Fatal("key id")
	}
	if k.MAC("a", "b") == k.MAC("ab") {
		t.Fatal("HMAC musi rozdzielać części")
	}
	other := NewKeyring(Random(32))
	if err := other.AddWrapped(1, "data", w, true); err == nil {
		t.Fatal("zły klucz główny musi być wykryty")
	}
}
