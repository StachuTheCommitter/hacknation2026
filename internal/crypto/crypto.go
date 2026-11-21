// Package crypto: szyfrowanie pól w aplikacji (AES-256-GCM, envelope KEK/DEK) i odciski HMAC-SHA256.
//
// Format szyfrogramu: 0x01 | key_id (4 B, big endian) | nonce (12 B, losowy przy każdym szyfrowaniu) | ciphertext+tag.
// AAD wiąże szyfrogram z miejscem zapisu ("tabela.kolumna:klucz") – nie da się go przenieść do innego wiersza.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

const version byte = 0x01

var ErrNoKey = errors.New("crypto: nieznany identyfikator klucza")

// Keyring przechowuje odwinięte klucze danych.
type Keyring struct {
	mu       sync.RWMutex
	master   []byte
	data     map[uint32][]byte
	activeID uint32
	hmacKey  []byte
}

// ParseMasterKey dekoduje 32-bajtowy klucz główny z base64.
func ParseMasterKey(b64 string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("ASI_MASTER_KEY: niepoprawny base64: %w", err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("ASI_MASTER_KEY: oczekiwano 32 bajtów, jest %d", len(k))
	}
	return k, nil
}

// NewMasterKey generuje nowy klucz główny (base64).
func NewMasterKey() string {
	return base64.StdEncoding.EncodeToString(Random(32))
}

func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func NewKeyring(master []byte) *Keyring {
	return &Keyring{master: master, data: map[uint32][]byte{}}
}

// Wrap szyfruje klucz danych kluczem głównym.
func (k *Keyring) Wrap(id uint32, dek []byte) ([]byte, error) {
	return seal(k.master, id, dek, []byte(fmt.Sprintf("dek:%d", id)))
}

// AddWrapped odwija i rejestruje klucz danych.
func (k *Keyring) AddWrapped(id uint32, purpose string, wrapped []byte, active bool) error {
	dek, err := open(func(uint32) ([]byte, error) { return k.master, nil }, wrapped, []byte(fmt.Sprintf("dek:%d", id)))
	if err != nil {
		return fmt.Errorf("odwijanie klucza %d: %w (czy ASI_MASTER_KEY jest właściwy?)", id, err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	switch purpose {
	case "data":
		k.data[id] = dek
		if active {
			k.activeID = id
		}
	case "hmac":
		if active || k.hmacKey == nil {
			k.hmacKey = dek
		}
	}
	return nil
}

func (k *Keyring) ActiveID() uint32 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.activeID
}

// Encrypt szyfruje aktywnym kluczem danych. Pusty tekst → nil.
func (k *Keyring) Encrypt(aad string, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	k.mu.RLock()
	id, key := k.activeID, k.data[k.activeID]
	k.mu.RUnlock()
	if key == nil {
		return nil, ErrNoKey
	}
	return seal(key, id, plaintext, []byte(aad))
}

// MustEncrypt – wersja dla miejsc, w których brak klucza jest błędem programisty.
func (k *Keyring) MustEncrypt(aad string, plaintext []byte) []byte {
	b, err := k.Encrypt(aad, plaintext)
	if err != nil {
		panic(err)
	}
	return b
}

// Decrypt odszyfrowuje dowolnym znanym kluczem.
func (k *Keyring) Decrypt(aad string, ct []byte) ([]byte, error) {
	if len(ct) == 0 {
		return nil, nil
	}
	return open(func(id uint32) ([]byte, error) {
		k.mu.RLock()
		defer k.mu.RUnlock()
		key := k.data[id]
		if key == nil {
			return nil, ErrNoKey
		}
		return key, nil
	}, ct, []byte(aad))
}

// KeyID zwraca identyfikator klucza użytego w szyfrogramie.
func KeyID(ct []byte) uint32 {
	if len(ct) < 5 {
		return 0
	}
	return binary.BigEndian.Uint32(ct[1:5])
}

// MAC liczy HMAC-SHA256 (hex, 32 znaki) z części danych.
func (k *Keyring) MAC(parts ...string) string {
	k.mu.RLock()
	key := k.hmacKey
	k.mu.RUnlock()
	m := hmac.New(sha256.New, key)
	for i, p := range parts {
		if i > 0 {
			m.Write([]byte{0x1f})
		}
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil)[:16])
}

func seal(key []byte, id uint32, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 5, 5+12+len(plaintext)+16)
	out[0] = version
	binary.BigEndian.PutUint32(out[1:5], id)
	nonce := Random(12)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

func open(keyFor func(uint32) ([]byte, error), ct, aad []byte) ([]byte, error) {
	if len(ct) < 5+12+16 || ct[0] != version {
		return nil, errors.New("crypto: niepoprawny format szyfrogramu")
	}
	key, err := keyFor(binary.BigEndian.Uint32(ct[1:5]))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, ct[5:17], ct[17:], aad)
}

// SHA256Hex – zwykły hash (np. tokenów sesji).
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Token generuje losowy token URL-safe.
func Token(prefix string, n int) string {
	return prefix + base64.RawURLEncoding.EncodeToString(Random(n))
}
