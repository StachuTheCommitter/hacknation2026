// Package core: logika control plane – cele, przebiegi, dispatcher, analiza, zmiany, findings.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"asi/internal/config"
	"asi/internal/crypto"
	"asi/internal/db"
)

type App struct {
	DB     *pgxpool.Pool
	Keys   *crypto.Keyring
	Cfg    config.Config
	Th     config.Thresholds
	Events *Broker
	Sigs   *SigStore

	finalizeMu sync.Mutex
	dispatchMu sync.Mutex
}

// Actor – kto wykonuje operację (do audytu i pól created_by).
type Actor struct {
	UserID string
	Email  string
	IP     string
	Perms  map[string]bool
}

func (a Actor) Name() string {
	if a.Email != "" {
		return a.Email
	}
	return "system"
}

func (a Actor) Can(p string) bool { return a.Perms[p] }

var System = Actor{Email: "system"}

// ErrNotFound / ErrInvalid – błędy mapowane przez API na 404 / 400.
var (
	ErrNotFound = errors.New("nie znaleziono")
	ErrConflict = errors.New("konflikt")
)

// InvalidError – błąd walidacji z listą szczegółów.
type InvalidError struct {
	Msg     string
	Details any
}

func (e *InvalidError) Error() string { return e.Msg }

func Invalid(msg string, details any) error { return &InvalidError{msg, details} }

// New łączy się z bazą, migruje, ładuje klucze i inicjalizuje dane startowe.
func New(ctx context.Context, cfg config.Config) (*App, error) {
	if cfg.MasterKey == "" {
		return nil, errors.New("brak ASI_MASTER_KEY (wygeneruj: asi keygen)")
	}
	master, err := crypto.ParseMasterKey(cfg.MasterKey)
	if err != nil {
		return nil, err
	}
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx, pool); err != nil {
		return nil, err
	}
	a := &App{DB: pool, Keys: crypto.NewKeyring(master), Cfg: cfg, Th: cfg.Thresholds(), Events: NewBroker()}
	if err := a.loadKeys(ctx); err != nil {
		return nil, err
	}
	a.Sigs = &SigStore{app: a}
	if err := a.Seed(ctx); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	if err := a.Sigs.Reload(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *App) loadKeys(ctx context.Context) error {
	var n int
	if err := a.DB.QueryRow(ctx, `select count(*) from encryption_keys`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		for id, purpose := range map[uint32]string{1: "data", 2: "hmac"} {
			w, err := a.Keys.Wrap(id, crypto.Random(32))
			if err != nil {
				return err
			}
			if _, err := a.DB.Exec(ctx, `insert into encryption_keys(id,purpose,wrapped,active) values($1,$2,$3,true)`, id, purpose, w); err != nil {
				return err
			}
		}
		slog.Info("utworzono klucze danych")
	}
	rows, err := a.DB.Query(ctx, `select id,purpose,wrapped,active from encryption_keys where retired_at is null or purpose='data' order by id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int32
		var purpose string
		var w []byte
		var active bool
		if err := rows.Scan(&id, &purpose, &w, &active); err != nil {
			return err
		}
		if err := a.Keys.AddWrapped(uint32(id), purpose, w, active); err != nil {
			return err
		}
	}
	return rows.Err()
}

// RotateDataKey tworzy nowy aktywny klucz danych i przeszyfrowuje istniejące rekordy.
func (a *App) RotateDataKey(ctx context.Context, actor Actor) (int, error) {
	var maxID int32
	if err := a.DB.QueryRow(ctx, `select coalesce(max(id),0) from encryption_keys`).Scan(&maxID); err != nil {
		return 0, err
	}
	id := uint32(maxID + 1)
	w, err := a.Keys.Wrap(id, crypto.Random(32))
	if err != nil {
		return 0, err
	}
	old := a.Keys.ActiveID()
	if _, err := a.DB.Exec(ctx, `update encryption_keys set active=false where purpose='data'`); err != nil {
		return 0, err
	}
	if _, err := a.DB.Exec(ctx, `insert into encryption_keys(id,purpose,wrapped,active) values($1,'data',$2,true)`, id, w); err != nil {
		return 0, err
	}
	if err := a.Keys.AddWrapped(id, "data", w, true); err != nil {
		return 0, err
	}
	n, err := a.reencryptAll(ctx)
	if err != nil {
		return n, err
	}
	a.DB.Exec(ctx, `update encryption_keys set retired_at=now() where id=$1`, old)
	a.Audit(ctx, actor, "keys.rotate", "encryption_key", fmt.Sprint(id), map[string]any{"reencrypted": n, "retired": old})
	return n, nil
}

// encColumns – wszystkie kolumny szyfrowane wraz z wyrażeniem AAD.
var encColumns = []struct{ table, col, keyExpr, aadExpr string }{
	{"services", "raw_enc", "id::text", "'services.raw_enc:'||id::text"},
	{"http_endpoints", "raw_enc", "id::text", "'http_endpoints.raw_enc:'||id::text"},
	{"observations", "raw_enc", "id::text", "'observations.raw_enc:'||entity_key"},
	{"notes", "body_enc", "id::text", "'notes.body_enc:'||id::text"},
	{"targets", "note_enc", "id::text", "'targets.note_enc:'||id::text"},
	{"settings", "value_enc", "key", "'settings.value_enc:'||key"},
}

func (a *App) reencryptAll(ctx context.Context) (int, error) {
	total := 0
	active := a.Keys.ActiveID()
	for _, c := range encColumns {
		for {
			rows, err := a.DB.Query(ctx, fmt.Sprintf(`select %s, %s, %s from %s where %s is not null and get_byte(%s,1)*16777216+get_byte(%s,2)*65536+get_byte(%s,3)*256+get_byte(%s,4) <> $1 limit 500`,
				c.keyExpr, c.aadExpr, c.col, c.table, c.col, c.col, c.col, c.col, c.col), int64(active))
			if err != nil {
				return total, err
			}
			type item struct {
				k, aad string
				ct     []byte
			}
			var items []item
			for rows.Next() {
				var it item
				if err := rows.Scan(&it.k, &it.aad, &it.ct); err != nil {
					rows.Close()
					return total, err
				}
				if crypto.KeyID(it.ct) != active {
					items = append(items, it)
				}
			}
			rows.Close()
			if len(items) == 0 {
				break
			}
			for _, it := range items {
				aad := it.aad
				pt, err := a.Keys.Decrypt(aad, it.ct)
				if err != nil {
					return total, fmt.Errorf("%s.%s %s: %w", c.table, c.col, it.k, err)
				}
				nct, _ := a.Keys.Encrypt(aad, pt)
				if _, err := a.DB.Exec(ctx, fmt.Sprintf(`update %s set %s=$1 where %s=$2`, c.table, c.col, c.keyExpr), nct, it.k); err != nil {
					return total, err
				}
				total++
			}
		}
	}
	return total, nil
}

// ---------------- ustawienia ----------------

func (a *App) GetSetting(ctx context.Context, key string, v any) error {
	var raw []byte
	err := a.DB.QueryRow(ctx, `select value from settings where key=$1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (a *App) SetSetting(ctx context.Context, key string, v any) error {
	b, _ := json.Marshal(v)
	_, err := a.DB.Exec(ctx, `insert into settings(key,value) values($1,$2) on conflict(key) do update set value=$2, updated_at=now()`, key, b)
	return err
}

func (a *App) GetSecret(ctx context.Context, key string) (string, error) {
	var ct []byte
	err := a.DB.QueryRow(ctx, `select value_enc from settings where key=$1`, key).Scan(&ct)
	if errors.Is(err, pgx.ErrNoRows) || len(ct) == 0 {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	pt, err := a.Keys.Decrypt("settings.value_enc:"+key, ct)
	return string(pt), err
}

func (a *App) SetSecret(ctx context.Context, key, value string) error {
	ct, err := a.Keys.Encrypt("settings.value_enc:"+key, []byte(value))
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `insert into settings(key,value,value_enc) values($1,'{}',$2) on conflict(key) do update set value_enc=$2, updated_at=now()`, key, ct)
	return err
}

// ---------------- audyt ----------------

func (a *App) Audit(ctx context.Context, actor Actor, action, objType, objID string, details map[string]any) {
	if details == nil {
		details = map[string]any{}
	}
	b, _ := json.Marshal(details)
	var uid any
	if actor.UserID != "" {
		uid = actor.UserID
	}
	if _, err := a.DB.Exec(ctx, `insert into audit_log(user_id,actor,action,object_type,object_id,details,ip) values($1,$2,$3,$4,$5,$6,$7)`,
		uid, actor.Name(), action, objType, objID, b, actor.IP); err != nil {
		slog.Error("audit", "err", err)
	}
}

// ---------------- zdarzenia (SSE) ----------------

type Event struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

type Broker struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func NewBroker() *Broker { return &Broker{subs: map[chan Event]struct{}{}} }

func (b *Broker) Subscribe() chan Event {
	ch := make(chan Event, 32)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broker) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

func (b *Broker) Publish(t string, data any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- Event{t, data}:
		default: // wolny odbiorca – pomijamy, UI i tak odświeży dane
		}
	}
}

// helpers

func nowUTC() time.Time { return time.Now().UTC() }

func jsonb(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
