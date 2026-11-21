package core

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Pola edytowalne per typ encji (wymóg 14).
var OverrideFields = map[string][]string{
	"host":    {"owner", "description", "category", "priority", "muted", "lifecycle", "os", "devicetype"},
	"service": {"service_name", "product", "version", "category", "priority", "muted", "description"},
	"http":    {"title", "technologies", "category", "priority", "muted", "description"},
}

func fieldAllowed(etype, field string) bool {
	for _, f := range OverrideFields[etype] {
		if f == field {
			return true
		}
	}
	return false
}

type OverrideView struct {
	Field        string    `json:"field"`
	Value        any       `json:"value"`
	ScannerValue any       `json:"scanner_value"`
	AtEdit       any       `json:"scanner_value_at_edit"`
	Conflict     bool      `json:"conflict"`
	By           string    `json:"by"`
	At           time.Time `json:"at"`
}

// scannerValue zwraca bieżącą wartość pola z danych skanera.
func (a *App) scannerValue(ctx context.Context, etype, key, field string) any {
	p := strings.Split(key, "/")
	ip := p[0]
	var v any
	switch etype {
	case "host":
		switch field {
		case "os", "devicetype":
			var s string
			a.DB.QueryRow(ctx, `select `+field+` from hosts where ip=$1::inet`, ip).Scan(&s)
			v = s
		case "category":
			var cats []string
			a.DB.QueryRow(ctx, `select coalesce(array_agg(distinct category order by category),'{}') from classifications c join hosts h on h.id=c.host_id where h.ip=$1::inet and c.active and c.confidence>=0.45`, ip).Scan(&cats)
			v = cats
		}
	case "service":
		if len(p) < 3 {
			return nil
		}
		switch field {
		case "service_name", "product", "version":
			var s string
			a.DB.QueryRow(ctx, `select s.`+field+` from services s join hosts h on h.id=s.host_id where h.ip=$1::inet and s.proto=$2 and s.port=$3`, ip, p[1], atoi(p[2])).Scan(&s)
			v = s
		case "category":
			var cats []string
			a.DB.QueryRow(ctx, `select coalesce(array_agg(distinct c.category order by c.category),'{}') from classifications c join services s on s.id=c.entity_id join hosts h on h.id=s.host_id
				where h.ip=$1::inet and s.proto=$2 and s.port=$3 and c.active and c.confidence>=0.45`, ip, p[1], atoi(p[2])).Scan(&cats)
			v = cats
		}
	case "http":
		id := a.httpIDByKey(ctx, key)
		switch field {
		case "title":
			var s string
			a.DB.QueryRow(ctx, `select title from http_endpoints where id=$1`, id).Scan(&s)
			v = s
		case "technologies":
			var t []string
			a.DB.QueryRow(ctx, `select coalesce(array_agg(name||case when version<>'' then ' '||version else '' end order by name),'{}') from technologies where entity_type='http' and entity_id=$1 and active`, id).Scan(&t)
			v = t
		case "category":
			var cats []string
			a.DB.QueryRow(ctx, `select coalesce(array_agg(category order by category),'{}') from classifications where entity_type='http' and entity_id=$1 and active and confidence>=0.45`, id).Scan(&cats)
			v = cats
		}
	}
	return v
}

func (a *App) httpIDByKey(ctx context.Context, key string) string {
	p := strings.Split(key, "/")
	if len(p) < 5 {
		return ""
	}
	vhost := p[4]
	if vhost == "-" {
		vhost = ""
	}
	var id string
	a.DB.QueryRow(ctx, `select e.id from http_endpoints e join services s on s.id=e.service_id join hosts h on h.id=e.host_id
		where h.ip=$1::inet and s.port=$2 and e.scheme=$3 and e.vhost=$4`, p[0], atoi(p[2]), p[3], vhost).Scan(&id)
	return id
}

func (a *App) SetOverride(ctx context.Context, actor Actor, etype, key, field string, value any) error {
	if !fieldAllowed(etype, field) {
		return Invalid("pole "+field+" nie jest edytowalne dla "+etype, OverrideFields[etype])
	}
	switch field {
	case "priority":
		f, ok := value.(float64)
		if !ok || f < 0 || f > 100 {
			return Invalid("priorytet musi być liczbą 0–100", nil)
		}
	case "muted":
		if _, ok := value.(bool); !ok {
			return Invalid("muted: true/false", nil)
		}
	}
	sv := a.scannerValue(ctx, etype, key, field)
	var old []byte
	a.DB.QueryRow(ctx, `select value from overrides where entity_type=$1 and entity_key=$2 and field=$3`, etype, key, field).Scan(&old)
	_, err := a.DB.Exec(ctx, `insert into overrides(entity_type,entity_key,field,value,scanner_value_at_edit,updated_by) values($1,$2,$3,$4,$5,$6)
		on conflict(entity_type,entity_key,field) do update set value=$4, scanner_value_at_edit=$5, updated_by=$6, updated_at=now()`,
		etype, key, field, jsonb(value), jsonb(sv), actor.Name())
	if err != nil {
		return err
	}
	a.DB.Exec(ctx, `insert into override_history(entity_type,entity_key,field,old_value,new_value,changed_by) values($1,$2,$3,$4,$5,$6)`, etype, key, field, old, jsonb(value), actor.Name())
	a.Audit(ctx, actor, "override.set", etype, key, map[string]any{"field": field})
	if field == "priority" || field == "muted" {
		a.RescoreKey(ctx, key)
	}
	return nil
}

func (a *App) DeleteOverride(ctx context.Context, actor Actor, etype, key, field string) error {
	var old []byte
	if a.DB.QueryRow(ctx, `delete from overrides where entity_type=$1 and entity_key=$2 and field=$3 returning value`, etype, key, field).Scan(&old) != nil {
		return ErrNotFound
	}
	a.DB.Exec(ctx, `insert into override_history(entity_type,entity_key,field,old_value,new_value,changed_by) values($1,$2,$3,$4,null,$5)`, etype, key, field, old, actor.Name())
	a.Audit(ctx, actor, "override.delete", etype, key, map[string]any{"field": field})
	if field == "priority" || field == "muted" {
		a.RescoreKey(ctx, key)
	}
	return nil
}

// ConfirmOverride – analityk potwierdza swoją wartość mimo zmiany wykrytej przez skaner.
func (a *App) ConfirmOverride(ctx context.Context, actor Actor, etype, key, field string) error {
	sv := a.scannerValue(ctx, etype, key, field)
	ct, _ := a.DB.Exec(ctx, `update overrides set scanner_value_at_edit=$4, updated_by=$5, updated_at=now() where entity_type=$1 and entity_key=$2 and field=$3`, etype, key, field, jsonb(sv), actor.Name())
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "override.confirm", etype, key, map[string]any{"field": field})
	return nil
}

// Overrides zwraca nadpisania encji z flagą konfliktu.
func (a *App) Overrides(ctx context.Context, etype, key string) map[string]OverrideView {
	out := map[string]OverrideView{}
	rows, err := a.DB.Query(ctx, `select field, value, scanner_value_at_edit, updated_by, updated_at from overrides where entity_type=$1 and entity_key=$2`, etype, key)
	if err != nil {
		return out
	}
	type row struct {
		f     string
		v, at []byte
		by    string
		when  time.Time
	}
	var rs []row
	for rows.Next() {
		var r row
		rows.Scan(&r.f, &r.v, &r.at, &r.by, &r.when)
		rs = append(rs, r)
	}
	rows.Close()
	for _, r := range rs {
		var v, at any
		json.Unmarshal(r.v, &v)
		json.Unmarshal(r.at, &at)
		sv := normalizeVal(a.scannerValue(ctx, etype, key, r.f))
		ov := OverrideView{Field: r.f, Value: v, ScannerValue: sv, AtEdit: at, By: r.by, At: r.when}
		if r.f != "priority" && r.f != "muted" && r.f != "description" && r.f != "owner" && r.f != "lifecycle" {
			ov.Conflict = !reflect.DeepEqual(normalizeVal(at), sv)
		}
		out[r.f] = ov
	}
	return out
}

// OverridesFor – nadpisania dla wielu kluczy (do list).
func (a *App) OverridesFor(ctx context.Context, etype string, keys []string) map[string]map[string]any {
	out := map[string]map[string]any{}
	if len(keys) == 0 {
		return out
	}
	rows, err := a.DB.Query(ctx, `select entity_key, field, value from overrides where entity_type=$1 and entity_key = any($2)`, etype, keys)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, f string
		var raw []byte
		rows.Scan(&k, &f, &raw)
		var v any
		json.Unmarshal(raw, &v)
		if out[k] == nil {
			out[k] = map[string]any{}
		}
		out[k][f] = v
	}
	return out
}

type OverrideHistory struct {
	Field string    `json:"field"`
	Old   any       `json:"old"`
	New   any       `json:"new"`
	By    string    `json:"by"`
	At    time.Time `json:"at"`
}

func (a *App) OverrideHistory(ctx context.Context, etype, key string) []OverrideHistory {
	rows, err := a.DB.Query(ctx, `select field, old_value, new_value, changed_by, changed_at from override_history where entity_type=$1 and entity_key=$2 order by changed_at desc limit 50`, etype, key)
	if err != nil {
		return nil
	}
	out, _ := pgx.CollectRows(rows, func(r pgx.CollectableRow) (OverrideHistory, error) {
		var h OverrideHistory
		var o, n []byte
		err := r.Scan(&h.Field, &o, &n, &h.By, &h.At)
		json.Unmarshal(o, &h.Old)
		json.Unmarshal(n, &h.New)
		return h, err
	})
	return out
}

// ---------------- tagi i notatki ----------------

type Tag struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
	Count int    `json:"count"`
}

func (a *App) ListTags(ctx context.Context) ([]Tag, error) {
	rows, err := a.DB.Query(ctx, `select t.id, t.name, t.color, (select count(*) from entity_tags e where e.tag_id=t.id) from tags t order by t.name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Tag])
}

func (a *App) TagEntity(ctx context.Context, actor Actor, etype, key, tag string, add bool) error {
	tag = strings.TrimSpace(strings.ToLower(tag))
	if tag == "" || len(tag) > 40 {
		return Invalid("niepoprawna nazwa tagu", nil)
	}
	var id string
	if err := a.DB.QueryRow(ctx, `insert into tags(name) values($1) on conflict(name) do update set name=excluded.name returning id`, tag).Scan(&id); err != nil {
		return err
	}
	if add {
		a.DB.Exec(ctx, `insert into entity_tags(entity_type,entity_key,tag_id,created_by) values($1,$2,$3,$4) on conflict do nothing`, etype, key, id, actor.Name())
	} else {
		a.DB.Exec(ctx, `delete from entity_tags where entity_type=$1 and entity_key=$2 and tag_id=$3`, etype, key, id)
	}
	a.Audit(ctx, actor, map[bool]string{true: "tag.add", false: "tag.remove"}[add], etype, key, map[string]any{"tag": tag})
	return nil
}

func (a *App) EntityTags(ctx context.Context, etype, key string) []string {
	var tags []string
	a.DB.QueryRow(ctx, `select coalesce(array_agg(t.name order by t.name),'{}') from entity_tags e join tags t on t.id=e.tag_id where e.entity_type=$1 and e.entity_key=$2`, etype, key).Scan(&tags)
	return tags
}

type Note struct {
	ID        string    `json:"id"`
	Body      string    `json:"body"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (a *App) AddNote(ctx context.Context, actor Actor, etype, key, body string) (string, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", Invalid("notatka jest pusta", nil)
	}
	var id string
	if err := a.DB.QueryRow(ctx, `insert into notes(entity_type,entity_key,body_enc,created_by) values($1,$2,'\x00',$3) returning id`, etype, key, actor.Name()).Scan(&id); err != nil {
		return "", err
	}
	ct, _ := a.Keys.Encrypt("notes.body_enc:"+id, []byte(body))
	a.DB.Exec(ctx, `update notes set body_enc=$2 where id=$1`, id, ct)
	a.Audit(ctx, actor, "note.add", etype, key, nil)
	return id, nil
}

func (a *App) DeleteNote(ctx context.Context, actor Actor, id string) error {
	ct, _ := a.DB.Exec(ctx, `delete from notes where id=$1`, id)
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "note.delete", "note", id, nil)
	return nil
}

func (a *App) Notes(ctx context.Context, etype, key string) []Note {
	rows, err := a.DB.Query(ctx, `select id, body_enc, created_by, created_at, updated_at from notes where entity_type=$1 and entity_key=$2 order by created_at desc`, etype, key)
	if err != nil {
		return nil
	}
	var out []Note
	for rows.Next() {
		var n Note
		var ct []byte
		rows.Scan(&n.ID, &ct, &n.CreatedBy, &n.CreatedAt, &n.UpdatedAt)
		if pt, err := a.Keys.Decrypt("notes.body_enc:"+n.ID, ct); err == nil {
			n.Body = string(pt)
		}
		out = append(out, n)
	}
	rows.Close()
	return out
}

// ---------------- wyciszenia ----------------

type Suppression struct {
	ID        string     `json:"id"`
	EntityKey string     `json:"entity_key"`
	SigID     string     `json:"sig_id"`
	Reason    string     `json:"reason"`
	Until     *time.Time `json:"until"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

func (a *App) ListSuppressions(ctx context.Context) ([]Suppression, error) {
	rows, err := a.DB.Query(ctx, `select id, entity_key, sig_id, reason, until, created_by, created_at from suppressions order by created_at desc`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Suppression])
}

func (a *App) AddSuppression(ctx context.Context, actor Actor, s Suppression) error {
	if s.EntityKey == "" && s.SigID == "" {
		return Invalid("podaj encję lub sygnaturę", nil)
	}
	_, err := a.DB.Exec(ctx, `insert into suppressions(entity_key,sig_id,reason,until,created_by) values($1,$2,$3,$4,$5)`, s.EntityKey, s.SigID, s.Reason, s.Until, actor.Name())
	if err == nil {
		a.Audit(ctx, actor, "suppression.add", "suppression", s.EntityKey+s.SigID, map[string]any{"reason": s.Reason})
		if s.EntityKey != "" {
			a.RescoreKey(ctx, s.EntityKey)
		}
	}
	return err
}

func (a *App) DeleteSuppression(ctx context.Context, actor Actor, id string) error {
	var key string
	if a.DB.QueryRow(ctx, `delete from suppressions where id=$1 returning entity_key`, id).Scan(&key) != nil {
		return ErrNotFound
	}
	if key != "" {
		a.RescoreKey(ctx, key)
	}
	a.Audit(ctx, actor, "suppression.delete", "suppression", id, nil)
	return nil
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
