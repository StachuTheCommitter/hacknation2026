package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/auth"
	"asi/internal/crypto"
	"asi/internal/rbac"
)

const (
	sessionTTL  = 8 * time.Hour
	sessionIdle = 30 * time.Minute
)

type Session struct {
	Token string
	CSRF  string
}

var ErrAuth = errors.New("niepoprawny e-mail lub hasło")
var ErrLocked = errors.New("konto tymczasowo zablokowane po nieudanych próbach logowania")

// Login weryfikuje hasło (argon2id), blokuje po 5 próbach na 15 min i tworzy sesję.
func (a *App) Login(ctx context.Context, email, password, ip, ua string) (*Session, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var id, hash string
	var active bool
	var locked *time.Time
	err := a.DB.QueryRow(ctx, `select id, password_hash, is_active, locked_until from users where lower(email)=$1`, email).Scan(&id, &hash, &active, &locked)
	if err != nil {
		auth.CheckPassword("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA", password) // stały czas
		a.Audit(ctx, Actor{Email: email, IP: ip}, "auth.login_failed", "user", email, map[string]any{"reason": "unknown"})
		return nil, ErrAuth
	}
	if locked != nil && locked.After(time.Now()) {
		return nil, ErrLocked
	}
	if !active || !auth.CheckPassword(hash, password) {
		a.DB.Exec(ctx, `update users set failed_logins=failed_logins+1, locked_until=case when failed_logins+1>=5 then now()+interval '15 minutes' else locked_until end where id=$1`, id)
		a.Audit(ctx, Actor{UserID: id, Email: email, IP: ip}, "auth.login_failed", "user", id, nil)
		return nil, ErrAuth
	}
	a.DB.Exec(ctx, `update users set failed_logins=0, locked_until=null, last_login_at=now() where id=$1`, id)
	s := &Session{Token: crypto.Token("", 32), CSRF: crypto.Token("", 24)}
	_, err = a.DB.Exec(ctx, `insert into sessions(id_hash,user_id,csrf_hash,expires_at,ip,user_agent) values($1,$2,$3,$4,$5,$6)`,
		crypto.SHA256Hex([]byte(s.Token)), id, crypto.SHA256Hex([]byte(s.CSRF)), time.Now().Add(sessionTTL), ip, truncate(ua, 300))
	if err != nil {
		return nil, err
	}
	a.DB.Exec(ctx, `delete from sessions where expires_at < now()`)
	a.Audit(ctx, Actor{UserID: id, Email: email, IP: ip}, "auth.login", "user", id, nil)
	return s, nil
}

// SessionActor zwraca użytkownika sesji z uprawnieniami (i sprawdza hash CSRF dla metod modyfikujących).
func (a *App) SessionActor(ctx context.Context, token, csrf string, checkCSRF bool, ip string) (*Actor, error) {
	if token == "" {
		return nil, ErrAuth
	}
	var uid, email, csrfHash string
	var lastSeen time.Time
	err := a.DB.QueryRow(ctx, `select s.user_id, u.email, s.csrf_hash, s.last_seen_at from sessions s join users u on u.id=s.user_id
		where s.id_hash=$1 and s.expires_at>now() and u.is_active`, crypto.SHA256Hex([]byte(token))).Scan(&uid, &email, &csrfHash, &lastSeen)
	if err != nil {
		return nil, ErrAuth
	}
	if time.Since(lastSeen) > sessionIdle {
		a.DB.Exec(ctx, `delete from sessions where id_hash=$1`, crypto.SHA256Hex([]byte(token)))
		return nil, ErrAuth
	}
	if checkCSRF && crypto.SHA256Hex([]byte(csrf)) != csrfHash {
		return nil, errors.New("csrf")
	}
	if time.Since(lastSeen) > 30*time.Second {
		a.DB.Exec(ctx, `update sessions set last_seen_at=now() where id_hash=$1`, crypto.SHA256Hex([]byte(token)))
	}
	act := &Actor{UserID: uid, Email: email, IP: ip, Perms: map[string]bool{}}
	rows, _ := a.DB.Query(ctx, `select rp.permission from users u join role_permissions rp on rp.role_id=u.role_id where u.id=$1`, uid)
	for rows.Next() {
		var p string
		rows.Scan(&p)
		act.Perms[p] = true
	}
	rows.Close()
	return act, nil
}

func (a *App) Logout(ctx context.Context, token string, actor Actor) {
	a.DB.Exec(ctx, `delete from sessions where id_hash=$1`, crypto.SHA256Hex([]byte(token)))
	a.Audit(ctx, actor, "auth.logout", "user", actor.UserID, nil)
}

type Me struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Role        string   `json:"role"`
	RoleDesc    string   `json:"role_description"`
	Permissions []string `json:"permissions"`
}

func (a *App) Me(ctx context.Context, actor Actor) (*Me, error) {
	m := &Me{ID: actor.UserID, Email: actor.Email}
	err := a.DB.QueryRow(ctx, `select u.display_name, r.name, r.description from users u join roles r on r.id=u.role_id where u.id=$1`, actor.UserID).Scan(&m.DisplayName, &m.Role, &m.RoleDesc)
	for p := range actor.Perms {
		m.Permissions = append(m.Permissions, p)
	}
	return m, err
}

// ---------------- użytkownicy ----------------

type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	RoleID      string     `json:"role_id"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	LastLogin   *time.Time `json:"last_login_at"`
	LockedUntil *time.Time `json:"locked_until"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (a *App) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := a.DB.Query(ctx, `select u.id, u.email, u.display_name, u.role_id, r.name, u.is_active, u.last_login_at, u.locked_until, u.created_at
		from users u join roles r on r.id=u.role_id order by u.email`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[User])
}

type UserInput struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	RoleID      string `json:"role_id"`
	Password    string `json:"password"`
	IsActive    *bool  `json:"is_active"`
}

func (a *App) CreateUser(ctx context.Context, actor Actor, in UserInput) (string, error) {
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !strings.Contains(in.Email, "@") {
		return "", Invalid("niepoprawny e-mail", nil)
	}
	if err := auth.ValidatePassword(in.Password); err != nil {
		return "", Invalid(err.Error(), nil)
	}
	var id string
	err := a.DB.QueryRow(ctx, `insert into users(email,display_name,password_hash,role_id) values($1,$2,$3,$4) returning id`,
		in.Email, in.DisplayName, auth.HashPassword(in.Password), in.RoleID).Scan(&id)
	if err != nil {
		return "", Invalid("użytkownik już istnieje lub rola jest niepoprawna", nil)
	}
	a.Audit(ctx, actor, "user.create", "user", id, map[string]any{"email": in.Email, "role": in.RoleID})
	return id, nil
}

func (a *App) UpdateUser(ctx context.Context, actor Actor, id string, in UserInput) error {
	if in.RoleID != "" {
		// ochrona: nie można odebrać ostatniemu administratorowi uprawnienia users:manage
		var stillAdmin int
		a.DB.QueryRow(ctx, `select count(*) from users u join role_permissions rp on rp.role_id=u.role_id where rp.permission='users:manage' and u.is_active and u.id<>$1`, id).Scan(&stillAdmin)
		var newHas bool
		a.DB.QueryRow(ctx, `select exists(select 1 from role_permissions where role_id=$1 and permission='users:manage')`, in.RoleID).Scan(&newHas)
		if stillAdmin == 0 && !newHas {
			return Invalid("nie można odebrać uprawnień ostatniemu administratorowi", nil)
		}
		a.DB.Exec(ctx, `update users set role_id=$2 where id=$1`, id, in.RoleID)
		a.DB.Exec(ctx, `delete from sessions where user_id=$1`, id)
	}
	if in.DisplayName != "" {
		a.DB.Exec(ctx, `update users set display_name=$2 where id=$1`, id, in.DisplayName)
	}
	if in.Password != "" {
		if err := auth.ValidatePassword(in.Password); err != nil {
			return Invalid(err.Error(), nil)
		}
		a.DB.Exec(ctx, `update users set password_hash=$2, failed_logins=0, locked_until=null where id=$1`, id, auth.HashPassword(in.Password))
		a.DB.Exec(ctx, `delete from sessions where user_id=$1`, id)
	}
	if in.IsActive != nil {
		if !*in.IsActive && id == actor.UserID {
			return Invalid("nie można dezaktywować własnego konta", nil)
		}
		a.DB.Exec(ctx, `update users set is_active=$2 where id=$1`, id, *in.IsActive)
		if !*in.IsActive {
			a.DB.Exec(ctx, `delete from sessions where user_id=$1`, id)
		}
	}
	a.Audit(ctx, actor, "user.update", "user", id, map[string]any{"role": in.RoleID, "password_changed": in.Password != "", "active": in.IsActive})
	return nil
}

func (a *App) DeleteUser(ctx context.Context, actor Actor, id string) error {
	if id == actor.UserID {
		return Invalid("nie można usunąć własnego konta", nil)
	}
	ct, _ := a.DB.Exec(ctx, `delete from users where id=$1`, id)
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Audit(ctx, actor, "user.delete", "user", id, nil)
	return nil
}

// ---------------- role ----------------

type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsSystem    bool     `json:"is_system"`
	Permissions []string `json:"permissions"`
	Users       int      `json:"users"`
}

func (a *App) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := a.DB.Query(ctx, `select r.id, r.name, r.description, r.is_system, coalesce((select array_agg(permission order by permission) from role_permissions where role_id=r.id),'{}'),
		(select count(*) from users where role_id=r.id) from roles r order by r.is_system desc, r.created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Role])
}

func (a *App) SaveRole(ctx context.Context, actor Actor, r Role) (string, error) {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return "", Invalid("nazwa roli jest wymagana", nil)
	}
	for _, p := range r.Permissions {
		if !rbac.Known(p) {
			return "", Invalid("nieznane uprawnienie "+p, nil)
		}
	}
	if r.ID == "" {
		if err := a.DB.QueryRow(ctx, `insert into roles(name,description) values($1,$2) returning id`, r.Name, r.Description).Scan(&r.ID); err != nil {
			return "", Invalid("rola o tej nazwie już istnieje", nil)
		}
	} else {
		var name string
		var sys bool
		if a.DB.QueryRow(ctx, `select name, is_system from roles where id=$1`, r.ID).Scan(&name, &sys) != nil {
			return "", ErrNotFound
		}
		if name == rbac.RoleAdmin {
			return "", Invalid("rola ADMIN ma zawsze pełne uprawnienia i nie może być edytowana", nil)
		}
		if sys && r.Name != name {
			return "", Invalid("nie można zmienić nazwy roli systemowej", nil)
		}
		a.DB.Exec(ctx, `update roles set name=$2, description=$3 where id=$1`, r.ID, r.Name, r.Description)
	}
	a.DB.Exec(ctx, `delete from role_permissions where role_id=$1`, r.ID)
	for _, p := range r.Permissions {
		a.DB.Exec(ctx, `insert into role_permissions values($1,$2) on conflict do nothing`, r.ID, p)
	}
	a.Audit(ctx, actor, "role.save", "role", r.ID, map[string]any{"name": r.Name, "permissions": r.Permissions})
	return r.ID, nil
}

func (a *App) DeleteRole(ctx context.Context, actor Actor, id string) error {
	var sys bool
	var users int
	if a.DB.QueryRow(ctx, `select is_system, (select count(*) from users where role_id=$1) from roles where id=$1`, id).Scan(&sys, &users) != nil {
		return ErrNotFound
	}
	if sys {
		return Invalid("nie można usunąć roli systemowej", nil)
	}
	if users > 0 {
		return Invalid("rola jest przypisana do użytkowników", nil)
	}
	a.DB.Exec(ctx, `delete from roles where id=$1`, id)
	a.Audit(ctx, actor, "role.delete", "role", id, nil)
	return nil
}
