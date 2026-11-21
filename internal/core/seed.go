package core

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"

	"asi/internal/auth"
	"asi/internal/crypto"
	"asi/internal/model"
	"asi/internal/rbac"
)

// Seed tworzy role domyślne, pierwszego administratora, profile, sygnatury wbudowane i (opcjonalnie) dane demo.
func (a *App) Seed(ctx context.Context) error {
	for _, r := range rbac.Defaults {
		var id string
		err := a.DB.QueryRow(ctx, `select id from roles where name=$1`, r.Name).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := a.DB.QueryRow(ctx, `insert into roles(name,description,is_system) values($1,$2,true) returning id`, r.Name, r.Description).Scan(&id); err != nil {
				return err
			}
			for _, p := range r.Perms {
				a.DB.Exec(ctx, `insert into role_permissions values($1,$2) on conflict do nothing`, id, p)
			}
		} else if err != nil {
			return err
		}
		if r.Name == rbac.RoleAdmin { // administrator zawsze ma komplet uprawnień
			for _, p := range r.Perms {
				a.DB.Exec(ctx, `insert into role_permissions values($1,$2) on conflict do nothing`, id, p)
			}
		}
	}
	if a.Cfg.BootstrapEmail != "" && a.Cfg.BootstrapPassword != "" {
		if err := a.ensureUser(ctx, a.Cfg.BootstrapEmail, "Administrator", a.Cfg.BootstrapPassword, rbac.RoleAdmin); err != nil {
			return err
		}
	}
	if a.Cfg.SeedDemoUsers {
		for _, u := range []struct{ email, name, role string }{
			{"admin@lab", "Admin (demo)", rbac.RoleAdmin},
			{"editor@lab", "Edytor (demo)", rbac.RoleEditor},
			{"modifier@lab", "Modyfikator (demo)", rbac.RoleModifier},
			{"viewer@lab", "Obserwator (demo)", rbac.RoleViewer},
		} {
			if err := a.ensureUser(ctx, u.email, u.name, "demo-password-"+strings.Split(u.email, "@")[0], u.role); err != nil {
				return err
			}
		}
	}
	for _, p := range []struct {
		name string
		mod  func(*model.Profile)
	}{
		{"Domyślny (top-1000)", func(p *model.Profile) {}},
		{"Szybki (top-100)", func(p *model.Profile) { p.TCPPorts = "top-100"; p.NmapIntensity = 5 }},
		{"Laboratorium", func(p *model.Profile) {
			p.TCPPorts = "top-1000,3000,6379,8081,8291,8443,9100,10000"
			p.UDPPorts = ""
			p.RetryDelaysSec = []int{20, 60}
		}},
		// porty z szablonu laboratorium organizatorów (usługi wystawione na portach hosta)
		{"Lab organizatorów (porty hosta)", func(p *model.Profile) {
			p.TCPPorts = "top-1000,21,80,81,443,2223,3001,5432,5672,5673,6379,8080-8090,8474,8666,8787,8888,15432,15672,15673,21000-21010"
			p.RetryDelaysSec = []int{20, 60}
			p.DiscoveryEngine = "none" // pojedynczy host: discovery zbędne, skanujemy porty bezpośrednio
			p.PortscanScope = "all"
		}},
		// mały cel (kilka hostów): wszystkie porty TCP – 65 535 × host przy 2000 pps to ok. 35 s
		{"Wszystkie porty (1-65535)", func(p *model.Profile) {
			p.TCPPorts = "1-65535"
			p.PortscanScope = "all"
			p.RetryDelaysSec = []int{20, 60}
		}},
	} {
		prof := model.DefaultProfile()
		p.mod(&prof)
		a.DB.Exec(ctx, `insert into scan_profiles(name,config) values($1,$2) on conflict(name) do nothing`, p.name, jsonb(prof))
	}
	if err := a.loadBuiltinSignatures(ctx); err != nil {
		return err
	}
	for _, t := range a.parseWorkerTokens() {
		var exists bool
		a.DB.QueryRow(ctx, `select true from workers where name=$1`, t[0]).Scan(&exists)
		if !exists {
			a.DB.Exec(ctx, `insert into workers(name,token_hash,status) values($1,$2,'new')`, t[0], auth.HashPassword(t[1]))
			slog.Info("zarejestrowano worker z konfiguracji", "name", t[0])
		}
	}
	if a.Cfg.DDURL != "" {
		var cfg DDConfig
		a.GetSetting(ctx, "defectdojo", &cfg)
		if cfg.URL == "" {
			cfg = DDConfig{URL: a.Cfg.DDURL, AutoPush: true, ProductType: "ASI", Product: "ASI", Engagement: "ASI Continuous Discovery"}
			a.SetSetting(ctx, "defectdojo", cfg)
			if a.Cfg.DDToken != "" {
				a.SetSecret(ctx, "dd_token", a.Cfg.DDToken)
			}
		}
	}
	if a.Cfg.SeedDemoLab {
		return a.seedLab(ctx)
	}
	return nil
}

func (a *App) parseWorkerTokens() [][2]string {
	var out [][2]string
	for _, p := range strings.Split(a.Cfg.WorkerTokens, ",") {
		kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(kv) == 2 && kv[0] != "" && kv[1] != "" {
			out = append(out, [2]string{kv[0], kv[1]})
		}
	}
	return out
}

func (a *App) ensureUser(ctx context.Context, email, name, pw, role string) error {
	var exists bool
	a.DB.QueryRow(ctx, `select true from users where email=$1`, email).Scan(&exists)
	if exists {
		return nil
	}
	_, err := a.DB.Exec(ctx, `insert into users(email,display_name,password_hash,role_id) values($1,$2,$3,(select id from roles where name=$4))`,
		email, name, auth.HashPassword(pw), role)
	if err == nil {
		slog.Info("utworzono użytkownika", "email", email, "role", role)
	}
	return err
}

// seedLab – scope, wykluczenia i grupy dla środowiska laboratoryjnego (sekcja 23).
func (a *App) seedLab(ctx context.Context) error {
	var n int
	a.DB.QueryRow(ctx, `select count(*) from target_groups`).Scan(&n)
	if n > 0 {
		return nil
	}
	a.DB.Exec(ctx, `insert into scope_allow(cidr,note,created_by) values('10.77.0.0/16','Sieć laboratorium ASI','system') on conflict do nothing`)
	a.DB.Exec(ctx, `insert into exclusions(value,reason,created_by) values('10.77.250.0/24','Workery skanujące (nie skanujemy siebie)','system'),('10.77.0.1','Brama sieci Docker','system') on conflict do nothing`)
	var profID string
	a.DB.QueryRow(ctx, `select id from scan_profiles where name='Laboratorium'`).Scan(&profID)
	sys := System
	g1, err := a.CreateGroup(ctx, sys, GroupInput{Name: "Lab – usługi", Description: "Podsieci z usługami laboratorium (10.77.1.0–10.77.8.255)",
		ProfileID: profID, RatePPS: 2000, HTTPRPS: 40, MaxParallelSweeps: 2, MaxParallelProbes: 4, AlwaysAllowed: true})
	if err != nil {
		return err
	}
	if _, err := a.AddTargets(ctx, sys, g1.ID, []string{"10.77.1.0-10.77.8.255", "staging.lab.local", "portal.lab.local", "intranet.lab.local"}, "manual", []string{"lab"}); err != nil {
		return err
	}
	g2, err := a.CreateGroup(ctx, sys, GroupInput{Name: "Lab – cała sieć /16", Description: "65 536 adresów – demonstracja skali, podziału i okien czasowych",
		ProfileID: profID, RatePPS: 4500, HTTPRPS: 40, MaxParallelSweeps: 3, MaxParallelProbes: 4, AlwaysAllowed: true})
	if err != nil {
		return err
	}
	_, err = a.AddTargets(ctx, sys, g2.ID, []string{"10.77.0.0/16"}, "manual", []string{"lab", "scale"})
	slog.Info("utworzono dane laboratorium")
	return err
}

// GenerateWorkerToken tworzy (lub odnawia) token workera.
func (a *App) GenerateWorkerToken(ctx context.Context, actor Actor, name, vantage string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", Invalid("nazwa workera jest wymagana", nil)
	}
	tok := crypto.Token("asi_wk_", 24)
	_, err := a.DB.Exec(ctx, `insert into workers(name,token_hash,vantage) values($1,$2,$3)
		on conflict(name) do update set token_hash=$2, vantage=coalesce(nullif($3,''),workers.vantage)`, name, auth.HashPassword(tok), vantage)
	if err != nil {
		return "", err
	}
	a.Audit(ctx, actor, "worker.token", "worker", name, nil)
	return tok, nil
}
