package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFactoryReset(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	// install-time hints must not come back after a reset
	t.Setenv("GM_DOMAIN", "env.example")
	t.Setenv("GM_TAILSCALE_IP", "100.64.0.9")
	seed := func() {
		f.set(func(d *Data) {
			d.Settings.Domain, d.Settings.WafParanoia = "example.com", 3
			d.Settings.TopoHops = []TopoHop{{Kind: "firewall"}}
			d.Services = []*Service{{ID: "s1", Subdomain: "photos", Upstream: "immich:2283", Exposure: ExposurePublic, Enabled: true}}
			d.AGroups, d.AGroupsInit = []AGroup{{Name: "family"}}, true
			d.ManagedDNS = []string{"photos.example.com"}
			d.CFWAF.ThreatRuleID = "r1"
			d.Dashboard = []Widget{{ID: "w1", Type: "stat"}}
			d.Roles = append(d.Roles, &Role{ID: "custom", Name: "맞춤", Perms: []string{"config"}})
			d.Dirty, d.Pending = true, []string{"x"}
		})
	}
	seed()
	secret := f.app.store.Snapshot().ProxySecret

	// preview is counts only
	_, p := boss.do("GET", "/api/reset/plan", "")
	if p["services"].(float64) != 1 || p["groups"].(float64) != 1 || p["cfRules"].(float64) != 1 || p["roles"].(float64) != 1 {
		t.Fatalf("plan: %v", p)
	}
	// the confirm word is required
	boss.must(400, "POST", "/api/reset", `{"confirm":"reset"}`)
	if f.app.store.Snapshot().Settings.Domain != "example.com" {
		t.Fatal("reset without confirm changed data")
	}
	// an operator cannot reset
	op := f.user(t, boss, "op", "operator")
	if code, m := op.do("POST", "/api/reset", `{"confirm":"초기화"}`); code != 403 {
		t.Fatalf("operator reset: %d %v", code, m)
	}

	// runtime state that a reset must clear too
	f.set(func(d *Data) { d.Settings.CaddyContainer, d.Settings.CrowdSecLAPI = "my-caddy", "http://cs:1" })
	f.app.mon.addReq(ReqRec{T: time.Now().UnixMilli(), Host: "photos.example.com", Status: 200, Ms: 100})
	f.app.mon.mu.Lock()
	f.app.mon.certs = []CertInfo{{FQDN: "photos.example.com"}}
	f.app.mon.health["s1"] = &HealthState{}
	f.app.mon.mu.Unlock()
	oldBk := filepath.Join(f.dir, "backups", "20200101-000000-apply")
	os.MkdirAll(oldBk, 0o700)
	oldUI := cfTokenUIPath
	cfTokenUIPath = filepath.Join(f.dir, "secrets", "cf_token")
	defer func() { cfTokenUIPath = oldUI }()
	os.MkdirAll(filepath.Dir(cfTokenUIPath), 0o700)
	os.WriteFile(cfTokenUIPath, []byte("ui-token-not-real"), 0o600)
	if len(f.events(t, "audit")) == 0 {
		t.Fatal("expected some audit rows before the reset")
	}

	// reset keeping accounts
	accts := len(f.app.store.Snapshot().Accounts)
	code, m := boss.do("POST", "/api/reset", `{"confirm":"초기화"}`)
	if code != 200 {
		t.Fatalf("reset: %d %v", code, m)
	}
	d := f.app.store.Snapshot()
	if d.Settings.Domain != "" || d.Settings.TailscaleIP != "" || d.Settings.WafParanoia != 1 || len(d.Settings.TopoHops) != 0 || len(d.Services) != 0 ||
		len(d.ManagedDNS) != 0 || d.CFWAF.ThreatRuleID != "" || d.Dashboard != nil || d.Dirty || len(d.Pending) != 0 {
		t.Fatalf("not reset: %+v", d.Settings.Domain)
	}
	if len(d.Accounts) != accts || d.role("custom") == nil || d.ProxySecret != secret {
		t.Fatal("reset without accounts touched accounts / roles / proxy secret")
	}
	// the data file was backed up first
	bk := m["plan"].(map[string]any)["backup"].(string)
	b, err := os.ReadFile(filepath.Join(bk, "gilmok.json"))
	if err != nil || !strings.Contains(string(b), "photos") {
		t.Fatalf("backup: %v", err)
	}
	// code defaults, not the GM_* environment and not the old values
	if d.Settings.CaddyContainer != "caddy" || d.Settings.CrowdSecLAPI != "http://crowdsec:8080" {
		t.Fatalf("container settings not reset: %q %q", d.Settings.CaddyContainer, d.Settings.CrowdSecLAPI)
	}
	f.app.mon.mu.Lock()
	monLeft := len(f.app.mon.reqs) + len(f.app.mon.coarse) + len(f.app.mon.fine) + len(f.app.mon.certs) + len(f.app.mon.health)
	f.app.mon.mu.Unlock()
	if monLeft != 0 {
		t.Fatalf("dashboard memory not cleared (%d)", monLeft)
	}
	if _, err := os.Stat(oldBk); err == nil {
		t.Fatal("older backups kept")
	}
	if _, err := os.Stat(cfTokenUIPath); err == nil {
		t.Fatal("UI token kept")
	}
	boss.must(200, "GET", "/api/state", "") // still logged in
	// the log database starts over: the reset is the only audit entry
	ev := f.events(t, "audit")
	if len(ev) != 1 || !strings.Contains(ev[0].Msg, "초기화") {
		t.Fatalf("audit after reset: %d", len(ev))
	}

	// reset with accounts: only the initial admin is left and every session ends
	seed()
	if code, m := op.do("POST", "/api/reset", `{"confirm":"초기화","accounts":true}`); code != 403 {
		t.Fatalf("operator accounts reset: %d %v", code, m)
	}
	boss.must(200, "POST", "/api/reset", `{"confirm":"초기화","accounts":true}`)
	d = f.app.store.Snapshot()
	if len(d.Accounts) != 1 || d.Accounts[0].Name != "admin" || !d.Accounts[0].Bootstrap || d.role("custom") != nil || len(d.Roles) != 3 {
		t.Fatalf("accounts not reset: %d", len(d.Accounts))
	}
	if code, _ := boss.do("GET", "/api/state", ""); code != 401 {
		t.Fatalf("old session still valid: %d", code)
	}
	if code, _ := op.do("GET", "/api/state", ""); code != 401 {
		t.Fatalf("other session still valid: %d", code)
	}
}
