package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigExportImport(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCaddy, d.Settings.WafParanoia = "example.com", true, 2
		d.AGroups, d.AGroupsInit = []AGroup{{Name: "admins", Desc: "관리"}, {Name: "family"}}, true
		d.Services = []*Service{
			{ID: "s1", Subdomain: "photos", Upstream: "immich:2283", Exposure: ExposurePublic, Enabled: true, Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor", Groups: []string{"family"}}},
			{ID: "s2", Subdomain: "admin", Upstream: "dock:3000", Exposure: ExposureTailscale, Enabled: true},
		}
	})

	// export is a config dump with no secrets
	rec := boss.raw("GET", "/api/config/export", "")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "gilmok-config-") {
		t.Fatalf("export: %d", rec.Code)
	}
	body := rec.Body.String()
	sec := f.app.store.Snapshot().ProxySecret
	for _, needle := range []string{sec, "argon2", "proxySecret", "adminHash", "totpSecret"} {
		if needle != "" && strings.Contains(body, needle) {
			t.Fatalf("export leaks %q", needle)
		}
	}
	// no account data at the top level ("accounts" also appears as a permission id inside roles)
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"accounts", "adminHash", "proxySecret", "totpSecret"} {
		if _, ok := top[k]; ok {
			t.Fatalf("export has top-level %q", k)
		}
	}
	if !strings.Contains(body, "photos") || !strings.Contains(body, "example.com") || !strings.Contains(body, "admins") {
		t.Fatal("export missing config")
	}

	// mutate everything, then restore from the file
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.WafParanoia = "changed.example", 4
		d.Services = []*Service{{ID: "z", Subdomain: "zzz", Upstream: "z:1", Exposure: ExposurePublic, Enabled: true}}
		d.AGroups = nil
		d.Dirty, d.Pending = false, nil
	})
	accountsBefore := len(f.app.store.Snapshot().Accounts)

	imp := func(dry bool) (int, map[string]any) {
		msg := `{"name":"c.json","data":"` + base64.StdEncoding.EncodeToString([]byte(body)) + `","dry":` + map[bool]string{true: "true", false: "false"}[dry] + `}`
		return boss.do("POST", "/api/config/import", msg)
	}
	// preview changes nothing
	code, m := imp(true)
	if code != 200 {
		t.Fatalf("dry: %d %v", code, m)
	}
	if f.app.store.Snapshot().Settings.Domain != "changed.example" {
		t.Fatal("preview changed state")
	}
	if len(m["servicesAdd"].([]any)) != 2 || len(m["servicesRemove"].([]any)) != 1 {
		t.Fatalf("plan: %v", m)
	}
	// apply
	if code, m := imp(false); code != 200 {
		t.Fatalf("import: %d %v", code, m)
	}
	d := f.app.store.Snapshot()
	if d.Settings.Domain != "example.com" || d.Settings.WafParanoia != 2 || len(d.Services) != 2 || len(d.AGroups) != 2 || !d.Dirty {
		t.Fatalf("restore: %+v groups=%d dirty=%v", d.Settings.Domain, len(d.AGroups), d.Dirty)
	}
	// accounts / login are untouched by a restore
	if len(d.Accounts) != accountsBefore || d.ProxySecret != sec {
		t.Fatal("restore touched accounts or the proxy secret")
	}
	boss.must(200, "GET", "/api/state", "") // still logged in

	// a foreign file is rejected
	bad := base64.StdEncoding.EncodeToString([]byte(`{"format":"something-else","settings":{}}`))
	boss.must(400, "POST", "/api/config/import", `{"data":"`+bad+`","dry":true}`)
	// a config whose service points at an unregistered group is rejected
	var cf ConfigFile
	json.Unmarshal([]byte(body), &cf)
	cf.Groups = nil // drop the groups the services reference
	bb, _ := json.Marshal(cf)
	if code, _ := boss.do("POST", "/api/config/import", `{"data":"`+base64.StdEncoding.EncodeToString(bb)+`","dry":true}`); code != 400 {
		t.Fatalf("unregistered group: %d", code)
	}
}

func TestConfigImportPermsAndSafety(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) { d.Settings.Domain = "example.com" })
	good := configFrom(f.app.store.Snapshot())

	// an operator (no system/accounts) cannot restore a file that changes system / sec keys
	op := f.user(t, boss, "op", "operator")
	sysCfg := good
	sysCfg.Settings.CaddyContainer = "evil"
	b, _ := json.Marshal(sysCfg)
	body := `{"data":"` + base64.StdEncoding.EncodeToString(b) + `","dry":false}`
	if code, m := op.do("POST", "/api/config/import", body); code != 403 || m["perm"] != "system" {
		t.Fatalf("operator system restore: %d %v", code, m)
	}
	if f.app.store.Snapshot().Settings.CaddyContainer == "evil" {
		t.Fatal("operator changed a system setting via restore")
	}

	// a path into a forbidden folder is refused even for an admin
	badPath := good
	badPath.Settings.CaddyfilePath = "/etc/passwd"
	b, _ = json.Marshal(badPath)
	boss.must(400, "POST", "/api/config/import", `{"data":"`+base64.StdEncoding.EncodeToString(b)+`","dry":true}`)

	// a brace-escaping base skeleton is refused
	braces := good
	braces.Settings.CaddyBase = "}\nevil.com {"
	b, _ = json.Marshal(braces)
	boss.must(400, "POST", "/api/config/import", `{"data":"`+base64.StdEncoding.EncodeToString(b)+`","dry":true}`)

	// restoring roles never drops a role an account uses, nor the built-ins
	f.set(func(d *Data) {
		d.Roles = append(d.Roles, &Role{ID: "custom", Name: "맞춤", Perms: []string{"config"}})
		d.Accounts = append(d.Accounts, &Account{Name: "u1", Role: "custom"})
	})
	rolesCfg := configFrom(f.app.store.Snapshot())
	rolesCfg.Roles = []*Role{{ID: "viewer", Name: "보기", Perms: []string{}}} // only one role in the file
	b, _ = json.Marshal(rolesCfg)
	f.app.auth.mu.Lock() // keep the current reauth window fresh
	f.app.auth.mu.Unlock()
	boss.must(200, "POST", "/api/auth/reauth", `{"password":"`+testPW+`"}`)
	boss.must(200, "POST", "/api/config/import", `{"data":"`+base64.StdEncoding.EncodeToString(b)+`","dry":false}`)
	got := map[string]bool{}
	for _, r := range f.app.store.Snapshot().Roles {
		got[r.ID] = true
	}
	for _, id := range []string{"admin", "operator", "viewer", "custom"} {
		if !got[id] {
			t.Fatalf("restore dropped role %s (%v)", id, got)
		}
	}
}

func TestTopoHopsMigrationAndValidation(t *testing.T) {
	// the old single device becomes the first hop, once
	p := t.TempDir() + "/g.json"
	old := `{"settings":{"topoEdgeKind":"direct","topoEdgeName":"ufw","topoEdgeExtPort":443,"topoEdgeFwdPort":8443,"topoEdgeNote":"443만"}}`
	if err := osWrite(p, []byte(old)); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	st := s.Snapshot().Settings
	if len(st.TopoHops) != 1 || st.TopoHops[0].Kind != "firewall" || st.TopoHops[0].FwdPort != 8443 || !st.TopoHops[0].Tailnet || st.TopoEdgeKind != "" {
		t.Fatalf("migration: %+v / %q", st.TopoHops, st.TopoEdgeKind)
	}
	// a chain of several devices is saved; unknown kinds and odd ports are refused
	f := newFullApp(t)
	boss := f.admin(t)
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) {
		s.TopoHops = []TopoHop{{Kind: "firewall", Name: "edge-fw", Tailnet: true}, {Kind: "lb", Name: "haproxy", ExtPort: 443, FwdPort: 8443}, {Kind: "proxy"}}
	}))
	if got := f.app.store.Snapshot().Settings.TopoHops; len(got) != 3 || got[1].Kind != "lb" || f.app.store.Snapshot().Dirty {
		t.Fatalf("hops: %+v dirty=%v", got, f.app.store.Snapshot().Dirty)
	}
	boss.must(400, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.TopoHops = []TopoHop{{Kind: "teleporter"}} }))
	boss.must(400, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.TopoHops = []TopoHop{{Kind: "lb", FwdPort: 70000}} }))
}

// review v2: a config restore must not grant permissions or slip values past the settings form
func TestConfigImportNoEscalation(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) { d.Settings.Domain = "example.com" })
	op := f.user(t, boss, "op", "operator")
	enc := func(c ConfigFile) string {
		b, _ := json.Marshal(c)
		return `{"data":"` + base64.StdEncoding.EncodeToString(b) + `","dry":false}`
	}
	// operator rewrites the operator role to hold every permission
	cfg := configFrom(f.app.store.Snapshot())
	for _, r := range cfg.Roles {
		if r.ID == "operator" {
			r.Perms = allPermIDs()
		}
	}
	if code, m := op.do("POST", "/api/config/import", enc(cfg)); code != 403 || m["perm"] != "accounts" {
		t.Fatalf("operator role escalation: %d %v", code, m)
	}
	if d := f.app.store.Snapshot(); d.permsOf(d.account("op"))["accounts"] {
		t.Fatal("operator gained accounts permission")
	}
	// unknown permission ids are refused
	bad := configFrom(f.app.store.Snapshot())
	bad.Roles = append(bad.Roles, &Role{ID: "x", Name: "x", Perms: []string{"root"}})
	boss.must(400, "POST", "/api/config/import", enc(bad))
	// the same value checks as the settings form
	for _, mod := range []func(s *Settings){
		func(s *Settings) { s.WafDirectives = "SecRule ARGS \"@rx x\" \"id:1,deny\" ` }\n evil.com {" },
		func(s *Settings) { s.CfAllowIPs = "not-an-ip" },
		func(s *Settings) { s.DiskWarnPct, s.DiskCritPct, s.DiskStopPct = 5, 10, 20 },
		func(s *Settings) { s.WafMethods = "get; rm -rf" },
	} {
		c := configFrom(f.app.store.Snapshot())
		mod(&c.Settings)
		if code, m := boss.do("POST", "/api/config/import", enc(c)); code != 400 {
			t.Fatalf("unchecked value accepted: %d %v", code, m)
		}
	}
}
