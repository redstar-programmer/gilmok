package main

// Cases added from the scenario review (docs/TEST_SCENARIOS.md): AUTH-40, ACC-21, GRP-23, SVC-17.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupOnceAndSelfProtection(t *testing.T) {
	_, h := newAuthTestApp(t)
	boss := &tclient{t: t, h: h}
	boss.do("POST", "/api/auth/login", `{"name":"admin","password":"admin"}`)
	if code, m := boss.do("POST", "/api/auth/bootstrap", `{"name":"boss","display":"대표","password":"correct horse battery"}`); code != 200 {
		t.Fatalf("bootstrap: %d %v", code, m)
	}
	// AUTH-40: setup cannot run again once an account exists
	anon := &tclient{t: t, h: h}
	if code, _ := anon.do("POST", "/api/auth/setup", `{"name":"evil","password":"correct horse battery"}`); code != 409 {
		t.Fatalf("setup after accounts exist: %d", code)
	}
	// a second manager
	if code, m := boss.do("POST", "/api/accounts", `{"name":"lee","display":"이","role":"admin"}`); code != 200 {
		t.Fatalf("create lee: %d %v", code, m)
	}
	// ACC-21: even with another manager around, I cannot disable or demote myself
	if code, m := boss.do("PUT", "/api/accounts/boss", `{"display":"대표","role":"admin","disabled":true}`); code != 400 || !strings.Contains(m["error"].(string), "자기 계정") {
		t.Fatalf("self disable: %d %v", code, m)
	}
	if code, m := boss.do("PUT", "/api/accounts/boss", `{"display":"대표","role":"viewer"}`); code != 400 || !strings.Contains(m["error"].(string), "자기 계정") {
		t.Fatalf("self demote: %d %v", code, m)
	}
	// …but may change my display name, and may demote someone else
	if code, m := boss.do("PUT", "/api/accounts/boss", `{"display":"대표님","role":"admin"}`); code != 200 {
		t.Fatalf("self rename: %d %v", code, m)
	}
	if code, m := boss.do("PUT", "/api/accounts/lee", `{"display":"이","role":"viewer"}`); code != 200 {
		t.Fatalf("demote other: %d %v", code, m)
	}
}

// GRP-23: a rename that rewrites users_database.yml needs a fresh password, and nothing changes
// until it is given.
func TestGroupRenameTouchingUsersNeedsReauth(t *testing.T) {
	app, _ := newAuthTestApp(t)
	users := filepath.Join(t.TempDir(), "users_database.yml")
	orig := "users:\n  kim:\n    disabled: false\n    displayname: Kim\n    password: x\n    email: kim@example.com\n    groups:\n      - admins\n"
	if err := os.WriteFile(users, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = app.store.Update(func(d *Data) error {
		d.Settings.Domain, d.Settings.UseAuthelia, d.Settings.AutheliaUsers = "example.com", true, users
		d.AGroups, d.AGroupsInit = []AGroup{{Name: "admins"}}, true
		d.Services = []*Service{{ID: "a", Subdomain: "x", Authelia: AutheliaOpts{Enabled: true, Groups: []string{"admins"}}}}
		return nil
	})
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/groups/{name}", app.putGroup)
	mux.HandleFunc("DELETE /api/groups/{name}", app.deleteGroup)
	for _, req := range []*http.Request{
		httptest.NewRequest("PUT", "/api/groups/admins", strings.NewReader(`{"name":"ops"}`)),
		httptest.NewRequest("DELETE", "/api/groups/admins?purge=1", nil),
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req) // no session → no recent password check
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"reauth":true`) {
			t.Fatalf("%s: %d %s", req.Method, rec.Code, rec.Body.String())
		}
	}
	if b, _ := os.ReadFile(users); string(b) != orig {
		t.Fatal("users file changed without step-up")
	}
	d := app.store.Snapshot()
	if d.Services[0].Authelia.Groups[0] != "admins" || d.Dirty || d.AGroups[0].Name != "admins" {
		t.Fatalf("state changed without step-up: %+v %v", d.Services[0].Authelia, d.AGroups)
	}
}

// SVC-17: upstream cannot carry characters that start a comment, quote, or break the line.
func TestUpstreamInjection(t *testing.T) {
	st := Settings{Domain: "example.com"}
	for _, up := range []string{"app:80#x", "app:80\nevil", "app:80\"", "app:80'", "app:80`", "app\t:80", "app:80}"} {
		s := &Service{Subdomain: "a", Upstream: up, Exposure: ExposurePublic}
		if err := validateService(s, nil, st); err == nil {
			t.Fatalf("upstream %q accepted", up)
		}
	}
	// notes: every line becomes a comment — no directive escapes
	s := &Service{Subdomain: "a", Upstream: "app:80", Exposure: ExposurePublic, Enabled: true, Notes: "hi\nreverse_proxy evil:80"}
	out := GenerateCaddyfile(Data{Settings: st, Services: []*Service{s}})
	if strings.Contains(out, "\nreverse_proxy evil:80") || !strings.Contains(out, "# reverse_proxy evil:80") {
		t.Fatalf("notes escaped:\n%s", out)
	}
}
