package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type tclient struct {
	t      *testing.T
	h      http.Handler
	cookie string
}

func (c *tclient) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-GM", "1")
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck.Value
		}
	}
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func newAuthTestApp(t *testing.T) (*App, http.Handler) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "g.json"))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{store: store, cf: NewCF()}
	auth := newAuth(app)
	app.auth = auth
	S := auth.sensitive
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/state", auth.state)
	mux.HandleFunc("POST /api/auth/setup", auth.setup)
	mux.HandleFunc("POST /api/auth/login", auth.login)
	api := http.NewServeMux()
	api.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	api.HandleFunc("POST /api/apply", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	api.HandleFunc("PUT /api/settings", app.saveSettings)
	api.HandleFunc("POST /api/auth/password", auth.changePassword)
	api.HandleFunc("POST /api/auth/reauth", auth.reauth)
	api.HandleFunc("POST /api/auth/totp/begin", S(auth.totpBegin))
	api.HandleFunc("POST /api/auth/totp/enable", S(auth.totpEnable))
	api.HandleFunc("POST /api/auth/bootstrap", auth.bootstrap)
	api.HandleFunc("POST /api/accounts/require-2fa", S(auth.requireTwoFactor))
	api.HandleFunc("GET /api/accounts", auth.listAccounts)
	api.HandleFunc("POST /api/accounts", S(auth.createAccount))
	api.HandleFunc("PUT /api/accounts/{name}", S(auth.updateAccount))
	api.HandleFunc("DELETE /api/accounts/{name}", S(auth.deleteAccount))
	api.HandleFunc("POST /api/roles", S(auth.createRole))
	api.HandleFunc("PUT /api/roles/{id}", S(auth.updateRole))
	mux.Handle("/api/", auth.require(api))
	return app, mux
}

func enrol(t *testing.T, app *App, c *tclient, name string) []string {
	t.Helper()
	if code, _ := c.do("POST", "/api/auth/totp/begin", ""); code != 200 {
		t.Fatalf("begin: %d", code)
	}
	var sec string
	app.store.Read(func(d *Data) { sec = d.account(name).TOTPPending })
	code, m := c.do("POST", "/api/auth/totp/enable", `{"code":"`+totpCode(sec, time.Now())+`"}`)
	if code != 200 {
		t.Fatalf("enable: %d %v", code, m)
	}
	var out []string
	for _, x := range m["recovery"].([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestAccountsFlow(t *testing.T) {
	app, h := newAuthTestApp(t)
	admin := &tclient{t: t, h: h}

	// first run → admin / admin, which can only create the real admin account
	if code, m := admin.do("GET", "/api/auth/state", ""); code != 200 || m["firstRun"] != true {
		t.Fatalf("state: %v", m)
	}
	if code, m := admin.do("POST", "/api/auth/login", `{"name":"admin","password":"admin"}`); code != 200 {
		t.Fatalf("bootstrap login: %v", m)
	}
	if code, m := admin.do("GET", "/api/state", ""); code != 403 || m["gate"] != "bootstrap" {
		t.Fatalf("bootstrap gate expected: %d %v", code, m)
	}
	if code, _ := admin.do("POST", "/api/auth/bootstrap", `{"name":"admin","password":"correct horse battery"}`); code != 400 {
		t.Fatal("must not reuse the admin id")
	}
	if code, m := admin.do("POST", "/api/auth/bootstrap", `{"name":"boss","display":"대표","password":"correct horse battery"}`); code != 200 {
		t.Fatalf("bootstrap: %v", m)
	}
	if code, m := admin.do("GET", "/api/state", ""); code != 200 {
		t.Fatalf("new admin, 2FA optional by default: %d %v", code, m)
	}
	var boot *Account
	app.store.Read(func(d *Data) { x := *d.account("admin"); boot = &x })
	if !boot.Disabled || VerifyPassword(boot.Hash, "admin") {
		t.Fatalf("admin/admin must be disabled and unusable: %+v", boot)
	}
	app.auth.noteOK(globalKey)
	if code, _ := (&tclient{t: t, h: h}).do("POST", "/api/auth/login", `{"name":"admin","password":"admin"}`); code != 401 {
		t.Fatal("admin/admin still works")
	}
	app.auth.noteOK("192.0.2.1|admin")
	app.auth.noteOK(globalKey)
	if code, _ := admin.do("PUT", "/api/accounts/admin", `{"display":"x","role":"admin","disabled":false}`); code != 400 {
		t.Fatal("bootstrap account re-enabled")
	}
	// require 2FA for my own account (bulk endpoint) → gated until enrolled
	if code, m := admin.do("POST", "/api/accounts/require-2fa", `{"names":["boss","admin"],"require":true}`); code != 200 || len(m["skipped"].([]any)) != 1 {
		t.Fatalf("bulk require: %d %v", code, m)
	}
	if code, m := admin.do("GET", "/api/state", ""); code != 403 || m["gate"] != "2fa" {
		t.Fatalf("2FA gate expected: %d %v", code, m)
	}
	recov := enrol(t, app, admin, "boss")
	if len(recov) != 10 {
		t.Fatalf("recovery codes: %v", recov)
	}
	if code, _ := admin.do("GET", "/api/state", ""); code != 200 {
		t.Fatalf("after enrolment: %d", code)
	}

	// create a viewer with a temporary password
	code, m := admin.do("POST", "/api/accounts", `{"name":"Kim","display":"김","role":"viewer","require2fa":true}`)
	if code != 200 || m["tempPassword"] == "" {
		t.Fatalf("create: %d %v", code, m)
	}
	temp := m["tempPassword"].(string)
	kim := &tclient{t: t, h: h}
	if code, m := kim.do("POST", "/api/auth/login", `{"name":"kim","password":"wrong-password-123"}`); code != 401 || !strings.Contains(m["error"].(string), "아이디 또는 비밀번호") {
		t.Fatalf("bad login: %d %v", code, m)
	}
	app.auth.noteOK("192.0.2.1|kim") // httptest RemoteAddr
	app.auth.noteOK(globalKey)
	if code, m := kim.do("POST", "/api/auth/login", `{"name":"kim","password":"`+temp+`"}`); code != 200 {
		t.Fatalf("login: %d %v", code, m)
	}
	if code, m := kim.do("GET", "/api/state", ""); code != 403 || m["gate"] != "password" {
		t.Fatalf("password gate expected: %v", m)
	}
	if code, m := kim.do("POST", "/api/auth/password", `{"current":"`+temp+`","new":"another long phrase 9"}`); code != 200 {
		t.Fatalf("change pw: %v", m)
	}
	enrol(t, app, kim, "kim")
	// viewer: may read, may not write
	if code, _ := kim.do("GET", "/api/state", ""); code != 200 {
		t.Fatal("viewer read")
	}
	if code, m := kim.do("POST", "/api/apply", "{}"); code != 403 || m["perm"] != "apply" {
		t.Fatalf("viewer apply: %d %v", code, m)
	}
	if code, m := kim.do("GET", "/api/accounts", ""); code != 403 || m["perm"] != "accounts" {
		t.Fatalf("viewer accounts: %d %v", code, m)
	}
	// operator can apply but not change access security settings
	if code, m := admin.do("PUT", "/api/accounts/kim", `{"display":"김","role":"operator"}`); code != 200 {
		t.Fatalf("promote: %v", m)
	}
	if code, _ := kim.do("POST", "/api/apply", "{}"); code != 200 {
		t.Fatal("operator apply")
	}
	st := app.store.Snapshot().Settings
	st.SecIdleMin = 99
	b, _ := json.Marshal(st)
	if code, m := kim.do("PUT", "/api/settings", string(b)); code != 403 || m["perm"] != "accounts" {
		t.Fatalf("operator sec settings: %d %v", code, m)
	}
	// operator cannot point Gilmok at other files or programs (review ④)
	for _, k := range []string{"caddyfilePath", "caddyBin", "caddyMode"} {
		st := app.store.Snapshot().Settings
		raw, _ := json.Marshal(st)
		var mm map[string]any
		_ = json.Unmarshal(raw, &mm)
		mm[k] = map[string]string{"caddyfilePath": "/data/gilmok.json", "caddyBin": "/bin/sh", "caddyMode": "native"}[k]
		b2, _ := json.Marshal(mm)
		if code, m := kim.do("PUT", "/api/settings", string(b2)); code != 403 || m["perm"] != "system" {
			t.Fatalf("operator %s: %d %v", k, code, m)
		}
	}
	// even with the permission: no secret / system folders, only a caddy binary
	for k, v := range map[string]string{"caddyfilePath": "/run/secrets/cf_token", "autheliaUsers": "/proc/self/environ", "caddyBin": "/bin/sh"} {
		st := app.store.Snapshot().Settings
		raw, _ := json.Marshal(st)
		var mm map[string]any
		_ = json.Unmarshal(raw, &mm)
		mm[k] = v
		b2, _ := json.Marshal(mm)
		if code, m := admin.do("PUT", "/api/settings", string(b2)); code != 400 {
			t.Fatalf("admin %s=%s accepted: %d %v", k, v, code, m)
		}
	}

	// the last account manager cannot be removed or demoted
	// (the self-protection answers first here; either refusal is fine)
	if code, m := admin.do("PUT", "/api/accounts/boss", `{"display":"x","role":"viewer"}`); code != 400 || !(strings.Contains(m["error"].(string), "최소 하나") || strings.Contains(m["error"].(string), "자기 계정")) {
		t.Fatalf("demote last admin: %d %v", code, m)
	}
	if code, _ := admin.do("DELETE", "/api/accounts/boss", ""); code != 400 {
		t.Fatal("delete self")
	}
	// a custom role that lost 「accounts」 cannot strand the system either
	if code, m := admin.do("PUT", "/api/roles/admin", `{"name":"x","perms":[]}`); code != 400 {
		t.Fatalf("admin role edit: %v", m)
	}

	// disabling kills sessions immediately
	if code, _ := admin.do("PUT", "/api/accounts/kim", `{"display":"김","role":"operator","disabled":true}`); code != 200 {
		t.Fatal("disable")
	}
	if code, _ := kim.do("GET", "/api/state", ""); code != 401 {
		t.Fatalf("disabled account still in: %d", code)
	}

	// recovery code logs in once
	other := &tclient{t: t, h: h}
	if code, m := other.do("POST", "/api/auth/login", `{"name":"boss","password":"correct horse battery","code":"`+recov[0]+`"}`); code != 200 || m["usedRecovery"] != true {
		t.Fatalf("recovery login: %d %v", code, m)
	}
	again := &tclient{t: t, h: h}
	if code, _ := again.do("POST", "/api/auth/login", `{"name":"boss","password":"correct horse battery","code":"`+recov[0]+`"}`); code != 401 {
		t.Fatal("recovery code reused")
	}
	// secrets never leave the server
	_, m = admin.do("GET", "/api/accounts", "")
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), "argon2") || strings.Contains(string(raw), `"hash"`) || strings.Contains(string(raw), `"totp":"`) {
		t.Fatalf("secret leaked: %s", raw)
	}
}

func TestMigrateSingleAdmin(t *testing.T) {
	d := &Data{AdminHash: "$argon2id$x", TOTPSecret: "ABC"}
	migrateAccounts(d)
	if len(d.Accounts) != 1 || d.Accounts[0].Name != "admin" || d.Accounts[0].Role != "admin" || d.Accounts[0].TOTP != "ABC" || d.AdminHash != "" || len(d.Roles) != 3 {
		t.Fatalf("%+v %+v", d.Accounts, d.Roles)
	}
	if permFor("GET", "/api/state") != "" || permFor("POST", "/api/services") != "config" || permFor("DELETE", "/api/dns/records/x") != "apply" || permFor("POST", "/api/auth/password") != "" {
		t.Fatal("permFor")
	}
}

func TestTOTPReplayAndGlobalLock(t *testing.T) {
	app, _ := newAuthTestApp(t)
	sec := newTOTPSecret()
	_ = app.store.Update(func(d *Data) error {
		d.Accounts = []*Account{{Name: "kim", Role: "admin", TOTP: sec}}
		return nil
	})
	code := totpCode(sec, time.Now())
	snap := app.store.Snapshot()
	acct := snap.account("kim")
	if ok, _ := app.auth.checkSecondFactor(acct, code); !ok {
		t.Fatal("first use of a valid code must pass")
	}
	snap = app.store.Snapshot()
	acct = snap.account("kim")
	if ok, _ := app.auth.checkSecondFactor(acct, code); ok {
		t.Fatal("the same code must not work twice")
	}
	// the shared key needs far more failures than a per-client key
	for i := 0; i < 29; i++ {
		if d := app.auth.noteFail(globalKey); d > 0 {
			t.Fatalf("global key locked after %d failures", i+1)
		}
	}
	if d := app.auth.noteFail(globalKey); d <= 0 || d > 15*time.Minute {
		t.Fatalf("global lock = %v, want 1–15 min", d)
	}
	for i := 0; i < 4; i++ {
		app.auth.noteFail("1.2.3.4|kim")
	}
	if d := app.auth.noteFail("1.2.3.4|kim"); d != 5*time.Minute {
		t.Fatalf("per-client lock = %v", d)
	}
}
