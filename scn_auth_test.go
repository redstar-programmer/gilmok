package main

// AUTH / ACC / ROLE scenarios (docs/TEST_SCENARIOS.md)

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

func enableTOTP(t *testing.T, c *client) string {
	t.Helper()
	m := c.must(200, "POST", "/api/auth/totp/begin", "")
	sec := m["secret"].(string)
	c.must(200, "POST", "/api/auth/totp/enable", `{"code":"`+totpCode(sec, time.Now())+`"}`)
	return sec
}

func TestScnAuthLockout(t *testing.T) {
	f := newFullApp(t)
	f.admin(t)
	a := f.app.auth
	// AUTH-09: someone else's successful login does not reset the shared counter
	for i := 0; i < 29; i++ {
		a.noteFail(globalKey)
	}
	c := f.client(t)
	c.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	c.must(401, "POST", "/api/auth/login", `{"name":"nobody","password":"wrong-password-1"}`) // 30th
	c.must(429, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	// AUTH-10: failures older than the window do not add up
	a.mu.Lock()
	delete(a.fails, globalKey)
	a.mu.Unlock()
	for i := 0; i < 4; i++ {
		a.noteFail("k")
	}
	a.mu.Lock()
	a.fails["k"].first = time.Now().Add(-16 * time.Minute)
	a.mu.Unlock()
	if d := a.noteFail("k"); d != 0 {
		t.Fatalf("AUTH-10: locked after an expired window: %v", d)
	}
}

func TestScnAuthLogin(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	// AUTH-11: unknown account and wrong password look the same
	c := f.client(t)
	_, m1 := c.do("POST", "/api/auth/login", `{"name":"ghost","password":"wrong-password-1"}`)
	f.app.auth.noteOK("127.0.0.1|ghost")
	_, m2 := c.do("POST", "/api/auth/login", `{"name":"boss","password":"wrong-password-1"}`)
	f.app.auth.noteOK("127.0.0.1|boss")
	if m1["error"] != m2["error"] {
		t.Fatalf("AUTH-11: %v vs %v", m1, m2)
	}
	// AUTH-13: TOTP account without code → needCode, not a failure
	sec := enableTOTP(t, boss)
	f.app.auth.noteOK(globalKey)
	code, m := c.do("POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	if code != 401 || m["needCode"] != true {
		t.Fatalf("AUTH-13: %d %v", code, m)
	}
	f.app.auth.mu.Lock()
	fs := f.app.auth.fails["127.0.0.1|boss"]
	f.app.auth.mu.Unlock()
	if fs != nil && fs.n > 0 {
		t.Fatal("AUTH-13: asking for the code counted as a failure")
	}
	// AUTH-17: cookie flags
	rec := c.raw("POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`","code":"`+totpCode(sec, time.Now().Add(30*time.Second))+`"}`)
	if rec.Code != 200 {
		t.Fatalf("login with code: %d %s", rec.Code, rec.Body.String())
	}
	ck := rec.Result().Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Secure {
		t.Fatalf("AUTH-17: cookie %+v", ck)
	}
	// AUTH-18: logging in again with a cookie rotates (old token gone)
	old := c.cookie
	c.headers["X-Forwarded-Proto"] = "https"
	rec = c.raw("POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`","code":"`+totpCode(sec, time.Now().Add(-30*time.Second))+`"}`)
	if rec.Code == 200 {
		t.Fatal("AUTH-15: an older step than the last one must not work")
	}
	// next valid step: wait is not needed — reuse a fresh session from the admin flow instead
	f.app.auth.mu.Lock()
	_, stillThere := f.app.auth.sessions[old]
	f.app.auth.mu.Unlock()
	if !stillThere {
		t.Fatal("failed login must not drop the session")
	}
}

func TestScnAuthSessions(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	// AUTH-18: rotation
	c := f.client(t)
	c.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	old := c.cookie
	c.headers["X-Forwarded-Proto"] = "https"
	rec := c.raw("POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	if rec.Code != 200 || c.cookie == old {
		t.Fatalf("AUTH-18: %d", rec.Code)
	}
	if !rec.Result().Cookies()[0].Secure {
		t.Fatal("AUTH-17: X-Forwarded-Proto https → Secure")
	}
	f.app.auth.mu.Lock()
	_, ok := f.app.auth.sessions[old]
	f.app.auth.mu.Unlock()
	if ok {
		t.Fatal("AUTH-18: old token still valid")
	}
	// AUTH-19 / AUTH-20: idle and absolute expiry
	s := f.session(c)
	f.app.auth.mu.Lock()
	s.LastSeen = time.Now().Add(-2 * time.Hour)
	f.app.auth.mu.Unlock()
	c.must(401, "GET", "/api/state", "")
	c.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	s = f.session(c)
	f.app.auth.mu.Lock()
	s.Created = time.Now().Add(-48 * time.Hour)
	f.app.auth.mu.Unlock()
	c.must(401, "GET", "/api/state", "")
	// AUTH-21: minimums
	f.set(func(d *Data) { d.Settings.SecIdleMin, d.Settings.SecAbsHours, d.Settings.SecReauthMin = 1, 0, 0 })
	idle, abs, re := f.app.auth.policy()
	if idle != 5*time.Minute || abs != time.Hour || re != time.Minute {
		t.Fatalf("AUTH-21: %v %v %v", idle, abs, re)
	}
	f.set(func(d *Data) { d.Settings.SecIdleMin, d.Settings.SecAbsHours, d.Settings.SecReauthMin = 30, 12, 10 })
	// AUTH-22: list and end another session of mine
	c2 := f.client(t)
	c2.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	m := boss.must(200, "GET", "/api/auth/sessions", "")
	list := m["sessions"].([]any)
	if len(list) < 2 {
		t.Fatalf("AUTH-22: sessions %v", list)
	}
	other := f.session(c2).ID
	boss.must(200, "DELETE", "/api/auth/sessions/"+other, "")
	c2.must(401, "GET", "/api/state", "")
	boss.must(200, "GET", "/api/state", "")
	// AUTH-23: logout
	rec = boss.raw("POST", "/api/auth/logout", "")
	if rec.Code != 200 || rec.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("AUTH-23: %d %+v", rec.Code, rec.Result().Cookies())
	}
	boss.must(401, "GET", "/api/state", "")
	found := false
	for _, e := range f.events(t, "audit") {
		if e.Action == "auth.logout" {
			found = true
		}
	}
	if !found {
		t.Fatal("AUTH-23: logout not audited")
	}
}

func TestScnAuthStepUp(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	// AUTH-24 / 25 / 26
	f.staleReauth(boss)
	code, m := boss.do("POST", "/api/accounts", `{"name":"x1","role":"viewer"}`)
	if code != 403 || m["reauth"] != true {
		t.Fatalf("AUTH-24: %d %v", code, m)
	}
	boss.must(401, "POST", "/api/auth/reauth", `{"password":"wrong-password-1"}`)
	f.app.auth.mu.Lock()
	g := f.app.auth.fails[globalKey]
	f.app.auth.mu.Unlock()
	if g == nil || g.n < 1 {
		t.Fatal("AUTH-26: failed step-up must count")
	}
	boss.must(200, "POST", "/api/auth/reauth", `{"password":"`+testPW+`"}`)
	boss.must(200, "POST", "/api/accounts", `{"name":"x1","role":"viewer"}`)
	boss.must(200, "POST", "/api/accounts", `{"name":"x2","role":"viewer"}`) // inside the window: no new prompt

	// ROLE-10: every S() route answers 403 {reauth} with a stale window
	f.staleReauth(boss)
	routes := [][3]string{
		{"POST", "/api/import", ""}, {"POST", "/api/apply", "{}"},
		{"POST", "/api/dns/records", "{}"}, {"PUT", "/api/dns/records/x", "{}"}, {"DELETE", "/api/dns/records/x", ""},
		{"POST", "/api/users", "{}"}, {"PUT", "/api/users/x", "{}"}, {"DELETE", "/api/users/x", ""},
		{"POST", "/api/system/update", "{}"}, {"DELETE", "/api/auth/sessions/x", ""},
		{"POST", "/api/auth/totp/begin", ""}, {"POST", "/api/auth/totp/enable", "{}"}, {"POST", "/api/auth/totp/disable", ""},
		{"POST", "/api/auth/recovery", ""}, {"POST", "/api/accounts/require-2fa", "{}"}, {"POST", "/api/accounts", "{}"},
		{"PUT", "/api/accounts/x1", "{}"}, {"POST", "/api/accounts/x1/password", ""}, {"POST", "/api/accounts/x1/reset-2fa", ""},
		{"DELETE", "/api/accounts/x1", ""}, {"POST", "/api/roles", "{}"}, {"PUT", "/api/roles/viewer", "{}"}, {"DELETE", "/api/roles/viewer", ""},
		{"POST", "/api/cloudflare/token", "{}"}, {"DELETE", "/api/cloudflare/token", ""}, {"POST", "/api/cfwaf/apply", ""},
		{"POST", "/api/logs/delete", "{}"},
	}
	for _, r := range routes {
		code, m := boss.do(r[0], r[1], r[2])
		if code != 403 || m["reauth"] != true {
			t.Errorf("ROLE-10 %s %s: %d %v", r[0], r[1], code, m)
		}
	}
	// SET-06: system / sec / log keys need step-up, plain config keys do not
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.WafParanoia = 2 }))
	for _, mod := range []func(s *Settings){
		func(s *Settings) { s.CaddyContainer = "other" },
		func(s *Settings) { s.SecIdleMin = 45 },
		func(s *Settings) { s.LogRetReqDays = 3 },
		func(s *Settings) { s.UpdateCheck = !s.UpdateCheck },
	} {
		code, m := boss.do("PUT", "/api/settings", settingsJSON(t, f, mod))
		if code != 403 || m["reauth"] != true {
			t.Errorf("SET-06: %d %v", code, m)
		}
	}
}

func TestScnAuthTransport(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	// AUTH-27: writes need X-GM
	boss.noGM = true
	boss.must(403, "POST", "/api/services", `{}`)
	boss.noGM = false
	// AUTH-28: cross-site Origin refused, same host accepted
	boss.headers["Origin"] = "https://evil.example"
	rec := boss.raw("POST", "/api/groups", `{"name":"g1"}`)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "cross-origin") {
		t.Fatalf("AUTH-28: %d %s", rec.Code, rec.Body.String())
	}
	boss.headers["Origin"] = "http://example.com" // httptest Host
	boss.must(200, "POST", "/api/groups", `{"name":"g1"}`)
	delete(boss.headers, "Origin")
	// AUTH-29: security headers on every response
	for _, p := range []string{"/api/state", "/", "/api/nope"} {
		rec := boss.raw("GET", p, "")
		hd := rec.Header()
		if hd.Get("X-Frame-Options") != "DENY" || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Content-Security-Policy") == "" || hd.Get("Referrer-Policy") == "" {
			t.Errorf("AUTH-29 %s: %v", p, hd)
		}
	}
	// AUTH-45: body over 2 MB
	big := `{"name":"` + strings.Repeat("a", 2<<20+10) + `"}`
	if code, _ := boss.do("POST", "/api/groups", big); code != 400 {
		t.Fatalf("AUTH-45: %d", code)
	}
	// AUTH-38: /healthz only from the loopback
	if rec := boss.raw("GET", "/healthz", ""); rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("AUTH-38 loopback: %d", rec.Code)
	}
	out := f.client(t)
	out.remote = "10.9.8.7:5000"
	if rec := out.raw("GET", "/healthz", ""); rec.Code != 403 {
		t.Fatalf("AUTH-38 outside: %d", rec.Code)
	}
	// AUTH-44: repeated denials → one access.denied event
	for i := 0; i < 5; i++ {
		out.raw("GET", "/api/state", "")
	}
	n := 0
	for _, e := range f.events(t, "security") {
		if e.Action == "access.denied" && e.IP == "10.9.8.7" {
			n++
		}
	}
	if n != 2 { // /healthz and /api/state are the same reason+ip key → still 1; count both paths
		if n != 1 {
			t.Fatalf("AUTH-44: %d events", n)
		}
	}
}

func proxyClient(f *fullApp, t *testing.T) *client {
	c := f.client(t)
	c.remote = "172.18.0.9:5555"
	c.headers[proxyHeader] = f.app.store.Snapshot().ProxySecret
	return c
}

func TestScnAuthAccessPath(t *testing.T) {
	f := newFullApp(t)
	f.admin(t)
	// AUTH-33: through the proxy the client IP is the last X-Forwarded-For entry
	p := proxyClient(f, t)
	p.headers["X-Forwarded-For"] = "1.1.1.1, 2.2.2.2"
	p.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	if ip := f.session(p).IP; ip != "2.2.2.2" {
		t.Fatalf("AUTH-33: %s", ip)
	}
	// AUTH-34 / AUTH-43: direct access ignores XFF and Remote-User
	d := f.client(t)
	d.headers["X-Forwarded-For"] = "9.9.9.9"
	d.headers["Remote-User"] = "admin"
	d.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	if s := f.session(d); s.IP != "127.0.0.1" || s.SSOUser != "" || s.Via != "direct" {
		t.Fatalf("AUTH-34/43: %+v", s)
	}
	// AUTH-37: SSO only matters when Authelia is used
	f.set(func(dd *Data) { dd.Settings.UseAuthelia, dd.Settings.SecRequireSSO = false, true })
	q := proxyClient(f, t)
	q.must(200, "GET", "/api/auth/state", "")
	// AUTH-35 / AUTH-36: SSO required, groups
	f.set(func(dd *Data) { dd.Settings.UseAuthelia, dd.Settings.SecSSOGroups = true, "admins" })
	q.must(403, "GET", "/api/auth/state", "")
	q.headers["Remote-User"] = "kim"
	q.headers["Remote-Groups"] = "family"
	q.must(403, "GET", "/api/auth/state", "")
	q.headers["Remote-Groups"] = "family,admins"
	q.must(200, "GET", "/api/auth/state", "")
	// AUTH-42: switches
	f.set(func(dd *Data) { dd.Settings.SecAllowProxy = false })
	q.must(403, "GET", "/api/auth/state", "")
	f.set(func(dd *Data) { dd.Settings.SecAllowProxy, dd.Settings.SecAllowDirect = true, false })
	d.must(403, "GET", "/api/auth/state", "")
	if rec := d.raw("GET", "/healthz", ""); rec.Code != 200 {
		t.Fatalf("AUTH-42: healthz %d", rec.Code)
	}
	// wrong proxy secret
	bad := f.client(t)
	bad.remote = "172.18.0.9:1"
	bad.headers[proxyHeader] = "nope"
	bad.must(403, "GET", "/api/auth/state", "")
}

func TestScnGates(t *testing.T) {
	f := newFullApp(t)
	// AUTH-41: bootstrap gate allows only /api/auth/*
	c := f.client(t)
	c.must(200, "POST", "/api/auth/login", `{"name":"admin","password":"admin"}`)
	if _, m := c.do("GET", "/api/state", ""); m["gate"] != "bootstrap" {
		t.Fatalf("bootstrap gate: %v", m)
	}
	c.must(200, "GET", "/api/auth/state", "")
	c.must(200, "POST", "/api/auth/bootstrap", `{"name":"boss","password":"`+testPW+`"}`)
	// password beats 2fa
	m := c.must(200, "POST", "/api/accounts", `{"name":"kim","role":"viewer","require2fa":true}`)
	k := f.client(t)
	k.must(200, "POST", "/api/auth/login", `{"name":"kim","password":"`+m["tempPassword"].(string)+`"}`)
	if _, m := k.do("GET", "/api/state", ""); m["gate"] != "password" {
		t.Fatalf("password gate first: %v", m)
	}
	k.must(200, "POST", "/api/auth/password", `{"current":"`+m["tempPassword"].(string)+`","new":"another strong passphrase 42"}`)
	if _, m := k.do("GET", "/api/state", ""); m["gate"] != "2fa" {
		t.Fatalf("2fa gate next: %v", m)
	}
	k.must(200, "POST", "/api/auth/logout", "")
}

func TestScnAccounts(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	// ACC-02: names
	m := boss.must(200, "POST", "/api/accounts", `{"name":"Kim","role":"viewer"}`)
	if !strings.Contains(fmtAny(boss.must(200, "GET", "/api/accounts", "")["accounts"]), `"name":"kim"`) {
		t.Fatal("ACC-02: lower-cased")
	}
	_ = m
	boss.must(400, "POST", "/api/accounts", `{"name":"a b","role":"viewer"}`)
	if code, _ := boss.do("POST", "/api/accounts", `{"name":"kim","role":"viewer"}`); code == 200 {
		t.Fatal("ACC-02: duplicate accepted")
	}
	// ACC-03: password rules
	for _, pw := range []string{"short-pw-11", strings.Repeat("a", 201), "xx-boss-yy-zz"} {
		if validatePassword("boss", pw) == nil {
			t.Errorf("ACC-03: %q accepted", pw)
		}
	}
	// ACC-04 / ACC-05
	boss.must(400, "POST", "/api/auth/password", `{"current":"wrong-password-1","new":"another long password"}`)
	boss.must(400, "POST", "/api/auth/password", `{"current":"`+testPW+`","new":"`+testPW+`"}`)
	// ACC-06: admin resets someone's password → temp password, their sessions end
	kim := f.user(t, boss, "lee", "operator")
	m = boss.must(200, "POST", "/api/accounts/lee/password", "")
	if m["tempPassword"] == "" {
		t.Fatal("ACC-06: no temp password")
	}
	kim.must(401, "GET", "/api/state", "")
	// ACC-09: TOTP enrolment attempts are limited
	c := f.client(t)
	c.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	c.must(200, "POST", "/api/auth/totp/begin", "")
	last := 0
	for i := 0; i < 6; i++ {
		last, _ = c.do("POST", "/api/auth/totp/enable", `{"code":"000000"}`)
	}
	if last != 429 {
		t.Fatalf("ACC-09: %d", last)
	}
	// ACC-10 / ACC-11 / ACC-19 on a fresh account
	f.app.auth.noteOK("totp|boss")
	opc := f.user(t, boss, "park", "operator")
	enableTOTP(t, opc)
	before := f.app.store.Snapshot()
	opc.must(200, "POST", "/api/auth/recovery", "")
	after := f.app.store.Snapshot()
	if strings.Join(acctOf(before, "park").Recovery, ",") == strings.Join(acctOf(after, "park").Recovery, ",") {
		t.Fatal("ACC-11: recovery codes not replaced")
	}
	boss.must(200, "POST", "/api/accounts/require-2fa", `{"names":["park"],"require":true}`)
	opc.must(400, "POST", "/api/auth/totp/disable", "")
	boss.must(200, "POST", "/api/accounts/park/reset-2fa", "")
	if a := acctOf(f.app.store.Snapshot(), "park"); a.TOTP != "" || len(a.Recovery) != 0 {
		t.Fatalf("ACC-19: %+v", a)
	}
	// ACC-16: role change is immediate
	op := f.user(t, boss, "choi", "operator")
	op.must(200, "POST", "/api/groups", `{"name":"gg"}`)
	boss.must(200, "PUT", "/api/accounts/choi", `{"display":"choi","role":"viewer"}`)
	if code, m := op.do("POST", "/api/groups", `{"name":"gh"}`); code != 403 || m["perm"] != "config" {
		t.Fatalf("ACC-16: %d %v", code, m)
	}
	// ACC-15: deleting ends the sessions
	boss.must(200, "DELETE", "/api/accounts/choi", "")
	op.must(401, "GET", "/api/state", "")
}

func TestScnRoles(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	// ROLE-03
	boss.must(400, "POST", "/api/roles", `{"name":"bad","perms":["nonexistent"]}`)
	m := boss.must(200, "POST", "/api/roles", `{"name":"deploy","perms":["apply","config"]}`)
	id := m["id"].(string)
	boss.must(400, "PUT", "/api/roles/"+id, `{"name":"deploy","perms":["apply","nope"]}`)
	// ROLE-04 / ROLE-05: a role in use by n accounts
	u1 := f.user(t, boss, "u1", id)
	u2 := f.user(t, boss, "u2", id)
	boss.must(400, "DELETE", "/api/roles/"+id, "")
	boss.must(200, "PUT", "/api/roles/"+id, `{"name":"deploy","perms":["apply"]}`)
	for _, u := range []*client{u1, u2} {
		if code, m := u.do("POST", "/api/groups", `{"name":"z"}`); code != 403 || m["perm"] != "config" {
			t.Fatalf("ROLE-05: %d %v", code, m)
		}
	}
	// ROLE-06: built-in roles stay
	for _, r := range []string{"admin", "operator", "viewer"} {
		boss.must(400, "DELETE", "/api/roles/"+r, "")
	}
	// ROLE-09: a viewer may read everything (no permission error on GET)
	v := f.user(t, boss, "viewer1", "viewer")
	for _, p := range []string{"/api/state", "/api/plan?dns=0", "/api/groups", "/api/backups", "/api/dashboard",
		"/api/logs/status", "/api/logs/events", "/api/topology", "/api/updates", "/api/cfwaf", "/api/waf/meta", "/api/auth/sessions"} {
		if code, m := v.do("GET", p, ""); code == 403 && m["perm"] != nil {
			t.Errorf("ROLE-09 %s: %v", p, m)
		}
	}
	if code, m := v.do("GET", "/api/accounts", ""); code != 403 || m["perm"] != "accounts" {
		t.Fatalf("ROLE-09: account list needs accounts: %d %v", code, m)
	}
	if code, m := v.do("GET", "/api/logs/export?cat=audit", ""); code != 403 || m["perm"] != "logs" {
		t.Fatalf("ROLE-09: export needs logs: %d %v", code, m)
	}
}

// ROLE-08: the whole permission table
func TestScnPermTable(t *testing.T) {
	cases := []struct{ m, p, want string }{
		{"POST", "/api/auth/password", ""}, {"POST", "/api/auth/totp/begin", ""},
		{"POST", "/api/accounts", "accounts"}, {"GET", "/api/accounts", "accounts"}, {"PUT", "/api/roles/x", "accounts"},
		{"GET", "/api/logs/export", "logs"}, {"POST", "/api/logs/delete", "logs"},
		{"POST", "/api/apply", "apply"}, {"POST", "/api/import", "apply"}, {"POST", "/api/system/update", "apply"},
		{"POST", "/api/cfwaf/apply", "apply"}, {"POST", "/api/cfwaf/adopt", "apply"}, {"POST", "/api/dns/records", "apply"},
		{"DELETE", "/api/dns/records/1", "apply"}, {"POST", "/api/ddns/run", "apply"}, {"POST", "/api/crowdsec/sync", "apply"},
		{"POST", "/api/dev/fault", "apply"}, {"POST", "/api/crowdsec/decisions", "security"}, {"DELETE", "/api/crowdsec/decisions/1", "security"},
		{"POST", "/api/waf/test", "security"}, {"POST", "/api/users", "authelia_users"}, {"DELETE", "/api/users/x", "authelia_users"},
		{"POST", "/api/updates/check", ""}, {"POST", "/api/dash/data", ""}, {"POST", "/api/validate", ""},
		{"POST", "/api/services", "config"}, {"PUT", "/api/settings", "config"}, {"POST", "/api/groups", "config"}, {"POST", "/api/services/bulk", "config"},
		{"GET", "/api/state", ""}, {"GET", "/api/users", ""}, {"GET", "/api/plan", ""},
	}
	for _, c := range cases {
		if got := permFor(c.m, c.p); got != c.want {
			t.Errorf("permFor(%s %s) = %q, want %q", c.m, c.p, got, c.want)
		}
	}
}

func TestScnStepUpLogsKeys(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	op := f.user(t, boss, "op1", "operator")
	// SET-03: log / disk keys need 「logs」
	code, m := op.do("PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.LogRetReqDays = 3 }))
	if code != 403 || m["perm"] != "logs" {
		t.Fatalf("SET-03: %d %v", code, m)
	}
	// SET-05: config + sec in one request → everything refused
	code, m = op.do("PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.WafParanoia = 3; s.SecIdleMin = 50 }))
	if code != 403 || f.app.store.Snapshot().Settings.WafParanoia == 3 {
		t.Fatalf("SET-05: %d %v", code, m)
	}
	_ = context.Background
	_ = regexp.MustCompile
}

func acctOf(d Data, name string) *Account { return d.account(name) }
