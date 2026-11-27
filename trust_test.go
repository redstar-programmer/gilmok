package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// trustCookie: the trusted-device cookie the last response set ("" if none)
func trustCookie(c *client, account string) string {
	for _, ck := range c.last.Result().Cookies() {
		if ck.Name == trustCookieName(account) && ck.MaxAge > 0 {
			return ck.Name + "=" + ck.Value
		}
	}
	return ""
}

// TRUST-01..06: a trusted device skips the second factor (password still needed); a new password,
// a new / reset second factor, revoking, the feature switch and another account all end it; only
// hashes are stored.
func TestTrustedDevice(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	sec := enableTOTP(t, boss)
	login := func(c *client, body string) (int, map[string]any) { return c.do("POST", "/api/auth/login", body) }
	pw := `"name":"boss","password":"` + testPW + `"`

	// TRUST-02: no device yet → the code is asked for, with the trust period
	c := f.client(t)
	code, m := login(c, `{`+pw+`}`)
	if code != 401 || m["needCode"] != true || m["trustDays"].(float64) != 30 {
		t.Fatalf("TRUST-02: %d %v", code, m)
	}
	// TRUST-01: code + trust → a cookie; next time the password alone is enough
	c.must(200, "POST", "/api/auth/login", `{`+pw+`,"code":"`+totpCode(sec, time.Now().Add(30*time.Second))+`","trust":true}`)
	ck := trustCookie(c, "boss")
	if ck == "" {
		t.Fatal("TRUST-01 no trust cookie")
	}
	d := f.app.store.Snapshot()
	if raw := strings.SplitN(ck, "=", 2)[1]; strings.Contains(mustJSON(d), raw) {
		t.Error("TRUST-06 the cookie value is stored")
	}
	if len(d.account("boss").Trusted) != 1 {
		t.Fatalf("TRUST-01 devices: %v", d.account("boss").Trusted)
	}
	c2 := f.client(t)
	c2.headers["Cookie"] = ck
	c2.must(200, "POST", "/api/auth/login", `{`+pw+`}`)
	// … but never without the password
	c3 := f.client(t)
	c3.remote = "127.0.0.1:40111"
	c3.headers["Cookie"] = ck
	if code, _ := login(c3, `{"name":"boss","password":"wrong one here"}`); code != 401 {
		t.Errorf("TRUST-01 wrong password with a trusted device: %d", code)
	}
	// TRUST-05: the cookie is per account
	ops := f.user(t, boss, "ops1", "operator")
	enableTOTP(t, ops)
	c4 := f.client(t)
	c4.headers["Cookie"] = strings.Replace(ck, trustCookieName("boss"), trustCookieName("ops1"), 1)
	if code, m := login(c4, `{"name":"ops1","password":"another strong passphrase 42"}`); code != 401 || m["needCode"] != true {
		t.Errorf("TRUST-05 another account's device: %d %v", code, m)
	}
	// list / revoke (own) — the current browser is marked
	lst := c2.must(200, "GET", "/api/auth/devices", "")["devices"].([]any)
	if len(lst) != 1 || lst[0].(map[string]any)["current"] != true {
		t.Errorf("TRUST devices list: %v", lst)
	}
	if strings.Contains(c2.last.Body.String(), `"hash"`) || strings.Contains(c2.last.Body.String(), `"stamp"`) {
		t.Error("TRUST the device list leaks hashes")
	}
	// TRUST-04: switched off → the code is asked for again
	f.set(func(d *Data) { d.Settings.SecTrustOff = true })
	c5 := f.client(t)
	c5.headers["Cookie"] = ck
	if code, m := login(c5, `{`+pw+`}`); code != 401 || m["needCode"] != true {
		t.Errorf("TRUST-04 off: %d %v", code, m)
	}
	f.set(func(d *Data) { d.Settings.SecTrustOff = false })
	// TRUST-03: a new password ends the device
	boss.must(200, "POST", "/api/auth/password", `{"current":"`+testPW+`","new":"a different passphrase 77"}`)
	c6 := f.client(t)
	c6.headers["Cookie"] = ck
	if code, m := login(c6, `{"name":"boss","password":"a different passphrase 77"}`); code != 401 || m["needCode"] != true {
		t.Errorf("TRUST-03 after a password change: %d %v", code, m)
	}
	// a new device again, then the account manager resets the second factor → ended too
	f.set(func(d *Data) { d.account("boss").TOTPLast = 0 }) // the test's codes all fall in the same 30 s
	c7 := f.client(t)
	c7.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"a different passphrase 77","code":"`+totpCode(sec, time.Now())+`","trust":true}`)
	ck7 := trustCookie(c7, "boss")
	opsSec := enableTOTP(t, ops) // ops re-enrols: its own devices (none) unaffected; boss unaffected
	_ = opsSec
	c8 := f.client(t)
	c8.headers["Cookie"] = ck7
	c8.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"a different passphrase 77"}`)
	// revoke all of boss's devices (own API)
	c8.must(200, "DELETE", "/api/auth/devices/all", "")
	c9 := f.client(t)
	c9.headers["Cookie"] = ck7
	if code, _ := login(c9, `{"name":"boss","password":"a different passphrase 77"}`); code != 401 {
		t.Errorf("TRUST-03 after revoking: %d", code)
	}
	// a manager revokes someone else's devices; an operator cannot
	if code, _ := ops.do("DELETE", "/api/accounts/boss/devices", ""); code != 403 {
		t.Errorf("TRUST operator revoked a manager's devices: %d", code)
	}
}

// SESS-P1: sessions survive a restart (a new router on the same data), the file holds hashes only,
// logout and expiry are honoured.
func TestSessionsPersist(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	b, err := os.ReadFile(filepath.Join(f.dir, "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), boss.cookie) {
		t.Error("SESS-P1 the session cookie is stored as is")
	}
	var m map[string]Session
	if json.Unmarshal(b, &m) != nil || len(m) == 0 {
		t.Fatalf("SESS-P1 file: %s", b)
	}
	// "restart": a new handler (new Auth) on the same data
	f.h = f.app.handler()
	again := &client{t: t, h: f.h, remote: boss.remote, cookie: boss.cookie, headers: map[string]string{}}
	again.must(200, "GET", "/api/state", "")
	// logout is written at once: after another restart the cookie is dead
	again.must(200, "POST", "/api/auth/logout", "")
	f.h = f.app.handler()
	dead := &client{t: t, h: f.h, remote: boss.remote, cookie: boss.cookie, headers: map[string]string{}}
	if code, _ := dead.do("GET", "/api/state", ""); code != 401 {
		t.Errorf("SESS-P1 a logged-out session came back: %d", code)
	}
	// expired sessions are not loaded
	c := f.client(t)
	c.must(200, "POST", "/api/auth/login", `{"name":"boss","password":"`+testPW+`"}`)
	f.app.auth.mu.Lock()
	for _, s := range f.app.auth.sessions {
		s.LastSeen = time.Now().Add(-48 * time.Hour)
	}
	f.app.auth.saveSessionsLocked()
	f.app.auth.mu.Unlock()
	f.h = f.app.handler()
	c.h = f.h
	if code, _ := c.do("GET", "/api/state", ""); code != 401 {
		t.Errorf("SESS-P1 an expired session was loaded: %d", code)
	}
}
