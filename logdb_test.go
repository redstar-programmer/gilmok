package main

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitFlush(t *testing.T, l *LogDB, want int64) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if l.written.Load() >= want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("writer did not flush: written=%d want %d err=%s", l.written.Load(), want, l.Stats().LastErr)
}

func TestLogDB(t *testing.T) {
	l, err := openLogDB(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.w.Close(); l.r.Close() })
	now := time.Now().UnixMilli()
	for i := 0; i < 300; i++ {
		st := 200
		if i%10 == 0 {
			st = 502
		}
		l.Req(ReqRec{T: now - int64(i)*1000, Host: []string{"a.x", "b.x"}[i%2], Method: "GET", URI: "/p?q=1", Status: st, Ms: float64(i), Size: 10, IP: "198.51.100.1"})
	}
	l.Event(Event{Cat: "audit", Action: "설정 변경", Msg: "test change", Actor: "admin"})
	l.Event(Event{Cat: "security", Level: "warn", Action: "waf.block", Msg: "WAF 차단"})
	b := Bucket{}
	b.add(ReqRec{Status: 200, Ms: 12})
	l.Metrics([]metricRow{{Ts: now / 1000 / 60 * 60, Host: "", B: b}})
	waitFlush(t, l, 303)

	ctx := context.Background()
	rows, err := l.QueryRequests(ctx, ReqQuery{Status: "5xx", Limit: 100})
	if err != nil || len(rows) != 30 {
		t.Fatalf("5xx rows %d %v", len(rows), err)
	}
	rows, _ = l.QueryRequests(ctx, ReqQuery{Host: "a.x", Limit: 10, SlowFirst: true})
	if len(rows) != 10 || rows[0].Ms != 298 {
		t.Fatalf("slow first: %+v", rows[0])
	}
	page2, _ := l.QueryRequests(ctx, ReqQuery{Before: rows[0].ID, Limit: 5})
	if len(page2) != 5 || page2[0].ID >= rows[0].ID {
		t.Fatal("cursor paging")
	}
	top, err := l.TopRequests(ctx, "host", 0, now+1, "", 5)
	errA := 0.0
	for _, x := range top {
		if x.Key == "a.x" {
			errA = x.Err
		}
	}
	if err != nil || len(top) != 2 || top[0].N != 150 || errA != 20 {
		t.Fatalf("top %+v %v", top, err)
	}
	evs, _ := l.QueryEvents(ctx, EventQuery{Cat: "audit", Q: "change"})
	if len(evs) != 1 || evs[0].Actor != "admin" {
		t.Fatalf("events %+v", evs)
	}
	if evs, _ := l.QueryEvents(ctx, EventQuery{Q: "100%_"}); len(evs) != 0 {
		t.Fatal("LIKE wildcards must be escaped")
	}
	mb, err := l.MetricBuckets(ctx, "", 0, now/1000+60)
	if err != nil || len(mb) != 1 {
		t.Fatalf("metrics %v %v", mb, err)
	}
	c := l.Counts(ctx)
	if c["requests"].Rows != 300 || c["audit"].Rows != 1 || c["security"].Rows != 1 || c["metrics"].Rows != 1 {
		t.Fatalf("counts %+v", c)
	}
	n, err := l.deleteBefore("requests", now-100*1000) // older than 100 s
	if err != nil || n < 195 || n > 205 {
		t.Fatalf("delete %d %v", n, err)
	}
	if n, _ := l.deleteBefore("security", 0); n != 1 {
		t.Fatal("delete all security")
	}
	if c := l.Counts(ctx); c["audit"].Rows != 1 {
		t.Fatal("deleting security must not touch audit")
	}

	// disk guard "stop": requests skipped, events kept (default), never blocks
	l.level.Store(LvlStop)
	before := l.skipped.Load()
	l.Req(ReqRec{T: now, Host: "a.x"})
	l.Event(Event{Cat: "system", Msg: "still logged"})
	if l.skipped.Load() != before+1 {
		t.Fatal("request not skipped at stop level")
	}
	waitFlush(t, l, 304)
	l.keepEvents.Store(false)
	l.Event(Event{Cat: "system", Msg: "dropped"})
	if l.skipped.Load() != before+2 {
		t.Fatal("event not skipped when keepEvents is off")
	}
	// a full queue drops instead of blocking
	l.level.Store(LvlOK)
	done := make(chan bool)
	go func() {
		for i := 0; i < 60000; i++ {
			l.Req(ReqRec{T: now, Host: "flood"})
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("producer blocked")
	}
}

func TestTOTP(t *testing.T) {
	// RFC 6238 SHA1 vector: secret "12345678901234567890", T=59 → 94287082 (last 6 digits 287082)
	sec := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got := totpCode(sec, time.Unix(59, 0)); got != "287082" {
		t.Fatalf("totp %s", got)
	}
	if !totpVerify(sec, totpCode(sec, time.Now())) || totpVerify(sec, "000000") && totpCode(sec, time.Now()) != "000000" {
		t.Fatal("verify")
	}
	if len(newTOTPSecret()) != 32 {
		t.Fatal("secret length")
	}
}

func TestAccessGuard(t *testing.T) {
	store, _ := OpenStore(filepath.Join(t.TempDir(), "g.json"))
	ensureProxySecret(store)
	_ = store.Update(func(d *Data) error { d.Settings.UseAuthelia = true; return nil })
	app := &App{store: store}
	a := newAuth(app)
	a.gwAt = time.Now()
	a.gateways = nil
	sec := store.Snapshot().ProxySecret

	req := func(remote string, hdr map[string]string) access {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote + ":5555"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return a.checkAccess(r)
	}
	if acc := req("127.0.0.1", nil); !acc.ok || acc.via != "direct" {
		t.Fatalf("loopback: %+v", acc)
	}
	if acc := req("172.18.0.9", nil); acc.ok {
		t.Fatal("another container must be refused")
	}
	if acc := req("172.18.0.5", map[string]string{proxyHeader: "wrong"}); acc.ok {
		t.Fatal("wrong secret accepted")
	}
	if acc := req("172.18.0.5", map[string]string{proxyHeader: sec}); acc.ok {
		t.Fatal("SSO required by default — Remote-User missing must be refused")
	}
	if acc := req("172.18.0.5", map[string]string{proxyHeader: sec, "Remote-User": "alice"}); !acc.ok || acc.ssoUser != "alice" {
		t.Fatalf("proxy + sso: %+v", acc)
	}
	_ = store.Update(func(d *Data) error { d.Settings.SecSSOGroups = "admins"; return nil })
	if acc := req("172.18.0.5", map[string]string{proxyHeader: sec, "Remote-User": "bob", "Remote-Groups": "users"}); acc.ok {
		t.Fatal("group restriction ignored")
	}
	if acc := req("172.18.0.5", map[string]string{proxyHeader: sec, "Remote-User": "alice", "Remote-Groups": "users,admins"}); !acc.ok {
		t.Fatal("group member refused")
	}
	a.gateways = nil
	a.gwAt = time.Now()
	a.gateways = append(a.gateways, []byte{172, 18, 0, 1})
	if acc := req("172.18.0.1", nil); !acc.ok || acc.via != "direct" {
		t.Fatalf("host-published port (gateway) must be direct: %+v", acc)
	}
	// without Authelia in use there is no SSO to require
	_ = store.Update(func(d *Data) error { d.Settings.UseAuthelia = false; d.Settings.SecSSOGroups = ""; return nil })
	if acc := req("172.18.0.5", map[string]string{proxyHeader: sec}); !acc.ok {
		t.Fatalf("no Authelia: proxy secret alone must be enough: %+v", acc)
	}
}

func TestProxyHeaderGenerate(t *testing.T) {
	st := testSettings()
	st.CaddyBase = "{\n}\n"
	st.SecSelfService = "g1"
	d := Data{Settings: st, ProxySecret: "s3cr3t", Services: []*Service{{ID: "g1", Subdomain: "gilmok", Enabled: true, Exposure: ExposureTailscale, Upstream: "gilmok:8080", Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor"}}}}
	gen := GenerateCaddyfile(d)
	if !strings.Contains(gen, "\trequest_header X-Gilmok-Proxy \"s3cr3t\" # gilmok\n") {
		t.Fatalf("proxy header missing:\n%s", gen)
	}
	_, got, _, _ := ImportCaddyfile(gen, st)
	if len(got) != 1 || got[0].Extra != "" {
		t.Fatalf("proxy header leaked into Extra: %+v", got[0])
	}
}
