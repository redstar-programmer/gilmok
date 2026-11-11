package main

// DNS / CFT / DDNS / CFW / CS scenarios

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScnDNSPlan(t *testing.T) {
	st := defaultSettings()
	st.Domain, st.TailscaleIP, st.UseCloudflare = "example.com", "100.64.0.5", true
	d := Data{Settings: st, ManagedDNS: []string{"p1.example.com", "pub.example.com"}, Services: []*Service{
		{ID: "1", Subdomain: "p1", Exposure: ExposureTailscale, Enabled: true, ManageDNS: true},
		{ID: "2", Subdomain: "p2", Exposure: ExposureTailscale, Enabled: true, ManageDNS: true},
		{ID: "3", Subdomain: "p3", Exposure: ExposureTailscale, Enabled: true, ManageDNS: true, Proxied: true},
		{ID: "4", Subdomain: "pub", Exposure: ExposurePublic, Enabled: true, ManageDNS: true, Proxied: false},
	}}
	recs := []DNSRecord{
		{ID: "a", Type: "A", Name: "p1.example.com", Content: "100.64.0.5"},
		{ID: "b", Type: "A", Name: "pub.example.com", Content: "2.2.2.2", Proxied: true},
		{ID: "c", Type: "A", Name: "rdp.example.com", Content: "9.9.9.9"},
	}
	acts := PlanDNS(d, recs, "2.2.2.2", "", d.ManagedDNS, nil)
	// DNS-07 (R10): every private service → Tailscale IP, DNS only
	for _, n := range []string{"p2.example.com", "p3.example.com"} {
		a := findAct(acts, "A", n)
		if a == nil || a.Action != "create" || a.content != "100.64.0.5" || a.proxied {
			t.Fatalf("DNS-07 %s: %+v", n, a)
		}
	}
	if a := findAct(acts, "A", "p1.example.com"); a == nil || a.Action != "ok" {
		t.Fatalf("DNS-07 p1: %+v", a)
	}
	// DNS-08: Proxied → DNS only
	if a := findAct(acts, "A", "pub.example.com"); a == nil || a.Action != "update" || a.proxied {
		t.Fatalf("DNS-08: %+v", a)
	}
	// DNS-12: a hand-made record is never in the plan
	if findAct(acts, "A", "rdp.example.com") != nil {
		t.Fatal("DNS-12: manual record touched")
	}
	// DNS-13: no token → apply skips DNS without calling Cloudflare
	f, sf := newStack(t)
	stackDocker(t, sf)
	t.Setenv("GM_CF_TOKEN", "")
	t.Setenv("GM_CF_TOKEN_FILE", "")
	oldUI := cfTokenUIPath
	t.Cleanup(func() { cfTokenUIPath = oldUI })
	cfTokenUIPath = filepath.Join(f.dir, "secrets", "none")
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()
	f.set(func(d *Data) { d.Settings.UseCloudflare = true })
	if _, err := f.app.Apply(false); err != nil || hits != 0 {
		t.Fatalf("DNS-13: %v hits=%d", err, hits)
	}
}

func TestScnDNSEditAndToken(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	cf := newFakeCFDNS(t)
	f.set(func(d *Data) { d.Settings.Domain, d.Settings.UseCloudflare = "example.com", true })
	// DNS-14: another zone's name stays inside this zone; odd types refused
	boss.must(200, "POST", "/api/dns/records", `{"type":"TXT","name":"evil.com","content":"hi"}`)
	if cf.byName("TXT", "evil.com.example.com") == nil || cf.byName("TXT", "evil.com") != nil {
		t.Fatalf("DNS-14 name: %v", cf.writes)
	}
	for _, typ := range []string{"NS", "SRV", "CAA"} {
		boss.must(400, "POST", "/api/dns/records", `{"type":"`+typ+`","name":"x","content":"y"}`)
	}
	// CFT-04: a token from the container → the UI cannot store one
	boss.must(409, "POST", "/api/cloudflare/token", `{"token":"abc"}`)
	// CFT-05: the token never comes back
	for _, p := range []string{"/api/cloudflare/token", "/api/state"} {
		boss.raw("GET", p, "")
		if strings.Contains(boss.last.Body.String(), "test-token-not-real") {
			t.Fatalf("CFT-05: %s leaks the token", p)
		}
	}
	// CFT-06: deleting the UI-stored token
	t.Setenv("GM_CF_TOKEN", "")
	cfTokenUIPath = filepath.Join(f.dir, "secrets", "cf_token")
	os.MkdirAll(filepath.Dir(cfTokenUIPath), 0o700)
	os.WriteFile(cfTokenUIPath, []byte("ui-token-not-real"), 0o600)
	if cfTokenSourceName() == "" {
		t.Fatal("CFT-06 setup")
	}
	boss.must(200, "DELETE", "/api/cloudflare/token", "")
	if _, err := os.Stat(cfTokenUIPath); err == nil || f.app.cf.Configured() {
		t.Fatal("CFT-06: token still there")
	}
	for _, e := range f.events(t, "audit") {
		if strings.Contains(e.Detail, "ui-token-not-real") || strings.Contains(e.Detail, "test-token-not-real") {
			t.Fatal("CFT-05: token in the audit log")
		}
	}
}

func TestScnDDNS(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	cf := newFakeCFDNS(t,
		DNSRecord{ID: "1", Type: "A", Name: "pub.example.com", Content: "2.2.2.2", Proxied: true},
		DNSRecord{ID: "2", Type: "A", Name: "dns.example.com", Content: "2.2.2.2"},
		DNSRecord{ID: "3", Type: "A", Name: "priv.example.com", Content: "100.64.0.5"},
	)
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCloudflare, d.Settings.TailscaleIP = "example.com", true, "100.64.0.5"
		d.Settings.DDNSEnabled = false
		d.LastPublicIP = "2.2.2.2"
		d.Services = []*Service{
			{ID: "a", Subdomain: "pub", Exposure: ExposurePublic, Enabled: true, ManageDNS: true, Proxied: true},
			{ID: "b", Subdomain: "dns", Exposure: ExposurePublic, Enabled: true, ManageDNS: true, DNSOnly: true},
			{ID: "c", Subdomain: "priv", Exposure: ExposureTailscale, Enabled: true, ManageDNS: true},
		}
	})
	ip := "2.2.2.2"
	publicIPFn = func(ctx context.Context, v6 bool) (string, error) {
		if v6 {
			return "", fmt.Errorf("no v6")
		}
		return ip, nil
	}
	// DDNS-10: run now needs DDNS on
	boss.must(400, "POST", "/api/ddns/run", "")
	f.set(func(d *Data) { d.Settings.DDNSEnabled = true })
	// DDNS-06 / DDNS-07: address change → public (incl. DNS only) updated, private untouched
	ip = "3.3.3.3"
	m := boss.must(200, "POST", "/api/ddns/run", "")
	if m["result"] != "updated" || cf.byName("A", "pub.example.com").Content != "3.3.3.3" || cf.byName("A", "dns.example.com").Content != "3.3.3.3" || cf.byName("A", "priv.example.com").Content != "100.64.0.5" {
		t.Fatalf("DDNS-06/07: %v %v", m, cf.writes)
	}
	if !cf.byName("A", "pub.example.com").Proxied {
		t.Fatal("DDNS-03: proxied flag changed")
	}
	// DDNS-05: same IP, but Cloudflare drifted → fixed at the drift check
	cf.mu.Lock()
	r := cf.recs["1"]
	r.Content = "9.9.9.9"
	cf.recs["1"] = r
	cf.mu.Unlock()
	if s := f.app.ddnsOnce(false); s.Result != "ok" || cf.byName("A", "pub.example.com").Content != "9.9.9.9" {
		t.Fatalf("DDNS-05: checked too early: %+v", s)
	}
	f.set(func(d *Data) { d.DDNS.Synced = time.Now().Add(-2 * ddnsDriftCheck) })
	if s := f.app.ddnsOnce(false); s.Result != "updated" || cf.byName("A", "pub.example.com").Content != "3.3.3.3" {
		t.Fatalf("DDNS-05: %+v", s)
	}
	// DDNS-09: change / fail / recover are system events
	cf.mu.Lock()
	cf.recs["1"] = DNSRecord{ID: "1", Type: "A", Name: "pub.example.com", Content: "3.3.3.3", Proxied: true}
	cf.mu.Unlock()
	ip = ""
	publicIPFn = func(ctx context.Context, v6 bool) (string, error) { return "", fmt.Errorf("offline") }
	f.app.ddnsOnce(true)
	publicIPFn = func(ctx context.Context, v6 bool) (string, error) {
		if v6 {
			return "", fmt.Errorf("no v6")
		}
		return "3.3.3.3", nil
	}
	f.app.ddnsOnce(true)
	acts := map[string]int{}
	for _, e := range f.events(t, "system") {
		acts[e.Action]++
	}
	if acts["ddns.update"] < 1 || acts["ddns.fail"] != 1 || acts["ddns.recover"] != 1 {
		t.Fatalf("DDNS-09: %v", acts)
	}
}

func TestScnCFWAFMore(t *testing.T) {
	// CFW-02: the threat expression has a length limit
	st := defaultSettings()
	st.Domain, st.CfThreatRule, st.GuardBots, st.GuardAI, st.GuardPaths = "example.com", true, true, true, true
	var ips []string
	for i := 0; i < 600; i++ {
		ips = append(ips, fmt.Sprintf("203.0.%d.%d", i/250, i%250+1))
	}
	st.CfDenyIPs = strings.Join(ips, "\n")
	if _, err := threatExpression(Data{Settings: st}); err == nil {
		t.Fatal("CFW-02: oversize expression accepted")
	}
	// CFW-12: saving settings keeps the Cloudflare rule ids (stored outside Settings)
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) { d.Settings.Domain = "example.com"; d.CFWAF.AsnRuleID, d.CFWAF.ListID = "r1", "l1" })
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.CfAsnRule = true }))
	if w := f.app.store.Snapshot().CFWAF; w.AsnRuleID != "r1" || w.ListID != "l1" {
		t.Fatalf("CFW-12: %+v", w)
	}
	// CFW-13 / CFW-14: edge events through GraphQL
	perm := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[{"id":"z1"}]}`)
		case r.URL.Path == "/graphql":
			if perm {
				fmt.Fprint(w, `{"data":null,"errors":[{"message":"not authorized for that account","extensions":{"code":"authz"}}]}`)
				return
			}
			ev := map[string]any{"action": "block", "source": "firewallCustom", "ruleId": "r9", "datetime": time.Now().UTC().Format(time.RFC3339), "clientIP": "198.51.100.4", "clientCountryName": "US", "clientRequestHTTPHost": "a.example.com", "clientRequestPath": "/wp-login.php"}
			b, _ := json.Marshal(map[string]any{"data": map[string]any{"viewer": map[string]any{"zones": []any{map[string]any{"firewallEventsAdaptive": []any{ev, ev}}}}}})
			w.Write(b)
		default:
			fmt.Fprint(w, `{"success":true,"errors":[],"result":{}}`)
		}
	}))
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()
	t.Setenv("GM_CF_TOKEN", "test-token-not-real-0000000000")
	t.Setenv("GM_CF_TOKEN_FILE", "")
	f.set(func(d *Data) { d.Settings.UseCloudflare = true })
	m := boss.must(200, "GET", "/api/cfwaf/events?since=1h", "")
	if !strings.Contains(fmtAny(m), "198.51.100.4") || !strings.Contains(fmtAny(m), "/wp-login.php") {
		t.Fatalf("CFW-13: %v", m)
	}
	perm = true
	code, m := boss.do("GET", "/api/cfwaf/events", "")
	if code != 400 || m["perms"] == nil {
		t.Fatalf("CFW-14: %d %v", code, m)
	}
	boss.must(200, "GET", "/api/state", "") // the rest still works
}

func TestScnCrowdSec(t *testing.T) {
	// CS-06 (R12): over the list limit → newest decisions kept, the rest counted
	var ds []Decision
	for i := 0; i < csListMax+50; i++ {
		ds = append(ds, Decision{ID: int64(i + 1), Type: "ban", Scope: "Ip", Value: fmt.Sprintf("8.%d.%d.%d", i/65536%256, i/256%256, i%256)})
	}
	items, dropped := banItemsN(ds)
	if len(items) != csListMax || dropped != 50 || containsStr(items, "8.0.0.0") || !containsStr(items, fmt.Sprintf("8.%d.%d.%d", (csListMax+49)/65536%256, (csListMax+49)/256%256, (csListMax+49)%256)) {
		t.Fatalf("CS-06: %d dropped=%d", len(items), dropped)
	}
	// CS-07: no decisions → empty list (old bans lifted)
	if items, _ := banItemsN(nil); len(items) != 0 {
		t.Fatal("CS-07")
	}

	f := newFullApp(t)
	boss := f.admin(t)
	fd := installFakeDocker(t, func(args []string, stdin []byte) (string, error) { return "ok", nil })
	f.set(func(d *Data) { d.Settings.UseCrowdSec, d.Settings.CrowdSecContainer = true, "cs" })
	// CS-08 / CS-13: input checks before cscli runs
	for _, bad := range []string{`{"ip":"--scope Range","duration":"4h"}`, `{"ip":"1.2.3.4 --type captcha","duration":"4h"}`, `{"ip":"1.2.3.4","duration":"4h; rm"}`, `{"ip":"1.2.3.4","duration":"10s"}`, `{"ip":"1.2.3.4","reason":"--x \"y\""}`, `{"ip":"300.1.1.1"}`} {
		boss.must(400, "POST", "/api/crowdsec/decisions", bad)
	}
	if fd.count("cscli") != 0 {
		t.Fatalf("CS-13: cscli ran for bad input: %v", fd.joined())
	}
	boss.must(200, "POST", "/api/crowdsec/decisions", `{"ip":"203.0.113.9","duration":"2h","reason":"test ban"}`)
	boss.must(200, "POST", "/api/crowdsec/decisions", `{"ip":"203.0.113.0/24"}`)
	if fd.count("decisions add --ip 203.0.113.9 --duration 2h") != 1 || fd.count("decisions add --range 203.0.113.0/24") != 1 {
		t.Fatalf("CS-08: %v", fd.joined())
	}
	// CS-09
	boss.must(400, "DELETE", "/api/crowdsec/decisions/abc", "")
	boss.must(200, "DELETE", "/api/crowdsec/decisions/42", "")
	if fd.count("decisions delete --id 42") != 1 {
		t.Fatalf("CS-09: %v", fd.joined())
	}
	// CS-10: two syncs at once never overlap
	var inFlight, maxIn int32
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			m := atomic.LoadInt32(&maxIn)
			if n <= m || atomic.CompareAndSwapInt32(&maxIn, m, n) {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		w.Write([]byte("null"))
	}))
	defer lapi.Close()
	t.Setenv("GM_CROWDSEC_KEY", "k-test")
	t.Setenv("GM_CF_TOKEN", "test-token-not-real-0000000000")
	f.set(func(d *Data) {
		d.Settings.UseCloudflare, d.Settings.CrowdSecEnabled, d.Settings.CrowdSecSync, d.Settings.CrowdSecLAPI = true, true, true, lapi.URL
	})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.app.crowdsecSyncOnce() }()
	}
	wg.Wait()
	if maxIn != 1 {
		t.Fatalf("CS-10: %d at once", maxIn)
	}
	// CS-12: no key → the check says so
	t.Setenv("GM_CROWDSEC_KEY", "")
	r := f.app.checkCrowdSec(context.Background())
	if !strings.Contains(fmtAny(r), "키") {
		t.Fatalf("CS-12: %s", fmtAny(r))
	}
}
