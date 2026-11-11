package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWAFAndCrowdSecGenerateRoundTrip(t *testing.T) {
	st := testSettings()
	st.CaddyBase = "{\n\tacme_dns cloudflare x\n}\n\n(cf_only) {\n\ttls internal\n}\n\n(authelia) {\n\trespond 401\n}\n"
	st.CrowdSecEnabled = true
	st.WafParanoia = 2
	st.WafDirectives = "SecRuleRemoveById 920350"
	svcs := []*Service{
		{ID: "1", Subdomain: "joplin", Enabled: true, Exposure: ExposurePublic, Proxied: true, MTLS: true, Upstream: "app:22300", WAF: WAFBlock},
		{ID: "2", Subdomain: "immich", Enabled: true, Exposure: ExposurePublic, Proxied: false, Upstream: "immich_server:2283", WAF: WAFDetect},
		{ID: "3", Subdomain: "list", Enabled: true, Exposure: ExposureTailscale, Upstream: "servicelist:80", Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor"}},
	}
	gen := GenerateCaddyfile(Data{Settings: st, Services: svcs})
	for _, want := range []string{
		"(gm_waf_block) {", "(gm_waf_detect) {", "SecRuleEngine On", "SecRuleEngine DetectionOnly",
		"tx.blocking_paranoia_level=2", "SecRuleRemoveById 920350", "SecRequestBodyAccess Off",
		"joplin.example.com {\n\timport cf_only\n\tlog # gilmok\n\tlog_append gm_real_ip {http.request.header.Cf-Connecting-Ip}\n\timport gm_waf_block\n",
		"immich.example.com {\n\tlog # gilmok\n\timport gm_waf_detect\n\treverse_proxy", // dashboard log (DashLogs) but no real IP
	} {
		if !strings.Contains(gen, want) {
			t.Fatalf("generated Caddyfile missing %q:\n%s", want, gen)
		}
	}
	// gray-cloud site must never carry the real-IP field (forgeable header)
	if i := strings.Index(gen, "immich.example.com {"); strings.Contains(gen[i:i+120], realIPField) {
		t.Fatal("gray site got gm_real_ip")
	}
	if strings.Index(gen, "SecRuleRemoveById") < strings.Index(gen, "Include @owasp_crs/*.conf") {
		t.Fatal("exclusions must come after the CRS include")
	}

	base, got, _, err := ImportCaddyfile(gen, st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(base, "gm_waf") {
		t.Fatalf("managed snippets leaked into the base skeleton:\n%s", base)
	}
	by := map[string]*Service{}
	for _, s := range got {
		by[s.Subdomain] = s
	}
	if s := by["joplin"]; s == nil || s.WAF != WAFBlock || s.Extra != "" || !s.MTLS {
		t.Fatalf("joplin round trip: %+v", s)
	}
	if s := by["immich"]; s == nil || s.WAF != WAFDetect || s.Extra != "" {
		t.Fatalf("immich round trip: %+v", s)
	}
	// a user's own `log` directive is kept (and not duplicated)
	svcs[0].Extra = "log {\n\toutput stdout\n}"
	gen2 := GenerateCaddyfile(Data{Settings: st, Services: svcs})
	if j := gen2[strings.Index(gen2, "joplin.example.com"):]; strings.Contains(j[:strings.Index(j, "}\n\n")], "\tlog # gilmok") {
		t.Fatal("bare log added although Extra has a log block")
	}
	if !strings.Contains(gen2, "log_append gm_real_ip") {
		t.Fatal("log_append missing")
	}
}

func TestParseWAFLine(t *testing.T) {
	line := `{"level":"warn","ts":1793848114.819745,"logger":"http.handlers.waf","msg":"[client \"172.17.0.1\"] Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 8) [file \"@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf\"] [line \"7664\"] [id \"949110\"] [rev \"\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 8)\"] [data \"\"] [severity \"unknown\"] [ver \"OWASP_CRS/4.25.0\"] [hostname \"\"] [uri \"/?id=1%27%20OR%201=1--\"] [unique_id \"eVnoRamqvZxOtkyF\"]"}`
	ev, ok := parseWAFLine(line)
	if !ok || ev.Action != "denied" || ev.RuleID != "949110" || ev.URI != "/?id=1%27%20OR%201=1--" || ev.TxID != "eVnoRamqvZxOtkyF" || !strings.HasPrefix(ev.Msg, "Inbound Anomaly") {
		t.Fatalf("%+v", ev)
	}
	if _, ok := parseWAFLine(`{"level":"warn","logger":"http.handlers.waf","msg":"key not found in collection"}`); ok {
		t.Fatal("noise line parsed")
	}
}

func TestBanItems(t *testing.T) {
	got := banItems([]Decision{
		{Type: "ban", Scope: "Ip", Value: "203.0.113.77"},
		{Type: "ban", Scope: "Ip", Value: "203.0.113.77"},
		{Type: "ban", Scope: "Ip", Value: "172.18.0.1"}, // docker bridge — never
		{Type: "ban", Scope: "Ip", Value: "192.168.1.10"},
		{Type: "captcha", Scope: "Ip", Value: "198.51.100.1"},
		{Type: "ban", Scope: "Ip", Value: "2001:db8::1"},
		{Type: "ban", Scope: "Range", Value: "198.51.100.0/24"},
		{Type: "ban", Scope: "Range", Value: "0.0.0.0/1"},
	})
	want := "198.51.100.0/24,2001:db8::/64,203.0.113.77"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v want %s", got, want)
	}
}

// ---------------------------------------------------------------- fake Cloudflare

type fakeCF struct {
	mu    sync.Mutex
	rs    *cfRuleset
	lists []CFList
	items map[string][]string
	seq   int
	calls []string
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	ok := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, `{"success":true,"errors":[],"result":%s}`, b)
	}
	body, _ := io.ReadAll(r.Body)
	p := r.URL.Path
	const ep = "/zones/z1/rulesets/phases/http_request_firewall_custom/entrypoint"
	switch {
	case p == "/zones" && r.Method == "GET":
		ok([]map[string]string{{"id": "z1"}})
	case p == "/zones/z1":
		ok(map[string]any{"account": map[string]string{"id": "acc1"}})
	case p == ep && r.Method == "GET":
		if f.rs == nil {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10003,"message":"could not find entrypoint ruleset"}]}`)
			return
		}
		ok(f.rs)
	case p == ep && r.Method == "PUT":
		var in struct{ Rules []CFRule }
		_ = json.Unmarshal(body, &in)
		f.rs = &cfRuleset{ID: "rs1"}
		for _, x := range in.Rules {
			f.add(x, false)
		}
		ok(f.rs)
	case p == "/zones/z1/rulesets/rs1/rules" && r.Method == "POST":
		var in struct {
			CFRule
			Position map[string]int `json:"position"`
		}
		_ = json.Unmarshal(body, &in)
		f.add(in.CFRule, in.Position["index"] == 1)
		ok(f.rs)
	case strings.HasPrefix(p, "/zones/z1/rulesets/rs1/rules/") && r.Method == "PATCH":
		id := strings.TrimPrefix(p, "/zones/z1/rulesets/rs1/rules/")
		var in CFRule
		_ = json.Unmarshal(body, &in)
		for i := range f.rs.Rules {
			if f.rs.Rules[i].ID == id {
				in.ID = id
				if in.Ref == "" {
					in.Ref = f.rs.Rules[i].Ref
				}
				f.rs.Rules[i] = in
			}
		}
		ok(f.rs)
	case p == "/accounts/acc1/rules/lists" && r.Method == "GET":
		ok(f.lists)
	case p == "/accounts/acc1/rules/lists" && r.Method == "POST":
		var in CFList
		_ = json.Unmarshal(body, &in)
		in.ID = "list1"
		f.lists = append(f.lists, in)
		ok(in)
	case strings.HasPrefix(p, "/accounts/acc1/rules/lists/") && strings.HasSuffix(p, "/items") && r.Method == "PUT":
		var in []map[string]string
		_ = json.Unmarshal(body, &in)
		var ips []string
		for _, x := range in {
			ips = append(ips, x["ip"])
		}
		f.items[strings.Split(p, "/")[5]] = ips
		ok(map[string]string{"operation_id": "op1"})
	default:
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"success":false,"errors":[{"code":7003,"message":"no route %s %s"}]}`, r.Method, p)
	}
}

func (f *fakeCF) add(x CFRule, first bool) {
	f.seq++
	x.ID = fmt.Sprintf("r%d", f.seq)
	if x.Ref == "" {
		x.Ref = x.ID
	}
	if first {
		f.rs.Rules = append([]CFRule{x}, f.rs.Rules...)
	} else {
		f.rs.Rules = append(f.rs.Rules, x)
	}
}

func TestCloudflareWAFFlow(t *testing.T) {
	fake := &fakeCF{items: map[string][]string{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()
	t.Setenv("GM_CF_TOKEN", "test-token-not-real-0000000000")
	t.Setenv("GM_CF_TOKEN_FILE", "")

	// the zone already has a hand-made rule plus an unrelated one
	fake.rs = &cfRuleset{ID: "rs1", Rules: []CFRule{
		{ID: "u1", Ref: "u1", Action: "managed_challenge", Expression: "(not ip.src.asnum in {4766 9318})", Description: "KR ISP only", Enabled: true},
		{ID: "u2", Ref: "u2", Action: "block", Expression: `(http.request.uri.path contains "/wp-admin")`, Description: "mine", Enabled: true},
	}}
	store, err := OpenStore(filepath.Join(t.TempDir(), "g.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: store, cf: NewCF()}
	a.cs.kick = make(chan struct{}, 1)
	ctx := context.Background()

	v := a.cfwafView(ctx)
	if v.Error != "" || len(v.Adoptable) != 1 || v.Adoptable[0].ID != "u1" {
		t.Fatalf("view: %+v", v)
	}
	// adopt via handler
	rec := httptest.NewRecorder()
	a.postCFWAFAdopt(rec, httptest.NewRequest("POST", "/api/cfwaf/adopt", strings.NewReader(`{"id":"u1"}`)))
	if rec.Code != 200 {
		t.Fatalf("adopt: %d %s", rec.Code, rec.Body)
	}
	d := store.Snapshot()
	if d.CFWAF.AsnRuleID != "u1" || d.Settings.CfAsnList != "4766 9318" || !d.Settings.CfAsnRule {
		t.Fatalf("adopt state: %+v %+v", d.CFWAF, d.Settings)
	}
	// turn on CrowdSec sync, switch the ASN rule to block, apply
	_ = store.Update(func(x *Data) error {
		x.Settings.CfAsnAction = "block"
		x.Settings.CrowdSecEnabled, x.Settings.CrowdSecSync = true, true
		x.Settings.UseCrowdSec, x.Settings.UseCloudflare = true, true
		return nil
	})
	L := &logger{}
	if err := a.applyCFWAF(ctx, L); err != nil {
		t.Fatalf("apply: %v\n%s", err, strings.Join(L.lines, "\n"))
	}
	rules := fake.rs.Rules
	if len(rules) != 3 || rules[0].Ref != refCrowdSec || rules[0].Expression != "ip.src in $gilmok_crowdsec" || rules[0].Action != "block" {
		t.Fatalf("crowdsec rule must be first: %+v", rules)
	}
	var asn, mine *CFRule
	for i := range rules {
		switch rules[i].ID {
		case "u1":
			asn = &rules[i]
		case "u2":
			mine = &rules[i]
		}
	}
	if asn == nil || asn.Action != "block" || asn.Expression != "not ip.src.asnum in {4766 9318}" || asn.Ref != "u1" {
		t.Fatalf("adopted rule not updated in place: %+v", asn)
	}
	if mine == nil || mine.Description != "mine" || mine.Action != "block" {
		t.Fatalf("unrelated rule touched: %+v", mine)
	}
	if len(fake.lists) != 1 || fake.lists[0].Name != csListName {
		t.Fatalf("list: %+v", fake.lists)
	}
	// second apply is a no-op
	n := len(fake.calls)
	if err := a.applyCFWAF(ctx, &logger{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range fake.calls[n:] {
		if !strings.HasPrefix(c, "GET ") {
			t.Fatalf("second apply wrote: %v", fake.calls[n:])
		}
	}
	// plan shows everything ok
	for _, p := range a.cfwafView(ctx).Items {
		if p.Action != "ok" && p.Action != "skip" {
			t.Fatalf("plan not clean: %+v", p)
		}
	}

	// CrowdSec → list sync with a fake LAPI
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k-test" || r.URL.Query().Get("origins") != "crowdsec,cscli" {
			w.WriteHeader(403)
			return
		}
		fmt.Fprint(w, `[{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.77","scenario":"x"},{"id":2,"origin":"crowdsec","type":"ban","scope":"Ip","value":"172.18.0.1"}]`)
	}))
	defer lapi.Close()
	t.Setenv("GM_CROWDSEC_KEY", "k-test")
	_ = store.Update(func(x *Data) error { x.Settings.CrowdSecLAPI = lapi.URL; return nil })
	a.crowdsecSyncOnce()
	if a.cs.status.Error != "" || strings.Join(fake.items["list1"], ",") != "203.0.113.77" {
		t.Fatalf("sync: %+v items=%v", a.cs.status, fake.items)
	}
	n = len(fake.calls)
	a.crowdsecSyncOnce() // unchanged → no write
	for _, c := range fake.calls[n:] {
		if strings.HasPrefix(c, "PUT ") {
			t.Fatal("unchanged decisions re-pushed")
		}
	}
}

func TestDashLogsAndBuckets(t *testing.T) {
	st := testSettings()
	st.CaddyBase = "{\n}\n"
	svcs := []*Service{{ID: "1", Subdomain: "list", Enabled: true, Exposure: ExposureTailscale, Upstream: "servicelist:80"}}
	on := GenerateCaddyfile(Data{Settings: st, Services: svcs})
	st.DashLogs = false
	off := GenerateCaddyfile(Data{Settings: st, Services: svcs})
	if !strings.Contains(on, "\tlog # gilmok\n") || strings.Contains(off, "log") {
		t.Fatalf("dash logs:\n%s\n---\n%s", on, off)
	}
	_, got, _, _ := ImportCaddyfile(on, st)
	if len(got) != 1 || got[0].Extra != "" {
		t.Fatalf("generated log line leaked into Extra: %+v", got)
	}

	r, ok := parseAccessLine(`{"level":"info","ts":1793848114.780806,"logger":"http.log.access.log3","msg":"handled request","request":{"remote_ip":"172.17.0.1","client_ip":"172.17.0.1","proto":"HTTP/1.1","method":"GET","host":"Joplin.example.com:18443","uri":"/x?a=1","headers":{}},"duration":0.123456,"size":42,"status":503,"gm_real_ip":"1.2.3.4"}`)
	if !ok || r.Host != "joplin.example.com" || r.Status != 503 || r.Ms != 123.46 || r.IP != "1.2.3.4" || r.T != 1793848114780 {
		t.Fatalf("%+v", r)
	}
	m := newMonitor()
	now := time.Now().UnixMilli()
	for i := 0; i < 100; i++ {
		ms := 10.0
		if i >= 95 {
			ms = 900
		}
		st := 200
		if i%10 == 0 {
			st = 500
		}
		m.addReq(ReqRec{T: now - int64(i)*1000, Host: "a", Status: st, Ms: ms, Size: 10})
	}
	tot := m.total(15*time.Minute, "")
	if tot.N != 100 || tot.S5 != 10 || tot.Bytes != 1000 || tot.pct(0.95) > 10 || tot.pct(0.99) < 500 || tot.pct(0.99) > 900 {
		t.Fatalf("total %+v p95=%v p99=%v", tot, tot.pct(0.95), tot.pct(0.99))
	}
	if m.total(15*time.Minute, "b").N != 0 {
		t.Fatal("host filter")
	}
	_, ts, bs := m.series(time.Hour, "", 60)
	if len(ts) != len(bs) || len(bs) < 55 || len(bs) > 61 {
		t.Fatalf("series points %d", len(bs))
	}
	w := Widget{Type: "scatter", Range: "24h", W: 9}
	if normalizeWidget(&w) != nil || w.Range != "1h" || w.W != 4 || w.ID == "" {
		t.Fatalf("%+v", w)
	}
	if normalizeWidget(&Widget{Type: "stat", Metric: "nope"}) == nil {
		t.Fatal("bad metric accepted")
	}
}

func TestComponentsGenerate(t *testing.T) {
	st := testSettings()
	st.CaddyBase = "{\n}\n"
	st.CrowdSecEnabled = true
	svcs := []*Service{{ID: "1", Subdomain: "a", Enabled: true, Exposure: ExposurePublic, Proxied: true, MTLS: true, Upstream: "a:80", Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor"}}}
	full := GenerateCaddyfile(Data{Settings: st, Services: svcs})
	for _, want := range []string{"import cf_only", "import authelia", "log_append gm_real_ip"} {
		if !strings.Contains(full, want) {
			t.Fatalf("full edge missing %q", want)
		}
	}
	st.UseAuthelia, st.UseCloudflare = false, false
	bare := GenerateCaddyfile(Data{Settings: st, Services: svcs})
	for _, not := range []string{"import cf_only", "import authelia", "log_append gm_real_ip"} {
		if strings.Contains(bare, not) {
			t.Fatalf("Caddy-only install must not contain %q:\n%s", not, bare)
		}
	}
}
