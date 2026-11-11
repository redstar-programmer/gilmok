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
)

func TestGuardAndServiceWAF(t *testing.T) {
	st := testSettings()
	st.CaddyBase = "{\n\temail x@example.com\n}\n"
	st.GuardBots, st.GuardAI, st.GuardPaths, st.GuardEmptyUA = true, true, true, true
	st.GuardUA = "evilbot\nBadCrawler"
	st.GuardPathList = "/secret-admin"
	st.WafGroupsOff = []string{"944", "999", "944"}
	st.WafExclude = []WafExclusion{{ID: "920350", Note: "IP Host"}}
	st.WafInbound, st.WafOutbound = 10, 4
	svcs := []*Service{
		{ID: "1", Subdomain: "app", Enabled: true, Exposure: ExposurePublic, Upstream: "app:80", WAF: WAFBlock, Guard: true},
		{ID: "2", Subdomain: "photo-x", Enabled: true, Exposure: ExposurePublic, Upstream: "p:80", WAF: WAFBlock,
			WAFParanoia: 2, WAFExclude: []WafExclusion{{ID: "942100"}}},
		{ID: "3", Subdomain: "plain", Enabled: true, Exposure: ExposurePublic, Upstream: "q:80"},
	}
	gen := GenerateCaddyfile(Data{Settings: st, Services: svcs})
	for _, want := range []string{
		"(gm_guard) {", "@gm_guard_bot header_regexp User-Agent `(?i)(sqlmap|", "evilbot|badcrawler)`",
		"@gm_guard_ai header_regexp User-Agent `(?i)(gptbot|", "@gm_guard_noua expression",
		"@gm_guard_path path */.env* ", "*/secret-admin*", "header @gm_guard_bot X-Gilmok-Block bot", "respond @gm_guard_bot 403",
		"(gm_waf_block) {", "(gm_waf_block_photo_x_2) {", "tx.blocking_paranoia_level=2", "SecRuleRemoveById 942100",
		"SecRuleRemoveById 944000-944999", "SecRuleRemoveById 920350", "tx.inbound_anomaly_score_threshold=10",
		"tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE",
		"app.example.com {\n\tlog # gilmok\n\timport gm_guard\n\timport gm_waf_block\n",
		"photo-x.example.com {\n\tlog # gilmok\n\timport gm_waf_block_photo_x_2\n",
	} {
		if !strings.Contains(gen, want) {
			t.Fatalf("missing %q:\n%s", want, gen)
		}
	}
	if strings.Contains(gen, "999000") {
		t.Fatal("unknown group must be ignored")
	}
	if i := strings.Index(gen, "(gm_waf_block) {"); strings.Contains(gen[i:strings.Index(gen[i:], "\n}\n")+i], "942100") {
		t.Fatal("service exclusion leaked into the shared snippet")
	}
	base, got, _, err := ImportCaddyfile(gen, st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(base, "gm_guard") || strings.Contains(base, "gm_waf") {
		t.Fatalf("managed snippets in base:\n%s", base)
	}
	by := map[string]*Service{}
	for _, s := range got {
		by[s.Subdomain] = s
	}
	if s := by["app"]; s == nil || !s.Guard || s.WAF != WAFBlock || s.Extra != "" {
		t.Fatalf("app: %+v", s)
	}
	if s := by["photo-x"]; s == nil || s.WAF != WAFBlock || s.Extra != "" {
		t.Fatalf("photo-x: %+v", s)
	}
	// no category selected → no snippet and no import (would be a Caddy error)
	st.GuardBots, st.GuardAI, st.GuardPaths, st.GuardEmptyUA, st.GuardUA, st.GuardPathList = false, false, false, false, "", ""
	gen = GenerateCaddyfile(Data{Settings: st, Services: svcs})
	if strings.Contains(gen, "gm_guard") {
		t.Fatalf("guard without categories:\n%s", gen)
	}
	// validation
	if _, err := validateWafExclusions([]WafExclusion{{ID: "94210"}}); err == nil {
		t.Fatal("5-digit id accepted")
	}
	if err := validateGuardLists(Settings{GuardUA: "bad`tick"}); err == nil {
		t.Fatal("backtick accepted")
	}
	if guardCategory(st, "Mozilla sqlmap/1", "/") != "bot" || guardCategory(st, "x", "/A/.ENV") != "path" || guardCategory(st, "", "/") != "noua" {
		t.Fatal("guardCategory")
	}
}

func TestCFExpressions(t *testing.T) {
	d := Data{Settings: testSettings(), Services: []*Service{
		{ID: "a", Subdomain: "a", Enabled: true, Exposure: ExposurePublic, Proxied: true},
		{ID: "b", Subdomain: "b", Enabled: false, Exposure: ExposurePublic, Proxied: true},
	}}
	st := &d.Settings
	st.CfAsnList, st.CfGeoCountries, st.CfGeoMode = "4766 9318", "", "allow"
	if e, _ := geoExpression(d); e != "not ip.src.asnum in {4766 9318}" {
		t.Fatalf("asn only must keep the old expression: %s", e)
	}
	st.CfGeoCountries, st.CfGeoBots = "kr jp", true
	if e, _ := geoExpression(d); e != `not (ip.src.country in {"KR" "JP"} or ip.src.asnum in {4766 9318}) and not cf.client.bot` {
		t.Fatalf("geo allow: %s", e)
	}
	st.CfGeoMode, st.CfGeoBots, st.CfAsnList, st.CfGeoHosts = "block", false, "", []string{"a"}
	if e, _ := geoExpression(d); e != `http.host in {"a.example.com"} and ip.src.country in {"KR" "JP"}` {
		t.Fatalf("geo block: %s", e)
	}
	st.CfGeoHosts = []string{"b"} // disabled only → error, never silently zone-wide
	if _, err := geoExpression(d); err == nil {
		t.Fatal("scope of disabled services must fail")
	}
	st.CfThreatBots, st.CfThreatPaths, st.CfDenyIPs = true, true, "203.0.113.5\n198.51.100.0/24"
	e, err := threatExpression(d)
	if err != nil || !strings.HasPrefix(e, "(ip.src in {203.0.113.5 198.51.100.0/24} or lower(http.user_agent) contains \"sqlmap\"") || !strings.Contains(e, `lower(http.request.uri.path) contains "/.env"`) {
		t.Fatalf("threat: %v %s", err, e)
	}
	st.CfThreatBots, st.CfThreatPaths, st.CfDenyIPs, st.GuardUA, st.GuardPathList = false, false, "", "", ""
	if _, err := threatExpression(d); err == nil {
		t.Fatal("empty threat rule accepted")
	}
	if _, err := parseIPList("1.2.3.4\nnope"); err == nil {
		t.Fatal("bad ip accepted")
	}
}

// fakeCF2: both phases, delete, position after, zone plan.
type fakeCF2 struct {
	mu    sync.Mutex
	sets  map[string]*cfRuleset // phase → ruleset
	plan  string
	seq   int
	calls []string
}

func (f *fakeCF2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	ok := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, `{"success":true,"errors":[],"result":%s}`, b)
	}
	body, _ := io.ReadAll(r.Body)
	p := r.URL.Path
	byID := func(id string) (*cfRuleset, string) {
		for ph, rs := range f.sets {
			if rs != nil && rs.ID == id {
				return rs, ph
			}
		}
		return nil, ""
	}
	switch {
	case p == "/zones" && r.Method == "GET":
		ok([]map[string]string{{"id": "z1"}})
	case p == "/zones/z1":
		ok(map[string]any{"account": map[string]string{"id": "acc1"}, "plan": map[string]string{"legacy_id": f.plan}})
	case strings.HasPrefix(p, "/zones/z1/rulesets/phases/"):
		ph := strings.TrimSuffix(strings.TrimPrefix(p, "/zones/z1/rulesets/phases/"), "/entrypoint")
		if r.Method == "PUT" {
			var in struct{ Rules []CFRule }
			_ = json.Unmarshal(body, &in)
			f.sets[ph] = &cfRuleset{ID: "rs_" + ph}
			for _, x := range in.Rules {
				f.insert(f.sets[ph], x, nil)
			}
			ok(f.sets[ph])
			return
		}
		if f.sets[ph] == nil {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10003,"message":"not found"}]}`)
			return
		}
		ok(f.sets[ph])
	case strings.HasPrefix(p, "/zones/z1/rulesets/"):
		parts := strings.Split(strings.TrimPrefix(p, "/zones/z1/rulesets/"), "/")
		rs, _ := byID(parts[0])
		if rs == nil {
			w.WriteHeader(404)
			return
		}
		switch {
		case len(parts) == 2 && r.Method == "POST":
			var in struct {
				CFRule
				Position map[string]any `json:"position"`
			}
			_ = json.Unmarshal(body, &in)
			f.insert(rs, in.CFRule, in.Position)
		case len(parts) == 3 && r.Method == "PATCH":
			var in CFRule
			_ = json.Unmarshal(body, &in)
			for i := range rs.Rules {
				if rs.Rules[i].ID == parts[2] {
					in.ID = parts[2]
					if in.Ref == "" {
						in.Ref = rs.Rules[i].Ref
					}
					rs.Rules[i] = in
				}
			}
		case len(parts) == 3 && r.Method == "DELETE":
			for i := range rs.Rules {
				if rs.Rules[i].ID == parts[2] {
					rs.Rules = append(rs.Rules[:i], rs.Rules[i+1:]...)
					break
				}
			}
		}
		ok(rs)
	default:
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"success":false,"errors":[{"code":7003,"message":"no route %s %s"}]}`, r.Method, p)
	}
}

func (f *fakeCF2) insert(rs *cfRuleset, x CFRule, pos map[string]any) {
	f.seq++
	x.ID = fmt.Sprintf("r%d", f.seq)
	if x.Ref == "" {
		x.Ref = x.ID
	}
	at := len(rs.Rules)
	if pos != nil {
		if v, ok := pos["index"].(float64); ok {
			at = int(v) - 1
		}
		if after, ok := pos["after"].(string); ok {
			for i, r := range rs.Rules {
				if r.ID == after {
					at = i + 1
				}
			}
		}
	}
	rs.Rules = append(rs.Rules[:at], append([]CFRule{x}, rs.Rules[at:]...)...)
}

func TestCloudflareEdgeRules(t *testing.T) {
	fake := &fakeCF2{sets: map[string]*cfRuleset{cfPhase: {ID: "rs1", Rules: []CFRule{{ID: "u1", Ref: "u1", Action: "block", Expression: "true", Description: "mine", Enabled: true}}}}, plan: "free"}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()
	t.Setenv("GM_CF_TOKEN", "test-token-not-real-0000000000")
	t.Setenv("GM_CF_TOKEN_FILE", "")
	store, err := OpenStore(filepath.Join(t.TempDir(), "g.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: store, cf: NewCF()}
	ctx := context.Background()
	_ = store.Update(func(x *Data) error {
		x.Settings.Domain, x.Settings.UseCloudflare = "example.com", true
		x.Settings.CfAllowRule, x.Settings.CfAllowIPs = true, "203.0.113.9"
		x.Settings.CfThreatRule = true // defaults: bots + paths
		x.Settings.CfRateRule = true
		return nil
	})
	if err := a.applyCFWAF(ctx, &logger{}); err != nil {
		t.Fatal(err)
	}
	rules := fake.sets[cfPhase].Rules
	if len(rules) != 3 || rules[0].Ref != refAllow || rules[0].Action != "skip" || rules[0].ActionParameters["ruleset"] != "current" || rules[1].ID != "u1" || rules[2].Ref != refThreat {
		t.Fatalf("custom rules/order: %+v", rules)
	}
	rr := fake.sets[cfRatePhase]
	if rr == nil || len(rr.Rules) != 1 || rr.Rules[0].Ratelimit == nil || rr.Rules[0].Ratelimit.RequestsPerPeriod != 30 || !strings.Contains(rr.Rules[0].Expression, `"/login"`) {
		t.Fatalf("rate rule: %+v", rr)
	}
	// re-apply = no writes
	n := len(fake.calls)
	if err := a.applyCFWAF(ctx, &logger{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range fake.calls[n:] {
		if !strings.HasPrefix(c, "GET ") {
			t.Fatalf("second apply wrote: %v", fake.calls[n:])
		}
	}
	// over the Free limit (5): custom + geo + 1 hand-made + 2 existing = 5 ok, crowdsec would make 6
	_ = store.Update(func(x *Data) error {
		x.Settings.CfCustomRule, x.Settings.CfCustomExpr = true, `http.request.uri.path eq "/x"`
		x.Settings.CfAsnRule, x.Settings.CfAsnList = true, "4766 9318"
		x.Settings.UseCrowdSec, x.Settings.CrowdSecEnabled, x.Settings.CrowdSecSync = true, true, true
		return nil
	})
	v := a.cfwafView(ctx)
	if v.Plan != "free" || v.Limit != 5 || v.After != 6 || v.OverLimit == "" {
		t.Fatalf("limit view: plan=%s limit=%d after=%d over=%q", v.Plan, v.Limit, v.After, v.OverLimit)
	}
	n = len(fake.calls)
	if err := a.applyCFWAF(ctx, &logger{}); err == nil || !strings.Contains(err.Error(), "한도") {
		t.Fatalf("over limit must refuse: %v", err)
	}
	for _, c := range fake.calls[n:] {
		if !strings.HasPrefix(c, "GET ") {
			t.Fatalf("refused apply wrote: %v", fake.calls[n:])
		}
	}
	// turning a Gilmok rule off deletes it (frees a slot)
	_ = store.Update(func(x *Data) error {
		x.Settings.UseCrowdSec, x.Settings.CfThreatRule, x.Settings.CfRateRule = false, false, false
		return nil
	})
	if err := a.applyCFWAF(ctx, &logger{}); err != nil {
		t.Fatal(err)
	}
	refs := []string{}
	for _, r := range fake.sets[cfPhase].Rules {
		refs = append(refs, r.Ref)
	}
	if strings.Join(refs, ",") != "gilmok_allow,u1,gilmok_asn,gilmok_custom" {
		t.Fatalf("after turning off: %v", refs)
	}
	if len(fake.sets[cfRatePhase].Rules) != 0 || store.Snapshot().CFWAF.ThreatRuleID != "" {
		t.Fatalf("rate/threat not deleted: %+v %+v", fake.sets[cfRatePhase], store.Snapshot().CFWAF)
	}
	// invalid settings for an enabled rule: nothing is written
	_ = store.Update(func(x *Data) error { x.Settings.CfAllowIPs = ""; return nil })
	if err := a.applyCFWAF(ctx, &logger{}); err == nil {
		t.Fatal("empty allow list accepted")
	}
}

func TestMigrateRemoveByID(t *testing.T) {
	ex, rest := migrateRemoveByID(nil, "SecRuleRemoveById 913100\nSecRuleUpdateTargetById 942100 \"!ARGS:pw\"\nSecRuleRemoveById 942100-942199")
	if len(ex) != 2 || ex[0].ID != "913100" || ex[1].ID != "942100-942199" || rest != `SecRuleUpdateTargetById 942100 "!ARGS:pw"` {
		t.Fatalf("%+v %q", ex, rest)
	}
}

func TestCFWAFPermissionMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[{"id":"z1"}]}`)
		case strings.Contains(r.URL.Path, "/rulesets/"):
			w.WriteHeader(403)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)
		default:
			fmt.Fprint(w, `{"success":true,"errors":[],"result":{"plan":{"legacy_id":"free"}}}`)
		}
	}))
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()
	t.Setenv("GM_CF_TOKEN", "test-token-not-real-0000000000")
	t.Setenv("GM_CF_TOKEN_FILE", "")
	store, err := OpenStore(filepath.Join(t.TempDir(), "g.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: store, cf: NewCF()}
	v := a.cfwafView(context.Background())
	if v.Error == "" || len(v.Perms) != 1 || v.Perms[0] != permWAF || !strings.Contains(v.Error, "영역 WAF") {
		t.Fatalf("view: %+v", v)
	}
	if err := a.applyCFWAF(context.Background(), &logger{}); permOf(err) != permWAF {
		t.Fatalf("apply must report the missing permission: %v", err)
	}
}

func TestAdoptASNMode(t *testing.T) {
	for expr, want := range map[string]string{
		"not ip.src.asnum in {4766 9318}":            "not",
		"(not ip.src.asnum in {4766})":               "not",
		"(ip.src.asnum in {12345})":                  "",
		"ip.src.asnum in {12345 678}":                "",
		"ip.src.asnum in {1} and http.host eq \"a\"": "nomatch",
		"not ip.src.country in {\"KR\"}":             "nomatch",
	} {
		m := reASN.FindStringSubmatch(expr)
		switch {
		case want == "nomatch" && m != nil:
			t.Fatalf("%q must not be adoptable", expr)
		case want != "nomatch" && m == nil:
			t.Fatalf("%q must be adoptable", expr)
		case want == "not" && strings.TrimSpace(m[1]) != "not", want == "" && m != nil && strings.TrimSpace(m[1]) != "":
			t.Fatalf("%q negation: %q", expr, m[1])
		}
	}
	// the blocked list round-trips through the geo expression unchanged in meaning
	d := Data{Settings: Settings{CfGeoMode: "block", CfAsnList: "12345"}}
	if e, _ := geoExpression(d); e != "ip.src.asnum in {12345}" {
		t.Fatalf("block mode: %q", e)
	}
}
