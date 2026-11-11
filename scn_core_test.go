package main

// STORE / SET / SVC / CADDY scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestMain: the test binary doubles as a fake `caddy` for native mode (CADDY-17).
func TestMain(m *testing.M) {
	if os.Getenv("GM_FAKE_CADDY") == "1" {
		args := strings.Join(os.Args[1:], " ")
		if strings.Contains(args, "validate") {
			for i, a := range os.Args {
				if a == "--config" && i+1 < len(os.Args) {
					b, _ := os.ReadFile(os.Args[i+1])
					if strings.Contains(string(b), "BROKEN") {
						fmt.Println("Error: adapting config using caddyfile: unrecognized directive: BROKEN")
						os.Exit(1)
					}
				}
			}
			fmt.Println("Valid configuration")
			os.Exit(0)
		}
		if strings.Contains(args, "reload") {
			os.Exit(0)
		}
		fmt.Println("v2.99.0 fake")
		os.Exit(0)
	}
	// tests never ask the real Tailscale DNS (tests that need it fake tsMagicLookup)
	tsMagicLookup = func(context.Context, string) ([]string, bool) { return nil, false }
	os.Exit(m.Run())
}

func TestScnStore(t *testing.T) {
	dir := t.TempDir()
	// STORE-01 / STORE-02
	t.Setenv("GM_DOMAIN", "env.example")
	t.Setenv("GM_TAILSCALE_IP", "100.64.0.9")
	p := filepath.Join(dir, "g.json")
	s, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	st := s.Snapshot().Settings
	if st.Domain != "env.example" || st.TailscaleIP != "100.64.0.9" || st.CaddyContainer == "" {
		t.Fatalf("STORE-01/02: %+v", st)
	}
	_ = s.Update(func(d *Data) error { d.Settings.Domain = "kept.example"; return nil })
	t.Setenv("GM_DOMAIN", "other.example")
	s2, _ := OpenStore(p)
	if s2.Snapshot().Settings.Domain != "kept.example" {
		t.Fatal("STORE-02: env must not override an existing file")
	}
	// STORE-04: callback error → memory untouched
	err = s2.Update(func(d *Data) error {
		d.Settings.Domain = "dirty.example"
		d.Services = append(d.Services, &Service{ID: "x"})
		return errors.New("stop")
	})
	if err == nil || s2.Snapshot().Settings.Domain != "kept.example" || len(s2.Snapshot().Services) != 0 {
		t.Fatalf("STORE-04: %v %+v", err, s2.Snapshot().Settings.Domain)
	}
	// STORE-03: save fails (tmp path is a directory) → error, file and memory unchanged
	before, _ := os.ReadFile(p)
	if err := os.Mkdir(p+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s2.Update(func(d *Data) error { d.Settings.Domain = "lost.example"; return nil }); err == nil {
		t.Fatal("STORE-03: save error not reported")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) || s2.Snapshot().Settings.Domain != "kept.example" {
		t.Fatal("STORE-03: file or memory changed by a failed save")
	}
	os.Remove(p + ".tmp")
	// STORE-05: snapshots are independent copies
	_ = s2.Update(func(d *Data) error { d.Services = []*Service{{ID: "a", Subdomain: "a"}}; return nil })
	snap := s2.Snapshot()
	snap.Services[0].Subdomain = "changed"
	if s2.Snapshot().Services[0].Subdomain != "a" {
		t.Fatal("STORE-05: snapshot shares memory")
	}
	// STORE-06 / STORE-07
	var d Data
	d.markDirty("x")
	d.markDirty("x")
	d.markDirty("y")
	if len(d.Pending) != 2 || !d.Dirty {
		t.Fatalf("STORE-06: %v", d.Pending)
	}
	// STORE-08: corrupt file → error, not overwritten
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0o600)
	if _, err := OpenStore(bad); err == nil {
		t.Fatal("STORE-08: corrupt file accepted")
	}
	if b, _ := os.ReadFile(bad); string(b) != "{not json" {
		t.Fatal("STORE-08: corrupt file overwritten")
	}
	// STORE-10: concurrent readers and writers stay consistent
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_ = s2.Update(func(d *Data) error { d.markDirty(fmt.Sprintf("c%d", i)); return nil })
		}(i)
		go func() { defer wg.Done(); _ = s2.Snapshot() }()
	}
	wg.Wait()
	if n := len(s2.Snapshot().Pending); n != 20 {
		t.Fatalf("STORE-10: %d pending", n)
	}
}

func TestScnSettings(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCaddy = "example.com", true
		d.Services = []*Service{{ID: "a", Subdomain: "a", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true, WAF: WAFDetect}}
		d.Dirty, d.Pending = false, nil
	})
	// SET-01: a key that changes the generated Caddyfile → pending
	m := boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.WafParanoia = 3 }))
	if m["pending"] != true || !f.app.store.Snapshot().Dirty {
		t.Fatalf("SET-01: %v", m)
	}
	// SET-12: display-only keys are not pending
	f.set(func(d *Data) { d.Dirty, d.Pending = false, nil })
	m = boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.TopoEdgeName = "공유기"; s.TopoEdgeKind = "router" }))
	if m["pending"] != false || f.app.store.Snapshot().Dirty {
		t.Fatalf("SET-12: %v", m)
	}
	// SET-10: domain normalisation / refusal / empty allowed
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.Domain = " Example.COM. " }))
	if got := f.app.store.Snapshot().Settings.Domain; got != "example.com" {
		t.Fatalf("SET-10: %q", got)
	}
	boss.must(400, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.Domain = "exa mple" }))
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.Domain = "" }))
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.Domain = "example.com" }))
	// SET-14: traversal and system folders
	for _, p := range []string{"/data/../etc/passwd", "/proc/self/environ", "relative/Caddyfile", "/run/secrets/x", filepath.ToSlash(filepath.Join(f.dir, "x"))} {
		code, m := boss.do("PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.CaddyfilePath = p }))
		if code != 400 {
			t.Errorf("SET-14 %s: %d %v", p, code, m)
		}
	}
	// SET-08: an odd existing path is not re-checked when unchanged
	f.set(func(d *Data) { d.Settings.AutheliaUsers = "/etc/odd/users.yml" })
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.WafParanoia = 2 }))
	// both access paths off is refused
	boss.must(400, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.SecAllowDirect, s.SecAllowProxy = false, false }))
	// SET-13: audited with the changed keys
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.WafParanoia = 4; s.WafInbound = 9 }))
	ok := false
	for _, e := range f.events(t, "audit") {
		if e.Action == "설정 변경" && strings.Contains(e.Target, "wafParanoia") && strings.Contains(e.Target, "wafInbound") {
			ok = true
		}
	}
	if !ok {
		t.Fatal("SET-13: changed keys not audited")
	}
}

func TestScnServices(t *testing.T) {
	st := Settings{Domain: "example.com"}
	v := func(s Service, all ...*Service) (*Service, error) {
		x := s
		return &x, validateService(&x, all, st)
	}
	// SVC-02
	if s, err := v(Service{Subdomain: " Photos ", Upstream: "a:1", Exposure: ExposurePublic}); err != nil || s.Subdomain != "photos" {
		t.Fatalf("SVC-02 lower: %v %v", s, err)
	}
	for _, sub := range []string{"a b", "a_b", ""} {
		if _, err := v(Service{Subdomain: sub, Upstream: "a:1", Exposure: ExposurePublic}); err == nil {
			t.Errorf("SVC-02 %q accepted", sub)
		}
	}
	if _, err := v(Service{Subdomain: "@", Upstream: "a:1", Exposure: ExposurePublic}); err != nil {
		t.Fatal("SVC-02 root", err)
	}
	// SVC-03
	if _, err := v(Service{ID: "n", Subdomain: "a", Upstream: "a:1", Exposure: ExposurePublic}, &Service{ID: "o", Subdomain: "a"}); err == nil {
		t.Fatal("SVC-03 duplicate")
	}
	// SVC-04 / 05
	s, _ := v(Service{Subdomain: "a", Upstream: "a:1", Exposure: ExposureTailscale, Proxied: true, MTLS: true})
	if s.Proxied || s.MTLS {
		t.Fatal("SVC-04")
	}
	s, _ = v(Service{Subdomain: "a", Upstream: "a:1", Exposure: ExposurePublic, MTLS: true})
	if s.MTLS {
		t.Fatal("SVC-05")
	}
	// SVC-06
	s, _ = v(Service{Subdomain: "a", Upstream: "a:1", Extra: "x", Exposure: ExposurePublic, DNSOnly: true, WAF: WAFBlock, Guard: true, Authelia: AutheliaOpts{Enabled: true}})
	if s.Upstream != "" || s.Extra != "" || s.WAF != WAFOff || s.Guard || s.Authelia.Enabled {
		t.Fatalf("SVC-06: %+v", s)
	}
	// SVC-07 / 08
	if _, err := v(Service{Subdomain: "a", Exposure: ExposurePublic}); err == nil {
		t.Fatal("SVC-07")
	}
	if _, err := v(Service{Subdomain: "a", Upstream: "a{", Exposure: ExposurePublic}); err == nil {
		t.Fatal("SVC-08")
	}
	if _, err := v(Service{Subdomain: "a", Upstream: "a:1", Exposure: "nowhere"}); err == nil {
		t.Fatal("exposure")
	}
	// SVC-11 / SVC-16
	s, _ = v(Service{Subdomain: "a", Upstream: "a:1", Exposure: ExposurePublic, WAFParanoia: 5})
	if s.Authelia.Policy != "two_factor" || s.WAFParanoia != 0 {
		t.Fatalf("SVC-11/16: %+v", s)
	}
	// CADDY-18: the proxy header is never typed into a service
	if _, err := v(Service{Subdomain: "a", Upstream: "a:1", Exposure: ExposurePublic, Extra: "request_header X-Gilmok-Proxy abc"}); err == nil {
		t.Fatal("CADDY-18")
	}
	// SVC-10 (R9): every site follows the domain
	d := Data{Settings: Settings{Domain: "new.example", TailscalePort: 8443}, Services: []*Service{
		{ID: "1", Subdomain: "a", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true},
		{ID: "2", Subdomain: "b", Upstream: "b:1", Exposure: ExposurePublic, Enabled: true},
		{ID: "3", Subdomain: "@", Upstream: "c:1", Exposure: ExposurePublic, Enabled: true},
	}}
	out := GenerateCaddyfile(d)
	for _, h := range []string{"a.new.example {", "b.new.example {", "\nnew.example {"} {
		if !strings.Contains(out, h) {
			t.Errorf("SVC-10: missing %q", h)
		}
	}

	// HTTP: SVC-14 unknown ids, SVC-15 own site
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) { d.Settings.Domain = "example.com" })
	boss.must(400, "PUT", "/api/services/nope", `{"subdomain":"z","upstream":"z:1","exposure":"public"}`)
	boss.must(404, "DELETE", "/api/services/nope", "")
	selfNameOnce.Do(func() {})
	prev := selfName
	selfName = "gm-self"
	t.Cleanup(func() { selfName = prev })
	m := boss.must(200, "POST", "/api/services", `{"subdomain":"gilmok","upstream":"gm-self:8080","exposure":"tailscale","enabled":true}`)
	if f.app.store.Snapshot().Settings.SecSelfService != m["id"] {
		t.Fatal("SVC-15: own site not detected")
	}
}

func TestScnCaddyGenerate(t *testing.T) {
	d := Data{Settings: Settings{Domain: "example.com", TailscalePort: 9443, UseCaddy: true}, Services: []*Service{
		{ID: "1", Subdomain: "zeta", Upstream: "z:1", Exposure: ExposurePublic, Enabled: true},
		{ID: "2", Subdomain: "priv", Upstream: "p:1", Exposure: ExposureTailscale, Enabled: true},
		{ID: "3", Subdomain: "off", Upstream: "o:1", Exposure: ExposurePublic, Enabled: false},
		{ID: "4", Subdomain: "dnsonly", Exposure: ExposurePublic, Enabled: true, DNSOnly: true},
		{ID: "5", Subdomain: "alpha", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true},
	}}
	out := GenerateCaddyfile(d)
	// CADDY-04 private listener, CADDY-11 disabled, CADDY-12 DNS only
	if !strings.Contains(out, "priv.example.com:9443 {") {
		t.Error("CADDY-04")
	}
	if strings.Contains(out, "off.example.com") || strings.Contains(out, "dnsonly.example.com") {
		t.Error("CADDY-11/12")
	}
	// CADDY-15: public first, by name; stable
	if !(strings.Index(out, "alpha.example.com") < strings.Index(out, "zeta.example.com") && strings.Index(out, "zeta.example.com") < strings.Index(out, "priv.example.com")) {
		t.Error("CADDY-15 order")
	}
	if GenerateCaddyfile(d) != out {
		t.Error("CADDY-15 not stable")
	}
}

func TestScnCaddyPlanAndApplyGuards(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	cf := filepath.Join(f.dir, "Caddyfile")
	sec := f.app.store.Snapshot().ProxySecret
	os.WriteFile(cf, []byte("# current\nx {\n\trequest_header X-Gilmok-Proxy \""+sec+"\" # gilmok\n}\n"), 0o644)
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCaddy, d.Settings.CaddyfilePath, d.Settings.CaddyBase = "example.com", true, cf, "{\n}\n"
		d.Services = []*Service{{ID: "g", Subdomain: "gilmok", Upstream: "gm:8080", Exposure: ExposureTailscale, Enabled: true}}
		d.Settings.SecSelfService = "g"
	})
	// CADDY-10: the plan never shows the secret
	boss.raw("GET", "/api/plan?dns=0", "")
	body := boss.last.Body.String()
	if strings.Contains(body, sec) || !strings.Contains(body, "숨김") {
		t.Fatalf("CADDY-10: secret visible or not masked")
	}
	// CADDY-16 / APPLY-01: no domain → apply refused
	f.set(func(d *Data) { d.Settings.Domain = "" })
	_, m := boss.do("POST", "/api/apply", `{}`)
	if m["ok"] == true {
		t.Fatalf("APPLY-01: %v", m)
	}
	// APPLY-02: current file missing → stop (nothing to roll back to)
	f.set(func(d *Data) {
		d.Settings.Domain = "example.com"
		d.Settings.CaddyfilePath = filepath.Join(f.dir, "missing")
	})
	_, m = boss.do("POST", "/api/apply", `{}`)
	if m["ok"] == true {
		t.Fatalf("APPLY-02: %v", m)
	}
}

func TestScnCaddyModes(t *testing.T) {
	// docker: validate pipes the candidate into `docker exec -i <ctr> caddy validate --config /dev/stdin`
	fd := installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		if strings.Contains(string(stdin), "BROKEN") {
			return "Error: adapting config using caddyfile: BROKEN", errors.New("exit 1")
		}
		return "Valid configuration", nil
	})
	st := Settings{CaddyMode: "docker", CaddyContainer: "cad", CaddyfileInCtr: "/etc/caddy/Caddyfile"}
	if err := validateCaddy(st, "a {\n}\n"); err != nil {
		t.Fatal(err)
	}
	if err := validateCaddy(st, "BROKEN"); err == nil {
		t.Fatal("CADDY-17 docker: broken accepted")
	}
	if err := reloadCaddy(st); err != nil || fd.count("exec cad caddy reload --config /etc/caddy/Caddyfile") != 1 {
		t.Fatalf("CADDY-17 docker reload: %v %v", err, fd.joined())
	}
	// api: /adapt then /load
	var paths []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if strings.Contains(string(b), "BROKEN") {
			http.Error(w, `{"error":"adapting config: BROKEN"}`, 400)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	cf := filepath.Join(t.TempDir(), "Caddyfile")
	os.WriteFile(cf, []byte("a {\n}\n"), 0o644)
	st = Settings{CaddyMode: "api", CaddyAdmin: srv.URL, CaddyfilePath: cf}
	if err := validateCaddy(st, "a {\n}\n"); err != nil {
		t.Fatal(err)
	}
	if err := validateCaddy(st, "BROKEN"); err == nil {
		t.Fatal("CADDY-17 api: broken accepted")
	}
	if err := reloadCaddy(st); err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "/adapt,/adapt,/load" {
		t.Fatalf("CADDY-17 api calls: %v", paths)
	}
	// native: the test binary plays caddy
	exe, _ := os.Executable()
	t.Setenv("GM_FAKE_CADDY", "1")
	st = Settings{CaddyMode: "native", CaddyBin: exe, CaddyfilePath: cf}
	if err := validateCaddy(st, "a {\n}\n"); err != nil {
		t.Fatalf("CADDY-17 native: %v", err)
	}
	if err := validateCaddy(st, "BROKEN"); err == nil {
		t.Fatal("CADDY-17 native: broken accepted")
	}
	if err := reloadCaddy(st); err != nil {
		t.Fatal(err)
	}
	_ = context.Background
	_ = json.Marshal
}
