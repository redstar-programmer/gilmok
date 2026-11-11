package main

// FRESH-xx: a new user setting everything up with Gilmok (docs/TEST_SCENARIOS.md 「새 사용자 설치 흐름」).
// Each case is one thing that went wrong (or could) on a real first install — certificates, mTLS,
// networks, imports — plus the error answers of the endpoints involved.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FRESH-01..05: fitting an imported / older base to a Caddy Gilmok installed
func TestFreshFitManagedBase(t *testing.T) {
	old := "{\n\temail a@b.c\n}\n\n(cf_only) {\n\ttls {\n\t\tclient_auth {\n\t\t\ttrust_pool file /etc/caddy/cf-origin-pull-ca.pem\n\t\t}\n\t}\n}\n\n(authelia) {\n\tforward_auth authelia:9091 {\n\t\turi /api/authz/forward-auth\n\t}\n}\n"
	d := &Data{Settings: Settings{CaddyBase: old, UseCloudflare: true, UseAuthelia: true},
		Stacks: map[string]*ManagedStack{"caddy": {Container: "gilmok-caddy"}, "authelia": {Container: "gilmok-authelia"}}}
	nb, ch := fitManagedBase(d, true)
	for _, want := range []string{"trust_pool file " + caddyCAPath, "forward_auth gilmok-authelia:9091", "acme_dns cloudflare {env.CLOUDFLARE_API_TOKEN}"} {
		if !strings.Contains(nb, want) {
			t.Fatalf("FRESH-01 missing %q in\n%s", want, nb)
		}
	}
	if len(ch) != 3 {
		t.Fatalf("FRESH-01 changes: %v", ch)
	}
	// FRESH-02: running it again changes nothing
	d.Settings.CaddyBase = nb
	if _, ch := fitManagedBase(d, true); len(ch) != 0 {
		t.Fatalf("FRESH-02 not idempotent: %v", ch)
	}
	// FRESH-03: no token → no acme_dns (it would use an empty token)
	d.Settings.CaddyBase = old
	if nb, _ := fitManagedBase(d, false); strings.Contains(nb, "acme_dns") {
		t.Fatal("FRESH-03 acme_dns without a token")
	}
	// FRESH-04: snippets the services need are added when missing
	d.Settings.CaddyBase = "{\n\temail a@b.c\n}\n"
	d.Services = []*Service{
		{Subdomain: "a", Exposure: ExposurePublic, Proxied: true, MTLS: true, Enabled: true},
		{Subdomain: "b", Exposure: ExposureTailscale, Enabled: true, Authelia: AutheliaOpts{Enabled: true}},
	}
	nb, _ = fitManagedBase(d, false)
	if !strings.Contains(nb, "(cf_only) {") || !strings.Contains(nb, "(authelia) {") || !strings.Contains(nb, "forward_auth gilmok-authelia:9091") {
		t.Fatalf("FRESH-04 snippets not added:\n%s", nb)
	}
	// FRESH-05: not a managed Caddy → never touched
	d.Stacks = nil
	if nb, ch := fitManagedBase(d, true); nb != d.Settings.CaddyBase || len(ch) != 0 {
		t.Fatal("FRESH-05 a Caddy Gilmok did not install must not be changed")
	}
}

// FRESH-06..09: sites that would make Caddy refuse the whole configuration are held, the rest applied
func TestFreshHoldSites(t *testing.T) {
	f := newFullApp(t)
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCaddy, d.Settings.UseCloudflare, d.Settings.UseAuthelia = "example.com", true, true, true
		d.Settings.CaddyBase = "{\n}\n(authelia) {\n\tforward_auth x:9091\n}\n"
	})
	d := f.app.store.Snapshot()
	d.Services = []*Service{
		{Subdomain: "ok", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true},
		{Subdomain: "gate", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true, Authelia: AutheliaOpts{Enabled: true}},
		{Subdomain: "mtls", Upstream: "a:1", Exposure: ExposurePublic, Proxied: true, MTLS: true, Enabled: true},
		{Subdomain: "snip", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true, Extra: "import my_headers"},
		{Subdomain: "file", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true, Extra: "import /etc/caddy/extra/*.caddy"},
		{Subdomain: "waf", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true, Extra: "import gm_waf_block"},
	}
	gen, held := f.app.caddyGenData(d)
	joined := strings.Join(held, " | ")
	// FRESH-06: missing cf_only → the mTLS site is held
	if !strings.Contains(joined, "mtls (") {
		t.Fatalf("FRESH-06: %v", held)
	}
	// FRESH-07: an unknown snippet in the extra directives → held
	if !strings.Contains(joined, "snip (") {
		t.Fatalf("FRESH-07: %v", held)
	}
	// FRESH-08: defined snippets, file imports and Gilmok's own gm_* snippets are fine
	for _, sub := range []string{"ok (", "gate (", "file (", "waf ("} {
		if strings.Contains(joined, sub) {
			t.Fatalf("FRESH-08 %s held wrongly: %v", sub, held)
		}
	}
	// FRESH-09: held sites are left out of the generated file, the others stay
	out := GenerateCaddyfile(gen)
	if strings.Contains(out, "mtls.example.com") || strings.Contains(out, "snip.example.com") || !strings.Contains(out, "gate.example.com") {
		t.Fatalf("FRESH-09 generated:\n%s", out)
	}
	// and the stored data is not changed by it
	for _, s := range d.Services {
		if !s.Enabled {
			t.Fatal("FRESH-09 caddyGenData must not modify the caller's services")
		}
	}
}

// FRESH-10: an Authelia / CrowdSec installed without a network choice joins Caddy's network
// (it went to Gilmok's alphabetically-first network before and Caddy could not reach Authelia → 502)
func TestFreshNetworkFollowsCaddy(t *testing.T) {
	f := newFullApp(t)
	f.set(func(d *Data) {
		d.Settings.CaddyMode, d.Settings.CaddyContainer = "docker", "my-caddy"
		d.SelfName = "gilmok"
	})
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.HasSuffix(j, " my-caddy") && strings.Contains(j, "Networks"):
			return `{"reverseproxy":{}}`, nil
		case strings.HasSuffix(j, " gilmok") && strings.Contains(j, "Networks"):
			return `{"gilmok_default":{},"reverseproxy":{}}`, nil
		}
		return "", nil
	})
	if got := f.app.caddyNetwork(context.Background()); got != "reverseproxy" {
		t.Fatalf("FRESH-10: %q", got)
	}
	// FRESH-11: no Caddy container → "" (the old automatic choice applies)
	f.set(func(d *Data) { d.Settings.CaddyContainer = "" })
	if got := f.app.caddyNetwork(context.Background()); got != "" {
		t.Fatalf("FRESH-11: %q", got)
	}
}

// FRESH-12: the network list for the install dialogs carries counts and Caddy's / Gilmok's networks
func TestFreshNetworkAdviceData(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	f.set(func(d *Data) {
		d.Settings.CaddyMode, d.Settings.CaddyContainer = "docker", "my-caddy"
		d.SelfName = "gilmok"
	})
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(j, "network ls"):
			return "bridge|bridge\nhost|host\nreverseproxy|bridge\nlonely|bridge", nil
		case strings.HasPrefix(j, "network inspect"):
			return "reverseproxy|12\nlonely|0", nil
		case strings.HasSuffix(j, " my-caddy"):
			return `{"reverseproxy":{}}`, nil
		case strings.HasSuffix(j, " gilmok"):
			return `{"gilmok_default":{}}`, nil
		}
		return "", nil
	})
	m := c.must(200, "GET", "/api/docker/networks", "")
	if fmt.Sprint(m["networks"]) != "[lonely reverseproxy]" || m["counts"].(map[string]any)["reverseproxy"] != float64(12) {
		t.Fatalf("FRESH-12 list: %v", m)
	}
	if fmt.Sprint(m["caddy"].(map[string]any)["networks"]) != "[reverseproxy]" || fmt.Sprint(m["self"]) != "[gilmok_default]" {
		t.Fatalf("FRESH-12 caddy/self: %v", m)
	}
}

// FRESH-13: Authelia check fails (with the fix) when Caddy and Authelia share no network
func TestFreshAutheliaNetworkCheck(t *testing.T) {
	f := newFullApp(t)
	cfg := filepath.Join(f.dir, "configuration.yml")
	os.WriteFile(cfg, []byte("access_control:\n  default_policy: deny\n"), 0o644)
	f.set(func(d *Data) {
		d.Settings.UseCaddy, d.Settings.UseAuthelia, d.Settings.CaddyMode = true, true, "docker"
		d.Settings.CaddyContainer, d.Settings.AutheliaCtr, d.Settings.AutheliaConfig = "cad", "auth", cfg
	})
	nets := map[string]string{"cad": `{"reverseproxy":{}}`, "auth": `{"gilmok_default":{}}`}
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		j := strings.Join(args, " ")
		if strings.Contains(j, "Networks") {
			return nets[args[len(args)-1]], nil
		}
		if args[0] == "inspect" && strings.Contains(j, "State.Status") {
			return "running|authelia/authelia|2026-01-01", nil
		}
		return "authelia v4.38.0", nil
	})
	find := func() map[string]string {
		r := f.app.checkAuthelia()
		for _, c := range r.Checks {
			if c.ID == "net" {
				return map[string]string{"status": c.Status, "detail": c.Detail}
			}
		}
		return nil
	}
	if c := find(); c == nil || c["status"] != "fail" || !strings.Contains(c["detail"], "docker network connect reverseproxy auth") {
		t.Fatalf("FRESH-13 split networks: %v", c)
	}
	nets["auth"] = `{"reverseproxy":{}}`
	if c := find(); c == nil || c["status"] != "ok" {
		t.Fatalf("FRESH-13 shared network: %v", c)
	}
}

// FRESH-14: the Caddy check tells "Proxied sites without the DNS challenge" (the 525 of a first install)
func TestFreshCertMethodCheck(t *testing.T) {
	f := newFullApp(t)
	cf := filepath.Join(f.dir, "Caddyfile")
	os.WriteFile(cf, []byte("a.example.com {\n\treverse_proxy x:1\n}\n"), 0o644)
	f.set(func(d *Data) {
		d.Settings.UseCaddy, d.Settings.UseCloudflare, d.Settings.CaddyMode, d.Settings.CaddyfilePath = true, true, "docker", cf
		d.Services = []*Service{{Subdomain: "a", Exposure: ExposurePublic, Proxied: true, Enabled: true, Upstream: "x:1"}}
	})
	installFakeDocker(t, func(args []string, _ []byte) (string, error) { return "", fmt.Errorf("no docker") })
	// the check itself needs a running Caddy; the rule it applies:
	for src, want := range map[string]bool{
		"{\n\tacme_dns cloudflare {env.T}\n}\n":                  true,
		"a.example.com {\n\ttls {\n\t\tdns cloudflare x\n\t}\n}": true,
		"{\n\tlocal_certs\n}\n":                                  true,
		"a.example.com {\n\ttls /c/cert.pem /c/key.pem\n}":       true,
		"a.example.com {\n\treverse_proxy x:1\n}\n":              false,
	} {
		if reCertConfigured.MatchString(src) != want {
			t.Fatalf("FRESH-14 %q → %v", src, !want)
		}
	}
}

// FRESH-15..18: error answers of today's endpoints
func TestFreshEndpointErrors(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	viewer := f.user(t, c, "viewer9", "viewer")
	f.set(func(d *Data) { d.Settings.Domain = "example.com"; d.Settings.UseCloudflare = true })
	t.Setenv("GM_CF_TOKEN", "")
	t.Setenv("GM_CF_TOKEN_FILE", "")

	// FRESH-15: mTLS / CA without a managed Caddy → 404 with a reason; viewer → 403
	if code, m := c.do("POST", "/api/stacks/caddy/mtls", `{}`); code != 404 || !strings.Contains(fmt.Sprint(m["error"]), "길목이 설치한 Caddy") {
		t.Fatalf("FRESH-15 mtls: %d %v", code, m)
	}
	if code, _ := c.do("POST", "/api/stacks/caddy/ca", `{"pem":"x"}`); code != 404 {
		t.Fatalf("FRESH-15 ca: %d", code)
	}
	if code, _ := viewer.do("POST", "/api/stacks/caddy/mtls", `{}`); code != 403 {
		t.Fatalf("FRESH-15 viewer: %d", code)
	}
	// FRESH-16: managed Caddy, but no token → 400 that says so; a bad PEM → 400
	f.set(func(d *Data) {
		d.Stacks = map[string]*ManagedStack{"caddy": {Name: "caddy", Container: "gilmok-caddy", Dir: filepath.Join(f.dir, "stacks", "caddy")}}
	})
	if code, m := c.do("POST", "/api/stacks/caddy/mtls", `{}`); code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "토큰") {
		t.Fatalf("FRESH-16 no token: %d %v", code, m)
	}
	if code, m := c.do("POST", "/api/stacks/caddy/ca", `{"pem":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}`); code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "CA") {
		t.Fatalf("FRESH-16 bad PEM: %d %v", code, m)
	}
	// a good PEM is stored where the managed Caddy reads it
	caPEM, _, _, _ := genMTLS("example.com", time.Now())
	body, _ := json.Marshal(map[string]string{"pem": caPEM})
	c.must(200, "POST", "/api/stacks/caddy/ca", string(body))
	if _, err := os.Stat(filepath.Join(f.dir, "stacks", "caddy", "conf", "certs", "cf-origin-pull-ca.pem")); err != nil {
		t.Fatalf("FRESH-16 CA not stored: %v", err)
	}
	// FRESH-17: Cloudflare refuses (missing permission) → the answer names the permission
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zones" {
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[{"id":"z1"}]}`)
			return
		}
		w.WriteHeader(403)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
	}))
	defer srv.Close()
	oldAPI := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = oldAPI }()
	t.Setenv("GM_CF_TOKEN", "test-token-value-1234567890abcdefghij")
	if code, m := c.do("POST", "/api/stacks/caddy/mtls", `{}`); code != 502 || !strings.Contains(fmt.Sprint(m["error"]), "SSL") {
		t.Fatalf("FRESH-17 permission: %d %v", code, m)
	}
	// FRESH-18: proxy import — empty request, unknown format, oversized file, no domain
	if code, _ := c.do("POST", "/api/import/sites", `{"format":"nginx","files":[]}`); code != 400 {
		t.Fatalf("FRESH-18 no files: %d", code)
	}
	if code, _ := c.do("POST", "/api/import/sites", `{"format":"apache","files":[{"name":"a","content":"x"}]}`); code != 400 {
		t.Fatalf("FRESH-18 unknown format: %d", code)
	}
	big, _ := json.Marshal(map[string]any{"format": "nginx", "files": []importFile{{Name: "big.conf", Content: strings.Repeat("#", 1<<20+10)}}})
	if code, m := c.do("POST", "/api/import/sites", string(big)); code != 200 || !strings.Contains(fmt.Sprint(m["warnings"]), "1MB") {
		t.Fatalf("FRESH-18 oversized file is skipped with a warning: %d %v", code, m)
	}
	f.set(func(d *Data) { d.Settings.Domain = "" })
	if code, m := c.do("POST", "/api/import/sites", `{"format":"nginx","files":[{"name":"a.conf","content":"server { server_name a.b.c; location / { proxy_pass http://x:1; } }"}]}`); code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "도메인") {
		t.Fatalf("FRESH-18 no domain: %d %v", code, m)
	}
	// broken nginx → a warning, not a crash
	f.set(func(d *Data) { d.Settings.Domain = "example.com" })
	if code, m := c.do("POST", "/api/import/sites", `{"format":"nginx","files":[{"name":"bad.conf","content":"server { server_name a.example.com; "}]}`); code != 200 || !strings.Contains(fmt.Sprint(m["warnings"]), "닫히지 않은") {
		t.Fatalf("FRESH-18 broken nginx: %d %v", code, m)
	}
}

// FRESH-19: importing an old Caddyfile BEFORE installing Caddy — the install fits that base
// (the CA path / Authelia name / DNS certificates of the old Caddy broke the first real install)
func TestFreshImportThenInstall(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	t.Setenv("GM_CF_TOKEN_FILE", "")
	t.Setenv("GM_CF_TOKEN", "test-token-value-1234567890abcdefghij")
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCloudflare, d.Settings.UseCaddy = "example.com", true, true
		d.Settings.CaddyBase = "{\n\temail a@b.c\n}\n\n(cf_only) {\n\ttls {\n\t\tclient_auth {\n\t\t\ttrust_pool file /etc/caddy/cf-origin-pull-ca.pem\n\t\t}\n\t}\n}\n"
		d.Services = []*Service{{ID: "s1", Subdomain: "notes", Upstream: "app:1", Exposure: ExposurePublic, Proxied: true, MTLS: true, Enabled: true}}
	})
	fd := &fakeStackDocker{}
	installFakeDocker(t, fd.handle)
	boss.must(202, "POST", "/api/stacks/caddy/install", `{"httpsPort":"8444"}`)
	if j := waitStackJob(t, boss, "caddy"); j["state"] != "ok" {
		t.Fatalf("install: %v", j)
	}
	base := f.app.store.Snapshot().Settings.CaddyBase
	if !strings.Contains(base, "trust_pool file "+caddyCAPath) || !strings.Contains(base, "acme_dns cloudflare") || !strings.Contains(base, "email a@b.c") {
		t.Fatalf("FRESH-19 base not fitted (or imported options lost):\n%s", base)
	}
}

// FRESH-23: a successful apply marks the setup as done (the wizard offer stops for tab-only setups)
func TestFreshApplyMarksSetupDone(t *testing.T) {
	f, sf := newStack(t)
	stackDocker(t, sf)
	f.set(func(d *Data) { d.SetupDone = false })
	if _, err := f.app.Apply(false); err != nil {
		t.Fatal(err)
	}
	if !f.app.store.Snapshot().SetupDone {
		t.Fatal("FRESH-23 SetupDone not set by a successful apply")
	}
}
