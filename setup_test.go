package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupDetectAndDone(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)

	// a stacks folder like the deploy layout, with a Caddyfile and Authelia files
	root := t.TempDir()
	old := stacksRoot
	stacksRoot = root
	defer func() { stacksRoot = old }()
	os.MkdirAll(filepath.Join(root, "caddy"), 0o755)
	os.MkdirAll(filepath.Join(root, "authelia-config"), 0o755)
	os.WriteFile(filepath.Join(root, "caddy", "Caddyfile"), []byte("(cf_only) {\n}\nphotos.example.org {\n  reverse_proxy immich:2283\n}\nnotes.example.org {\n  forward_auth authelia:9091\n}\n"), 0o644)
	os.WriteFile(filepath.Join(root, "authelia-config", "configuration.yml"), []byte("x: 1\n"), 0o644)
	os.WriteFile(filepath.Join(root, "authelia-config", "users_database.yml"), []byte("users: {}\n"), 0o644)
	f.set(func(d *Data) {
		d.Settings.CaddyfilePath, d.Settings.AutheliaConfig, d.Settings.AutheliaUsers = "", "", ""
	})

	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return strings.Join([]string{
				`{"Names":"edge-caddy","Image":"my/caddy-cloudflare:latest","State":"running"}`,
				`{"Names":"old-caddy","Image":"caddy:2","State":"exited"}`,
				`{"Names":"sso","Image":"authelia/authelia:latest","State":"running"}`,
				`{"Names":"db","Image":"postgres:16","State":"running"}`,
			}, "\n"), nil
		}
		return "", nil
	})

	_, m := boss.do("GET", "/api/setup/detect", "")
	sg, _ := m["suggest"].(map[string]any)
	if sg == nil {
		t.Fatalf("detect: %v", m)
	}
	want := map[string]any{
		"caddyContainer": "edge-caddy", "autheliaContainer": "sso", "domain": "example.org",
		"caddyfilePath": filepath.ToSlash(filepath.Join(root, "caddy", "Caddyfile")),
		"autheliaUsers": filepath.ToSlash(filepath.Join(root, "authelia-config", "users_database.yml")),
		"useCaddy":      true, "useAuthelia": true, "useCloudflare": true, "useCrowdSec": false,
	}
	for k, v := range want {
		if sg[k] != v {
			t.Fatalf("suggest %s = %v, want %v (%v)", k, sg[k], v, sg)
		}
	}
	if m["sites"].(float64) != 2 {
		t.Fatalf("sites: %v", m["sites"])
	}
	// detection saves nothing
	if f.app.store.Snapshot().Settings.CaddyContainer == "edge-caddy" {
		t.Fatal("detect changed settings")
	}

	// a fresh install asks; done stops asking; a reset asks again
	_, st := boss.do("GET", "/api/state", "")
	if st["setupDone"] != false {
		t.Fatalf("fresh setupDone: %v", st["setupDone"])
	}
	boss.must(200, "POST", "/api/setup/done", `{"done":true}`)
	if !f.app.store.Snapshot().SetupDone {
		t.Fatal("done not saved")
	}
	viewer := f.user(t, boss, "viewer1", "viewer")
	viewer.must(403, "POST", "/api/setup/done", `{"done":false}`)
	boss.must(200, "POST", "/api/reset", `{"confirm":"초기화"}`)
	if f.app.store.Snapshot().SetupDone {
		t.Fatal("reset kept setupDone")
	}
}

// the token the Caddy container already has can be adopted without ever being sent to the UI
func TestCFTokenFromCaddy(t *testing.T) {
	const good = "goodtoken_abcdefghijklmnopqrstuvwxyz0123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != good {
			w.WriteHeader(401)
			w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"result":null}`))
			return
		}
		switch r.URL.Path {
		case "/user/tokens/verify":
			w.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
		case "/zones":
			w.Write([]byte(`{"success":true,"result":[{"id":"z1"}]}`))
		default:
			w.Write([]byte(`{"success":true,"result":[]}`))
		}
	}))
	defer srv.Close()
	oldAPI := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = oldAPI }()

	f := newFullApp(t)
	boss := f.admin(t)
	oldUI := cfTokenUIPath
	cfTokenUIPath = filepath.Join(f.dir, "secrets", "cf_token")
	defer func() { cfTokenUIPath = oldUI }()
	t.Setenv("GM_CF_TOKEN_FILE", "")
	t.Setenv("GM_CF_TOKEN", "")
	f.set(func(d *Data) { d.Settings.Domain, d.Settings.CaddyContainer = "example.com", "edge-caddy" })

	env := ""
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		if args[0] == "inspect" {
			return "PATH=/usr/bin\n" + env, nil
		}
		if args[0] == "ps" {
			return `{"Names":"edge-caddy","Image":"caddy:2","State":"running"}`, nil
		}
		return "", nil
	})
	// no token in the container → clear error
	boss.must(400, "POST", "/api/cloudflare/token", `{"fromCaddy":true}`)
	env = "CLOUDFLARE_API_TOKEN=" + good
	_, m := boss.do("GET", "/api/setup/detect", "")
	if m["caddyToken"] != true || strings.Contains(boss.last.Body.String(), good) {
		t.Fatalf("detect: caddyToken=%v (value must not appear)", m["caddyToken"])
	}
	boss.must(200, "POST", "/api/cloudflare/token", `{"fromCaddy":true}`)
	if strings.Contains(boss.last.Body.String(), good) {
		t.Fatal("token value in response")
	}
	if b, _ := os.ReadFile(cfTokenUIPath); string(b) != good {
		t.Fatal("token not stored")
	}
}

// Gilmok can register itself as a CrowdSec bouncer; the key is stored, used, never returned
func TestCrowdSecBouncerCreate(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	old := csKeyUIPath
	csKeyUIPath = filepath.Join(f.dir, "secrets", "crowdsec_key")
	defer func() { csKeyUIPath = old }()
	t.Setenv("GM_CROWDSEC_KEY_FILE", "")
	t.Setenv("GM_CROWDSEC_KEY", "")
	const key = "bouncerkey0123456789abcdef"
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		if strings.Contains(strings.Join(args, " "), "cscli bouncers add") {
			return key + "\n", nil
		}
		return "", nil
	})
	if csKey() != "" {
		t.Fatal("expected no key")
	}
	viewer := f.user(t, boss, "viewer2", "viewer")
	viewer.must(403, "POST", "/api/crowdsec/bouncer", "")
	boss.must(200, "POST", "/api/crowdsec/bouncer", "")
	if strings.Contains(boss.last.Body.String(), key) {
		t.Fatal("key in response")
	}
	if csKey() != key {
		t.Fatal("key not used")
	}
	// a key from the deployment wins and cannot be replaced here
	t.Setenv("GM_CROWDSEC_KEY", "fromenv")
	boss.must(409, "POST", "/api/crowdsec/bouncer", "")
	// a factory reset removes the key Gilmok made
	t.Setenv("GM_CROWDSEC_KEY", "")
	boss.must(200, "POST", "/api/reset", `{"confirm":"초기화"}`)
	if csKey() != "" {
		t.Fatal("reset kept the bouncer key")
	}
}
