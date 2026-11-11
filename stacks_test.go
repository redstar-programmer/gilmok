package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// a fake Docker that remembers whether the managed Caddy was started
type fakeStackDocker struct {
	mu            sync.Mutex
	up            bool
	failExec      bool
	autheliaFatal bool
	usedPort      string
	calls         []string
}

func (f *fakeStackDocker) handle(args []string, _ []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j := strings.Join(args, " ")
	f.calls = append(f.calls, j)
	switch {
	case args[0] == "version":
		return "27.1.0", nil
	case args[0] == "inspect" && strings.Contains(j, "State.Status"):
		if f.up && strings.HasSuffix(j, "gilmok-caddy") {
			return "running|caddy", nil
		}
		if f.up && strings.HasSuffix(j, "gilmok-authelia") {
			return "running|authelia", nil
		}
		if f.up && strings.HasSuffix(j, "crowdsec") {
			return "running|crowdsec", nil
		}
		return "", errors.New("no such container")
	case args[0] == "inspect" && strings.Contains(j, "StartedAt"):
		return time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), nil
	case args[0] == "inspect" && strings.Contains(j, ".Config.Labels"):
		return "", errors.New("no such container")
	case args[0] == "ps":
		if f.usedPort != "" {
			return "edge-proxy|0.0.0.0:" + f.usedPort + "->443/tcp, [::]:" + f.usedPort + "->443/tcp", nil
		}
		return "", nil
	case args[0] == "network":
		return "", nil
	case args[0] == "compose":
		if strings.Contains(j, " up -d") {
			// a compose file containing BREAKME does not start (to test the rollback)
			for i, a := range args {
				if a == "--project-directory" && i+1 < len(args) {
					if b, _ := os.ReadFile(filepath.Join(args[i+1], "compose.yml")); strings.Contains(string(b), "BREAKME") {
						return "Error response from daemon: network BREAKME not found", errors.New("exit 1")
					}
				}
			}
			f.up = true
		}
		if strings.HasSuffix(j, " down") {
			f.up = false
		}
		return "", nil
	case args[0] == "exec" && strings.Contains(j, "caddy validate"):
		if f.failExec {
			return "Error: adapting config using caddyfile: BROKEN", errors.New("exit 1")
		}
		return "Valid configuration", nil
	case args[0] == "exec" && strings.Contains(j, "cscli bouncers list"):
		return "name,ip address,valid\ngilmok,,true", nil
	case args[0] == "logs":
		if f.autheliaFatal {
			return `level=fatal msg="Can't continue due to the errors loading the configuration"`, nil
		}
		return "level=info msg=\"Startup complete\"\nlevel=info msg=\"CrowdSec Local API listening on 0.0.0.0:8080\"", nil
	}
	return "", nil
}

func (f *fakeStackDocker) called(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func waitStackJob(t *testing.T, c *client, name string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_, m := c.do("GET", "/api/stacks", "")
		v := m["stacks"].(map[string]any)[name].(map[string]any)
		if j, ok := v["job"].(map[string]any); ok && j["state"] != "running" {
			return j
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("stack job did not finish")
	return nil
}

func TestManagedCaddyInstall(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	t.Setenv("GM_CF_TOKEN_FILE", "")
	t.Setenv("GM_CF_TOKEN", "")
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCloudflare, d.Settings.UseTailscale, d.Settings.CaddyBase = "example.com", true, true, ""
		d.Settings.TopoPrivKind = "ts_serve"
		d.Services = []*Service{{ID: "s1", Subdomain: "photos", Upstream: "immich:2283", Exposure: ExposurePublic, Enabled: true}}
	})
	fd := &fakeStackDocker{usedPort: "443"}
	installFakeDocker(t, fd.handle)

	// preflight sees the port clash; installing refuses on it
	_, m := boss.do("POST", "/api/stacks/caddy/preflight", `{}`)
	clash := false
	for _, c := range m["checks"].([]any) {
		c := c.(map[string]any)
		if strings.HasPrefix(c["label"].(string), "포트 :443") && c["status"] == "fail" {
			clash = true
		}
	}
	if !clash {
		t.Fatalf("port clash not found: %v", m["checks"])
	}
	boss.must(202, "POST", "/api/stacks/caddy/install", `{"httpsPort":"443"}`)
	if j := waitStackJob(t, boss, "caddy"); j["state"] != "fail" || !strings.Contains(j["error"].(string), "포트") {
		t.Fatalf("clash install: %v", j)
	}

	// another host port → installs
	viewer := f.user(t, boss, "viewer4", "viewer")
	viewer.must(403, "POST", "/api/stacks/caddy/install", `{"httpsPort":"8444"}`)
	boss.must(400, "POST", "/api/stacks/caddy/install", `{"httpsPort":"99999"}`)
	boss.must(400, "POST", "/api/stacks/caddy/install", `{"container":"bad name!"}`)
	boss.must(202, "POST", "/api/stacks/caddy/install", `{"httpsPort":"8444","tls":"internal"}`)
	if j := waitStackJob(t, boss, "caddy"); j["state"] != "ok" {
		t.Fatalf("install: %v", j)
	}
	d := f.app.store.Snapshot()
	rec := d.Stacks["caddy"]
	if rec == nil || rec.Container != "gilmok-caddy" || rec.Network != "gilmok-net" {
		t.Fatalf("record: %+v", rec)
	}
	if d.Settings.CaddyContainer != "gilmok-caddy" || d.Settings.CaddyfilePath != filepath.Join(rec.Dir, "conf", "Caddyfile") || !d.Settings.UseCaddy {
		t.Fatalf("settings not adopted: %+v", d.Settings.CaddyfilePath)
	}
	if !strings.Contains(d.Settings.CaddyBase, "(cf_only)") || !strings.Contains(d.Settings.CaddyBase, "local_certs") {
		t.Fatalf("base skeleton: %s", d.Settings.CaddyBase)
	}
	compose, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml"))
	for _, want := range []string{"container_name: gilmok-caddy", `"8444:443"`, `"127.0.0.1:8443:8443"`, "name: gilmok-net", "gilmok.managed: caddy", "/conf:/etc/caddy"} {
		if !strings.Contains(string(compose), want) {
			t.Fatalf("compose.yml lacks %q:\n%s", want, compose)
		}
	}
	if strings.Contains(string(compose), "2019") {
		t.Fatal("admin API published")
	}
	cf, _ := os.ReadFile(filepath.Join(rec.Dir, "conf", "Caddyfile"))
	if !strings.Contains(string(cf), "photos.example.com") {
		t.Fatal("Caddyfile not generated")
	}
	if fi, err := os.Stat(filepath.Join(rec.Dir, ".env")); err != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf(".env: %v", err)
	}
	if !strings.Contains(string(compose), "name: gilmok-caddy") || !fd.called("build --pull") {
		t.Fatal("compose build not run")
	}
	// the generated Caddyfile path is accepted by the settings guard
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.WafParanoia = 2 }))

	// one job at a time
	f.app.stk.mu.Lock()
	f.app.stk.cur = &StackJob{State: "running", Stack: "caddy", Action: "install"}
	f.app.stk.mu.Unlock()
	boss.must(409, "POST", "/api/stacks/caddy/restart", `{}`)
	f.app.stk.mu.Lock()
	f.app.stk.cur = nil
	f.app.stk.mu.Unlock()

	// a reset keeps the record (the container is outside Gilmok)
	boss.must(200, "POST", "/api/reset", `{"confirm":"초기화"}`)
	if f.app.store.Snapshot().Stacks["caddy"] == nil {
		t.Fatal("reset dropped the managed stack record")
	}
	// remove (keep data)
	boss.must(202, "POST", "/api/stacks/caddy/remove", `{}`)
	if j := waitStackJob(t, boss, "caddy"); j["state"] != "ok" {
		t.Fatalf("remove: %v", j)
	}
	if f.app.store.Snapshot().Stacks["caddy"] != nil {
		t.Fatal("record kept after remove")
	}
	if _, err := os.Stat(filepath.Join(rec.Dir, "compose.yml")); err != nil {
		t.Fatal("data deleted although kept")
	}
}

func TestManagedCaddyVerifyFailCleansUp(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	fd := &fakeStackDocker{failExec: true}
	installFakeDocker(t, fd.handle)
	boss.must(202, "POST", "/api/stacks/caddy/install", `{"httpsPort":"8445"}`)
	j := waitStackJob(t, boss, "caddy")
	if j["state"] != "fail" || !strings.Contains(j["error"].(string), "BROKEN") {
		t.Fatalf("verify fail: %v", j)
	}
	if !fd.called(" down") || f.app.store.Snapshot().Stacks["caddy"] != nil {
		t.Fatal("failed install not cleaned up")
	}
	if f.app.store.Snapshot().Settings.CaddyContainer == "gilmok-caddy" {
		t.Fatal("settings adopted although the install failed")
	}
}

func TestManagedComposeTarget(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services: {}\n"), 0o644)
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		if args[0] == "inspect" {
			return `{"com.docker.compose.project":"gilmok-caddy","com.docker.compose.service":"caddy","com.docker.compose.project.working_dir":"` + filepath.ToSlash(dir) + `","com.docker.compose.project.config_files":"` + filepath.ToSlash(filepath.Join(dir, "compose.yml")) + `","gilmok.managed":"caddy"}`, nil
		}
		return "", nil
	})
	tg, err := resolveCompose("gilmok-caddy", "", "")
	if err != nil || tg.LocalDir != filepath.ToSlash(dir) || tg.Service != "caddy" || len(tg.DaemonFiles) != 1 {
		t.Fatalf("managed target: %+v %v", tg, err)
	}
}

func TestCaddyPrivBindAndPorts(t *testing.T) {
	cases := map[string]string{"ts_serve": "127.0.0.1", "": "127.0.0.1", "vpn": "0.0.0.0"}
	for k, want := range cases {
		if got := caddyPrivBind(Settings{TopoPrivKind: k}); got != want {
			t.Fatalf("%s: %s", k, got)
		}
	}
	if caddyPrivBind(Settings{TopoPrivKind: "ts_direct", TailscaleIP: "100.70.1.2"}) != "100.70.1.2" {
		t.Fatal("ts_direct")
	}
	if !portClash(":443", []string{"0.0.0.0:443"}) || portClash("127.0.0.1:8443", []string{"100.70.1.2:8443"}) || !portClash("127.0.0.1:8443", []string{":::8443"}) {
		t.Fatal("portClash")
	}
}

func TestManagedAutheliaInstall(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	fd := &fakeStackDocker{}
	installFakeDocker(t, fd.handle)
	const pw = "Authelia-first-pass-1"

	// no domain yet → refused before anything starts
	boss.must(400, "POST", "/api/stacks/authelia/install", `{"adminUser":"admin","secretPassword":"`+pw+`"}`)
	f.set(func(d *Data) {
		// an imported portal that still points at the old Authelia
		d.Services = []*Service{{ID: "p0", Subdomain: "login", Upstream: "authelia:9091", Exposure: ExposurePublic, Enabled: true}}
		d.Settings.Domain, d.Settings.UseCloudflare, d.Settings.AutheliaCtr = "example.com", true, "authelia"
		d.Settings.CaddyBase = "(authelia) {\n\tforward_auth authelia:9091 {\n\t\turi /api/authz/forward-auth\n\t}\n}\n"
	})
	boss.must(400, "POST", "/api/stacks/authelia/install", `{"adminUser":"admin","secretPassword":"short"}`)
	boss.must(400, "POST", "/api/stacks/authelia/install", `{"adminUser":"bad name","secretPassword":"`+pw+`"}`)

	boss.must(202, "POST", "/api/stacks/authelia/install", `{"adminUser":"admin","secretPassword":"`+pw+`"}`)
	j := waitStackJob(t, boss, "authelia")
	if j["state"] != "ok" {
		t.Fatalf("install: %v", j)
	}
	for _, l := range j["log"].([]any) {
		if strings.Contains(l.(string), pw) {
			t.Fatal("password in the job log")
		}
	}
	d := f.app.store.Snapshot()
	rec := d.Stacks["authelia"]
	if rec == nil || rec.Options["secretPassword"] != "" || rec.Options["portal"] != "auth" {
		t.Fatalf("record: %+v", rec)
	}
	st := d.Settings
	if st.AutheliaCtr != "gilmok-authelia" || st.AutheliaConfig != filepath.Join(rec.Dir, "config", "configuration.yml") || !st.UseAuthelia {
		t.Fatalf("settings not adopted: %+v", st.AutheliaConfig)
	}
	if !strings.Contains(st.CaddyBase, "forward_auth gilmok-authelia:9091") {
		t.Fatalf("Caddy snippet not repointed: %s", st.CaddyBase)
	}
	// the existing portal follows the new Authelia; no second portal is added
	var portal *Service
	for _, s := range d.Services {
		if s.Subdomain == "auth" {
			t.Fatal("a second portal was added")
		}
		if s.Subdomain == "login" {
			portal = s
		}
	}
	if portal == nil || portal.Upstream != "gilmok-authelia:9091" || portal.Authelia.Enabled || !d.Dirty {
		t.Fatalf("portal service: %+v", portal)
	}
	cfg, _ := os.ReadFile(st.AutheliaConfig)
	for _, want := range []string{"authelia_url: 'https://auth.example.com'", "domain: 'example.com'", "filesystem:", "access_control:", "path: '/config/users_database.yml'"} {
		if !strings.Contains(string(cfg), want) {
			t.Fatalf("configuration.yml lacks %q", want)
		}
	}
	for _, name := range []string{"jwt", "session", "storage"} {
		b, err := os.ReadFile(filepath.Join(rec.Dir, "secrets", name))
		if err != nil || len(b) != 64 || strings.Contains(string(cfg), string(b)) {
			t.Fatalf("secret %s: %v", name, err)
		}
	}
	users, err := LoadUsers(st.AutheliaUsers)
	if err != nil || users["admin"] == nil || !VerifyPassword(users["admin"].Password, pw) || !contains(users["admin"].Groups, "admins") {
		t.Fatalf("users: %v", err)
	}
	compose, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml"))
	if !strings.Contains(string(compose), "AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE") || strings.Contains(string(compose), "ports:") {
		t.Fatalf("compose: %s", compose)
	}
	// Gilmok's own Authelia handling works on the managed files; the admins group is registered
	boss.must(200, "GET", "/api/users", "")
	hasAdmins := false
	for _, g := range d.AGroups {
		hasAdmins = hasAdmins || g.Name == "admins"
	}
	if !hasAdmins {
		t.Fatal("admins group not registered")
	}
	_, m := boss.do("GET", "/api/stacks", "")
	if strings.Contains(boss.last.Body.String(), pw) || m == nil {
		t.Fatal("password in /api/stacks")
	}
}

func TestManagedAutheliaStartFails(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) { d.Settings.Domain = "example.com" })
	fd := &fakeStackDocker{autheliaFatal: true}
	installFakeDocker(t, fd.handle)
	boss.must(202, "POST", "/api/stacks/authelia/install", `{"adminUser":"admin","secretPassword":"Authelia-first-pass-1"}`)
	j := waitStackJob(t, boss, "authelia")
	if j["state"] != "fail" || !fd.called(" down") || f.app.store.Snapshot().Stacks["authelia"] != nil {
		t.Fatalf("fatal start: %v", j)
	}
}

func TestManagedCrowdSecInstall(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	old := csKeyUIPath
	csKeyUIPath = filepath.Join(f.dir, "secrets", "crowdsec_key")
	defer func() { csKeyUIPath = old }()
	t.Setenv("GM_CROWDSEC_KEY_FILE", filepath.Join(f.dir, "empty-key")) // the deploy mounts an empty file
	os.WriteFile(filepath.Join(f.dir, "empty-key"), nil, 0o600)
	t.Setenv("GM_CROWDSEC_KEY", "")
	f.set(func(d *Data) {
		d.Settings.CaddyContainer, d.Settings.UseCloudflare, d.Settings.CrowdSecEnabled = "edge-caddy", true, false
		d.Dirty = false
	})
	fd := &fakeStackDocker{}
	installFakeDocker(t, fd.handle)

	boss.must(202, "POST", "/api/stacks/crowdsec/install", `{}`)
	j := waitStackJob(t, boss, "crowdsec")
	if j["state"] != "ok" {
		t.Fatalf("install: %v", j)
	}
	d := f.app.store.Snapshot()
	rec := d.Stacks["crowdsec"]
	if rec == nil || rec.Options["caddyCtr"] != "edge-caddy" {
		t.Fatalf("record: %+v", rec)
	}
	st := d.Settings
	if !st.UseCrowdSec || st.CrowdSecContainer != "gilmok-crowdsec" || st.CrowdSecLAPI != "http://gilmok-crowdsec:8080" || !st.CrowdSecEnabled || !st.CrowdSecSync || !d.Dirty {
		t.Fatalf("settings not adopted: %+v", st.CrowdSecLAPI)
	}
	// one key: generated, kept by Gilmok, handed to the container through .env
	key := csKey()
	env, _ := os.ReadFile(filepath.Join(rec.Dir, ".env"))
	if len(key) != 48 || !strings.Contains(string(env), "CROWDSEC_BOUNCER_KEY="+key) {
		t.Fatalf("bouncer key: %q", key)
	}
	if strings.Contains(boss.last.Body.String(), key) {
		t.Fatal("key in a response")
	}
	compose, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml"))
	for _, want := range []string{"/var/run/docker.sock:/var/run/docker.sock:ro", "parsers/s01-parse/gilmok-caddy-logs.yaml:ro", "BOUNCER_KEY_gilmok: ${CROWDSEC_BOUNCER_KEY:-}", "gilmok.managed: crowdsec"} {
		if !strings.Contains(string(compose), want) {
			t.Fatalf("compose lacks %q", want)
		}
	}
	if strings.Contains(string(compose), "ports:") {
		t.Fatal("CrowdSec publishes a port")
	}
	acq, _ := os.ReadFile(filepath.Join(rec.Dir, "acquis.d", "gilmok-caddy.yaml"))
	if !strings.Contains(string(acq), "- edge-caddy") || !strings.Contains(string(acq), "type: gmcaddy") {
		t.Fatalf("acquis: %s", acq)
	}
	parser, _ := os.ReadFile(filepath.Join(rec.Dir, "parsers", "gilmok-caddy-logs.yaml"))
	if !strings.Contains(string(parser), "name: gilmok/caddy-logs") {
		t.Fatal("parser not written")
	}

	// a restart is "done" only once CrowdSec serves again (it used to report done ~30s too early)
	boss.must(202, "POST", "/api/stacks/crowdsec/restart", `{}`)
	rj := waitStackJob(t, boss, "crowdsec")
	ready := false
	for _, l := range rj["log"].([]any) {
		ready = ready || strings.Contains(l.(string), "준비됨")
	}
	if rj["state"] != "ok" || !ready {
		t.Fatalf("restart did not wait for readiness: %v", rj)
	}
	// the bouncer is re-registered with Gilmok's key (a kept CrowdSec database had the old key after a reset)
	if !fd.called("cscli bouncers delete gilmok") || !fd.called("cscli bouncers add gilmok -k") {
		t.Fatal("bouncer gilmok was not re-registered with the current key")
	}

	// the Caddy container changes → CrowdSec follows (acquisition rewritten, restarted)
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.CaddyContainer = "gilmok-caddy" }))
	acq, _ = os.ReadFile(filepath.Join(rec.Dir, "acquis.d", "gilmok-caddy.yaml"))
	if !strings.Contains(string(acq), "- gilmok-caddy") || f.app.store.Snapshot().Stacks["crowdsec"].Options["caddyCtr"] != "gilmok-caddy" {
		t.Fatalf("acquis not following Caddy: %s", acq)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !fd.called(" restart") {
		if time.Now().After(deadline) {
			t.Fatal("CrowdSec not restarted")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestAdoptAutheliaAddsPortal(t *testing.T) {
	d := &Data{Settings: Settings{Domain: "example.com", AutheliaCtr: "authelia", UseCloudflare: true}}
	adoptAutheliaStack(d, &ManagedStack{Container: "gilmok-authelia", Dir: t.TempDir(), Options: map[string]string{"portal": "auth", "addPortal": "1"}})
	if len(d.Services) != 1 || d.Services[0].Subdomain != "auth" || d.Services[0].Upstream != "gilmok-authelia:9091" || d.Services[0].Authelia.Enabled || !d.Services[0].Proxied {
		t.Fatalf("portal: %+v", d.Services)
	}
	// a second adopt (reinstall) does not add another
	adoptAutheliaStack(d, &ManagedStack{Container: "gilmok-authelia", Dir: t.TempDir(), Options: map[string]string{"portal": "auth", "addPortal": "1"}})
	if len(d.Services) != 1 {
		t.Fatal("portal added twice")
	}
}

func TestManagedComposeEdit(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	fd := &fakeStackDocker{}
	installFakeDocker(t, fd.handle)
	// install on a network the user chose
	boss.must(400, "POST", "/api/stacks/caddy/install", `{"httpsPort":"8446","network":"bridge"}`)
	boss.must(202, "POST", "/api/stacks/caddy/install", `{"httpsPort":"8446","network":"edge"}`)
	if j := waitStackJob(t, boss, "caddy"); j["state"] != "ok" {
		t.Fatalf("install: %v", j)
	}
	rec := f.app.store.Snapshot().Stacks["caddy"]
	if rec.Network != "edge" {
		t.Fatalf("network: %s", rec.Network)
	}
	_, m := boss.do("GET", "/api/stacks/caddy/compose", "")
	orig := m["content"].(string)
	if !strings.Contains(orig, "name: edge") || m["custom"] != false {
		t.Fatalf("compose: %v", m)
	}
	put := func(content string) (int, map[string]any) {
		b, _ := json.Marshal(map[string]string{"content": content})
		return boss.do("PUT", "/api/stacks/caddy/compose", string(b))
	}
	// what Gilmok needs to keep managing it is protected
	if code, _ := put(strings.Replace(orig, "gilmok.managed: caddy", "other: x", 1)); code != 400 {
		t.Fatal("label removal accepted")
	}
	if code, _ := put(strings.Replace(orig, "container_name: gilmok-caddy", "container_name: other", 1)); code != 400 {
		t.Fatal("container rename accepted")
	}
	if code, _ := put("services: [oops"); code != 400 {
		t.Fatal("broken YAML accepted")
	}
	// a valid edit: another network → applied, recorded, Gilmok joins it
	edited := strings.Replace(orig, "name: edge", "name: proxy-net", 1)
	if code, m := put(edited); code != 202 {
		t.Fatalf("edit: %d %v", code, m)
	}
	if j := waitStackJob(t, boss, "caddy"); j["state"] != "ok" {
		t.Fatalf("apply: %v", j)
	}
	rec = f.app.store.Snapshot().Stacks["caddy"]
	if rec.Network != "proxy-net" || rec.Options["customCompose"] != "1" {
		t.Fatalf("record after edit: %+v", rec)
	}
	if b, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml")); !strings.Contains(string(b), "proxy-net") {
		t.Fatal("file not written")
	}
	// a file that does not start is rolled back
	broken := strings.Replace(edited, "name: proxy-net", "name: BREAKME", 1)
	put(broken)
	if j := waitStackJob(t, boss, "caddy"); j["state"] != "fail" {
		t.Fatalf("broken apply: %v", j)
	}
	if b, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml")); strings.Contains(string(b), "BREAKME") || !strings.Contains(string(b), "proxy-net") {
		t.Fatal("not rolled back")
	}
	// a reinstall keeps the edited file
	boss.must(202, "POST", "/api/stacks/caddy/install", `{}`)
	waitStackJob(t, boss, "caddy")
	if b, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml")); !strings.Contains(string(b), "proxy-net") {
		t.Fatal("reinstall dropped the edited compose.yml")
	}
	// back to the generated file
	boss.must(202, "POST", "/api/stacks/caddy/compose-reset", `{}`)
	if j := waitStackJob(t, boss, "caddy"); j["state"] != "ok" {
		t.Fatalf("reset: %v", j)
	}
	if f.app.store.Snapshot().Stacks["caddy"].Options["customCompose"] != "" {
		t.Fatal("custom flag kept after reset")
	}
	// networks list for the install form
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		return "bridge|bridge\nhost|host\nnone|null\nproxy-net|bridge\nedge|bridge", nil
	})
	_, m = boss.do("GET", "/api/docker/networks", "")
	if got := fmt.Sprint(m["networks"]); got != "[edge proxy-net]" {
		t.Fatalf("networks: %s", got)
	}
}

// two installs under different container names never share a compose project (one would replace the other)
func TestStackProjectPerContainer(t *testing.T) {
	if stackProject("gilmok-caddy") != "gilmok-caddy" || stackProject("GM.test_Caddy") != "gm-test_caddy" {
		t.Fatalf("stackProject: %s", stackProject("GM.test_Caddy"))
	}
	f := newFullApp(t)
	boss := f.admin(t)
	old := csKeyUIPath
	csKeyUIPath = filepath.Join(f.dir, "secrets", "crowdsec_key")
	defer func() { csKeyUIPath = old }()
	t.Setenv("GM_CROWDSEC_KEY_FILE", "")
	t.Setenv("GM_CROWDSEC_KEY", "")
	fd := &fakeStackDocker{}
	installFakeDocker(t, fd.handle)
	boss.must(202, "POST", "/api/stacks/crowdsec/install", `{"container":"other-crowdsec"}`)
	waitStackJob(t, boss, "crowdsec")
	rec := f.app.store.Snapshot().Stacks["crowdsec"]
	b, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml"))
	if !strings.Contains(string(b), "\nname: other-crowdsec\n") {
		t.Fatalf("project name: %s", b)
	}
	for _, c := range fd.calls {
		if strings.Contains(c, " -p ") {
			t.Fatalf("compose called with a fixed -p: %s", c)
		}
	}
	// an edited file must keep its own project name
	_, m := boss.do("GET", "/api/stacks/crowdsec/compose", "")
	noName := strings.Replace(m["content"].(string), "name: other-crowdsec\n", "", 1)
	bb, _ := json.Marshal(map[string]string{"content": noName})
	boss.must(400, "PUT", "/api/stacks/crowdsec/compose", string(bb))
}

// the editor's live check validates without writing anything
func TestComposeCheckEndpoint(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	fd := &fakeStackDocker{}
	installFakeDocker(t, fd.handle)
	boss.must(202, "POST", "/api/stacks/caddy/install", `{"httpsPort":"8447"}`)
	waitStackJob(t, boss, "caddy")
	rec := f.app.store.Snapshot().Stacks["caddy"]
	before, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml"))
	body := func(c string) string { b, _ := json.Marshal(map[string]string{"content": c}); return string(b) }
	_, m := boss.do("POST", "/api/stacks/caddy/compose-check", body(strings.Replace(string(before), "gilmok.managed: caddy", "x: y", 1)))
	if m["ok"] != false || !strings.Contains(fmt.Sprint(m["error"]), "gilmok.managed") {
		t.Fatalf("bad file: %v", m)
	}
	_, m = boss.do("POST", "/api/stacks/caddy/compose-check", body(string(before)+"\n# comment\n"))
	if m["ok"] != true {
		t.Fatalf("good file: %v", m)
	}
	after, _ := os.ReadFile(filepath.Join(rec.Dir, "compose.yml"))
	if string(after) != string(before) {
		t.Fatal("check wrote the file")
	}
	ents, _ := os.ReadDir(rec.Dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "compose.candidate") {
			t.Fatal("candidate file left behind")
		}
	}
}

// A managed Caddy installed before the Cloudflare token existed must switch to the DNS challenge
// (HTTP-01 / TLS-ALPN fail behind the Cloudflare proxy → every Proxied site 525).
func TestEnsureAcmeDNS(t *testing.T) {
	base := "# 길목이 설치한 Caddy\n{\n\tservers {\n\t\ttrusted_proxies static 1.2.3.4/32\n\t}\n}\n\n(cf_only) {\n}\n"
	nb, ok := ensureAcmeDNS(base)
	if !ok || !strings.Contains(nb, "{\n\tacme_dns cloudflare {env.CLOUDFLARE_API_TOKEN}\n\tservers {") {
		t.Fatalf("into the global block: %v\n%s", ok, nb)
	}
	if _, again := ensureAcmeDNS(nb); again {
		t.Fatal("must not add it twice")
	}
	nb, ok = ensureAcmeDNS("# c\n(cf_only) {\n}\n")
	if !ok || !strings.HasPrefix(nb, "# c\n{\n\tacme_dns cloudflare {env.CLOUDFLARE_API_TOKEN}\n}\n") {
		t.Fatalf("no global block: %s", nb)
	}
	for _, keep := range []string{"{\n\tlocal_certs\n}\n", "a.example.com {\n\ttls {\n\t\tdns cloudflare {env.X}\n\t}\n}\n", "{\n\tacme_dns cloudflare x\n}\n"} {
		if _, ok := ensureAcmeDNS(keep); ok {
			t.Fatalf("already has a method: %s", keep)
		}
	}
}

// Importing an old Caddyfile into a Gilmok-installed Caddy keeps its base (DNS certificates, CA path,
// Authelia snippet), points old Authelia upstreams at the managed Authelia and keeps the portal site.
func TestImportIntoManagedStack(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	managedBase := "{\n\tacme_dns cloudflare {env.CLOUDFLARE_API_TOKEN}\n}\n\n(cf_only) {\n\ttls {\n\t\tclient_auth {\n\t\t\ttrust_pool file /etc/caddy/certs/cf-origin-pull-ca.pem\n\t\t}\n\t}\n}\n"
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCaddy, d.Settings.UseAuthelia = "example.com", true, true
		d.Settings.CaddyBase = managedBase
		d.Stacks = map[string]*ManagedStack{"caddy": {Name: "caddy", Container: "gilmok-caddy", Dir: f.dir}, "authelia": {Name: "authelia", Container: "gilmok-authelia", Dir: f.dir}}
		d.Services = []*Service{{ID: "p", Subdomain: "login", Upstream: "gilmok-authelia:9091", Exposure: ExposurePublic, Enabled: true, Authelia: AutheliaOpts{Policy: "two_factor"}}}
	})
	old := "{\n\temail a@b.c\n}\n(cf_only) {\n\ttls {\n\t\tclient_auth {\n\t\t\ttrust_pool file /etc/caddy/cf-origin-pull-ca.pem\n\t\t}\n\t}\n}\n" +
		"auth.example.com {\n\timport cf_only\n\treverse_proxy authelia:9091\n}\n" +
		"wiki.example.com {\n\treverse_proxy wiki:3000\n}\n"
	body, _ := json.Marshal(map[string]string{"name": "Caddyfile", "content": old})
	c.must(200, "POST", "/api/import", string(body))
	d := f.app.store.Snapshot()
	if d.Settings.CaddyBase != managedBase {
		t.Fatalf("the managed base must be kept, got:\n%s", d.Settings.CaddyBase)
	}
	ups := map[string]string{}
	for _, s := range d.Services {
		ups[s.Subdomain] = s.Upstream
	}
	if ups["auth"] != "gilmok-authelia:9091" || ups["wiki"] != "wiki:3000" || ups["login"] != "gilmok-authelia:9091" {
		t.Fatalf("services after import: %v", ups)
	}
}
