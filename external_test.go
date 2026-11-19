package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const extAuthCfg = `# my Authelia
theme: dark
authentication_backend:
  file:
    path: /config/users_database.yml
    watch: %WATCH%
access_control:
  default_policy: deny
  rules:
    - domain: 'old.example.com'
      policy: one_factor
session:
  cookies:
    - domain: example.com
`

// EXT-01: Authelia outside Docker — apply writes access_control without docker, leaves a restart
// notice; 「다시 시작했어요」 checks /api/health; a failed start can put the previous file back; a
// Caddy failure in the same apply clears the notice.
func TestAutheliaExternalApply(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "configuration.yml")
	users := filepath.Join(dir, "users_database.yml")
	orig := strings.Replace(extAuthCfg, "%WATCH%", "false", 1)
	_ = os.WriteFile(cfg, []byte(orig), 0o600)
	_ = os.WriteFile(users, []byte("users:\n  alice:\n    displayname: Alice\n    password: \"$argon2id$v=19$m=65536,t=3,p=4$x$y\"\n    email: a@example.com\n    groups: [admins]\n"), 0o600)
	health := http.StatusOK
	var hmu sync.Mutex
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hmu.Lock()
		defer hmu.Unlock()
		if r.URL.Path != "/api/health" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(health)
	}))
	defer hs.Close()
	docker := installFakeDocker(t, func(args []string, _ []byte) (string, error) { return "", nil })
	_ = f.app.store.Update(func(d *Data) error {
		d.Settings.Domain = "example.com"
		d.Settings.UseCaddy, d.Settings.UseCloudflare, d.Settings.UseCrowdSec = false, false, false
		d.Settings.UseAuthelia, d.Settings.AutheliaMode, d.Settings.AutheliaURL = true, "external", hs.URL
		d.Settings.AutheliaConfig, d.Settings.AutheliaUsers = cfg, users
		d.Services = []*Service{{ID: "s1", Subdomain: "app", Upstream: "app:80", Exposure: ExposurePublic, Enabled: true, Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor", Groups: []string{"admins"}}}}
		return nil
	})
	lines, err := f.app.Apply(false)
	if err != nil {
		t.Fatalf("EXT-01 apply: %v\n%s", err, strings.Join(lines, "\n"))
	}
	for _, c := range docker.calls {
		if strings.Contains(strings.Join(c.Args, " "), "authelia") || c.Args[0] == "restart" {
			t.Errorf("EXT-01: docker used for an Authelia outside Docker: %v", c.Args)
		}
	}
	now, _ := os.ReadFile(cfg)
	if !strings.Contains(string(now), "app.example.com") || !strings.Contains(string(now), "# my Authelia") || !strings.Contains(string(now), "watch: false") {
		t.Fatalf("EXT-01: access_control not written (or the rest touched):\n%s", now)
	}
	if p := f.app.store.Snapshot().AutheliaRestart; p == nil || p.What != "access_control" || p.Backup == "" {
		t.Fatalf("EXT-01: no restart notice: %+v", p)
	}
	st := boss.must(200, "GET", "/api/state", "")
	if ar, _ := st["autheliaRestart"].(map[string]any); ar == nil || ar["file"] != "configuration.yml" || ar["backup"] != nil {
		t.Errorf("EXT-01 state view: %v", st["autheliaRestart"])
	}

	// Authelia did not come up → 502 with the option to put the previous file back
	hmu.Lock()
	health = http.StatusServiceUnavailable
	hmu.Unlock()
	if code, m := boss.do("POST", "/api/authelia/restarted", "{}"); code != 502 || m["canRestore"] != true {
		t.Fatalf("EXT-01 failed restart: %d %v", code, m)
	}
	boss.must(200, "POST", "/api/authelia/restore", "{}")
	if back, _ := os.ReadFile(cfg); string(back) != orig {
		t.Fatalf("EXT-01: restore did not put the previous file back:\n%s", back)
	}
	if p := f.app.store.Snapshot().AutheliaRestart; p == nil || p.What != "restore" {
		t.Fatalf("EXT-01: after a restore Authelia still has to restart: %+v", p)
	}
	hmu.Lock()
	health = http.StatusOK
	hmu.Unlock()
	if m := boss.must(200, "POST", "/api/authelia/restarted", "{}"); m["checked"] != true {
		t.Errorf("EXT-01 restarted: %v", m)
	}
	if f.app.store.Snapshot().AutheliaRestart != nil {
		t.Fatal("EXT-01: notice not cleared after a healthy restart")
	}

	// users: with watch → no notice; without → a notice
	if _, err := f.app.ApplyUsers(map[string]*AUser{"bob": {DisplayName: "Bob", Password: "$argon2id$v=19$m=65536,t=3,p=4$x$y", Email: "b@example.com", Groups: []string{}}}); err != nil {
		t.Fatal(err)
	}
	if p := f.app.store.Snapshot().AutheliaRestart; p == nil || p.What != "users" {
		t.Fatalf("EXT-01: users without watch need a restart: %+v", p)
	}
	_ = f.app.store.Update(func(d *Data) error { d.AutheliaRestart = nil; return nil })
	_ = os.WriteFile(cfg, []byte(strings.Replace(extAuthCfg, "%WATCH%", "true", 1)), 0o600)
	if _, err := f.app.ApplyUsers(map[string]*AUser{"bob": {DisplayName: "Bob", Password: "$argon2id$v=19$m=65536,t=3,p=4$x$y", Email: "b@example.com", Groups: []string{}}}); err != nil {
		t.Fatal(err)
	}
	// watch: true — normally reloaded by Authelia, but not on folders without change events: the
	// notice stays, marked so the screen says "probably already in"
	if p := f.app.store.Snapshot().AutheliaRestart; p == nil || p.What != "users" || !p.Watch {
		t.Errorf("EXT-01: watch: true → a soft notice: %+v", p)
	}

	// the connection check does not look for a container
	r := f.app.checkAuthelia()
	ids := map[string]string{}
	for _, c := range r.Checks {
		ids[c.ID] = c.Status
	}
	if ids["health"] != "ok" || ids["watch"] != "ok" || ids["ctr"] != "info" || ids["mount"] != "" {
		t.Errorf("EXT-01 check: %v", ids)
	}
}

// EXT-02: the YAML check used outside Docker.
func TestValidateAutheliaYAML(t *testing.T) {
	for in, ok := range map[string]bool{
		"access_control:\n  default_policy: deny\n  rules:\n    - domain: a.example.com\n      policy: one_factor\n": true,
		"access_control:\n  default_policy: two_factor\n":                                                            true,
		"access_control:\n  default_policy: deny\n  rules: nope\n":                                                   false,
		"access_control:\n  default_policy: allow\n":                                                                 false,
		"theme: dark\n":               false,
		"access_control: [unclosed\n": false,
	} {
		if err := validateAutheliaYAML(in); (err == nil) != ok {
			t.Errorf("EXT-02 %q: %v", in, err)
		}
	}
}

// EXT-03: CrowdSec outside Docker — the machine account is checked by logging in, manual ban /
// unban go to the LAPI (an alert with the decision / DELETE), a pasted bouncer key is checked.
func TestCrowdSecExternal(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	old1, old2 := csKeyUIPath, csMachinePath
	csKeyUIPath, csMachinePath = filepath.Join(f.dir, "secrets", "crowdsec_key"), filepath.Join(f.dir, "secrets", "crowdsec_machine")
	t.Cleanup(func() { csKeyUIPath, csMachinePath = old1, old2 })
	csJWT.Lock()
	csJWT.key = ""
	csJWT.Unlock()
	var mu sync.Mutex
	var alerts []string
	var deleted []string
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/v1/watchers/login":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["machine_id"] != "gilmok" || in["password"] != "right-password" {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"message":"incorrect Username or Password"}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":200,"expire":"2099-01-01T00:00:00Z","token":"jwt-1"}`))
		case r.URL.Path == "/v1/alerts" && r.Method == "POST":
			if r.Header.Get("Authorization") != "Bearer jwt-1" {
				w.WriteHeader(401)
				return
			}
			b, _ := io.ReadAll(r.Body)
			alerts = append(alerts, string(b))
			_, _ = w.Write([]byte(`["1"]`))
		case strings.HasPrefix(r.URL.Path, "/v1/decisions/") && r.Method == "DELETE":
			if r.Header.Get("Authorization") != "Bearer jwt-1" {
				w.WriteHeader(401)
				return
			}
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/v1/decisions/"))
			_, _ = w.Write([]byte(`{"nbDeleted":"1"}`))
		case r.URL.Path == "/v1/decisions":
			if r.Header.Get("X-Api-Key") != "good-key" {
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(`null`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer lapi.Close()
	docker := installFakeDocker(t, func(args []string, _ []byte) (string, error) { return "", nil })
	_ = f.app.store.Update(func(d *Data) error {
		d.Settings.UseCrowdSec, d.Settings.CrowdSecMode, d.Settings.CrowdSecLAPI = true, "external", lapi.URL
		return nil
	})

	boss.must(400, "POST", "/api/crowdsec/machine", `{"id":"gilmok","password":"wrong-password"}`)
	if csMachinePassword() != "" {
		t.Fatal("EXT-03: a machine account that cannot log in was saved")
	}
	boss.must(200, "POST", "/api/crowdsec/machine", `{"id":"gilmok","password":"right-password"}`)
	if f.app.store.Snapshot().Settings.CrowdSecMachine != "gilmok" || csMachinePassword() != "right-password" {
		t.Fatal("EXT-03: machine account not saved")
	}
	if b, _ := os.ReadFile(f.app.store.path); strings.Contains(string(b), "right-password") {
		t.Fatal("EXT-03: the machine password ended up in gilmok.json")
	}
	if st := boss.must(200, "GET", "/api/state", ""); st["csMachineSet"] != true || strings.Contains(mustJSON(st), "right-password") {
		t.Error("EXT-03: state shows the password or not the flag")
	}

	boss.must(200, "POST", "/api/crowdsec/decisions", `{"ip":"203.0.113.7","duration":"4h","reason":"test ban"}`)
	boss.must(200, "POST", "/api/crowdsec/decisions", `{"ip":"198.51.100.0/24","duration":"1h"}`)
	boss.must(200, "DELETE", "/api/crowdsec/decisions/5", "")
	mu.Lock()
	if len(alerts) != 2 || !strings.Contains(alerts[0], `"value":"203.0.113.7"`) || !strings.Contains(alerts[0], `"scope":"Ip"`) || !strings.Contains(alerts[0], `"duration":"4h"`) ||
		!strings.Contains(alerts[1], `"scope":"Range"`) || len(deleted) != 1 || deleted[0] != "5" {
		t.Errorf("EXT-03 LAPI calls: alerts=%v deleted=%v", alerts, deleted)
	}
	mu.Unlock()

	boss.must(400, "POST", "/api/crowdsec/bouncer", `{"key":"bad-key"}`)
	boss.must(200, "POST", "/api/crowdsec/bouncer", `{"key":"good-key"}`)
	if csKey() != "good-key" {
		t.Error("EXT-03: pasted bouncer key not saved")
	}
	for _, c := range docker.calls {
		if c.Args[0] == "exec" {
			t.Errorf("EXT-03: docker exec used for a CrowdSec outside Docker: %v", c.Args)
		}
	}
	r := f.app.checkCrowdSec(t.Context())
	ids := map[string]string{}
	for _, c := range r.Checks {
		ids[c.ID] = c.Status
	}
	if ids["machine"] != "ok" || ids["lapi"] != "ok" || ids["ctr"] != "info" {
		t.Errorf("EXT-03 check: %v", ids)
	}
}
