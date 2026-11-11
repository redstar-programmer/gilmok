package main

// APPLY / AU / GRP (docker paths) scenarios — fake docker + fake Cloudflare DNS

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- fake Cloudflare DNS

type fakeCFDNS struct {
	mu         sync.Mutex
	recs       map[string]DNSRecord
	next       int
	failDelete map[string]bool
	writes     []string
}

func newFakeCFDNS(t *testing.T, recs ...DNSRecord) *fakeCFDNS {
	f := &fakeCFDNS{recs: map[string]DNSRecord{}, failDelete: map[string]bool{}}
	for _, r := range recs {
		f.recs[r.ID] = r
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		ok := func(v any) {
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":%s,"result_info":{"page":1,"total_pages":1}}`, b)
		}
		switch {
		case r.URL.Path == "/zones":
			ok([]map[string]string{{"id": "z1", "name": r.URL.Query().Get("name")}})
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == "GET":
			var list []DNSRecord
			for _, x := range f.recs {
				list = append(list, x)
			}
			ok(list)
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == "POST":
			var x DNSRecord
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &x)
			f.next++
			x.ID = fmt.Sprintf("n%d", f.next)
			f.recs[x.ID] = x
			f.writes = append(f.writes, "create "+x.Type+" "+x.Name+" "+x.Content)
			ok(x)
		case strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/")
			if r.Method == "DELETE" {
				if f.failDelete[id] {
					fmt.Fprint(w, `{"success":false,"errors":[{"code":1000,"message":"boom"}],"result":null}`)
					return
				}
				f.writes = append(f.writes, "delete "+f.recs[id].Type+" "+f.recs[id].Name)
				delete(f.recs, id)
				ok(map[string]string{"id": id})
				return
			}
			var x DNSRecord
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &x)
			cur := f.recs[id]
			if x.Content != "" {
				cur.Content = x.Content
			}
			if strings.Contains(string(b), `"proxied"`) {
				cur.Proxied = x.Proxied
			}
			f.recs[id] = cur
			f.writes = append(f.writes, "update "+cur.Type+" "+cur.Name+" "+cur.Content)
			ok(cur)
		default:
			ok(map[string]any{})
		}
	}))
	t.Cleanup(srv.Close)
	old := cfAPI
	cfAPI = srv.URL
	t.Cleanup(func() { cfAPI = old })
	t.Setenv("GM_CF_TOKEN", "test-token-not-real-0000000000")
	t.Setenv("GM_CF_TOKEN_FILE", "")
	return f
}

func (f *fakeCFDNS) byName(typ, name string) *DNSRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.recs {
		if r.Type == typ && r.Name == name {
			x := r
			return &x
		}
	}
	return nil
}

// ---------------------------------------------------------------- a full stack on disk

type stackFiles struct {
	caddyfile, autheliaCfg, users string
}

const autheliaCfg = `# Authelia config (test)
server:
  address: 'tcp://:9091'
access_control:
  default_policy: deny
  rules:
    - domain: 'old.example.com'
      policy: one_factor
notifier:
  filesystem:
    filename: /config/notification.txt
`

// stackDocker answers like the real containers, reading the files on disk:
// a configuration / users file with the fault marker makes Authelia log level=fatal,
// a Caddyfile with the broken directive makes `caddy reload` fail.
func stackDocker(t *testing.T, sf stackFiles) *fakeDocker {
	return installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "caddy validate"):
			if strings.Contains(string(stdin), "BROKEN") {
				return "Error: adapting config using caddyfile: BROKEN", fmt.Errorf("exit status 1")
			}
			return "Valid configuration", nil
		case strings.Contains(j, "caddy reload"):
			b, _ := os.ReadFile(sf.caddyfile)
			if strings.Contains(string(b), "this_directive_does_not_exist") {
				return "Error: loading new config: unknown directive", fmt.Errorf("exit status 1")
			}
			return "", nil
		case strings.Contains(j, "config validate"):
			return "Configuration parsed and loaded successfully without errors.", nil
		case strings.HasPrefix(j, "restart"):
			return "", nil
		case strings.Contains(j, "{{.State.StartedAt}}"):
			return time.Now().UTC().Format(time.RFC3339Nano), nil
		case strings.HasPrefix(j, "logs"):
			for _, p := range []string{sf.autheliaCfg, sf.users} {
				if b, _ := os.ReadFile(p); strings.Contains(string(b), "gilmok_fault_injection") {
					return "time=x level=fatal msg=\"bad config\"", nil
				}
			}
			return "time=x level=info msg=\"Startup complete\"", nil
		}
		return "", fmt.Errorf("unexpected docker call: %s", j)
	})
}

func newStack(t *testing.T) (*fullApp, stackFiles) {
	f := newFullApp(t)
	cfgDir := filepath.Join(f.dir, "authelia")
	os.MkdirAll(cfgDir, 0o755)
	sf := stackFiles{caddyfile: filepath.Join(f.dir, "Caddyfile"), autheliaCfg: filepath.Join(cfgDir, "configuration.yml"), users: filepath.Join(cfgDir, "users_database.yml")}
	os.WriteFile(sf.caddyfile, []byte("# old\n"), 0o644)
	os.WriteFile(sf.autheliaCfg, []byte(autheliaCfg), 0o644)
	os.WriteFile(sf.users, []byte("users:\n  kim:\n    disabled: false\n    displayname: Kim\n    password: $argon2id$x\n    email: kim@example.com\n    groups:\n      - admins\n  lee:\n    disabled: false\n    displayname: Lee\n    password: $argon2id$y\n    email: lee@example.com\n    groups:\n      - admins\n      - family\n"), 0o600)
	f.set(func(d *Data) {
		d.Settings.Domain = "example.com"
		d.Settings.UseCaddy, d.Settings.UseAuthelia = true, true
		d.Settings.CaddyMode, d.Settings.CaddyContainer, d.Settings.CaddyfilePath, d.Settings.CaddyfileInCtr = "docker", "cad", sf.caddyfile, "/etc/caddy/Caddyfile"
		d.Settings.AutheliaCtr, d.Settings.AutheliaConfig, d.Settings.AutheliaUsers, d.Settings.AutheliaCtrDir = "auth", sf.autheliaCfg, sf.users, "/config"
		d.Settings.CaddyBase = "{\n\temail x@example.com\n}\n"
		d.Services = []*Service{
			{ID: "s1", Subdomain: "photos", Upstream: "immich:2283", Exposure: ExposurePublic, Enabled: true, ManageDNS: true, Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor", Groups: []string{"family"}}},
			{ID: "s2", Subdomain: "admin", Upstream: "dock:3000", Exposure: ExposurePublic, Enabled: true, ManageDNS: true, Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor", Groups: []string{"admins"}}},
		}
		d.AGroups, d.AGroupsInit = []AGroup{{Name: "admins"}, {Name: "family"}}, true
		d.Dirty, d.Pending = true, []string{"x"}
	})
	return f, sf
}

func read(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestScnApplySuccessAndNoop(t *testing.T) {
	f, sf := newStack(t)
	fd := stackDocker(t, sf)
	cf := newFakeCFDNS(t)
	f.set(func(d *Data) { d.Settings.UseCloudflare = true })
	publicIPFn = func(ctx context.Context, v6 bool) (string, error) { return "203.0.113.7", nil }
	// APPLY-04 (R5): validate → backup → Authelia → Caddy → DNS
	lines, err := f.app.Apply(false)
	if err != nil {
		t.Fatalf("APPLY-04: %v\n%s", err, strings.Join(lines, "\n"))
	}
	calls := strings.Join(fd.joined(), "\n")
	order := []string{"caddy validate", "config validate", "restart auth", "caddy reload"}
	last := -1
	for _, o := range order {
		i := strings.Index(calls, o)
		if i < 0 || i < last {
			t.Fatalf("APPLY-04 order: %s\n%s", o, calls)
		}
		last = i
	}
	if !strings.Contains(read(t, sf.caddyfile), "photos.example.com {") || !strings.Contains(read(t, sf.autheliaCfg), "group:family") || !strings.Contains(read(t, sf.autheliaCfg), "notifier:") {
		t.Fatal("APPLY-04: files not written (or other config lost)")
	}
	if r := cf.byName("A", "photos.example.com"); r == nil || r.Content != "203.0.113.7" {
		t.Fatalf("APPLY-04: DNS %v", cf.writes)
	}
	d := f.app.store.Snapshot()
	if d.Dirty || len(d.Pending) != 0 || d.LastApplied.IsZero() || len(d.ManagedDNS) != 2 {
		t.Fatalf("APPLY-04 state: %+v %v", d.Pending, d.ManagedDNS)
	}
	// APPLY-15: a backup folder exists
	if e, _ := os.ReadDir(filepath.Join(f.dir, "backups")); len(e) != 1 {
		t.Fatalf("APPLY-15: %d backups", len(e))
	}
	// APPLY-10: nothing changed → no validate / restart / reload
	n := len(fd.joined())
	if _, err := f.app.Apply(false); err != nil {
		t.Fatal(err)
	}
	if len(fd.joined()) != n {
		t.Fatalf("APPLY-10: docker called again: %v", fd.joined()[n:])
	}
}

func TestScnApplyFailures(t *testing.T) {
	f, sf := newStack(t)
	fd := stackDocker(t, sf)
	origCaddy, origAuth := read(t, sf.caddyfile), read(t, sf.autheliaCfg)
	// APPLY-03: validation fails → nothing written
	f.set(func(d *Data) { d.Services[0].Extra = "BROKEN" })
	if _, err := f.app.Apply(false); err == nil {
		t.Fatal("APPLY-03: broken Caddyfile applied")
	}
	if read(t, sf.caddyfile) != origCaddy || read(t, sf.autheliaCfg) != origAuth || fd.count("restart") != 0 {
		t.Fatal("APPLY-03: something was written")
	}
	f.set(func(d *Data) { d.Services[0].Extra = "" })
	// APPLY-05: Authelia fails to start → configuration.yml restored, Caddy untouched
	f.app.fault = FaultAutheliaStart
	if _, err := f.app.Apply(false); err == nil {
		t.Fatal("APPLY-05: no error")
	}
	if read(t, sf.autheliaCfg) != origAuth || read(t, sf.caddyfile) != origCaddy || fd.count("caddy reload") != 0 || fd.count("restart auth") != 2 {
		t.Fatalf("APPLY-05: %v", fd.joined())
	}
	// APPLY-06: Caddy reload fails → Caddyfile AND the Authelia change of the same apply restored
	f.app.fault = FaultCaddyReload
	if _, err := f.app.Apply(false); err == nil {
		t.Fatal("APPLY-06: no error")
	}
	if read(t, sf.autheliaCfg) != origAuth || read(t, sf.caddyfile) != origCaddy {
		t.Fatal("APPLY-06: not both restored")
	}
	if !f.app.store.Snapshot().Dirty {
		t.Fatal("APPLY-06: pending cleared after a failed apply")
	}
}

func TestScnApplyDNSPartial(t *testing.T) {
	f, sf := newStack(t)
	stackDocker(t, sf)
	// a managed record whose service is gone, and whose delete fails
	cf := newFakeCFDNS(t, DNSRecord{ID: "g1", Type: "A", Name: "gone.example.com", Content: "203.0.113.7"})
	cf.failDelete["g1"] = true
	f.set(func(d *Data) {
		d.Settings.UseCloudflare = true
		d.ManagedDNS = []string{"gone.example.com"}
		d.LastPublicIP = "203.0.113.7"
	})
	publicIPFn = func(ctx context.Context, v6 bool) (string, error) { return "203.0.113.7", nil }
	lines, _ := f.app.Apply(false)
	d := f.app.store.Snapshot()
	if !containsStr(d.ManagedDNS, "gone.example.com") || !containsStr(d.ManagedDNS, "photos.example.com") {
		t.Fatalf("APPLY-07: managed %v\n%s", d.ManagedDNS, strings.Join(lines, "\n"))
	}
	// DNS-06: deleting a service removes its A (and AAAA)
	cf.failDelete = map[string]bool{}
	f.set(func(d *Data) { d.Services = d.Services[1:] })
	f.app.Apply(false)
	if cf.byName("A", "photos.example.com") != nil || cf.byName("A", "gone.example.com") != nil {
		t.Fatalf("DNS-06: %v", cf.writes)
	}
}

func TestScnApplyConcurrentAndHealth(t *testing.T) {
	f, sf := newStack(t)
	fd := stackDocker(t, sf)
	// APPLY-11: two applies at once run one after the other
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, errs[i] = f.app.Apply(false) }(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || fd.count("restart auth") != 1 {
		t.Fatalf("APPLY-11: %v %v restarts=%d", errs[0], errs[1], fd.count("restart auth"))
	}
	// APPLY-13: in-place write keeps the file identity
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("one"), 0o644)
	a, _ := os.Stat(p)
	writeInPlace(p, []byte("two-longer"))
	b, _ := os.Stat(p)
	if !os.SameFile(a, b) || read(t, p) != "two-longer" {
		t.Fatal("APPLY-13")
	}
	// APPLY-14: last fatal before Startup complete = healthy; the other way round = failed
	for _, c := range []struct {
		logs string
		ok   bool
	}{{"level=fatal x\nStartup complete", true}, {"Startup complete\nlevel=fatal y", false}} {
		installFakeDocker(t, func(args []string, stdin []byte) (string, error) { return c.logs, nil })
		err := waitHealthy("auth", time.Now(), "Startup complete", 3*time.Second)
		if (err == nil) != c.ok {
			t.Fatalf("APPLY-14 %q: %v", c.logs, err)
		}
	}
	// APPLY-15: only the newest backups stay
	root := filepath.Join(t.TempDir(), "backups")
	for i := 0; i < backupKeep+5; i++ {
		os.MkdirAll(filepath.Join(root, fmt.Sprintf("20260101-0000%02d-apply", i)), 0o700)
	}
	pruneBackups(root, backupKeep)
	if e, _ := os.ReadDir(root); len(e) != backupKeep || e[0].Name() != "20260101-000005-apply" {
		t.Fatalf("APPLY-15 prune: %d", len(e))
	}
	d1, _ := backup(t.TempDir(), "x", nil)
	d2, _ := backup(filepath.Dir(filepath.Dir(d1)), "x", nil)
	if d1 == d2 {
		t.Fatal("APPLY-15: same-second backups overwrite each other")
	}
}

func TestScnApplyHTTP(t *testing.T) {
	f, sf := newStack(t)
	stackDocker(t, sf)
	boss := f.admin(t)
	// APPLY-16: no fault API without GM_DEV_FAULTS
	if code, _ := boss.do("POST", "/api/dev/fault", `{"kind":"caddy-reload"}`); code != 404 && code != 405 {
		t.Fatalf("APPLY-16: %d", code)
	}
	// APPLY-17: audited
	boss.must(200, "POST", "/api/apply", `{}`)
	ok := false
	for _, e := range f.events(t, "audit") {
		if strings.HasPrefix(e.Action, "적용") {
			ok = true
		}
	}
	if !ok {
		t.Fatal("APPLY-17: apply not audited")
	}
}

func TestScnAutheliaUsers(t *testing.T) {
	f, sf := newStack(t)
	fd := stackDocker(t, sf)
	boss := f.admin(t)
	// AU-02 / AU-03
	boss.must(400, "POST", "/api/users", `{"username":"a b","password":"long enough pw"}`)
	boss.must(400, "POST", "/api/users", `{"username":"한글","password":"long enough pw"}`)
	boss.must(400, "POST", "/api/users", `{"username":"park","password":"short9chr"}`)
	// AU-05: unknown group → nothing written
	before := read(t, sf.users)
	boss.must(400, "POST", "/api/users", `{"username":"park","password":"long enough pw","groups":["ghost"]}`)
	if read(t, sf.users) != before {
		t.Fatal("AU-05: file changed")
	}
	// AU-01 / AU-04 (R18): add with 2 registered groups → written + restart
	m := boss.must(200, "POST", "/api/users", `{"username":"park","displayname":"Park","password":"long enough pw","groups":["admins","family"]}`)
	if m["ok"] != true || fd.count("restart auth") != 1 {
		t.Fatalf("AU-01: %v", m)
	}
	u, _ := LoadUsers(sf.users)
	if strings.Join(u["park"].Groups, ",") != "admins,family" || !strings.HasPrefix(u["park"].Password, "$argon2id$") {
		t.Fatalf("AU-04: %+v", u["park"])
	}
	// AU-09
	boss.raw("GET", "/api/users", "")
	if strings.Contains(boss.last.Body.String(), "argon2") || strings.Contains(boss.last.Body.String(), "password") {
		t.Fatal("AU-09: hash leaked")
	}
	// AU-07: Authelia fails to start → file restored
	before = read(t, sf.users)
	f.app.fault = FaultUsersStart
	_, m = boss.do("PUT", "/api/users/park", `{"username":"park","displayname":"P2","groups":["admins"]}`)
	if m["ok"] == true || read(t, sf.users) != before {
		t.Fatalf("AU-07: %v", m)
	}
	// AU-08: two saves at once both land
	var wg sync.WaitGroup
	for _, n := range []string{"kim", "lee"} {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			boss.do("PUT", "/api/users/"+n, `{"username":"`+n+`","displayname":"changed-`+n+`","groups":["admins"]}`)
		}(n)
	}
	wg.Wait()
	u, _ = LoadUsers(sf.users)
	if u["kim"].DisplayName != "changed-kim" || u["lee"].DisplayName != "changed-lee" {
		t.Fatalf("AU-08: %s / %s", u["kim"].DisplayName, u["lee"].DisplayName)
	}
	// AU-06: the last user cannot go
	for _, n := range []string{"kim", "lee"} {
		boss.must(200, "DELETE", "/api/users/"+n, "")
	}
	boss.must(400, "DELETE", "/api/users/park", "")
}

func TestScnGroupsWithUsers(t *testing.T) {
	f, sf := newStack(t)
	fd := stackDocker(t, sf)
	boss := f.admin(t)
	// GRP-13 (R2): rename a group 2 users have → users file + restart, then services
	m := boss.must(200, "PUT", "/api/groups/admins", `{"name":"ops","desc":"운영"}`)
	u, _ := LoadUsers(sf.users)
	if m["users"] != float64(2) || m["services"] != float64(1) || !containsStr(u["kim"].Groups, "ops") || !containsStr(u["lee"].Groups, "ops") || fd.count("restart auth") != 1 {
		t.Fatalf("GRP-13: %v %v", m, u)
	}
	if f.app.store.Snapshot().Services[1].Authelia.Groups[0] != "ops" {
		t.Fatal("GRP-13: service not renamed")
	}
	// GRP-14: users apply fails → services and definitions unchanged
	f.app.fault = FaultUsersStart
	code, _ := boss.do("PUT", "/api/groups/family", `{"name":"kin"}`)
	d := f.app.store.Snapshot()
	if code == 200 || d.Services[0].Authelia.Groups[0] != "family" || !containsStr(groupNames(d), "family") {
		t.Fatalf("GRP-14: %d %v", code, d.Services[0].Authelia.Groups)
	}
	// GRP-17 (R1·R2): purge from services and users
	boss.must(200, "DELETE", "/api/groups/family?purge=1", "")
	u, _ = LoadUsers(sf.users)
	if containsStr(u["lee"].Groups, "family") || len(f.app.store.Snapshot().Services[0].Authelia.Groups) != 0 {
		t.Fatal("GRP-17: not purged everywhere")
	}
	// GRP-15: config only (no authelia_users) → refused before anything changes
	r := boss.must(200, "POST", "/api/roles", `{"name":"cfg","perms":["config"]}`)
	c := f.user(t, boss, "cfgonly", r["id"].(string))
	before := read(t, sf.users)
	code, m = c.do("PUT", "/api/groups/ops", `{"name":"ops2"}`)
	if code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "Authelia 사용자") || read(t, sf.users) != before {
		t.Fatalf("GRP-15: %d %v", code, m)
	}
}

func groupNames(d Data) []string {
	var out []string
	for _, g := range d.AGroups {
		out = append(out, g.Name)
	}
	return out
}
