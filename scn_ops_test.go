package main

// MON / DASH / LOG / AUD / UPD / COMP scenarios

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
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

func TestScnMonitor(t *testing.T) {
	m := newMonitor()
	now := time.Now().UnixMilli()
	// MON-03 (R17): WAF counted overall and per site when the host is known
	m.addWaf(WAFEvent{Time: time.UnixMilli(now), Host: "a.example.com"})
	m.addWaf(WAFEvent{Time: time.UnixMilli(now)})
	tot := m.total(time.Hour, "")
	if tot.Waf != 2 || m.total(time.Hour, "a.example.com").Waf != 1 || !m.dirty || m.lastTs != now {
		t.Fatalf("MON-03: all=%d a=%d dirty=%v", tot.Waf, m.total(time.Hour, "a.example.com").Waf, m.dirty)
	}
	// MON-05: lines older than 5 minutes before the newest are dropped (replay)
	m.addReq(ReqRec{T: now - 6*60*1000, Host: "a.example.com", Status: 200})
	if m.total(time.Hour, "").N != 0 {
		t.Fatal("MON-05: replayed old line counted")
	}
	// MON-04: the stream skips lines up to the last seen time; the same millisecond from a
	// different request is still a request (addReq keeps it)
	m.addReq(ReqRec{T: now, Host: "a.example.com", Status: 200})
	m.addReq(ReqRec{T: now, Host: "b.example.com", Status: 200})
	if m.total(time.Hour, "").N != 2 {
		t.Fatal("MON-04: same-ms requests lost")
	}
	// MON-06: ring buffer overwrites the oldest
	for i := 0; i < reqRingCap+10; i++ {
		m.addReq(ReqRec{T: now + int64(i), Host: "r.example.com", Status: 200})
	}
	if len(m.reqs) != reqRingCap {
		t.Fatalf("MON-06: %d", len(m.reqs))
	}
	// MON-07: old buckets pruned
	m.mu.Lock()
	m.fine[(time.Now().Unix()-2*fineKeep)/fineRes] = &Slot{Hosts: map[string]*Bucket{}}
	m.coarse[(time.Now().Unix()-2*coarseKeep)/coarseRes] = &Slot{Hosts: map[string]*Bucket{}}
	nf, nc := len(m.fine), len(m.coarse)
	m.mu.Unlock()
	m.prune()
	if len(m.fine) != nf-1 || len(m.coarse) != nc-1 {
		t.Fatal("MON-07")
	}
	// MON-08: save → load gives the same numbers
	a := &App{mon: m, dataDir: t.TempDir()}
	before := m.total(24*time.Hour, "").N
	a.saveMetrics()
	b := &App{mon: newMonitor(), dataDir: a.dataDir}
	b.loadMetrics()
	if got := b.mon.total(24*time.Hour, "").N; got != before || b.mon.lastTs != m.lastTs {
		t.Fatalf("MON-08: %d vs %d", got, before)
	}
}

func TestScnHealthProbe(t *testing.T) {
	f := newFullApp(t)
	// an upstream that answers, and one that does not
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	f.set(func(d *Data) {
		d.Services = []*Service{
			{ID: "up", Subdomain: "up", Upstream: ln.Addr().String(), Exposure: ExposurePublic, Enabled: true},
			{ID: "down", Subdomain: "down", Upstream: deadAddr, Exposure: ExposurePublic, Enabled: true},
		}
	})
	// MON-09: probes never overlap
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); f.app.probeHealth() }()
		go func() { defer wg.Done(); f.app.probeHealthBg() }()
	}
	wg.Wait()
	f.app.mon.mu.Lock()
	up, down := f.app.mon.health["up"], f.app.mon.health["down"]
	f.app.mon.mu.Unlock()
	if up == nil || !up.OK || down == nil || down.OK {
		t.Fatalf("MON-09: %+v %+v", up, down)
	}
	// MON-10: only transitions make events (the first run is a summary)
	f.events(t, "system")
	ln2, err := net.Listen("tcp", deadAddr)
	if err != nil {
		t.Fatalf("MON-10 setup: cannot reopen %s: %v", deadAddr, err)
	}
	defer ln2.Close()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	f.app.probeHealth()
	f.app.probeHealth()
	n := 0
	for _, e := range f.events(t, "system") {
		if e.Action == "service.up" && strings.Contains(e.Target, "down") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("MON-10: %d transition events", n)
	}
}

func TestScnDashboard(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	// DASH-01: default 12 widgets
	m := boss.must(200, "GET", "/api/dashboard", "")
	ws := m["widgets"].([]any)
	if len(ws) != 12 {
		t.Fatalf("DASH-01: %d", len(ws))
	}
	// DASH-02: save 5 in a new order; DASH-05 an unknown type is refused
	mine := []Widget{{Type: "events", Title: "e"}, {Type: "stat", Metric: "rpm"}, {Type: "top", Dim: "nope"}, {Type: "series", Metric: "latency"}, {Type: "health"}}
	b, _ := json.Marshal(map[string]any{"widgets": mine})
	m = boss.must(200, "PUT", "/api/dashboard", string(b))
	got := f.app.store.Snapshot().Dashboard
	if len(got) != 5 || got[0].Type != "events" || got[2].Dim != "host" {
		t.Fatalf("DASH-02: %+v", got)
	}
	b, _ = json.Marshal(map[string]any{"widgets": []Widget{{Type: "pie"}}})
	boss.must(400, "PUT", "/api/dashboard", string(b))
	// DASH-03
	boss.must(200, "PUT", "/api/dashboard", `{"reset":true}`)
	if f.app.store.Snapshot().Dashboard != nil {
		t.Fatal("DASH-03: reset kept a custom layout")
	}
	m = boss.must(200, "GET", "/api/dashboard", "")
	if len(m["widgets"].([]any)) != 12 {
		t.Fatal("DASH-03: reset does not serve the default 12 widgets")
	}
	// DASH-04 / DASH-05: one call answers every widget; a broken one does not break the rest
	now := time.Now().UnixMilli()
	for i := 0; i < 50; i++ {
		f.app.mon.addReq(ReqRec{T: now - int64(i*1000), Host: "a.example.com", Status: []int{200, 404, 503}[i%3], Ms: float64(i * 10)})
	}
	b, _ = json.Marshal(map[string]any{"widgets": []Widget{
		{ID: "s", Type: "stat", Metric: "requests", Range: "15m"}, {ID: "x", Type: "pie"},
		{ID: "t", Type: "top", Dim: "status", Range: "15m"}, {ID: "c", Type: "scatter", Range: "15m"},
	}})
	m = boss.must(200, "POST", "/api/dash/data", string(b))
	data := m["data"].(map[string]any)
	if data["s"] == nil || data["t"] == nil || data["c"] == nil || data["x"] != nil {
		t.Fatalf("DASH-04/05: %v", m)
	}
	// DASH-06: p95 interpolates inside the bucket
	var bk Bucket
	for i := 1; i <= 100; i++ {
		bk.add(ReqRec{Ms: float64(i), Status: 200})
	}
	if p := bk.pct(0.95); p < 90 || p > 100 {
		t.Fatalf("DASH-06: %v", p)
	}
	// DASH-07: a past moment / long range come from the log DB
	b, _ = json.Marshal(map[string]any{"at": now - 3600_000, "widgets": []Widget{{ID: "s", Type: "stat", Metric: "requests", Range: "1h"}, {ID: "w", Type: "series", Metric: "requests", Range: "7d"}}})
	m = boss.must(200, "POST", "/api/dash/data", string(b))
	if m["data"].(map[string]any)["s"] == nil || m["data"].(map[string]any)["w"] == nil {
		t.Fatalf("DASH-07: %v", m)
	}
	// DASH-08: odd ranges never overflow
	for _, q := range []string{"", "?from=abc&to=xyz", "?from=9223372036854775807&to=-9223372036854775808", "?min=-1&max=1e309"} {
		if code, _ := boss.do("GET", "/api/dash/requests"+q, ""); code != 200 {
			t.Errorf("DASH-08 %q: %d", q, code)
		}
	}
}

func TestScnLogDB(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	a := f.app
	// LOG-06 / LOG-07: disk levels
	free := uint64(50)
	diskUsageFn = func(p string) (uint64, uint64, error) { return 100, free, nil }
	defer func() { diskUsageFn = diskUsage }()
	f.set(func(d *Data) { d.Settings.DiskWarnPct, d.Settings.DiskCritPct, d.Settings.DiskStopPct = 20, 10, 5 })
	for _, c := range []struct {
		free uint64
		lvl  string
	}{{50, "ok"}, {15, "warn"}, {8, "critical"}, {3, "stop"}} {
		free = c.free
		a.checkDisk()
		if got := a.ldb.disk.Level; got != c.lvl {
			t.Fatalf("LOG-06 %d%%: %s", c.free, got)
		}
	}
	s0 := a.ldb.skipped.Load()
	a.ldb.Req(ReqRec{T: time.Now().UnixMilli(), Host: "x"})
	if a.ldb.skipped.Load() != s0+1 {
		t.Fatal("LOG-06: request logged while stopped")
	}
	a.ldb.keepEvents.Store(true)
	a.ldb.Event(Event{Cat: "system", Action: "kept.on.stop"})
	free = 0
	a.checkDisk()
	a.ldb.Event(Event{Cat: "system", Action: "dropped.below.1pct"})
	free = 50
	a.checkDisk()
	got := map[string]bool{}
	for _, e := range f.events(t, "system") {
		got[e.Action] = true
	}
	if !got["kept.on.stop"] || got["dropped.below.1pct"] {
		t.Fatalf("LOG-07: %v", got)
	}
	// LOG-08: export / delete need 「logs」
	op := f.user(t, boss, "op", "operator")
	op.must(403, "GET", "/api/logs/export?cat=audit", "")
	op.must(403, "POST", "/api/logs/delete", `{"cat":"audit","before":1}`)
	// LOG-10: filters are bound parameters
	for _, q := range []string{"' OR 1=1 --", "%", "_", `\`} {
		if _, err := a.ldb.QueryEvents(context.Background(), EventQuery{Q: q, Cat: "audit' OR '1'='1", Level: "x' --", Limit: 10}); err != nil {
			t.Fatalf("LOG-10 %q: %v", q, err)
		}
	}
	evs, _ := a.ldb.QueryEvents(context.Background(), EventQuery{Q: "' OR 1=1 --", Limit: 10})
	if len(evs) != 0 {
		t.Fatalf("LOG-10: injection matched %d rows", len(evs))
	}
	boss.must(400, "POST", "/api/logs/delete", `{"cat":"audit; DROP TABLE events","before":1}`)
	// LOG-05: the size cap never trims the last day, and uses the used size
	old := time.Now().Add(-10 * 24 * time.Hour).UnixMilli()
	for i := 0; i < 300; i++ {
		a.ldb.Req(ReqRec{T: old + int64(i), Host: "old", Status: 200})
		a.ldb.Req(ReqRec{T: time.Now().UnixMilli() - int64(i), Host: "new", Status: 200})
	}
	time.Sleep(1500 * time.Millisecond)
	if a.ldb.usedBytes() <= 0 {
		t.Fatal("LOG-05: usedBytes")
	}
	f.set(func(d *Data) { d.Settings.LogMaxDBMB = 50 })
	a.trimToCap(1) // 1 byte cap → trim everything allowed
	rows, _ := a.ldb.QueryRequests(context.Background(), ReqQuery{Limit: 1000})
	newN, oldN := 0, 0
	for _, r := range rows {
		if r.Host == "new" {
			newN++
		} else {
			oldN++
		}
	}
	if newN != 300 || oldN != 0 {
		t.Fatalf("LOG-05: new=%d old=%d", newN, oldN)
	}
}

func TestScnAudit(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) { d.Settings.Domain = "example.com" })
	// AUD-01: secrets in request bodies are masked
	v := redact(map[string]any{"password": "p1", "nested": map[string]any{"token": "t1", "apiKey": "k1"}, "list": []any{map[string]any{"secret": "s1"}}, "name": "kim"})
	if b := fmtAny(v); strings.Contains(b, "p1") || strings.Contains(b, "t1") || strings.Contains(b, "s1") || !strings.Contains(b, "kim") {
		t.Fatalf("AUD-01: %s", b)
	}
	// AUD-03 (R20): service diff
	m := boss.must(200, "POST", "/api/services", `{"subdomain":"a","upstream":"a:1","exposure":"public","enabled":true}`)
	id := m["id"].(string)
	boss.must(200, "PUT", "/api/services/"+id, `{"subdomain":"a","upstream":"a:2","exposure":"public","enabled":true,"notes":"n","waf":"detect"}`)
	// AUD-02 / AUD-05: failures are recorded
	boss.must(400, "POST", "/api/services", `{"subdomain":"bad one","upstream":"a:1","exposure":"public"}`)
	f.set(func(d *Data) {
		d.AGroups, d.AGroupsInit = []AGroup{{Name: "used"}}, true
		d.Services[0].Authelia.Groups = []string{"used"}
	})
	boss.must(409, "DELETE", "/api/groups/used", "")
	bad := `{"name":"x.csv","data":"` + strings.Repeat("A", 8) + `","dry":false}`
	boss.do("POST", "/api/services/bulk", bad)
	var diff, failSvc, failGrp bool
	for _, e := range f.events(t, "audit") {
		if e.Action == "서비스 수정" && strings.Contains(e.Detail, `"upstream"`) && strings.Contains(e.Detail, `"notes"`) && strings.Contains(e.Detail, `"waf"`) {
			diff = true
		}
		if e.Action == "서비스 추가" && e.Level == "error" && strings.Contains(e.Msg, "실패") {
			failSvc = true
		}
		if e.Action == "Authelia 그룹 삭제" && e.Level == "error" {
			failGrp = true
		}
	}
	if !diff || !failSvc || !failGrp {
		t.Fatalf("AUD-02/03/05: diff=%v svc=%v grp=%v", diff, failSvc, failGrp)
	}
}

func TestScnUpdates(t *testing.T) {
	f := newFullApp(t)
	// registry: every https request goes to one fake (digest per repo)
	var remote atomic.Value
	remote.Store("sha256:new")
	reg := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", remote.Load().(string))
	}))
	reg.TLS = &tls.Config{}
	reg.StartTLS()
	defer reg.Close()
	prevHTTP := regHTTP
	regHTTP = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, reg.Listener.Addr().String())
		},
	}}
	defer func() { regHTTP = prevHTTP }()
	local := "sha256:new"
	stack := t.TempDir()
	os.WriteFile(filepath.Join(stack, "docker-compose.yml"), []byte("services:\n  caddy:\n    build: .\n    environment:\n      - CLOUDFLARE_API_TOKEN=${CLOUDFLARE_API_TOKEN}\n"), 0o644)
	os.WriteFile(filepath.Join(stack, "Dockerfile"), []byte("FROM caddy:builder AS b\nFROM caddy:2\nCOPY --from=b /x /y\n"), 0o644)
	ctrID := "id-1"
	installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "{{.Config.Image}}|{{.Image}}"):
			return "authelia/authelia:latest|sha256:img", nil
		case strings.HasPrefix(j, "image inspect"):
			if strings.Contains(j, "caddy:") {
				return "[]", nil // base not kept locally (BuildKit)
			}
			return `["authelia/authelia@` + local + `"]`, nil
		case strings.Contains(j, "{{json .Config.Labels}}"):
			return `{"com.docker.compose.project":"cad","com.docker.compose.service":"caddy"}`, nil
		case strings.Contains(j, "{{.Id}}"):
			return ctrID, nil
		case strings.HasPrefix(j, "compose"):
			return "ok", nil
		}
		return "", fmt.Errorf("unexpected %s", j)
	})
	st := Settings{CaddyContainer: "cad", CaddyStackDir: stack, CaddyService: "caddy", AutheliaCtr: "auth"}
	// UPD-06: registry digest vs local RepoDigests
	it := f.app.checkContainer("authelia", "auth", st)
	if len(it) != 1 || it[0].Available {
		t.Fatalf("UPD-06 same: %+v", it)
	}
	local = "sha256:old"
	if it = f.app.checkContainer("authelia", "auth", st); !it[0].Available {
		t.Fatalf("UPD-06 newer: %+v", it)
	}
	// UPD-03 / UPD-07: locally built image → the manual compose folder's Dockerfile bases (stages skipped)
	installFakeDockerKeep := dockerRun
	dockerRun = func(ctx context.Context, stdin []byte, env []string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "{{.Config.Image}}|{{.Image}}") {
			return "cad-caddy|sha256:img", nil
		}
		if args[0] == "image" {
			return "[]", nil
		}
		return installFakeDockerKeep(ctx, stdin, env, args...)
	}
	it = f.app.checkContainer("caddy", "cad", st)
	if len(it) != 2 || !it[0].Built || it[0].Image != "caddy:builder" || it[0].Available {
		t.Fatalf("UPD-03/07: %+v", it)
	}
	// a newer base appears → available; UPD-08: after an update the baseline moves
	remote.Store("sha256:newer")
	if it = f.app.checkContainer("caddy", "cad", st); !it[0].Available {
		t.Fatalf("UPD-07 newer base: %+v", it)
	}
	f.set(func(d *Data) { d.Settings = st })
	info := f.app.resetBaselines("caddy")
	for _, x := range info.Items {
		if x.Target == "caddy" && x.Available {
			t.Fatalf("UPD-08: still available after update: %+v", x)
		}
	}
	dockerRun = installFakeDockerKeep
	// UPD-04: no token + ${CLOUDFLARE_API_TOKEN} → update refused
	t.Setenv("GM_CF_TOKEN", "")
	t.Setenv("GM_CF_TOKEN_FILE", "")
	oldUI := cfTokenUIPath
	t.Cleanup(func() { cfTokenUIPath = oldUI })
	cfTokenUIPath = filepath.Join(t.TempDir(), "none")
	if err := f.app.update("caddy", st, &logger{}); err == nil || !strings.Contains(err.Error(), "CLOUDFLARE_API_TOKEN") {
		t.Fatalf("UPD-04: %v", err)
	}
	// UPD-05: same container id after compose → 「이미 최신」
	t.Setenv("GM_CF_TOKEN", "test-token-not-real-0000000000")
	L := &logger{}
	if err := f.app.update("caddy", st, L); err != nil || !strings.Contains(strings.Join(L.lines, "\n"), "이미 최신") {
		t.Fatalf("UPD-05: %v %v", err, L.lines)
	}
	// UPD-09: the symlink is made once even when asked twice at once
	root := t.TempDir()
	target := filepath.Join(root, "local")
	os.MkdirAll(target, 0o755)
	link := filepath.Join(root, "daemon", "d", "x")
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs[i] = ensureLink(link, target) }(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil && !strings.Contains(e.Error(), "privilege") {
			t.Fatalf("UPD-09: %v", e)
		}
	}
	// UPD-11: token match compares, never prints
	r := &CheckResult{}
	installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		return "PATH=/x\nCLOUDFLARE_API_TOKEN=other-token-value\n", nil
	})
	tokenCheck(r, "cad")
	if b := fmtAny(r); !strings.Contains(b, "다릅니다") || strings.Contains(b, "other-token-value") || strings.Contains(b, "test-token-not-real") {
		t.Fatalf("UPD-11: %s", b)
	}
}

func TestScnComponents(t *testing.T) {
	base := Data{Settings: Settings{Domain: "example.com", TailscalePort: 8443, UseCaddy: true}, Services: []*Service{
		{ID: "1", Subdomain: "p", Upstream: "p:1", Exposure: ExposureTailscale, Enabled: true},
	}}
	// COMP-06: Tailscale off but a private service left → its listener stays
	if out := GenerateCaddyfile(base); !strings.Contains(out, "p.example.com:8443 {") {
		t.Fatalf("COMP-06: %s", out)
	}
	// COMP-04: Caddy off → apply has no Caddy step; services remain for DNS/health
	f, sf := newStack(t)
	fd := stackDocker(t, sf)
	f.set(func(d *Data) { d.Settings.UseCaddy = false })
	orig := read(t, sf.caddyfile)
	if _, err := f.app.Apply(false); err != nil {
		t.Fatal(err)
	}
	if fd.count("caddy") != 0 || read(t, sf.caddyfile) != orig {
		t.Fatalf("COMP-04: %v", fd.joined())
	}
}

// UPD-10: connection checks — container, file read/write, mount match, validation, WAF module
func TestScnConnectionCheck(t *testing.T) {
	f := newFullApp(t)
	cf := filepath.Join(f.dir, "Caddyfile")
	os.WriteFile(cf, []byte("a.example.com {\n}\n"), 0o644)
	inCtr := "a.example.com {\n}\n"
	installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "{{.State.Status}}"):
			return "running|caddy:2|2026-01-01", nil
		case strings.Contains(j, "caddy version"):
			return "v2.9.1 h1:x", nil
		case strings.Contains(j, "cat /etc/caddy/Caddyfile"):
			return inCtr, nil
		case strings.Contains(j, "caddy validate"):
			return "Valid configuration", nil
		case strings.Contains(j, "list-modules"):
			return "http.handlers.waf\nhttp.handlers.reverse_proxy", nil
		}
		return "", fmt.Errorf("no")
	})
	f.set(func(d *Data) {
		d.Settings.CaddyMode, d.Settings.CaddyContainer, d.Settings.CaddyfilePath, d.Settings.CaddyfileInCtr = "docker", "cad", cf, "/etc/caddy/Caddyfile"
	})
	status := func(r CheckResult, id string) string {
		for _, it := range r.Checks {
			if it.ID == id {
				return it.Status
			}
		}
		return "-"
	}
	r := f.app.checkCaddy()
	for _, id := range []string{"ctr", "file", "write", "mount", "valid", "waf"} {
		if status(r, id) != "ok" {
			t.Fatalf("UPD-10 %s: %s (%s)", id, status(r, id), fmtAny(r))
		}
	}
	// the container sees a different file → mount mismatch
	inCtr = "other {\n}\n"
	if r = f.app.checkCaddy(); status(r, "mount") != "fail" {
		t.Fatalf("UPD-10 mismatch: %s", fmtAny(r))
	}
	// container stopped
	installFakeDocker(t, func(args []string, stdin []byte) (string, error) { return "exited|caddy:2|x", nil })
	if r = f.app.checkCaddy(); status(r, "ctr") != "fail" || status(r, "mount") != "skip" {
		t.Fatalf("UPD-10 stopped: %s", fmtAny(r))
	}
}
