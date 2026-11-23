package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Performance and security scenarios (docs/TEST_SCENARIOS.md 「성능」·「보안 (대시보드·새 API)」).
// Timings are logged (go test -v -run 'Perf|SecDash') and checked against generous budgets so a slow
// CI box does not fail them; a budget miss means something became orders of magnitude slower.

// seedRequests writes n request rows straight into the log database (spread over `span`, ending now).
func seedRequests(t *testing.T, f *fullApp, n int, span time.Duration) {
	t.Helper()
	tx, err := f.app.ldb.w.Begin()
	if err != nil {
		t.Fatal(err)
	}
	st, err := tx.Prepare(`INSERT INTO requests(ts,host,method,uri,status,ms,size,ip,cc,via) VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	rnd := rand.New(rand.NewSource(1))
	hosts := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	ccs := []string{"KR", "US", "JP", "DE", "CN"}
	vias := []string{"cf", "direct"}
	codes := []int{200, 200, 200, 200, 200, 200, 304, 404, 403, 502}
	for i := 0; i < n; i++ {
		ts := now - rnd.Int63n(span.Milliseconds())
		if _, err := st.Exec(ts, hosts[i%len(hosts)], "GET", fmt.Sprintf("/p/%d", i%50), codes[rnd.Intn(len(codes))],
			rnd.ExpFloat64()*40, 1000, fmt.Sprintf("203.0.113.%d", i%250), ccs[i%len(ccs)], vias[i%2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func timed(fn func()) time.Duration { s := time.Now(); fn(); return time.Since(s) }

func pctDur(ds []time.Duration, p float64) time.Duration {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[min(len(ds)-1, int(float64(len(ds))*p))]
}

// the default layout as the browser sends it
func dashBody(t *testing.T, extra string) string {
	t.Helper()
	b, _ := json.Marshal(defaultDashboard())
	return `{"widgets":` + string(b) + extra + `}`
}

// PERF-01: the log writer takes a burst (one request per Caddy log line) without dropping and
// flushes it in batches.
func TestPerfLogIngest(t *testing.T) {
	f := newFullApp(t)
	const n = 50000
	now := time.Now().UnixMilli()
	d := timed(func() {
		for i := 0; i < n; i++ {
			f.app.ldb.Req(ReqRec{T: now - int64(i), Host: "a.example.com", Method: "GET", URI: "/", Status: 200, Ms: 3})
		}
		for i := 0; i < 300 && f.app.ldb.written.Load()+f.app.ldb.dropped.Load() < n; i++ {
			time.Sleep(50 * time.Millisecond)
		}
	})
	st := f.app.ldb.Stats()
	if st.Dropped > 0 || st.Written < n {
		t.Errorf("PERF-01 a burst lost requests: written %d dropped %d", st.Written, st.Dropped)
	}
	t.Logf("PERF-01 ingest %d rows in %v (%.0f rows/s), dropped %d", n, d, n/d.Seconds(), st.Dropped)
	if d > 20*time.Second {
		t.Errorf("PERF-01 ingest too slow: %v", d)
	}
}

// PERF-02: the in-memory monitor stays bounded (ring 20k) however many requests arrive.
func TestPerfMonitorBounded(t *testing.T) {
	m := newMonitor()
	now := time.Now().UnixMilli()
	d := timed(func() {
		for i := 0; i < 100000; i++ {
			m.addReq(ReqRec{T: now - int64(100000-i), Host: fmt.Sprintf("h%d.example.com", i%20), Status: 200, Ms: 5})
		}
	})
	n := len(m.recent(0))
	t.Logf("PERF-02 100k adds in %v, ring holds %d", d, n)
	if n > reqRingCap {
		t.Errorf("PERF-02 ring grew past its cap: %d", n)
	}
	if d > 5*time.Second {
		t.Errorf("PERF-02 addReq too slow: %v", d)
	}
}

// PERF-03: the dashboard (default 13 panels) — live from memory, a 7-day window from the database,
// and the same window with a filter — on 200k stored requests.
func TestPerfDashboardData(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	seedRequests(t, f, 200000, 7*24*time.Hour)
	now := time.Now().UnixMilli()
	for i := 0; i < reqRingCap; i++ {
		f.app.mon.addReq(ReqRec{T: now - int64(reqRingCap-i)*50, Host: "a.example.com", Status: 200 + (i%5)*100, Ms: float64(i % 300), CC: "KR", Via: "cf"})
	}
	cases := []struct {
		name, extra string
		budget      time.Duration
	}{
		{"live 1h", `,"range":"1h"`, 2 * time.Second},
		{"live 1h + filter", `,"range":"1h","filters":{"classes":[5],"countries":["KR"]}`, 2 * time.Second},
		{"db 7d", fmt.Sprintf(`,"from":%d,"to":%d`, now-7*24*3600_000, now), 8 * time.Second},
		{"db 7d + filter", fmt.Sprintf(`,"from":%d,"to":%d,"filters":{"countries":["KR","US"]}`, now-7*24*3600_000, now), 8 * time.Second},
	}
	for _, c := range cases {
		body := dashBody(t, c.extra)
		var d time.Duration
		var code int
		d = timed(func() { code, _ = boss.do("POST", "/api/dash/data", body) })
		t.Logf("PERF-03 %-18s %v (%d bytes)", c.name, d, boss.last.Body.Len())
		if code != 200 {
			t.Errorf("PERF-03 %s: %d %s", c.name, code, truncate(boss.last.Body.String(), 200))
		}
		if d > c.budget {
			t.Errorf("PERF-03 %s over budget: %v > %v", c.name, d, c.budget)
		}
	}
	// the request drill-down on the database stays bounded
	q := fmt.Sprintf("/api/dash/requests?from=%d&to=%d&min=0&max=1e12&db=1", now-7*24*3600_000, now)
	var r map[string]any
	d := timed(func() { r = boss.must(200, "GET", q, "") })
	got := len(r["requests"].([]any))
	t.Logf("PERF-03 drill-down 7d: %v, total %v, returned %d", d, r["total"], got)
	if got > 1000 || d > 5*time.Second {
		t.Errorf("PERF-03 drill-down: %d rows in %v", got, d)
	}
}

// PERF-04: Caddyfile generation for a large site list.
func TestPerfCaddyfile500(t *testing.T) {
	d := Data{Settings: defaultSettings()}
	d.Settings.Domain = "example.com"
	for i := 0; i < 500; i++ {
		d.Services = append(d.Services, &Service{ID: fmt.Sprintf("s%03d", i), Subdomain: fmt.Sprintf("svc%03d", i), Upstream: fmt.Sprintf("app%03d:8080", i), Enabled: true, WAF: []string{"", "detect", "block"}[i%3]})
	}
	var out string
	dur := timed(func() { out = GenerateCaddyfile(d) })
	t.Logf("PERF-04 500 sites → %d bytes in %v", len(out), dur)
	if !strings.Contains(out, "svc499.example.com") {
		t.Error("PERF-04 last site missing")
	}
	if dur > time.Second {
		t.Errorf("PERF-04 generation too slow: %v", dur)
	}
	if again := GenerateCaddyfile(d); again != out {
		t.Error("PERF-04 generation is not deterministic")
	}
}

// PERF-05: many browsers polling at once — every request answers, no error, p95 reported.
func TestPerfConcurrentPolling(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	seedRequests(t, f, 20000, time.Hour)
	body := dashBody(t, `,"range":"15m"`)
	paths := [][3]string{{"GET", "/api/state", ""}, {"GET", "/api/dashboard", ""}, {"POST", "/api/dash/data", body}, {"GET", "/api/health", ""}}
	var mu sync.Mutex
	var lat []time.Duration
	errs := 0
	var wg sync.WaitGroup
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			c := &client{t: t, h: f.h, remote: boss.remote, cookie: boss.cookie, headers: map[string]string{}}
			for i := 0; i < 20; i++ {
				p := paths[(g+i)%len(paths)]
				s := time.Now()
				rec := c.raw(p[0], p[1], p[2])
				mu.Lock()
				lat = append(lat, time.Since(s))
				if rec.Code != 200 {
					errs++
				}
				mu.Unlock()
			}
		}(g)
	}
	wg.Wait()
	p50, p95 := pctDur(lat, .5), pctDur(lat, .95)
	t.Logf("PERF-05 %d requests from 24 clients: p50 %v p95 %v, errors %d", len(lat), p50, p95, errs)
	if errs > 0 {
		t.Errorf("PERF-05 %d requests failed", errs)
	}
	if p95 > 3*time.Second {
		t.Errorf("PERF-05 p95 too high: %v", p95)
	}
}

// PERF-06: password checks are deliberately slow (argon2id); a flood of wrong passwords is cut off
// by the lockout before it can keep the CPU busy.
func TestPerfLoginFlood(t *testing.T) {
	f := newFullApp(t)
	f.admin(t)
	c := f.client(t)
	c.remote = "127.0.0.1:41000"
	one := timed(func() { c.do("POST", "/api/auth/login", `{"name":"boss","password":"wrong one"}`) })
	rest := timed(func() {
		for i := 0; i < 60; i++ {
			c.do("POST", "/api/auth/login", `{"name":"boss","password":"wrong one"}`)
		}
	})
	t.Logf("PERF-06 one failed login %v; 60 more (locked out) %v; last status %d", one, rest, c.last.Code)
	if c.last.Code != 429 && c.last.Code != 403 && c.last.Code != 423 {
		t.Errorf("PERF-06 flood not locked out: %d", c.last.Code)
	}
	if rest > 30*one+2*time.Second {
		t.Errorf("PERF-06 locked-out attempts still cost a full hash each: %v for 60 (one %v)", rest, one)
	}
}

// SECD-01: the dashboard API needs a session, takes writes only with the CSRF header, and a view-only
// account can look but not change the layout.
func TestSecDashAccess(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	viewer := f.user(t, boss, "viewer1", "viewer")
	anon := f.client(t)
	body := dashBody(t, `,"range":"15m"`)
	for _, p := range [][3]string{{"POST", "/api/dash/data", body}, {"GET", "/api/dash/vars", ""}, {"GET", "/api/dash/requests?from=0&to=1", ""}, {"GET", "/api/dashboard", ""}, {"PUT", "/api/dashboard", `{"reset":true}`}} {
		if code, _ := anon.do(p[0], p[1], p[2]); code != 401 {
			t.Errorf("SECD-01 anon %s %s: %d", p[0], p[1], code)
		}
	}
	viewer.must(200, "POST", "/api/dash/data", body)
	viewer.must(200, "GET", "/api/dash/vars", "")
	if code, _ := viewer.do("PUT", "/api/dashboard", `{"reset":true}`); code != 403 {
		t.Errorf("SECD-01 viewer changed the layout: %d", code)
	}
	boss.noGM = true
	if code, _ := boss.do("PUT", "/api/dashboard", `{"reset":true}`); code != 403 {
		t.Errorf("SECD-01 write without the CSRF header: %d", code)
	}
	// the pre-login writes too (login CSRF, language, logout)
	anon.noGM = true
	for _, p := range [][2]string{{"/api/auth/login", `{"name":"boss","password":"` + testPW + `"}`}, {"/api/auth/lang", `{"lang":"en"}`}, {"/api/auth/setup", `{}`}, {"/api/auth/logout", ``}} {
		if code, _ := anon.do("POST", p[0], p[1]); code != 403 {
			t.Errorf("SECD-01 %s without the CSRF header: %d", p[0], code)
		}
	}
}

// SECD-02: filter and drill-down values are data, never SQL.
func TestSecDashInjection(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	seedRequests(t, f, 2000, time.Hour)
	now := time.Now().UnixMilli()
	evil := []string{`x' OR '1'='1`, `"); DROP TABLE requests; --`, `%`, `_`, `a.example.com' --`}
	for _, e := range evil {
		js, _ := json.Marshal(e)
		body := dashBody(t, fmt.Sprintf(`,"from":%d,"to":%d,"filters":{"hosts":[%s],"countries":[%s],"vias":[%s]}`, now-3600_000, now, js, js, js))
		boss.must(200, "POST", "/api/dash/data", body)
		q := fmt.Sprintf("/api/dash/requests?from=%d&to=%d&db=1&hosts=%s&cc=%s", now-3600_000, now, urlQ(e), urlQ(e))
		if r := boss.must(200, "GET", q, ""); r["total"].(float64) != 0 {
			t.Errorf("SECD-02 %q matched %v rows", e, r["total"])
		}
	}
	var n int
	if err := f.app.ldb.r.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&n); err != nil || n != 2000 {
		t.Errorf("SECD-02 table changed: %d %v", n, err)
	}
}

func urlQ(s string) string {
	r := strings.NewReplacer("%", "%25", "&", "%26", "#", "%23", "+", "%2B", " ", "%20", "'", "%27", `"`, "%22", ";", "%3B", "=", "%3D")
	return r.Replace(s)
}

// SECD-03: stored layout fields are clamped / whitelisted — no script-ish colors, unknown views, huge
// titles or a thousand panels.
func TestSecDashStoredFields(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	long := strings.Repeat("가", 500)
	w := `[{"type":"health","title":"` + long + `","view":"<img onerror=x>","g":24,"w":6,"h":6,"opts":{"c.up":"javascript:alert(1)","c.down":"#ff0000","size":"xxl","group":"each","evil":"1"}}]`
	r := boss.must(200, "PUT", "/api/dashboard", `{"widgets":`+w+`}`)
	got := r["widgets"].([]any)[0].(map[string]any)
	if len([]rune(got["title"].(string))) > 40 || got["view"] != nil && got["view"] != "" {
		t.Errorf("SECD-03 title/view: %v / %v", len([]rune(got["title"].(string))), got["view"])
	}
	o, _ := got["opts"].(map[string]any)
	if len(o) != 2 || o["c.down"] != "#ff0000" || o["group"] != "each" {
		t.Errorf("SECD-03 opts: %v", o)
	}
	many := make([]string, 41)
	for i := range many {
		many[i] = `{"type":"events","g":24,"w":6,"h":6}`
	}
	if code, _ := boss.do("PUT", "/api/dashboard", `{"widgets":[`+strings.Join(many, ",")+`]}`); code != 400 {
		t.Errorf("SECD-03 41 panels accepted: %d", code)
	}
}

// SECD-04: one request cannot make the server do unbounded work — panel count, filter lists, window
// length and body size are all capped.
func TestSecDashBounds(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	viewer := f.user(t, boss, "viewer2", "viewer")
	seedRequests(t, f, 50000, 7*24*time.Hour)
	now := time.Now().UnixMilli()
	// 2,000 heavy panels (each a 7-day scatter) from a view-only account
	ws := make([]string, 2000)
	for i := range ws {
		ws[i] = fmt.Sprintf(`{"id":"p%d","type":"scatter","g":24,"w":6,"h":6}`, i)
	}
	body := fmt.Sprintf(`{"widgets":[%s],"from":%d,"to":%d,"filters":{"countries":["KR"]}}`, strings.Join(ws, ","), now-7*24*3600_000, now)
	var code int
	var m map[string]any
	d := timed(func() { code, m = viewer.do("POST", "/api/dash/data", body) })
	n := 0
	if data, ok := m["data"].(map[string]any); ok {
		n = len(data)
	}
	t.Logf("SECD-04 2000 panels: %d in %v, answered %d", code, d, n)
	if code != 400 || n > 0 {
		t.Errorf("SECD-04 2000 panels: %d, computed %d (cap 40)", code, n)
	}
	// a filter with 50,000 sites: no SQL error, no unbounded IN list
	hs := make([]string, 50000)
	for i := range hs {
		hs[i] = fmt.Sprintf(`"h%d.example.com"`, i)
	}
	body = dashBody(t, fmt.Sprintf(`,"from":%d,"to":%d,"filters":{"hosts":[%s]}`, now-3600_000, now, strings.Join(hs, ",")))
	d = timed(func() { code, m = viewer.do("POST", "/api/dash/data", body) })
	t.Logf("SECD-04 50k-site filter: %d in %v", code, d)
	if code != 200 && code != 400 {
		t.Errorf("SECD-04 huge filter: %d", code)
	}
	if code == 200 && strings.Contains(viewer.last.Body.String(), "too many SQL variables") {
		t.Error("SECD-04 huge filter reached SQLite")
	}
	// the same cap on the request list
	many := make([]string, 300)
	for i := range many {
		many[i] = fmt.Sprintf("h%d.example.com", i)
	}
	if code, _ := viewer.do("GET", fmt.Sprintf("/api/dash/requests?from=%d&to=%d&hosts=%s", now-3600_000, now, strings.Join(many, ",")), ""); code != 400 {
		t.Errorf("SECD-04 request list with 300 sites: %d", code)
	}
	if code != 400 {
		t.Errorf("SECD-04 dashboard filter with 50k sites: %d", code)
	}
	// windows
	for _, c := range []struct {
		from, to int64
		want    int
	}{{now - 32*24*3600_000, now, 400}, {now, now - 1000, 400}, {now + 3600_000, now + 7200_000, 400}, {-5, now, 400}} {
		code, _ := viewer.do("POST", "/api/dash/data", fmt.Sprintf(`{"widgets":[],"from":%d,"to":%d}`, c.from, c.to))
		if code != c.want {
			t.Errorf("SECD-04 window %d~%d: %d", c.from, c.to, code)
		}
	}
	// body over 2 MB
	big := `{"widgets":[],"filters":{"hosts":["` + strings.Repeat("a", 3<<20) + `"]}}`
	if code, _ := viewer.do("POST", "/api/dash/data", big); code == 200 {
		t.Error("SECD-04 a 3 MB body was accepted")
	}
}

// SECD-05: the web UI never builds HTML from strings (no innerHTML / eval), so request data (hosts,
// paths, user agents) cannot run as script; the CSV export defuses spreadsheet formulas.
func TestSecDashNoHTMLSinks(t *testing.T) {
	sinks := regexp.MustCompile(`\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write\(|\beval\(|new Function\(`)
	files, _ := os.ReadDir("web")
	for _, fe := range files {
		if !strings.HasSuffix(fe.Name(), ".js") {
			continue
		}
		b, err := os.ReadFile("web/" + fe.Name())
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if sinks.MatchString(line) && !strings.Contains(line, "// safe:") {
				t.Errorf("SECD-05 %s:%d: %s", fe.Name(), i+1, strings.TrimSpace(line))
			}
		}
	}
	b, _ := os.ReadFile("web/dashboard.js")
	if !strings.Contains(string(b), "const csvCell") || !strings.Contains(string(b), `/^[=+\-@]/`) {
		t.Error("SECD-05 the panel CSV export lost its formula guard")
	}
}

// SECD-06: security headers on the page and on the API.
func TestSecDashHeaders(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	for _, p := range []string{"/", "/api/state"} {
		rec := boss.raw("GET", p, "")
		hd := rec.Header()
		csp := hd.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src") || strings.Contains(csp, "unsafe-eval") || !strings.Contains(csp, "frame-ancestors 'none'") && hd.Get("X-Frame-Options") == "" {
			t.Errorf("SECD-06 %s CSP: %q", p, csp)
		}
		if hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("SECD-06 %s nosniff missing", p)
		}
		if hd.Get("Referrer-Policy") == "" {
			t.Errorf("SECD-06 %s Referrer-Policy missing", p)
		}
		if strings.Contains(csp, "script-src") && strings.Contains(csp, "'unsafe-inline'") && strings.Contains(strings.Split(csp, "script-src")[1], "'unsafe-inline'") {
			t.Errorf("SECD-06 %s inline scripts allowed: %q", p, csp)
		}
	}
}
