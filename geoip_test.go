package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GEO-01: who sent a request — Cloudflare's headers on Proxied sites, the address Caddy saw
// otherwise, Docker Desktop's gateway as unknown.
func TestGeoClientOf(t *testing.T) {
	line := func(remote, client, cfip, cfcc, real string) string {
		return `{"logger":"http.log.access.log0","ts":1793848114.5,"request":{"remote_ip":"` + remote + `","client_ip":"` + client + `","method":"GET","host":"a.example.com","uri":"/"},"status":200,"duration":0.01,"size":1,"gm_cf_ip":"` + cfip + `","gm_cf_cc":"` + cfcc + `","gm_real_ip":"` + real + `"}`
	}
	for _, c := range []struct {
		name, l, ip, cc, via string
	}{
		{"cloudflare", line("172.18.0.1", "172.18.0.1", "203.0.113.7", "kr", ""), "203.0.113.7", "KR", "cf"},
		{"mtls real ip first", line("172.18.0.1", "172.18.0.1", "203.0.113.7", "JP", "198.51.100.9"), "198.51.100.9", "JP", "cf"},
		{"tor / unknown country dropped", line("172.18.0.1", "172.18.0.1", "203.0.113.7", "T1", ""), "203.0.113.7", "", "cf"},
		{"direct (linux)", line("8.8.8.8", "8.8.8.8", "", "", ""), "8.8.8.8", "", "direct"},
		{"docker desktop gateway", line("172.18.0.1", "172.18.0.1", "", "", ""), "172.18.0.1", "", "hidden"},
		{"tailscale", line("100.101.102.103", "100.101.102.103", "", "", ""), "100.101.102.103", "", "tailnet"},
		{"lan", line("192.168.1.20", "192.168.1.20", "", "", ""), "192.168.1.20", "", "lan"},
		{"forged header is not an ip", line("8.8.4.4", "8.8.4.4", "not-an-ip", "", ""), "8.8.4.4", "", "direct"},
	} {
		r, ok := parseAccessLine(c.l)
		if !ok || r.IP != c.ip || r.CC != c.cc || r.Via != c.via {
			t.Errorf("GEO-01 %s: ok=%v ip=%q cc=%q via=%q", c.name, ok, r.IP, r.CC, r.Via)
		}
	}
	a := &App{}
	if a.geoCountry("8.8.8.8") != "" || a.geoCountry("192.168.1.1") != "" {
		t.Error("GEO-01: no database → no country")
	}
}

// GEO-02: the country block is generated only for public sites Caddy sees directly, only when
// Caddy is ready, never refuses private addresses, and is not imported as a service setting.
func TestGeoCaddySnippet(t *testing.T) {
	d := Data{Settings: defaultSettings()}
	d.Settings.Domain = "example.com"
	d.Settings.UseCaddy, d.Settings.UseCloudflare = true, true
	d.Settings.GeoMode, d.Settings.GeoCountries = "allow", "KR JP"
	d.Services = []*Service{
		{ID: "s1", Subdomain: "plex", Upstream: "plex:32400", Exposure: ExposurePublic, Enabled: true},
		{ID: "s2", Subdomain: "auth", Upstream: "authelia:9091", Exposure: ExposurePublic, Proxied: true, Enabled: true},
		{ID: "s3", Subdomain: "home", Upstream: "home:80", Exposure: ExposureTailscale, Enabled: true},
	}
	if g := GenerateCaddyfile(d); strings.Contains(g, "gm_geo") {
		t.Fatal("GEO-02: snippet generated although Caddy is not ready")
	}
	d.geoDB = "/etc/caddy/geoip/country.mmdb"
	g := GenerateCaddyfile(d)
	for _, want := range []string{"(gm_geo) {", "not client_ip private_ranges 100.64.0.0/10", `db_path "/etc/caddy/geoip/country.mmdb"`, "allow_countries KR JP", "header @gm_geo_block X-Gilmok-Block geo"} {
		if !strings.Contains(g, want) {
			t.Errorf("GEO-02 missing %q", want)
		}
	}
	if i := strings.Index(g, "plex.example.com {"); i < 0 || !strings.Contains(g[i:i+strings.Index(g[i:], "\n}")], "\timport gm_geo\n") {
		t.Error("GEO-02: the DNS only site did not get the country block")
	}
	for _, sub := range []string{"auth.example.com {", "home.example.com:"} {
		i := strings.Index(g, sub)
		if i < 0 {
			t.Fatalf("GEO-02: %s not generated", sub)
		}
		end := strings.Index(g[i:], "\n}")
		if strings.Contains(g[i:i+end], "import gm_geo") {
			t.Errorf("GEO-02: %s must not get the Caddy country block", sub)
		}
	}
	d.Settings.GeoMode = "block"
	if !strings.Contains(GenerateCaddyfile(d), "deny_countries KR JP") {
		t.Error("GEO-02: block mode")
	}
	d.Settings.GeoHosts = []string{"nope"}
	if strings.Contains(GenerateCaddyfile(d), "gm_geo") {
		t.Error("GEO-02: scope without the site still generated the block")
	}
	// import: the generated line is not kept as a user directive
	d.Settings.GeoHosts = nil
	_, got, _, err := ImportCaddyfile(GenerateCaddyfile(d), d.Settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if strings.Contains(s.Extra, "gm_geo") || strings.Contains(s.Extra, "gm_cf_") {
			t.Errorf("GEO-02: generated line leaked into Extra of %s: %q", s.Subdomain, s.Extra)
		}
	}
}

// GEO-03: settings — modes, ISO codes, a country required when on; the request log keeps the
// country, and an older log database gets the new columns.
func TestGeoSettingsAndLogDB(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	st := f.app.store.Snapshot().Settings
	for _, c := range []struct {
		mode, cc string
		code     int
	}{{"allow", "kr jp", 200}, {"block", "", 400}, {"allow", "KOR", 400}, {"maybe", "KR", 400}, {"", "", 200}} {
		s := st
		s.GeoMode, s.GeoCountries = c.mode, c.cc
		if code, _ := boss.do("PUT", "/api/settings", mustJSON(s)); code != c.code {
			t.Errorf("GEO-03 mode=%q cc=%q: %d", c.mode, c.cc, code)
		}
	}
	if f.app.store.Snapshot().Settings.GeoCountries != "" {
		t.Error("GEO-03: last save should have cleared the countries")
	}

	// a log database from before the columns existed
	dir := t.TempDir()
	old, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE requests(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, host TEXT NOT NULL, method TEXT, uri TEXT, status INTEGER, ms REAL, size INTEGER, ip TEXT)`); err != nil {
		t.Fatal(err)
	}
	_, _ = old.Exec(`INSERT INTO requests(ts,host,status,ms,size,ip) VALUES(1,'old',200,1,1,'')`)
	old.Close()
	l, err := openLogDB(filepath.Join(dir, "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.w.Close(); l.r.Close() })
	l.Req(ReqRec{T: 1000, Host: "a", Status: 200, IP: "203.0.113.7", CC: "KR", Via: "cf"})
	waitFlush(t, l, 1)
	rows, err := l.QueryRequests(context.Background(), ReqQuery{Host: "a", Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].CC != "KR" || rows[0].Via != "cf" {
		t.Fatalf("GEO-03 log db: %v %+v", err, rows)
	}
	if rows, err := l.QueryRequests(context.Background(), ReqQuery{Host: "old", Limit: 10}); err != nil || len(rows) != 1 {
		t.Fatalf("GEO-03 old row: %v %+v", err, rows)
	}
	top, err := l.TopRequests(context.Background(), "country", 0, 1<<62, "", 5)
	if err != nil || len(top) != 1 || top[0].Key != "KR" {
		t.Fatalf("GEO-03 top country: %v %+v", err, top)
	}
}

// GEO-04: the world map widget — countries with refusals, how many requests had a usable client
// address (so the widget can explain an empty map), live and from the log database; a Cloudflare
// request without CF-IPCountry still gets a country when the database knows the address.
func TestGeoMapWidget(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	now := time.Now().UnixMilli()
	recs := []ReqRec{
		{T: now - 1000, Host: "a.example.com", Status: 200, IP: "203.0.113.7", CC: "KR", Via: "cf"},
		{T: now - 2000, Host: "a.example.com", Status: 403, IP: "198.51.100.1", CC: "US", Via: "direct"},
		{T: now - 3000, Host: "a.example.com", Status: 200, IP: "198.51.100.1", CC: "US", Via: "direct"},
		{T: now - 4000, Host: "b.example.com", Status: 429, IP: "198.51.100.2", CC: "US", Via: "direct"},
		{T: now - 5000, Host: "b.example.com", Status: 200, IP: "172.18.0.1", Via: "hidden"},
		{T: now - 6000, Host: "b.example.com", Status: 200, IP: "192.168.1.5", Via: "lan"},
	}
	for _, r := range recs {
		f.app.mon.addReq(r)
		f.app.ldb.Req(r)
	}
	check := func(tag string, d map[string]any) {
		t.Helper()
		var got struct {
			Countries []geoRow       `json:"countries"`
			Via       map[string]int `json:"via"`
			Total     int            `json:"total"`
		}
		b, _ := json.Marshal(d)
		_ = json.Unmarshal(b, &got)
		if got.Total != 6 || len(got.Countries) != 2 || got.Countries[0].CC != "US" || got.Countries[0].N != 3 || got.Countries[0].Blocked != 2 || got.Countries[1].CC != "KR" || got.Countries[1].Blocked != 0 {
			t.Errorf("GEO-04 %s countries: %s", tag, b)
		}
		us := got.Countries[0]
		if us.St != [4]int{1, 0, 2, 0} || us.IPs != 2 || len(us.Hosts) != 2 || us.Hosts[0].Host != "a.example.com" || us.Hosts[0].N != 2 {
			t.Errorf("GEO-04 %s details: %+v", tag, us)
		}
		if got.Via["cf"] != 1 || got.Via["direct"] != 3 || got.Via["hidden"] != 1 || got.Via["lan"] != 1 {
			t.Errorf("GEO-04 %s via: %s", tag, b)
		}
	}
	for i := 0; i < 50; i++ { // the live map reads the log database while the ring is younger than the range
		var c int
		_ = f.app.ldb.r.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&c)
		if c == len(recs) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	b, _ := json.Marshal(map[string]any{"widgets": []Widget{{ID: "m", Type: "map"}}, "range": "1h"})
	m := boss.must(200, "POST", "/api/dash/data", string(b))
	check("live", m["data"].(map[string]any)["m"].(map[string]any))
	waitFlush(t, f.app.ldb, int64(len(recs)))
	b, _ = json.Marshal(map[string]any{"widgets": []Widget{{ID: "m", Type: "map"}}, "from": now - 3600_000, "to": now + 1000})
	m = boss.must(200, "POST", "/api/dash/data", string(b))
	d := m["data"].(map[string]any)["m"].(map[string]any)
	if d["history"] != true {
		t.Error("GEO-04: past window did not read the log database")
	}
	check("db", d)

	// the default dashboard has the map
	found := false
	for _, w := range defaultDashboard() {
		found = found || w.Type == "map"
	}
	if !found {
		t.Error("GEO-04: default dashboard without the map")
	}
	// no database → Cloudflare request without a country stays without one, nothing else is touched
	r := ReqRec{IP: "8.8.8.8", Via: "cf"}
	f.app.fillCountry(&r)
	l := ReqRec{IP: "192.168.1.5", Via: "lan"}
	f.app.fillCountry(&l)
	if r.CC != "" || l.CC != "" {
		t.Errorf("GEO-04 fillCountry without db: %+v %+v", r, l)
	}
}

// GEO-05: why client addresses are hidden on this server — Docker Desktop, rootless, Swarm,
// host network, a bridge network with / without IPv6, Caddy outside Docker.
func TestClientIPEnv(t *testing.T) {
	type env struct{ os, sec, mode, swarm, nets, v6 string }
	run := func(e env) ClientIPEnv {
		installFakeDocker(t, func(args []string, _ []byte) (string, error) {
			switch {
			case args[0] == "info":
				return `"` + e.os + `"|` + e.sec, nil
			case args[0] == "inspect":
				return e.mode + "|" + e.swarm + "|" + e.nets, nil
			case args[0] == "network":
				return e.v6, nil
			}
			return "", nil
		})
		return detectClientIPEnv(context.Background(), "caddy")
	}
	nets := `{"proxy":{},"bridge":{}}`
	for _, c := range []struct {
		name string
		e    env
		kind string
		v6   bool
	}{
		{"desktop", env{os: "Docker Desktop", sec: `["name=seccomp"]`}, "desktop", false},
		{"rootless", env{os: "Ubuntu 24.04", sec: `["name=seccomp","name=rootless"]`}, "rootless", false},
		{"host network", env{os: "Ubuntu 24.04", sec: `[]`, mode: "host", nets: `{"host":{}}`}, "hostnet", false},
		{"swarm", env{os: "Ubuntu 24.04", sec: `[]`, mode: "proxy", swarm: "abc", nets: nets}, "ingress", false},
		{"bridge without ipv6", env{os: "Ubuntu 24.04", sec: `[]`, mode: "proxy", nets: nets, v6: "false"}, "bridge", false},
		{"bridge with ipv6", env{os: "Debian GNU/Linux 12", sec: `[]`, mode: "proxy", nets: nets, v6: "true"}, "bridge", true},
	} {
		got := run(c.e)
		if got.Kind != c.kind || got.IPv6 != c.v6 {
			t.Errorf("GEO-05 %s: %+v", c.name, got)
		}
	}
	if got := run(env{os: "Ubuntu", sec: `[]`, mode: "proxy", nets: nets, v6: "false"}); len(got.Networks) != 2 || got.Networks[0] != "bridge" {
		t.Errorf("GEO-05 networks: %+v", got.Networks)
	}

	f := newFullApp(t)
	boss := f.admin(t)
	_ = f.app.store.Update(func(d *Data) error { d.Settings.UseCaddy, d.Settings.CaddyMode = true, "api"; return nil })
	clientEnvMu.Lock()
	clientEnvKey = ""
	clientEnvMu.Unlock()
	if m := boss.must(200, "GET", "/api/client-env", ""); m["kind"] != "outside" {
		t.Errorf("GEO-05 api mode: %v", m)
	}
	_ = f.app.store.Update(func(d *Data) error { d.Settings.UseCaddy = false; return nil })
	if m := boss.must(200, "GET", "/api/client-env", ""); m["kind"] != "none" {
		t.Errorf("GEO-05 no caddy: %v", m)
	}
}
