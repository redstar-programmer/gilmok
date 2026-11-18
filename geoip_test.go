package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
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
