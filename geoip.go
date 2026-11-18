package main

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// GeoIP: the country of a client IP, from DB-IP's free "IP to Country Lite" database (CC BY 4.0,
// monthly, no key; MaxMind .mmdb format). Gilmok downloads it into <data>/geoip and
//   - looks up the country of requests that did not come through Cloudflare (Proxied sites carry
//     Cf-Ipcountry, no lookup needed),
//   - copies it next to the Caddyfile for the country block of DNS only sites (Caddy module
//     caddy-maxmind-geolocation reads the same file).
// Attribution required by the licence: "IP Geolocation by DB-IP" (shown where countries are shown).

const (
	geoDBName    = "country.mmdb"
	geoMaxAge    = 32 * 24 * time.Hour
	geoURLFormat = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"
	geoModule    = "http.matchers.maxmind_geolocation"
)

var geoHTTP = &http.Client{Timeout: 2 * time.Minute}

type geoState struct {
	mu      sync.RWMutex
	db      *maxminddb.Reader
	built   time.Time // database build time
	fetched time.Time
	err     string
	busy    bool
}

func (a *App) geoPath() string { return filepath.Join(a.dataDir, "geoip", geoDBName) }

// geoOpen loads the file on disk (if any) and swaps it in.
func (a *App) geoOpen() error {
	db, err := maxminddb.Open(a.geoPath())
	if err != nil {
		return err
	}
	fi, _ := os.Stat(a.geoPath())
	a.geo.mu.Lock()
	old := a.geo.db
	a.geo.db = db
	a.geo.built = time.Unix(int64(db.Metadata.BuildEpoch), 0)
	if fi != nil {
		a.geo.fetched = fi.ModTime()
	}
	a.geo.mu.Unlock()
	if old != nil {
		go func() { time.Sleep(time.Minute); old.Close() }() // lookups in flight finish first
	}
	return nil
}

// geoCountry: ISO code ("KR") of a public IP; "" when unknown, private, or no database.
func (a *App) geoCountry(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil || !globalIP(addr) {
		return ""
	}
	a.geo.mu.RLock()
	db := a.geo.db
	a.geo.mu.RUnlock()
	if db == nil {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if db.Lookup(addr, &rec) != nil {
		return ""
	}
	return strings.ToUpper(rec.Country.ISOCode)
}

// globalIP: a globally routable address (not LAN, loopback, CGNAT / Tailscale, link-local …).
// fillCountry: the country of a public client address from the GeoIP database — for direct
// requests, and for Cloudflare ones when the zone does not send CF-IPCountry (IP Geolocation off).
func (a *App) fillCountry(r *ReqRec) {
	if r.CC == "" && (r.Via == "direct" || r.Via == "cf") {
		r.CC = a.geoCountry(r.IP)
	}
}

func globalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10
		return false
	}
	return true
}

// geoFetch downloads this month's database (the previous month's early in a month), checks it
// opens, and replaces the file atomically.
func (a *App) geoFetch(ctx context.Context) error {
	a.geo.mu.Lock()
	if a.geo.busy {
		a.geo.mu.Unlock()
		return errors.New("이미 받는 중입니다")
	}
	a.geo.busy = true
	a.geo.mu.Unlock()
	defer func() { a.geo.mu.Lock(); a.geo.busy = false; a.geo.mu.Unlock() }()

	dir := filepath.Dir(a.geoPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	now := time.Now().UTC()
	var last error
	for _, m := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf(geoURLFormat, m.Format("2006-01"))
		if err := a.geoDownload(ctx, url, dir); err != nil {
			last = err
			continue
		}
		if err := a.geoOpen(); err != nil {
			return err
		}
		a.geo.mu.Lock()
		a.geo.err = ""
		a.geo.mu.Unlock()
		a.logEvent("system", "info", "geoip.update", "DB-IP", fmt.Sprintf("GeoIP 국가 DB를 받았습니다 (%s)", m.Format("2006-01")), nil)
		a.syncGeoToCaddy()
		return nil
	}
	return last
}

func (a *App) geoDownload(ctx context.Context, url, dir string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "gilmok/"+version)
	resp, err := geoHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", path.Base(url), resp.StatusCode)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".country-*.mmdb")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, io.LimitReader(zr, 200<<20)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	db, err := maxminddb.Open(tmp.Name()) // must be a valid database before it replaces the old one
	if err != nil {
		return fmt.Errorf("받은 파일이 GeoIP DB가 아닙니다: %v", err)
	}
	db.Close()
	return os.Rename(tmp.Name(), a.geoPath())
}

// geoipLoop: load what is on disk, fetch when missing or older than a month; check daily.
func (a *App) geoipLoop() {
	_ = a.geoOpen()
	a.syncGeoToCaddy()
	for {
		if !a.store.Snapshot().Settings.GeoIPOff {
			a.geo.mu.RLock()
			stale := a.geo.db == nil || time.Since(a.geo.fetched) > geoMaxAge
			a.geo.mu.RUnlock()
			if stale {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				if err := a.geoFetch(ctx); err != nil {
					a.geo.mu.Lock()
					a.geo.err = err.Error()
					a.geo.mu.Unlock()
					a.logEvent("system", "warn", "geoip.fail", "DB-IP", fmt.Sprintf("GeoIP 국가 DB를 받지 못했습니다: %s", oneLine(err.Error())), nil)
					cancel()
					time.Sleep(6 * time.Hour)
					continue
				}
				cancel()
			}
		}
		time.Sleep(24 * time.Hour)
	}
}

// ---------------------------------------------------------------- Caddy side (country block)

// geoCaddyPaths: where the database goes for Caddy — Gilmok's side and the path Caddy sees.
// ok=false when Gilmok cannot place a file Caddy reads (admin API mode: different machines).
func (a *App) geoCaddyPaths(d Data) (local, inCaddy string, ok bool) {
	st := d.Settings
	if rec := d.Stacks["caddy"]; rec != nil && rec.Container == st.CaddyContainer && caddyMode(st) == "docker" {
		return filepath.Join(rec.Dir, "conf", "geoip", geoDBName), "/etc/caddy/geoip/" + geoDBName, true
	}
	switch caddyMode(st) {
	case "docker":
		if st.CaddyfilePath == "" || st.CaddyfileInCtr == "" {
			return "", "", false
		}
		return filepath.Join(filepath.Dir(st.CaddyfilePath), "geoip", geoDBName), path.Join(path.Dir(st.CaddyfileInCtr), "geoip", geoDBName), true
	case "native":
		p := filepath.Join(filepath.Dir(st.CaddyfilePath), "geoip", geoDBName)
		return p, filepath.ToSlash(p), true
	}
	return "", "", false
}

// syncGeoToCaddy copies the database next to the Caddyfile while the country block is on.
func (a *App) syncGeoToCaddy() {
	d := a.store.Snapshot()
	if d.Settings.GeoMode == "" || !d.Settings.UseCaddy {
		return
	}
	local, _, ok := a.geoCaddyPaths(d)
	if !ok {
		return
	}
	si, err := os.Stat(a.geoPath())
	if err != nil {
		return
	}
	if fi, err := os.Stat(local); err == nil && fi.Size() == si.Size() && !si.ModTime().After(fi.ModTime()) {
		return // the same database is already there
	}
	src, err := os.ReadFile(a.geoPath())
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return
	}
	tmp := local + ".tmp"
	if os.WriteFile(tmp, src, 0o644) == nil {
		_ = os.Rename(tmp, local) // a new inode: Caddy opens the file again on its next load
	}
}

// geoCaddyReady: Caddy can do the country block — the module is in its image and it sees the
// database. reason says what is missing. Cached for a minute.
var geoReadyCache struct {
	sync.Mutex
	at     time.Time
	key    string
	path   string
	reason string
}

func (a *App) geoCaddyReady(d Data) (inCaddy, reason string) {
	st := d.Settings
	local, inCaddy, ok := a.geoCaddyPaths(d)
	if !ok {
		return "", "Caddy 관리 API 연결 방식에서는 길목이 Caddy에 GeoIP DB를 둘 수 없습니다"
	}
	key := caddyMode(st) + "|" + st.CaddyContainer + "|" + inCaddy
	geoReadyCache.Lock()
	if geoReadyCache.key == key && time.Since(geoReadyCache.at) < time.Minute {
		p, r := geoReadyCache.path, geoReadyCache.reason
		geoReadyCache.Unlock()
		return p, r
	}
	geoReadyCache.Unlock()
	reason = ""
	if _, err := os.Stat(local); err != nil {
		reason = "GeoIP DB가 아직 없습니다 (받는 중이거나 실패 — Caddy 탭 › 보호 › 국가 차단에서 확인)"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		switch caddyMode(st) {
		case "docker":
			out, err := docker(ctx, nil, nil, "exec", st.CaddyContainer, "caddy", "list-modules")
			switch {
			case err != nil:
				reason = fmt.Sprintf("Caddy 컨테이너에 접속하지 못했습니다: %s", oneLine(out))
			case !strings.Contains(out, geoModule):
				reason = "Caddy 이미지에 GeoIP 모듈(caddy-maxmind-geolocation)이 없습니다"
			default:
				if _, err := docker(ctx, nil, nil, "exec", st.CaddyContainer, "test", "-r", inCaddy); err != nil {
					reason = fmt.Sprintf("Caddy 컨테이너가 %s 를 보지 못합니다 — Caddyfile만 파일 하나로 마운트했다면 폴더째 마운트하세요", inCaddy)
				}
			}
		case "native":
			out, err := localCaddy(st, "list-modules")
			if err != nil || !strings.Contains(out, geoModule) {
				reason = "Caddy 실행 파일에 GeoIP 모듈(caddy-maxmind-geolocation)이 없습니다"
			}
		}
	}
	p := inCaddy
	if reason != "" {
		p = ""
	}
	geoReadyCache.Lock()
	geoReadyCache.at, geoReadyCache.key, geoReadyCache.path, geoReadyCache.reason = time.Now(), key, p, reason
	geoReadyCache.Unlock()
	return p, reason
}

// ---------------------------------------------------------------- API

// GET /api/geoip — database state (and the Caddy side when the country block is on).
func (a *App) getGeoIP(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	a.geo.mu.RLock()
	out := map[string]any{"loaded": a.geo.db != nil, "error": a.geo.err, "busy": a.geo.busy, "off": d.Settings.GeoIPOff,
		"source": "DB-IP IP to Country Lite", "attribution": "IP Geolocation by DB-IP", "attributionUrl": "https://db-ip.com"}
	if a.geo.db != nil {
		out["built"] = a.geo.built.UnixMilli()
		out["fetched"] = a.geo.fetched.UnixMilli()
	}
	a.geo.mu.RUnlock()
	if d.Settings.GeoMode != "" && d.Settings.UseCaddy {
		a.syncGeoToCaddy()
		p, reason := a.geoCaddyReady(d)
		out["caddy"] = map[string]any{"ready": p != "", "path": p, "reason": reason}
	}
	if ip := r.URL.Query().Get("ip"); ip != "" {
		out["lookup"] = map[string]string{"ip": ip, "cc": a.geoCountry(ip)}
	}
	writeJSON(w, 200, out)
}

// POST /api/geoip/update — fetch the database now.
func (a *App) postGeoIPUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := a.geoFetch(ctx); err != nil {
		a.geo.mu.Lock()
		a.geo.err = err.Error()
		a.geo.mu.Unlock()
		fail(w, 502, fmt.Errorf("GeoIP DB를 받지 못했습니다: %v", err))
		return
	}
	geoReadyCache.Lock()
	geoReadyCache.key = ""
	geoReadyCache.Unlock()
	a.getGeoIP(w, r)
}

// ---------------------------------------------------------------- Caddyfile (country block)

const snippetGeo = "gm_geo"

// geoTarget: a site the Caddy country block applies to — public, seen by Caddy directly (Proxied
// sites behind Cloudflare use the Cloudflare rule: Caddy would see Cloudflare's address), in scope.
func geoTarget(d Data, s *Service) bool {
	st := d.Settings
	if st.GeoMode == "" || !s.Enabled || s.DNSOnly || s.Exposure != ExposurePublic || (s.Proxied && st.UseCloudflare) {
		return false
	}
	if len(st.GeoHosts) == 0 {
		return true
	}
	for _, id := range st.GeoHosts {
		if id == s.ID {
			return true
		}
	}
	return false
}

// geoActive: the snippet is generated (some site needs it and Caddy can do it).
func geoActive(d Data) bool {
	if d.geoDB == "" || d.Settings.GeoMode == "" {
		return false
	}
	for _, s := range d.Services {
		if geoTarget(d, s) {
			return true
		}
	}
	return false
}

// geoSnippet: refuse (403, X-Gilmok-Block: geo) clients whose country is not allowed. Private
// addresses (LAN, Tailscale 100.64/10, Docker's gateway) have no country and are never refused —
// so where Caddy cannot see real client IPs (Docker Desktop) the block lets everything through
// instead of locking everyone out.
func geoSnippet(d Data) string {
	if !geoActive(d) {
		return ""
	}
	cc, _ := parseCountries(d.Settings.GeoCountries)
	list := "allow_countries " + strings.Join(cc, " ")
	if d.Settings.GeoMode == "block" {
		list = "deny_countries " + strings.Join(cc, " ")
	}
	return "(" + snippetGeo + ") {\n" +
		"\t@gm_geo_block {\n" +
		"\t\tnot client_ip private_ranges 100.64.0.0/10\n" +
		"\t\tnot maxmind_geolocation {\n" +
		"\t\t\tdb_path \"" + d.geoDB + "\"\n" +
		"\t\t\t" + list + "\n" +
		"\t\t}\n" +
		"\t}\n" +
		"\troute {\n" +
		"\t\theader @gm_geo_block " + guardHeader + " geo\n" +
		"\t\trespond @gm_geo_block 403\n" +
		"\t}\n}\n"
}

// geoHeldText: why the country block is not in the generated Caddyfile ("" = it is, or it is off).
func geoHeldText(d Data, reason string) string {
	if d.Settings.GeoMode == "" || d.geoDB != "" {
		return ""
	}
	n := 0
	for _, s := range d.Services {
		if geoTarget(d, s) {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("국가 차단(Caddy) 대기 — 사이트 %d개: %s", n, reason)
}

// geoHeld: the plan's note when the country block is on but Caddy cannot do it yet.
func (a *App) geoHeld(gen Data) string {
	if gen.Settings.GeoMode == "" || gen.geoDB != "" || !gen.Settings.UseCaddy {
		return ""
	}
	_, reason := a.geoCaddyReady(gen)
	return geoHeldText(gen, reason)
}
