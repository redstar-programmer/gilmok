package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CrowdSec, Cloudflare-integrated:
//
//	Caddy (mTLS sites: access log + gm_real_ip) ─docker logs─▶ CrowdSec (gilmok/caddy-logs parser,
//	http scenarios) ─LAPI /v1/decisions (bouncer key)─▶ Gilmok ─▶ Cloudflare IP list $gilmok_crowdsec
//	◀─ custom rule "ip.src in $gilmok_crowdsec → block" (created in the Cloudflare tab).
//
// Blocking happens at the Cloudflare edge where the real client IP is known; nothing in this
// path trusts the Docker Desktop–rewritten peer address.

// csKeyFromEnv: a key handed in by the deployment (an empty secret file counts as none).
func csKeyFromEnv() string {
	if p := os.Getenv("GM_CROWDSEC_KEY_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			if k := strings.TrimSpace(string(b)); k != "" {
				return k
			}
		}
	}
	return strings.TrimSpace(os.Getenv("GM_CROWDSEC_KEY"))
}

func csKey() string {
	if k := csKeyFromEnv(); k != "" {
		return k
	}
	if csKeyUIPath != "" { // created by Gilmok itself (postCSBouncer)
		if b, err := os.ReadFile(csKeyUIPath); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

type Decision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

var lapiHTTP = &http.Client{Timeout: 15 * time.Second}

// csDecisions returns local decisions (scenarios + manual cscli) — not community blocklists,
// which would overflow Cloudflare's 10k list limit.
func csDecisions(ctx context.Context, st Settings) ([]Decision, error) {
	key := csKey()
	if key == "" {
		return nil, errors.New("CrowdSec 바운서 키가 없습니다 (GM_CROWDSEC_KEY_FILE)")
	}
	base := strings.TrimRight(st.CrowdSecLAPI, "/")
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/decisions?origins=crowdsec,cscli", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("User-Agent", "gilmok-bouncer/"+version)
	res, err := lapiHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CrowdSec LAPI(%s)에 연결하지 못했습니다: %v", base, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("CrowdSec이 바운서 키를 거부했습니다 (BOUNCER_KEY_gilmok 와 같은 값인지 확인)")
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("CrowdSec LAPI HTTP %d", res.StatusCode)
	}
	var ds []Decision // "null" when empty
	if err := json.Unmarshal(b, &ds); err != nil {
		return nil, fmt.Errorf("CrowdSec 응답 해석 실패: %v", err)
	}
	return ds, nil
}

// ---------------------------------------------------------------- sync loop

type CSSyncStatus struct {
	Enabled  bool      `json:"enabled"`
	LastRun  time.Time `json:"lastRun"`
	LastPush time.Time `json:"lastPush"`
	Pushed   int       `json:"pushed"`            // items in the Cloudflare list after the last push
	Pending  int       `json:"pending"`           // ban decisions seen in the last run
	Dropped  int       `json:"dropped,omitempty"` // did not fit Cloudflare's list limit (oldest decisions)
	Error    string    `json:"error,omitempty"`
	hash     string
}

type csState struct {
	mu     sync.Mutex
	status CSSyncStatus
	kick   chan struct{}
}

func (a *App) crowdsecSyncNow() {
	select {
	case a.cs.kick <- struct{}{}:
	default:
	}
}

func (a *App) crowdsecLoop() {
	for {
		st := a.store.Snapshot().Settings
		iv := time.Duration(st.CrowdSecInterval) * time.Second
		if iv < 15*time.Second {
			iv = 60 * time.Second
		}
		a.crowdsecSyncOnce()
		select {
		case <-a.cs.kick:
		case <-time.After(iv):
		}
	}
}

func (a *App) crowdsecSyncOnce() {
	a.csMu.Lock() // loop tick and "지금 동기화" must not PUT the list at the same time
	defer a.csMu.Unlock()
	d := a.store.Snapshot()
	st := d.Settings
	on := st.UseCrowdSec && st.UseCloudflare && st.CrowdSecEnabled && st.CrowdSecSync
	a.cs.mu.Lock()
	a.cs.status.Enabled = on
	a.cs.mu.Unlock()
	if !on || !a.cf.Configured() || csKey() == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	setErr := func(err error) {
		a.cs.mu.Lock()
		a.cs.status.LastRun = time.Now()
		a.cs.status.Error = err.Error()
		a.cs.mu.Unlock()
	}
	ds, err := csDecisions(ctx, st)
	if err != nil {
		setErr(err)
		return
	}
	items, dropped := banItemsN(ds)
	sum := sha256.Sum256([]byte(strings.Join(items, "\n")))
	h := hex.EncodeToString(sum[:])
	a.cs.mu.Lock()
	same := a.cs.status.hash == h && a.cs.status.Error == ""
	a.cs.status.Pending = len(items)
	a.cs.mu.Unlock()
	if same {
		a.cs.mu.Lock()
		a.cs.status.LastRun = time.Now()
		a.cs.mu.Unlock()
		return
	}
	acct, err := a.cf.AccountID(ctx, st.Domain)
	if err != nil {
		setErr(err)
		return
	}
	listID := d.CFWAF.ListID
	if listID == "" {
		l, err := a.cf.FindList(ctx, acct, csListName)
		if err != nil {
			setErr(err)
			return
		}
		if l == nil {
			setErr(errors.New("Cloudflare IP 목록이 없습니다 — Cloudflare 탭 「WAF 규칙」에서 먼저 적용하세요"))
			return
		}
		listID = l.ID
		_ = a.store.Update(func(x *Data) error { x.CFWAF.ListID = l.ID; return nil })
	}
	if err := a.cf.ReplaceListItems(ctx, acct, listID, items, "crowdsec via gilmok"); err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "10001") {
			_ = a.store.Update(func(x *Data) error { x.CFWAF.ListID = ""; return nil })
		}
		setErr(err)
		return
	}
	a.cs.mu.Lock()
	a.cs.status = CSSyncStatus{Enabled: true, LastRun: time.Now(), LastPush: time.Now(), Pushed: len(items), Pending: len(items) + dropped, Dropped: dropped, hash: h}
	if dropped > 0 {
		a.logEvent("security", "warn", "crowdsec.limit", csListName, fmt.Sprintf("차단 IP %d개가 Cloudflare 목록 한도(%d)를 넘어 오래된 것부터 빠졌습니다", dropped, csListMax), nil)
	}
	a.cs.mu.Unlock()
}

// ---------------------------------------------------------------- API

type csMetrics struct {
	Acquisition map[string]map[string]int `json:"acquisition"`
	Alerts      map[string]int            `json:"alerts"`
}

func csReadMetrics(ctr string) (*csMetrics, error) {
	out, err := ctrExec(ctr, nil, "cscli", "metrics", "-o", "json")
	if err != nil {
		return nil, errors.New(oneLine(out))
	}
	var m csMetrics
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return nil, fmt.Errorf("cscli metrics 해석 실패: %v", err)
	}
	return &m, nil
}

func (a *App) getCrowdSec(w http.ResponseWriter, r *http.Request) {
	st := a.store.Snapshot().Settings
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res := map[string]any{"keyConfigured": csKey() != ""}
	c := ctrStatus(st.CrowdSecContainer)
	res["container"] = c
	if ds, err := csDecisions(ctx, st); err != nil {
		res["decisionsError"] = err.Error()
	} else {
		if ds == nil {
			ds = []Decision{}
		}
		res["decisions"] = ds
		res["cloudflareItems"] = len(banItems(ds))
	}
	if c.State == "running" {
		if m, err := csReadMetrics(st.CrowdSecContainer); err == nil {
			res["metrics"] = m
		} else {
			res["metricsError"] = err.Error()
		}
	}
	a.cs.mu.Lock()
	res["sync"] = a.cs.status
	a.cs.mu.Unlock()
	writeJSON(w, 200, res)
}

var reCSReason = regexp.MustCompile(`^[\p{L}\p{N} ._:/-]{0,80}$`)

func (a *App) postCSDecision(w http.ResponseWriter, r *http.Request) {
	var in struct{ IP, Duration, Reason string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	st := a.store.Snapshot().Settings
	in.IP = strings.TrimSpace(in.IP)
	flag := "--ip"
	if strings.Contains(in.IP, "/") {
		if _, _, err := net.ParseCIDR(in.IP); err != nil {
			fail(w, 400, errors.New("IP 또는 CIDR 형식이 올바르지 않습니다"))
			return
		}
		flag = "--range"
	} else if net.ParseIP(in.IP) == nil {
		fail(w, 400, errors.New("IP 또는 CIDR 형식이 올바르지 않습니다"))
		return
	}
	if in.Duration == "" {
		in.Duration = "4h"
	}
	if dd, err := time.ParseDuration(in.Duration); err != nil || dd < time.Minute || dd > 365*24*time.Hour {
		fail(w, 400, errors.New("기간은 1m ~ 8760h 사이로 입력하세요 (예: 4h, 168h)"))
		return
	}
	if in.Reason == "" {
		in.Reason = "manual ban by gilmok" // must pass reCSReason (no parentheses)
	}
	if !reCSReason.MatchString(in.Reason) {
		fail(w, 400, errors.New("사유에는 글자·숫자·공백·._:/- 만 쓸 수 있습니다 (80자 이내)"))
		return
	}
	out, err := ctrExec(st.CrowdSecContainer, nil, "cscli", "decisions", "add", flag, in.IP, "--duration", in.Duration, "--reason", in.Reason)
	if err != nil {
		fail(w, 400, errors.New(oneLine(out)))
		return
	}
	a.crowdsecSyncNow()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) deleteCSDecision(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		fail(w, 400, errors.New("잘못된 id"))
		return
	}
	st := a.store.Snapshot().Settings
	out, err := ctrExec(st.CrowdSecContainer, nil, "cscli", "decisions", "delete", "--id", strconv.FormatInt(id, 10))
	if err != nil {
		fail(w, 400, errors.New(oneLine(out)))
		return
	}
	a.crowdsecSyncNow()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) postCSSync(w http.ResponseWriter, r *http.Request) {
	a.crowdsecSyncOnce()
	a.cs.mu.Lock()
	s := a.cs.status
	a.cs.mu.Unlock()
	writeJSON(w, 200, s)
}

// ---------------------------------------------------------------- connection check

func (a *App) checkCrowdSec(ctx context.Context) CheckResult {
	d := a.store.Snapshot()
	st := d.Settings
	r := CheckResult{Target: "crowdsec"}
	running := containerChecks(&r, st.CrowdSecContainer, "cscli", "version")
	if csKey() == "" {
		r.add("key", "바운서 키", "fail", "길목에 바운서 키가 없습니다 — 「바운서 키 만들기」(길목이 cscli bouncers add로 만들어 저장) 또는 배포 설정의 GM_CROWDSEC_KEY_FILE")
	} else if ds, err := csDecisions(ctx, st); err != nil {
		// just (re)started: the LAPI listens ~30s after the container comes up
		if t, ok := ctrStartedAt(st.CrowdSecContainer); ok && time.Since(t) < 2*time.Minute && strings.Contains(err.Error(), "connection refused") {
			r.add("lapi", "LAPI 연결 (바운서 키)", "warn", fmt.Sprintf("CrowdSec이 %d초 전에 시작되어 아직 준비 중입니다 — 잠시 뒤 「다시 확인」을 누르세요", int(time.Since(t).Seconds())))
		} else {
			msg := err.Error()
			if strings.Contains(msg, "no such host") {
				msg = "LAPI 주소의 컨테이너를 찾을 수 없습니다 — 컨테이너가 없거나 길목과 같은 Docker 네트워크에 있지 않습니다 (" + st.CrowdSecLAPI + ")"
			}
			r.add("lapi", "LAPI 연결 (바운서 키)", "fail", msg)
		}
	} else {
		r.add("lapi", "LAPI 연결 (바운서 키)", "ok", fmt.Sprintf("%s · 현재 차단 %d건", st.CrowdSecLAPI, len(banItems(ds))))
	}
	// the LAPI address names a different container than the CrowdSec container setting
	if u, err := url.Parse(st.CrowdSecLAPI); err == nil && u.Hostname() != "" && net.ParseIP(u.Hostname()) == nil &&
		u.Hostname() != "localhost" && st.CrowdSecContainer != "" && !strings.EqualFold(u.Hostname(), st.CrowdSecContainer) {
		r.add("lapi-match", "LAPI 주소 ↔ 컨테이너", "warn", fmt.Sprintf("LAPI 주소는 %s 를, CrowdSec 컨테이너 설정은 %s 를 가리킵니다 — 같은 컨테이너로 맞추세요 (아래 연결 설정)", u.Hostname(), st.CrowdSecContainer))
	}
	// sites whose access log CrowdSec reads: public + Proxied + mTLS (the real IP can be trusted only there)
	mtlsSites := 0
	for _, s := range d.Services {
		if s.Enabled && !s.DNSOnly && s.Exposure == ExposurePublic && s.Proxied && s.MTLS {
			mtlsSites++
		}
	}
	if running && st.UseCaddy && st.UseCloudflare {
		if out, err := ctrExec(st.CrowdSecContainer, nil, "cscli", "parsers", "list", "-o", "json"); err != nil {
			r.add("parser", "길목 파서 (gilmok/caddy-logs)", "fail", oneLine(out))
		} else if strings.Contains(out, `"gilmok/caddy-logs"`) {
			r.add("parser", "길목 파서 (gilmok/caddy-logs)", "ok", "Cf-Connecting-Ip(실제 IP)로 분석")
		} else {
			r.add("parser", "길목 파서 (gilmok/caddy-logs)", "fail", "parsers/s01-parse/gilmok-caddy-logs.yaml 이 마운트되지 않았습니다")
		}
		if m, err := csReadMetrics(st.CrowdSecContainer); err != nil {
			r.add("acq", "Caddy 로그 수집", "warn", err.Error())
		} else if v, ok := m.Acquisition["docker:"+st.CaddyContainer]; ok {
			r.add("acq", "Caddy 로그 수집", "ok", fmt.Sprintf("읽음 %d줄 · 분석 %d줄", v["reads"], v["parsed"]))
		} else if mtlsSites == 0 || !st.CrowdSecEnabled {
			r.add("acq", "Caddy 로그 수집", "info", "아직 넘길 로그가 없습니다 — 아래 「mTLS 사이트 접근 로그」가 생기면 채워집니다")
		} else if caddyHasRealIPLog(st.CaddyContainer) {
			// Caddy wrote real-IP access lines, yet CrowdSec read none: the acquisition is pointed elsewhere
			r.add("acq", "Caddy 로그 수집", "warn", fmt.Sprintf("Caddy(%s)에는 접근 로그가 있는데 CrowdSec이 읽지 못했습니다 — acquis 설정의 container_name 이 이 컨테이너인지 확인하세요", st.CaddyContainer))
		} else {
			r.add("acq", "Caddy 로그 수집", "info", "아직 들어온 요청이 없습니다 — mTLS 사이트에 요청이 오면 채워집니다 (정상)")
		}
	}
	if !st.UseCaddy || !st.UseCloudflare {
		// the Cloudflare-integrated design (real IP from mTLS sites, edge bans) does not apply
		r.finish()
		return r
	}
	n := 0
	for _, s := range d.Services {
		if s.Enabled && !s.DNSOnly && crowdsecLogging(s, st) {
			n++
		}
	}
	switch {
	case !st.CrowdSecEnabled:
		r.add("logging", "mTLS 사이트 접근 로그", "warn", "꺼져 있습니다 — 아래 설정에서 켜고 적용하세요")
	case n == 0:
		r.add("logging", "mTLS 사이트 접근 로그", "info", "CrowdSec이 분석할 사이트가 아직 없습니다. 길목은 실제 IP를 믿을 수 있는 「공개 · Proxied · mTLS」 서비스의 접근 로그만 넘깁니다 — 그런 서비스를 만들면 자동으로 포함됩니다 (지금 할 일은 없음)")
	default:
		r.add("logging", "mTLS 사이트 접근 로그", "ok", fmt.Sprintf("%d개 사이트 (적용 후 반영)", n))
	}
	a.cs.mu.Lock()
	s := a.cs.status
	a.cs.mu.Unlock()
	switch {
	case !st.CrowdSecSync:
		r.add("sync", "Cloudflare 동기화", "skip", "꺼져 있음")
	// sync problems are warnings: CrowdSec still judges and Gilmok shows it; only the edge block is missing
	case !a.cf.Configured():
		r.add("sync", "Cloudflare 동기화", "warn", "Cloudflare 토큰이 없습니다 — 판정·기록은 되지만 Cloudflare 엣지에서 차단하지는 않습니다")
	case s.Error != "":
		r.add("sync", "Cloudflare 동기화", "warn", s.Error+" — 판정·기록은 되지만 Cloudflare 엣지 차단은 멈춰 있습니다")
	case !s.LastPush.IsZero():
		r.add("sync", "Cloudflare 동기화", "ok", fmt.Sprintf("목록 %d건 · %s", s.Pushed, s.LastPush.Format("01-02 15:04:05")))
	default:
		r.add("sync", "Cloudflare 동기화", "warn", "아직 동기화하지 않았습니다")
	}
	r.finish()
	return r
}

// caddyHasRealIPLog: Caddy's recent output has an access line carrying gm_real_ip (an mTLS site was hit).
func caddyHasRealIPLog(ctr string) bool {
	if ctr == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "logs", "--tail", "2000", ctr)
	return err == nil && strings.Contains(out, "gm_real_ip")
}

// csKeyUIPath: a bouncer key Gilmok created itself (설정 마법사 / 빠른 설정) — used when the
// deployment did not hand one in (GM_CROWDSEC_KEY_FILE / GM_CROWDSEC_KEY). Set in main().
var csKeyUIPath string

// postCSBouncer registers Gilmok as a bouncer in the CrowdSec container (cscli bouncers add) and
// keeps the key in <data>/secrets/crowdsec_key (0600). The key is never returned or logged.
func (a *App) postCSBouncer(w http.ResponseWriter, r *http.Request) {
	if csKeyFromEnv() != "" {
		fail(w, 409, errors.New("바운서 키가 배포 설정(GM_CROWDSEC_KEY_FILE / GM_CROWDSEC_KEY)에 이미 지정되어 있습니다 — 그 값을 고치세요"))
		return
	}
	if csKeyUIPath == "" {
		fail(w, 500, errors.New("데이터 폴더를 알 수 없습니다"))
		return
	}
	d := a.store.Snapshot()
	st := d.Settings
	// a CrowdSec Gilmok installed: put its bouncer "gilmok" back on Gilmok's key (a kept database can
	// hold an older key) instead of adding another bouncer
	if rec := d.Stacks["crowdsec"]; rec != nil && rec.Container == st.CrowdSecContainer && csKey() != "" {
		if err := reRegisterBouncer(rec.Container); err != nil {
			fail(w, 502, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "bouncer": "gilmok"})
		return
	}
	name := "gilmok-" + time.Now().Format("20060102-150405")
	out, err := ctrExec(st.CrowdSecContainer, nil, "cscli", "bouncers", "add", name, "-o", "raw")
	key := strings.TrimSpace(out)
	if err != nil || key == "" || strings.ContainsAny(key, " \n\t") {
		fail(w, 502, fmt.Errorf("%s 에서 바운서를 만들지 못했습니다: %s", st.CrowdSecContainer, oneLine(out)))
		return
	}
	if err := os.MkdirAll(filepath.Dir(csKeyUIPath), 0o700); err != nil {
		fail(w, 500, err)
		return
	}
	if err := os.WriteFile(csKeyUIPath, []byte(key), 0o600); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "bouncer": name})
}
