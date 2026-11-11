package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- Caddy WAF / guard events

var (
	reAccHost   = regexp.MustCompile(`"host":"([^"]*)"`)
	reAccURI    = regexp.MustCompile(`"uri":"((?:[^"\\]|\\.)*)"`)
	reAccStatus = regexp.MustCompile(`"status":(\d+)`)
	reAccGuard  = regexp.MustCompile(`"` + guardHeader + `":\["([a-z]+)"\]`)
	reAccUA     = regexp.MustCompile(`"User-Agent":\["((?:[^"\\]|\\.)*)"\]`)
)

type accLine struct {
	ts         time.Time
	host, path string
}

func jsonUnquote(s string) string {
	var out string
	if json.Unmarshal([]byte(`"`+s+`"`), &out) == nil {
		return out
	}
	return s
}

func uriPath(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}

// parseAccLine reads an access-log line; guard = X-Gilmok-Block category when the guard blocked it.
func parseAccLine(line string) (al accLine, guard, ua, uri string, ok bool) {
	if !strings.Contains(line, `"logger":"http.log.access`) {
		return al, "", "", "", false
	}
	if m := reWafTs.FindStringSubmatch(line); m != nil {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			al.ts = time.Unix(0, int64(f*1e9))
		}
	}
	if m := reAccHost.FindStringSubmatch(line); m != nil {
		al.host = m[1]
	}
	if m := reAccURI.FindStringSubmatch(line); m != nil {
		uri = jsonUnquote(m[1])
		al.path = uriPath(uri)
	}
	if m := reAccGuard.FindStringSubmatch(line); m != nil {
		guard = m[1]
	}
	if m := reAccUA.FindStringSubmatch(line); m != nil {
		ua = jsonUnquote(m[1])
	}
	return al, guard, ua, uri, true
}

func (a *App) getWAFEvents(w http.ResponseWriter, r *http.Request) {
	st := a.store.Snapshot().Settings
	since := r.URL.Query().Get("since")
	if _, err := time.ParseDuration(since); err != nil {
		since = "24h"
	}
	if caddyMode(st) != "docker" {
		fail(w, 400, errors.New("WAF 이벤트는 Caddy가 Docker 컨테이너일 때 컨테이너 로그에서 읽습니다"))
		return
	}
	ctx, cancel := withTimeout(40 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "logs", "--since", since, "--tail", "80000", st.CaddyContainer)
	if err != nil {
		fail(w, 400, fmt.Errorf("Caddy 로그를 읽지 못했습니다: %s", oneLine(out)))
		return
	}
	var events []WAFEvent
	acc := map[string][]accLine{} // path → access lines (to find the host of a WAF event)
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if ev, ok := parseWAFLine(line); ok {
			ev.Kind = "waf"
			if len(ev.RuleID) >= 3 {
				ev.Group = ev.RuleID[:3]
			}
			events = append(events, ev)
			continue
		}
		al, guard, ua, uri, ok := parseAccLine(line)
		if !ok {
			continue
		}
		acc[al.path] = append(acc[al.path], al)
		if guard != "" {
			msg := guardCategoryText[guard]
			if ua != "" && (guard == "bot" || guard == "ai") {
				msg += " · " + ua
			}
			events = append(events, WAFEvent{Time: al.ts, Kind: "guard", Action: "denied", RuleID: guard, Group: "guard", Msg: msg, URI: uri, Host: al.host})
		}
	}
	// host of WAF events: an access line with the same path within 3 s
	for i := range events {
		e := &events[i]
		if e.Kind != "waf" || e.Host != "" {
			continue
		}
		best := 3 * time.Second
		for _, al := range acc[uriPath(e.URI)] {
			d := al.ts.Sub(e.Time)
			if d < 0 {
				d = -d
			}
			if d <= best {
				best, e.Host = d, al.host
			}
		}
	}
	counts := map[string]*WAFRuleCount{}
	groups := map[string]int{}
	hosts := map[string]int{}
	denied, guardN := 0, 0
	for _, ev := range events {
		key := ev.Kind + ":" + ev.RuleID
		c := counts[key]
		if c == nil {
			c = &WAFRuleCount{RuleID: ev.RuleID, Group: ev.Group, Msg: ev.Msg, Hosts: map[string]int{}}
			if ev.Kind == "guard" {
				c.Msg = guardCategoryText[ev.RuleID]
			}
			counts[key] = c
		}
		c.Count++
		if ev.Host != "" {
			c.Hosts[ev.Host]++
			hosts[ev.Host]++
		}
		if ev.Action == "denied" {
			c.Denied++
			denied++
		}
		groups[ev.Group]++
		if ev.Kind == "guard" {
			guardN++
		}
	}
	rules := []WAFRuleCount{}
	for _, c := range counts {
		rules = append(rules, *c)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Count > rules[j].Count })
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 { // newest first
		events[i], events[j] = events[j], events[i]
	}
	if len(events) > 500 {
		events = events[:500]
	}
	gl := []cfCount{}
	for k, v := range groups {
		label := "기본 차단 (봇·경로)"
		for _, g := range wafGroups {
			if g.ID == k {
				label = g.Name
			}
		}
		if k == "949" || k == "959" || k == "980" {
			label = "점수 합계 판정"
		}
		gl = append(gl, cfCount{Key: k, Label: label, Count: v})
	}
	sort.Slice(gl, func(i, j int) bool { return gl[i].Count > gl[j].Count })
	writeJSON(w, 200, map[string]any{"since": since, "events": events, "rules": rules, "denied": denied, "guard": guardN, "groups": gl, "hosts": hosts})
}

// ---------------------------------------------------------------- WAF test

type wafCase struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	UA    string `json:"ua"`
	Guard string `json:"guard"` // guard category that should block it ("" = WAF only)
	WAF   bool   `json:"waf"`   // OWASP CRS should catch it
}

var wafCases = []wafCase{
	{ID: "normal", Name: "정상 요청", Path: "/", UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gilmok-WAF-Test"},
	{ID: "sqli", Name: "SQL 인젝션", Path: "/?id=1%27%20OR%20%271%27=%271", UA: "Mozilla/5.0 Gilmok-WAF-Test", WAF: true},
	{ID: "xss", Name: "XSS", Path: "/?q=%3Cscript%3Ealert(1)%3C/script%3E", UA: "Mozilla/5.0 Gilmok-WAF-Test", WAF: true},
	{ID: "lfi", Name: "경로 탐색 (LFI)", Path: "/?file=../../../../etc/passwd", UA: "Mozilla/5.0 Gilmok-WAF-Test", WAF: true},
	{ID: "rce", Name: "명령 실행 (RCE)", Path: "/?cmd=%3Bcat%20/etc/passwd", UA: "Mozilla/5.0 Gilmok-WAF-Test", WAF: true},
	{ID: "bot", Name: "스캐너 User-Agent", Path: "/", UA: "sqlmap/1.8 (https://sqlmap.org)", Guard: "bot", WAF: true},
	{ID: "ai", Name: "AI 크롤러", Path: "/", UA: "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", Guard: "ai"},
	{ID: "path", Name: "공격 경로 (/.env)", Path: "/.env", UA: "Mozilla/5.0 Gilmok-WAF-Test", Guard: "path"},
}

type wafCaseResult struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Request  string `json:"request"`
	Status   int    `json:"status"`
	By       string `json:"by"`      // guard | waf | "" (passed) | auth (redirect to login)
	Expect   string `json:"expect"`  // block | pass | log (detect mode)
	Verdict  string `json:"verdict"` // ok | fail | info
	Note     string `json:"note"`
	Category string `json:"category,omitempty"`
}

func (a *App) postWAFTest(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	d := a.store.Snapshot()
	st := d.Settings
	if !st.UseCaddy || caddyMode(st) != "docker" {
		fail(w, 400, errors.New("WAF 시험은 Caddy가 Docker 컨테이너일 때만 할 수 있습니다"))
		return
	}
	var svc *Service
	for _, s := range d.Services {
		if s.ID == in.ID {
			svc = s
		}
	}
	if svc == nil || !svc.Enabled || svc.DNSOnly {
		fail(w, 400, errors.New("Caddy 사이트가 있는 켜진 서비스를 고르세요"))
		return
	}
	if st.UseCloudflare && svc.MTLS && svc.Proxied {
		fail(w, 400, errors.New("mTLS 사이트는 Cloudflare 인증서가 있어야 접속되므로 길목에서 직접 시험할 수 없습니다 — Cloudflare 탭 › 엣지 이벤트로 확인하세요"))
		return
	}
	port := caddyHTTPSPort(st.CaddyBase)
	if svc.Exposure == ExposureTailscale {
		port = st.TailscalePort
	}
	host := st.FQDN(svc.Subdomain)
	addr := net.JoinHostPort(st.CaddyContainer, strconv.Itoa(port))
	cl := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			},
			TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true}, // talking to our own Caddy by container name
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	g := guardLists(st, st.GuardBots, st.GuardAI, st.GuardEmptyUA, st.GuardPaths, st.GuardPHP)
	guardOn := func(cat string) bool {
		if !svc.Guard {
			return false
		}
		switch cat {
		case "bot":
			return len(g.bots) > 0 && st.GuardBots
		case "ai":
			return len(g.ai) > 0
		case "path":
			return st.GuardPaths
		}
		return false
	}
	var results []wafCaseResult
	for _, c := range wafCases {
		res := wafCaseResult{ID: c.ID, Name: c.Name, Request: "GET " + c.Path}
		if c.UA != "" && c.ID != "normal" && !strings.Contains(c.UA, "Gilmok-WAF-Test") {
			res.Request += "  (User-Agent: " + c.UA + ")"
		}
		switch {
		case c.Guard != "" && guardOn(c.Guard):
			res.Expect, res.Category = "block", "guard"
		case c.WAF && svc.WAF == WAFBlock:
			res.Expect = "block"
		case c.WAF && svc.WAF == WAFDetect:
			res.Expect = "log"
		default:
			res.Expect = "pass"
		}
		req, _ := http.NewRequestWithContext(r.Context(), "GET", "https://"+host+c.Path, nil)
		req.Header.Set("User-Agent", c.UA)
		resp, err := cl.Do(req)
		if err != nil {
			res.Verdict, res.Note = "fail", "연결 실패: "+oneLine(err.Error())
			results = append(results, res)
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		res.Status = resp.StatusCode
		blocked := resp.StatusCode == http.StatusForbidden
		switch {
		case resp.Header.Get(guardHeader) != "":
			res.By = "guard"
			res.Note = "기본 차단: " + guardCategoryText[resp.Header.Get(guardHeader)]
		case blocked:
			res.By = "waf"
		case resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(strings.ToLower(resp.Header.Get("Location")), "auth"):
			res.By = "auth"
		}
		switch {
		case res.By == "auth":
			res.Verdict, res.Note = "info", "Authelia 로그인으로 이동 — Caddy에서 인증(forward_auth)이 WAF보다 먼저 실행되므로, 로그인하지 않은 요청은 WAF까지 가지 않습니다"
		case res.Expect == "block" && blocked:
			res.Verdict = "ok"
		case res.Expect == "block":
			res.Verdict, res.Note = "fail", "막혀야 하는데 통과했습니다 — 「적용」을 했는지, Caddy 이미지에 Coraza가 있는지 확인하세요"
		case res.Expect == "log" && !blocked:
			res.Verdict, res.Note = "ok", "탐지만 모드 — 통과하고 WAF 이벤트에 기록됩니다"
		case res.Expect == "pass" && blocked && c.ID == "normal":
			res.Verdict, res.Note = "fail", "정상 요청이 막혔습니다 — 오탐입니다. WAF 이벤트에서 걸린 규칙을 확인하세요"
		case res.Expect == "pass" && blocked:
			res.Verdict, res.Note = "info", "설정상 통과 예상이었지만 막혔습니다 (다른 규칙이 잡음)"
		case res.Expect == "pass":
			res.Verdict = "info"
			if res.Note == "" {
				res.Note = "이 서비스 설정에서는 막지 않는 항목입니다"
			}
		default:
			res.Verdict = "info"
		}
		if c.ID == "normal" && !blocked && res.By != "auth" {
			res.Verdict, res.Note = "ok", fmt.Sprintf("HTTP %d — 정상 요청은 통과", resp.StatusCode)
		}
		results = append(results, res)
	}
	writeJSON(w, 200, map[string]any{"host": host, "waf": svc.WAF, "guard": svc.Guard, "results": results})
}

// getWAFMeta: presets and previews for the UI (lists live only here, not duplicated in JS).
func (a *App) getWAFMeta(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	res := map[string]any{
		"groups": wafGroups, "botUAs": guardBotUAs, "aiUAs": guardAIUAs, "paths": guardProbePaths,
		"categories": guardCategoryText, "cases": wafCases, "exprMax": cfExprMax, "actions": cfAsnActions,
		"guardSnippet": guardSnippet(d),
	}
	if e, err := threatExpression(d); err != nil {
		res["threatErr"] = err.Error()
	} else {
		res["threatExpr"], res["threatLen"] = e, len(e)
	}
	if e, err := geoExpression(d); err != nil {
		res["geoErr"] = err.Error()
	} else {
		res["geoExpr"] = e
	}
	writeJSON(w, 200, res)
}
