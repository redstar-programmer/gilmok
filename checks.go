package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Per-component connection checks shown as step 1 of the Caddy / Authelia / Cloudflare tabs.

type Check struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"` // ok | warn | fail | skip
	Detail string `json:"detail,omitempty"`
}

type CheckResult struct {
	Target    string         `json:"target"`
	Container *CtrStatus     `json:"container,omitempty"`
	Compose   *ComposeTarget `json:"compose,omitempty"`
	Checks    []Check        `json:"checks"`
	Status    string         `json:"status"` // worst of Checks
	Checked   time.Time      `json:"checked"`
}

func (r *CheckResult) add(id, label, status, detail string) {
	r.Checks = append(r.Checks, Check{id, label, status, detail})
}

func (r *CheckResult) finish() {
	rank := map[string]int{"skip": 0, "info": 0, "ok": 1, "warn": 2, "fail": 3} // info: nothing to do
	r.Status = "ok"
	for _, c := range r.Checks {
		if rank[c.Status] > rank[r.Status] {
			r.Status = c.Status
		}
	}
	r.Checked = time.Now()
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// containerChecks fills the container status + version; returns false if the container is not running.
func containerChecks(r *CheckResult, name string, versionCmd ...string) bool {
	c := ctrStatus(name)
	r.Container = &c
	switch {
	case name == "":
		r.add("ctr", "컨테이너", "fail", "컨테이너 이름이 비어 있습니다")
		return false
	case !c.Exists:
		r.add("ctr", "컨테이너", "fail", name+" 컨테이너를 찾을 수 없습니다 (이름·docker.sock 마운트 확인)")
		return false
	case c.State != "running":
		r.add("ctr", "컨테이너", "fail", fmt.Sprintf("%s 상태: %s", name, c.State))
		return false
	}
	if v, err := ctrExec(name, nil, versionCmd...); err == nil {
		v = strings.TrimSpace(strings.TrimPrefix(v, "authelia version "))
		v = strings.TrimSpace(strings.TrimPrefix(v, "version:")) // cscli version
		c.Version = strings.Fields(v + " ")[0]
		r.Container = &c
	}
	r.add("ctr", "컨테이너", "ok", fmt.Sprintf("%s 실행 중 · %s", name, c.Image))
	return true
}

// sameFile compares what this app reads locally with what the target container sees.
func sameFile(r *CheckResult, id, label, ctr, local, inCtr string, localData []byte) {
	out, err := ctrExec(ctr, nil, "cat", inCtr)
	switch {
	case err != nil:
		r.add(id, label, "warn", "컨테이너 안에서 파일을 읽지 못해 비교하지 못했습니다: "+oneLine(out))
	case strings.TrimSpace(out) == strings.TrimSpace(string(localData)):
		r.add(id, label, "ok", fmt.Sprintf("%s ↔ %s:%s 내용 일치", local, ctr, inCtr))
	default:
		r.add(id, label, "fail", fmt.Sprintf("앱이 보는 %s 와 컨테이너의 %s 내용이 다릅니다 — 마운트 경로를 확인하세요", local, inCtr))
	}
}

// composeChecks: can the update button work? (compose labels → mounted folder → `compose config -q`)
func composeChecks(r *CheckResult, ctr, manualDir, manualSvc string, env []string) {
	t, err := resolveCompose(ctr, manualDir, manualSvc)
	if t.Project != "" || t.DaemonDir != "" {
		r.Compose = &t
	}
	if err != nil {
		r.add("compose", "업데이트 준비 (compose)", "warn", err.Error())
		return
	}
	if err := composeCheck(t, env); err != nil {
		r.add("compose", "업데이트 준비 (compose)", "warn", err.Error())
		return
	}
	r.add("compose", "업데이트 준비 (compose)", "ok", fmt.Sprintf("%s / %s · %s", t.Project, t.Service, t.HostDir))
}

// caddyEnvToken: the Cloudflare token in the Caddy container's environment ("" if none). The value
// is only compared or stored — never returned to the UI or logged.
func caddyEnvToken(ctr string) string {
	if ctr == "" {
		return ""
	}
	ctx, cancel := withTimeout(10 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", ctr)
	if err != nil {
		return ""
	}
	cur := ""
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		for _, k := range []string{"CLOUDFLARE_API_TOKEN=", "CF_API_TOKEN="} {
			if v, ok := strings.CutPrefix(l, k); ok && v != "" && cur == "" {
				cur = v
			}
		}
	}
	return cur
}

// tokenCheck compares (never prints) the running Caddy's CLOUDFLARE_API_TOKEN with ours.
func tokenCheck(r *CheckResult, ctr string) {
	cur := caddyEnvToken(ctr)
	mine := cfToken()
	switch {
	case cur == "":
		return // this Caddy does not use a Cloudflare token
	case mine == "":
		r.add("cftoken", "Cloudflare 토큰 (업데이트용)", "warn", "길목에 토큰이 없습니다 — compose 파일이 ${CLOUDFLARE_API_TOKEN}을 쓰면 Caddy 업데이트를 막습니다 (.env 값으로 재생성 방지)")
	case mine == cur:
		r.add("cftoken", "Cloudflare 토큰 (업데이트용)", "ok", "실행 중인 Caddy와 같은 토큰")
	default:
		r.add("cftoken", "Cloudflare 토큰 (업데이트용)", "warn", "실행 중인 Caddy의 토큰과 다릅니다 — 업데이트하면 길목의 토큰으로 바뀝니다")
	}
}

func (a *App) checkCaddy() CheckResult {
	st := a.store.Snapshot().Settings
	r := CheckResult{Target: "caddy"}
	docker := caddyMode(st) == "docker"
	var running bool
	if docker {
		running = containerChecks(&r, st.CaddyContainer, "caddy", "version")
	} else {
		running = caddyConnChecks(&r, st)
	}

	b, err := os.ReadFile(st.CaddyfilePath)
	if err != nil {
		r.add("file", "Caddyfile 읽기", "fail", err.Error())
	} else {
		r.add("file", "Caddyfile 읽기", "ok", fmt.Sprintf("%s (%d줄)", st.CaddyfilePath, strings.Count(string(b), "\n")+1))
		if f, err := os.OpenFile(st.CaddyfilePath, os.O_WRONLY, 0); err != nil {
			r.add("write", "Caddyfile 쓰기 권한", "fail", err.Error())
		} else {
			f.Close()
			r.add("write", "Caddyfile 쓰기 권한", "ok", "")
		}
	}
	if running && err == nil {
		if docker {
			sameFile(&r, "mount", "마운트 일치", st.CaddyContainer, st.CaddyfilePath, st.CaddyfileInCtr, b)
		}
		if err := validateCaddy(st, string(b)); err != nil {
			r.add("valid", "현재 Caddyfile 검증", "fail", oneLine(err.Error()))
		} else {
			r.add("valid", "현재 Caddyfile 검증", "ok", "")
		}
	} else {
		r.add("mount", "마운트 일치", "skip", "컨테이너 또는 파일을 먼저 확인하세요")
	}
	if running {
		wafUsers := 0
		for _, s := range a.store.Snapshot().Services {
			if s.Enabled && !s.DNSOnly && s.WAF != WAFOff {
				wafUsers++
			}
		}
		switch has, err := caddyHasWAFMode(st); {
		case err != nil:
			r.add("waf", "WAF 모듈 (Coraza)", "warn", oneLine(err.Error()))
		case has:
			r.add("waf", "WAF 모듈 (Coraza)", "ok", fmt.Sprintf("http.handlers.waf · WAF 사용 서비스 %d개", wafUsers))
		case wafUsers > 0:
			r.add("waf", "WAF 모듈 (Coraza)", "fail", fmt.Sprintf("WAF를 켠 서비스가 %d개인데 이 Caddy 이미지에는 Coraza가 없습니다 — deploy/caddy/Dockerfile 로 다시 빌드하세요", wafUsers))
		default:
			r.add("waf", "WAF 모듈 (Coraza)", "skip", "이 Caddy 이미지에는 Coraza가 없습니다 (WAF를 쓰려면 deploy/caddy/Dockerfile)")
		}
		// Proxied sites: Cloudflare answers HTTP-01 / TLS-ALPN itself, so only the DNS challenge (or
		// certificate files) can get their certificates — otherwise every Proxied site fails with 525
		if st.UseCloudflare && err == nil {
			proxied := 0
			for _, s := range a.store.Snapshot().Services {
				if s.Enabled && !s.DNSOnly && s.Exposure == ExposurePublic && s.Proxied {
					proxied++
				}
			}
			if proxied > 0 && !reCertConfigured.MatchString(string(b)) {
				r.add("acme", "인증서 발급 방식", "fail", fmt.Sprintf("Proxied 사이트 %d개의 인증서를 받을 수 없습니다 — Cloudflare를 거치면 HTTP 인증이 막혀 525가 납니다. Caddy 탭 › 전역 설정 › 기본 골격의 전역 옵션에 acme_dns cloudflare {env.CLOUDFLARE_API_TOKEN} 를 넣고 적용하세요 (Caddy 컨테이너에 CLOUDFLARE_API_TOKEN 필요)", proxied))
			} else if proxied > 0 {
				r.add("acme", "인증서 발급 방식", "ok", "DNS 인증 또는 인증서 파일")
			}
		}
		if docker {
			if st.UseCloudflare {
				tokenCheck(&r, st.CaddyContainer)
			}
			composeChecks(&r, st.CaddyContainer, st.CaddyStackDir, st.CaddyService, caddyComposeEnv())
		} else {
			r.add("compose", "이미지 업데이트", "skip", "Docker가 아닌 Caddy는 길목에서 업데이트하지 않습니다 (caddy upgrade 또는 설치 프로그램 사용)")
		}
	}
	r.finish()
	return r
}

func (a *App) checkAuthelia() CheckResult {
	st := a.store.Snapshot().Settings
	r := CheckResult{Target: "authelia"}
	running := containerChecks(&r, st.AutheliaCtr, "authelia", "--version")
	// Caddy reaches Authelia by container name (forward_auth / the portal site): only on a shared network
	if running && st.UseCaddy && caddyMode(st) == "docker" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cn, an := ctrNetworks(ctx, st.CaddyContainer), ctrNetworks(ctx, st.AutheliaCtr)
		cancel()
		shared := ""
		for _, n := range an {
			for _, m := range cn {
				if n == m && shared == "" {
					shared = n
				}
			}
		}
		switch {
		case len(cn) == 0:
			// Caddy not running / not found: the Caddy check says so
		case shared != "":
			r.add("net", "Caddy ↔ Authelia 네트워크", "ok", shared)
		default:
			r.add("net", "Caddy ↔ Authelia 네트워크", "fail", fmt.Sprintf("Caddy(%s: %s)와 Authelia(%s: %s)가 다른 Docker 네트워크에 있어 Caddy가 Authelia를 찾지 못합니다 (502). 예: docker network connect %s %s — 다시 만들어져도 유지하려면 Authelia compose의 네트워크를 %s 로", st.CaddyContainer, strings.Join(cn, ", "), st.AutheliaCtr, strings.Join(an, ", "), cn[0], st.AutheliaCtr, cn[0]))
		}
	}

	cfg, err := os.ReadFile(st.AutheliaConfig)
	if err != nil {
		r.add("config", "configuration.yml 읽기", "fail", err.Error())
	} else {
		r.add("config", "configuration.yml 읽기", "ok", st.AutheliaConfig)
		if _, _, ok := topLevelBlock(strings.Split(string(cfg), "\n"), "access_control"); ok {
			r.add("ac", "access_control 블록", "ok", "이 블록만 앱이 다시 씁니다")
		} else {
			r.add("ac", "access_control 블록", "warn", "블록이 없습니다 — 적용 시 파일 끝에 추가됩니다")
		}
		// the candidate file used for validation is written next to the config
		probe := filepath.Join(filepath.Dir(st.AutheliaConfig), ".gilmok-probe")
		if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
			r.add("write", "config 폴더 쓰기 권한", "fail", err.Error())
		} else {
			os.Remove(probe)
			r.add("write", "config 폴더 쓰기 권한", "ok", "")
		}
	}
	if users, err := LoadUsers(st.AutheliaUsers); err != nil {
		r.add("users", "users_database.yml", "fail", err.Error())
	} else if len(users) == 0 {
		r.add("users", "users_database.yml", "warn", "사용자가 없습니다")
	} else {
		r.add("users", "users_database.yml", "ok", fmt.Sprintf("사용자 %d명", len(users)))
	}
	if running && err == nil {
		inCtr := strings.TrimRight(st.AutheliaCtrDir, "/") + "/" + filepath.Base(st.AutheliaConfig)
		sameFile(&r, "mount", "마운트 일치", st.AutheliaCtr, st.AutheliaConfig, inCtr, cfg)
	} else {
		r.add("mount", "마운트 일치", "skip", "컨테이너 또는 파일을 먼저 확인하세요")
	}
	if running {
		composeChecks(&r, st.AutheliaCtr, st.AutheliaStackDir, st.AutheliaService, nil)
	}
	r.finish()
	return r
}

func (a *App) checkCloudflare(ctx context.Context) CheckResult {
	d := a.store.Snapshot()
	st := d.Settings
	r := CheckResult{Target: "cloudflare"}
	tok, src := cfTokenSource()
	switch {
	case tok == "":
		r.add("token", "API 토큰", "fail", "토큰이 없습니다 — 아래 「API 토큰」 칸에 Cloudflare에서 만든 토큰을 붙여넣으세요 (만드는 방법도 그 위에 있습니다)")
		r.add("zone", "존 조회", "skip", "토큰을 넣은 뒤 확인합니다")
	case st.Domain == "":
		r.add("token", "API 토큰", "ok", "있음 · "+cfSourceText[src])
		r.add("zone", "존 조회", "fail", "도메인이 비어 있습니다 — 「도메인」 단계에서 도메인(예: example.com)을 넣으세요")
	default:
		if id, err := verifyCFToken(ctx, tok, st.Domain); err != nil {
			r.add("token", "API 토큰", "fail", err.Error()+" (출처: "+cfSourceText[src]+")")
			r.add("zone", "존 조회", "skip", "")
		} else {
			r.add("token", "API 토큰", "ok", "유효 · "+cfSourceText[src])
			r.add("zone", "존 조회", "ok", st.Domain+" · "+id)
			if recs, err := a.cf.Records(ctx, st.Domain); err != nil {
				r.add("dns", "DNS 레코드 읽기", "fail", err.Error())
			} else {
				r.add("dns", "DNS 레코드 읽기", "ok", fmt.Sprintf("%d개", len(recs)))
			}
		}
	}
	if ip, err := PublicIP(ctx); err != nil {
		r.add("ip", "공인 IP 확인", "warn", err.Error())
	} else {
		r.add("ip", "공인 IP 확인", "ok", ip)
	}
	if st.DDNSIPv6 {
		if ip6, err := PublicIP6(ctx); err != nil {
			r.add("ip6", "공인 IPv6 확인", "warn", err.Error()+" — AAAA 레코드는 만들거나 고치지 않습니다")
		} else {
			r.add("ip6", "공인 IPv6 확인", "ok", ip6)
		}
	}
	hasPriv := false
	for _, s := range a.store.Snapshot().Services {
		if s.Enabled && s.Exposure == ExposureTailscale {
			hasPriv = true
		}
	}
	label := "Tailscale IP"
	if !st.UseTailscale {
		label = "사설 서비스 IP"
	}
	switch {
	case !st.UseTailscale && !hasPriv:
		// no private sites: nothing to point at
	case st.TailscaleIP == "":
		r.add("ts", label, "warn", "사설 전용 서비스의 DNS 값이 비어 있습니다")
	default:
		r.add("ts", label, "ok", st.TailscaleIP)
	}
	r.finish()
	return r
}

func (a *App) getCheck(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("target") {
	case "caddy":
		writeJSON(w, 200, a.checkCaddy())
	case "authelia":
		writeJSON(w, 200, a.checkAuthelia())
	case "cloudflare":
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		writeJSON(w, 200, a.checkCloudflare(ctx))
	case "crowdsec":
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		writeJSON(w, 200, a.checkCrowdSec(ctx))
	default:
		fail(w, 404, errors.New("알 수 없는 대상"))
	}
}

// postValidate validates the candidate that the next apply would write — without writing anything.
func (a *App) postValidate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Target string }
	_ = readJSON(r, &in)
	d := a.store.Snapshot()
	st := d.Settings
	L := &logger{}
	var err error
	switch in.Target {
	case "caddy":
		if strings.TrimSpace(st.CaddyBase) == "" {
			err = errors.New("Caddy 기본 골격이 비어 있습니다")
			break
		}
		L.f("▶ 생성될 Caddyfile을 검증 (%s)", map[string]string{"docker": st.CaddyContainer + " 컨테이너 안에서", "native": "로컬 caddy 실행 파일로", "api": "Caddy 관리 API로"}[caddyMode(st)])
		if err = validateCaddy(st, GenerateCaddyfile(d)); err == nil {
			L.f("  ✓ 검증 통과")
		}
	case "authelia":
		var raw []byte
		if raw, err = os.ReadFile(st.AutheliaConfig); err != nil {
			break
		}
		L.f("▶ access_control을 바꾼 configuration.yml을 %s 안에서 검증", st.AutheliaCtr)
		if err = validateAutheliaConfig(st, ReplaceAccessControl(string(raw), GenerateAccessControl(d))); err == nil {
			L.f("  ✓ 검증 통과")
		}
	default:
		err = errors.New("알 수 없는 대상")
	}
	res := map[string]any{"log": L.lines, "ok": err == nil}
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, 200, res)
}

// ctrNetworks: the user-defined Docker networks a container is on (sorted).
func ctrNetworks(ctx context.Context, ctr string) []string {
	if ctr == "" {
		return nil
	}
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{json .NetworkSettings.Networks}}", ctr)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &m) != nil {
		return nil
	}
	var names []string
	for n := range m {
		if n != "bridge" && n != "host" && n != "none" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}
