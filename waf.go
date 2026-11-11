package main

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Caddy-side WAF: Coraza (github.com/corazawaf/coraza-caddy/v2) + embedded OWASP CRS.
// Gilmok generates two snippets after the base skeleton and imports one per service:
//
//	(gm_waf_block)  — SecRuleEngine On          (blocks, 403)
//	(gm_waf_detect) — SecRuleEngine DetectionOnly (logs only — start here)
//
// Each snippet wraps coraza_waf in `route { }` so no global `order` option is needed.
// Content inspection works regardless of the client IP (Docker Desktop rewrites it to the
// bridge gateway), so it protects orange, gray and Tailscale sites alike.

const (
	WAFOff    = ""
	WAFDetect = "detect"
	WAFBlock  = "block"

	snippetWAFBlock  = "gm_waf_block"
	snippetWAFDetect = "gm_waf_detect"
	realIPField      = "gm_real_ip" // access-log field with Cf-Connecting-Ip (mTLS sites only)
	wafModule        = "http.handlers.waf"
)

// CRS v4 rule groups that can be switched off (id prefix → description). The blocking
// evaluation groups (949/959/980) are never offered.
var wafGroups = []struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}{
	{"911", "HTTP 메서드 제한", "허용 목록 밖 메서드(TRACE 등) 차단"},
	{"913", "스캐너 탐지", "취약점 스캐너의 User-Agent·헤더"},
	{"920", "프로토콜 검사", "잘못된 HTTP 요청·헤더 형식"},
	{"921", "프로토콜 공격", "요청 스머글링, 헤더 인젝션"},
	{"922", "멀티파트 공격", "multipart 업로드 우회 시도"},
	{"930", "로컬 파일 포함 (LFI)", "../ 경로 탐색, 민감 파일 접근"},
	{"931", "원격 파일 포함 (RFI)", "외부 URL을 파일로 불러오기"},
	{"932", "원격 코드 실행 (RCE)", "셸 명령·스크립트 인젝션"},
	{"933", "PHP 인젝션", "PHP 함수·래퍼 악용"},
	{"934", "일반 공격", "Node.js·SSRF·템플릿 인젝션 등"},
	{"941", "XSS", "스크립트 삽입"},
	{"942", "SQL 인젝션", "SQL 구문 삽입"},
	{"943", "세션 고정", "세션 ID 강제 지정"},
	{"944", "Java 공격", "Java 역직렬화·Log4Shell 등"},
}

var reWafRuleID = regexp.MustCompile(`^[0-9]{6}(-[0-9]{6})?$`)

func validateWafExclusions(xs []WafExclusion) ([]WafExclusion, error) {
	var out []WafExclusion
	seen := map[string]bool{}
	for _, x := range xs {
		x.ID = strings.TrimSpace(x.ID)
		x.Note = strings.TrimSpace(x.Note)
		if x.ID == "" {
			continue
		}
		if !reWafRuleID.MatchString(x.ID) {
			return nil, fmt.Errorf("WAF 규칙 번호 %q 가 올바르지 않습니다 (예: 942100 또는 942100-942199)", x.ID)
		}
		if strings.ContainsAny(x.Note, "`\n") || len(x.Note) > 200 {
			return nil, fmt.Errorf("규칙 %s 의 메모가 너무 길거나 쓸 수 없는 문자가 있습니다", x.ID)
		}
		if !seen[x.ID] {
			seen[x.ID] = true
			out = append(out, x)
		}
	}
	return out, nil
}

func validWafGroups(gs []string) []string {
	ok := map[string]bool{}
	for _, g := range wafGroups {
		ok[g.ID] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, g := range gs {
		if ok[g] && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}

var reMethods = regexp.MustCompile(`^[A-Z]+( [A-Z]+)*$`)

// wafCustom: does the service need its own snippet (paranoia override or exclusions)?
func wafCustom(s *Service) bool { return s.WAFParanoia > 0 || len(s.WAFExclude) > 0 }

var reSnipName = regexp.MustCompile(`[^a-z0-9]+`)

// wafSnippetFor: the snippet a service imports.
func wafSnippetFor(s *Service) string {
	base := snippetWAFDetect
	if s.WAF == WAFBlock {
		base = snippetWAFBlock
	}
	if !wafCustom(s) {
		return base
	}
	sub := reSnipName.ReplaceAllString(strings.ToLower(s.Subdomain), "_")
	if sub == "_" || sub == "" {
		sub = "root"
	}
	name := base + "_" + strings.Trim(sub, "_")
	// "a-b" and "a.b" both become a_b — add part of the service id so two services never share
	// (and silently overwrite) one snippet
	if id := reSnipName.ReplaceAllString(strings.ToLower(s.ID), ""); id != "" {
		name += "_" + id[:min(6, len(id))]
	}
	return name
}

func wafSnippetName(mode string) string {
	if mode == WAFBlock {
		return snippetWAFBlock
	}
	return snippetWAFDetect
}

func wafSnippet(name, mode string, st Settings, svc *Service) string {
	engine := "DetectionOnly"
	if mode == WAFBlock {
		engine = "On"
	}
	pl := st.WafParanoia
	if svc != nil && svc.WAFParanoia > 0 {
		pl = svc.WAFParanoia
	}
	if pl < 1 || pl > 4 {
		pl = 1
	}
	dpl := st.WafDetectPL
	if dpl < pl || dpl > 4 {
		dpl = pl
	}
	body := "Off"
	if st.WafBodyAccess {
		body = "On"
	}
	lines := []string{
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		"SecRuleEngine " + engine,
		"SecRequestBodyAccess " + body,
	}
	if st.WafBodyLimitMB > 0 {
		lines = append(lines, fmt.Sprintf("SecRequestBodyLimit %d", st.WafBodyLimitMB<<20))
	}
	lines = append(lines,
		"SecRequestBodyLimitAction ProcessPartial",
		"SecResponseBodyAccess Off",
		"SecAuditEngine Off",
		fmt.Sprintf(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, pl),
	)
	if dpl > pl {
		lines = append(lines, fmt.Sprintf(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=%d"`, dpl))
	}
	in, out := st.WafInbound, st.WafOutbound
	if in > 0 && out > 0 && (in != 5 || out != 4) {
		lines = append(lines, fmt.Sprintf(`SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`, in, out))
	}
	if m := strings.TrimSpace(st.WafMethods); m != "" && reMethods.MatchString(m) {
		lines = append(lines, fmt.Sprintf(`SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=%s'"`, m))
	}
	lines = append(lines, "Include @owasp_crs/*.conf")
	for _, g := range validWafGroups(st.WafGroupsOff) {
		lines = append(lines, fmt.Sprintf("SecRuleRemoveById %s000-%s999", g, g))
	}
	addEx := func(xs []WafExclusion) {
		for _, x := range xs {
			if reWafRuleID.MatchString(x.ID) {
				lines = append(lines, "SecRuleRemoveById "+x.ID)
			}
		}
	}
	addEx(st.WafExclude)
	if svc != nil {
		addEx(svc.WAFExclude)
	}
	for _, l := range strings.Split(strings.TrimSpace(st.WafDirectives), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	var sb strings.Builder
	sb.WriteString("(" + name + ") {\n\troute {\n\t\tcoraza_waf {\n\t\t\tload_owasp_crs\n\t\t\tdirectives `\n")
	for _, l := range lines {
		sb.WriteString("\t\t\t\t" + l + "\n")
	}
	sb.WriteString("\t\t\t`\n\t\t}\n\t}\n}\n")
	return sb.String()
}

// managedSnippets returns the Gilmok-generated snippet section (empty when nothing uses it).
func managedSnippets(d Data) string {
	var parts []string
	if g := guardSnippet(d); g != "" {
		parts = append(parts, g)
	}
	used := map[string]bool{}
	var custom []*Service
	for _, s := range d.Services {
		if !s.Enabled || s.DNSOnly || (s.WAF != WAFBlock && s.WAF != WAFDetect) {
			continue
		}
		if wafCustom(s) {
			custom = append(custom, s)
		} else {
			used[s.WAF] = true
		}
	}
	for _, m := range []string{WAFBlock, WAFDetect} {
		if used[m] {
			parts = append(parts, wafSnippet(wafSnippetName(m), m, d.Settings, nil))
		}
	}
	for _, s := range custom {
		parts = append(parts, wafSnippet(wafSnippetFor(s), s.WAF, d.Settings, s))
	}
	if len(parts) == 0 {
		return ""
	}
	return "\n# ---- 길목 관리 스니펫 (기본 차단 · WAF: Coraza + OWASP CRS) — Caddy 탭에서 설정 ----\n" + strings.Join(parts, "")
}

func isManagedSnippet(header string) bool {
	return header == "("+snippetGuard+")" || strings.HasPrefix(header, "("+snippetWAFBlock) || strings.HasPrefix(header, "("+snippetWAFDetect)
}

// crowdsecLogging: access log + real client IP for sites only Cloudflare can reach (mTLS).
// Gray-cloud sites never get the field, so a forged Cf-Connecting-Ip header cannot reach CrowdSec.
func crowdsecLogging(s *Service, st Settings) bool {
	return st.UseCrowdSec && st.UseCloudflare && st.CrowdSecEnabled && s.Exposure == ExposurePublic && s.Proxied && s.MTLS
}

func extraHasLog(extra string) bool {
	for _, l := range strings.Split(extra, "\n") {
		f := strings.Fields(stripComment(strings.TrimSpace(l)))
		if len(f) > 0 && f[0] == "log" {
			return true
		}
	}
	return false
}

func validateWAFDirectives(s string) error {
	if strings.Contains(s, "`") {
		return fmt.Errorf("WAF 추가 규칙에는 ` (백틱)을 쓸 수 없습니다")
	}
	return nil
}

// ---------------------------------------------------------------- WAF events (from Caddy logs)

type WAFEvent struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`   // waf | guard
	Action string    `json:"action"` // denied | warning (guard: always denied)
	RuleID string    `json:"ruleId"` // guard: category (bot, ai, …)
	Group  string    `json:"group"`  // CRS group ("942") / guard
	Msg    string    `json:"msg"`
	Data   string    `json:"data"`
	URI    string    `json:"uri"`
	Host   string    `json:"host"` // from the matching access-log line (best effort)
	TxID   string    `json:"txId"`
}

type WAFRuleCount struct {
	RuleID string         `json:"ruleId"`
	Group  string         `json:"group"`
	Msg    string         `json:"msg"`
	Count  int            `json:"count"`
	Denied int            `json:"denied"`
	Hosts  map[string]int `json:"hosts"`
}

var (
	reWafField = regexp.MustCompile(`\[(id|msg|data|uri|unique_id) \\?"((?:[^"\\]|\\.)*?)\\?"\]`)
	reWafTs    = regexp.MustCompile(`"ts":([0-9.]+)`)
)

func parseWAFLine(line string) (WAFEvent, bool) {
	if !strings.Contains(line, `"logger":"`+wafModule+`"`) || !strings.Contains(line, "Coraza: ") {
		return WAFEvent{}, false
	}
	ev := WAFEvent{Action: "warning"}
	if strings.Contains(line, "Coraza: Access denied") {
		ev.Action = "denied"
	}
	if m := reWafTs.FindStringSubmatch(line); m != nil {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			ev.Time = time.Unix(0, int64(f*1e9))
		}
	}
	for _, m := range reWafField.FindAllStringSubmatch(line, -1) {
		v := strings.ReplaceAll(m[2], `\\`, `\`)
		switch m[1] {
		case "id":
			ev.RuleID = v
		case "msg":
			ev.Msg = v
		case "data":
			ev.Data = v
		case "uri":
			ev.URI = v
		case "unique_id":
			ev.TxID = v
		}
	}
	if len(ev.Data) > 200 {
		ev.Data = ev.Data[:200] + "…"
	}
	return ev, ev.RuleID != ""
}

// caddyHasWAF reports whether the running Caddy binary includes the Coraza module.
func caddyHasWAF(ctr string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "exec", ctr, "caddy", "list-modules")
	if err != nil {
		return false, err
	}
	return strings.Contains(out, wafModule), nil
}
