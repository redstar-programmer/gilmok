package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Basic blocking ("guard"): requests that are attacks no matter what the app is —
// scanner/attack-tool User-Agents, AI crawlers, missing User-Agent, well-known probe paths.
// The same categories are used in two places:
//
//   - Caddy: snippet (gm_guard) imported by services with Service.Guard (works for every site,
//     Proxied, DNS only and private, because it looks at the request, not the client IP)
//   - Cloudflare: the "위협 차단" custom rule (Proxied sites, blocked at the edge)
//
// Blocked responses carry X-Gilmok-Block: <category> so the WAF event view can count them.

const (
	snippetGuard = "gm_guard"
	guardHeader  = "X-Gilmok-Block"
)

// Attack tools / vulnerability scanners (lower-case User-Agent substrings).
var guardBotUAs = []string{
	"sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "dirbuster", "gobuster", "feroxbuster",
	"fuzz faster u fool", "wfuzz", "wpscan", "acunetix", "netsparker", "nessus", "openvas", "whatweb",
	"jaeles", "xsstrike", "commix", "arachni", "skipfish", "w3af", "zmeu", "morfeus", "havij",
	"sqlninja", "jorgee", "l9explore", "l9tcpid", "censysinspect", "expanse", "webinspect", "appscan",
}

// AI training / answer-engine crawlers.
var guardAIUAs = []string{
	"gptbot", "chatgpt-user", "oai-searchbot", "claudebot", "claude-web", "anthropic-ai", "ccbot",
	"bytespider", "perplexitybot", "amazonbot", "meta-externalagent", "meta-externalfetcher",
	"facebookbot", "cohere-ai", "diffbot", "imagesiftbot", "omgilibot", "youbot", "ai2bot", "timpibot", "scrapy",
}

// Probe paths (lower-case substrings of the URL path).
var guardProbePaths = []string{
	"/.env", "/.git/", "/.svn/", "/.hg/", "/.aws/", "/.ssh/", "/.vscode/", "/.idea/", "/.htpasswd", "/.htaccess",
	"/.ds_store", "/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-includes/", "/wp-content/", "/phpmyadmin",
	"/pma/", "/myadmin/", "/adminer", "/phpinfo", "/cgi-bin/", "/vendor/phpunit/", "/server-status", "/boaform/",
	"/hnap1", "/etc/passwd",
}

var guardCategoryText = map[string]string{
	"bot": "스캐너·공격 도구", "ai": "AI 크롤러", "noua": "User-Agent 없음", "path": "공격 경로", "php": "PHP 요청", "custom": "사용자 목록", "ip": "차단 IP",
}

var reGuardEntry = regexp.MustCompile(`^[a-z0-9 ._/\-:+;()]{2,80}$`)

// splitEntries: one entry per line (or comma), trimmed, lower-cased, de-duplicated.
func splitEntries(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' || r == '\r' }) {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func validateGuardLists(st Settings) error {
	for _, e := range splitEntries(st.GuardUA) {
		if !reGuardEntry.MatchString(e) {
			return fmt.Errorf("차단할 User-Agent %q 에 쓸 수 없는 문자가 있습니다 (영문·숫자·공백·. _ / - : + ; ( ) 만)", e)
		}
	}
	for _, e := range splitEntries(st.GuardPathList) {
		if !strings.HasPrefix(e, "/") || !reGuardEntry.MatchString(e) || strings.Contains(e, " ") {
			return fmt.Errorf("차단할 경로 %q 는 / 로 시작하고 공백이 없어야 합니다", e)
		}
	}
	return nil
}

type guardSet struct {
	bots, ai, paths []string
	noUA, php       bool
}

// guardLists returns what is blocked; custom entries join the bot (UA) and path lists.
func guardLists(st Settings, bots, ai, noUA, paths, php bool) guardSet {
	var g guardSet
	custUA, custPath := splitEntries(st.GuardUA), splitEntries(st.GuardPathList)
	if bots {
		g.bots = append(append([]string{}, guardBotUAs...), custUA...)
	} else {
		g.bots = custUA
	}
	if ai {
		g.ai = guardAIUAs
	}
	if paths {
		g.paths = append(append([]string{}, guardProbePaths...), custPath...)
	} else {
		g.paths = custPath
	}
	g.noUA, g.php = noUA, php
	return g
}

func (g guardSet) empty() bool {
	return len(g.bots) == 0 && len(g.ai) == 0 && len(g.paths) == 0 && !g.noUA && !g.php
}

func uaRegexp(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = regexp.QuoteMeta(s)
	}
	return "(?i)(" + strings.Join(q, "|") + ")"
}

// guardSnippet: Caddy snippet; "" when nothing is selected or no service uses it.
func guardSnippet(d Data) string {
	used := false
	for _, s := range d.Services {
		if s.Enabled && !s.DNSOnly && s.Guard {
			used = true
		}
	}
	st := d.Settings
	g := guardLists(st, st.GuardBots, st.GuardAI, st.GuardEmptyUA, st.GuardPaths, st.GuardPHP)
	if !used || g.empty() {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("(" + snippetGuard + ") {\n")
	type m struct{ name, cat, def string }
	var ms []m
	if len(g.bots) > 0 {
		ms = append(ms, m{"gm_guard_bot", "bot", "header_regexp User-Agent `" + uaRegexp(g.bots) + "`"})
	}
	if len(g.ai) > 0 {
		ms = append(ms, m{"gm_guard_ai", "ai", "header_regexp User-Agent `" + uaRegexp(g.ai) + "`"})
	}
	if g.noUA {
		ms = append(ms, m{"gm_guard_noua", "noua", "expression `{http.request.header.User-Agent} == \"\"`"})
	}
	if len(g.paths) > 0 {
		ps := make([]string, len(g.paths))
		for i, p := range g.paths {
			ps[i] = "*" + p + "*"
		}
		ms = append(ms, m{"gm_guard_path", "path", "path " + strings.Join(ps, " ")})
	}
	if g.php {
		ms = append(ms, m{"gm_guard_php", "php", "path *.php"})
	}
	for _, x := range ms {
		sb.WriteString("\t@" + x.name + " " + x.def + "\n")
	}
	sb.WriteString("\troute {\n")
	for _, x := range ms {
		sb.WriteString("\t\theader @" + x.name + " " + guardHeader + " " + x.cat + "\n")
		sb.WriteString("\t\trespond @" + x.name + " 403\n")
	}
	sb.WriteString("\t}\n}\n")
	return sb.String()
}

// ---------------------------------------------------------------- Cloudflare expressions

func cfStr(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }

// parseIPList validates IPs / CIDRs (one per line); IPv6 hosts become /64 (Cloudflare list rule).
func parseIPList(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == '\r' || r == '\t' }) {
		v := f
		if strings.Contains(f, "/") {
			_, n, err := net.ParseCIDR(f)
			if err != nil {
				return nil, fmt.Errorf("IP 대역 %q 가 올바르지 않습니다", f)
			}
			v = n.String()
		} else if ip := net.ParseIP(f); ip == nil {
			return nil, fmt.Errorf("IP %q 가 올바르지 않습니다", f)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

var reCountry = regexp.MustCompile(`^[A-Z]{2}$`)

func parseCountries(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(strings.ToUpper(s), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if !reCountry.MatchString(f) {
			return nil, fmt.Errorf("국가 코드 %q 가 올바르지 않습니다 (예: KR, JP, US)", f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// hostScope turns service ids into `http.host in {…}`; "" = whole zone.
func hostScope(d Data, ids []string) (string, error) {
	if len(ids) == 0 {
		return "", nil
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var hosts []string
	for _, s := range d.Services {
		if want[s.ID] && s.Enabled {
			hosts = append(hosts, cfStr(d.Settings.FQDN(s.Subdomain)))
		}
	}
	if len(hosts) == 0 {
		return "", errors.New("선택한 대상 서비스가 모두 없어졌거나 꺼져 있습니다 — 대상을 다시 고르세요")
	}
	sort.Strings(hosts)
	return "http.host in {" + strings.Join(hosts, " ") + "}", nil
}

func orJoin(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

const cfExprMax = 4096

func threatExpression(d Data) (string, error) {
	st := d.Settings
	g := guardLists(st, st.CfThreatBots, st.CfThreatAI, st.CfThreatEmptyUA, st.CfThreatPaths, st.CfThreatPHP)
	ips, err := parseIPList(st.CfDenyIPs)
	if err != nil {
		return "", err
	}
	var parts []string
	if len(ips) > 0 {
		parts = append(parts, "ip.src in {"+strings.Join(ips, " ")+"}")
	}
	for _, ua := range append(append([]string{}, g.bots...), g.ai...) {
		parts = append(parts, "lower(http.user_agent) contains "+cfStr(ua))
	}
	if g.noUA {
		parts = append(parts, `http.user_agent eq ""`)
	}
	for _, p := range g.paths {
		parts = append(parts, "lower(http.request.uri.path) contains "+cfStr(p))
	}
	if g.php {
		parts = append(parts, `lower(http.request.uri.path) contains ".php"`)
	}
	if len(parts) == 0 {
		return "", errors.New("위협 차단에서 차단할 항목을 하나 이상 고르세요")
	}
	expr := orJoin(parts)
	scope, err := hostScope(d, st.CfThreatHosts)
	if err != nil {
		return "", err
	}
	if scope != "" {
		expr = scope + " and " + expr
	}
	if len(expr) > cfExprMax {
		return "", fmt.Errorf("위협 차단 규칙 식이 너무 깁니다 (%d자, 한도 %d자) — 항목(AI 크롤러, 사용자 목록 등)을 줄이세요", len(expr), cfExprMax)
	}
	return expr, nil
}

func geoExpression(d Data) (string, error) {
	st := d.Settings
	asns, err := parseASNs(st.CfAsnList)
	if err != nil {
		return "", err
	}
	cc, err := parseCountries(st.CfGeoCountries)
	if err != nil {
		return "", err
	}
	if len(asns) == 0 && len(cc) == 0 {
		return "", errors.New("국가 또는 통신사(ASN)를 하나 이상 입력하세요")
	}
	var conds []string
	if len(cc) > 0 {
		q := make([]string, len(cc))
		for i, c := range cc {
			q[i] = cfStr(c)
		}
		conds = append(conds, "ip.src.country in {"+strings.Join(q, " ")+"}")
	}
	if len(asns) > 0 {
		conds = append(conds, strings.TrimPrefix(asnExpression(asns), "not "))
	}
	var expr string
	if st.CfGeoMode == "block" {
		expr = orJoin(conds)
	} else if len(conds) == 1 {
		expr = "not " + conds[0]
	} else {
		expr = "not " + orJoin(conds)
	}
	if st.CfGeoBots {
		expr += " and not cf.client.bot"
	}
	scope, err := hostScope(d, st.CfGeoHosts)
	if err != nil {
		return "", err
	}
	if scope != "" {
		expr = scope + " and " + expr
	}
	return expr, nil
}

// guardCategory guesses which basic-blocking category a request falls in (edge event view).
func guardCategory(st Settings, ua, path string) string {
	ua, path = strings.ToLower(ua), strings.ToLower(path)
	if ua == "" {
		return "noua"
	}
	for _, x := range guardBotUAs {
		if strings.Contains(ua, x) {
			return "bot"
		}
	}
	for _, x := range guardAIUAs {
		if strings.Contains(ua, x) {
			return "ai"
		}
	}
	for _, x := range splitEntries(st.GuardUA) {
		if strings.Contains(ua, x) {
			return "custom"
		}
	}
	for _, x := range append(append([]string{}, guardProbePaths...), splitEntries(st.GuardPathList)...) {
		if strings.Contains(path, x) {
			return "path"
		}
	}
	if strings.Contains(path, ".php") {
		return "php"
	}
	return ""
}

// guardActive: the guard snippet exists (some category selected) — otherwise sites must not import it.
func guardActive(d Data) bool {
	st := d.Settings
	return !guardLists(st, st.GuardBots, st.GuardAI, st.GuardEmptyUA, st.GuardPaths, st.GuardPHP).empty()
}
