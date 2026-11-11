package main

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	snippetMTLS     = "cf_only"
	snippetAuthelia = "authelia"
	generatedBanner = "# ===== 길목(Gilmok)이 생성한 파일입니다. 직접 수정하면 다음 적용 때 덮어써집니다. =====\n" +
		"# 전역 옵션/스니펫(기본 골격)은 길목 > 설정 > Caddy 기본 골격에서 수정하세요.\n"
)

// ---------------------------------------------------------------- import

type caddyBlock struct {
	header   string   // first line without trailing "{"
	body     []string // inner lines (raw)
	comments []string // comment lines directly above the block
}

// splitTopLevel splits a Caddyfile into top-level blocks. Comments directly
// above a block are attached to it; other top-level lines are ignored.
func splitTopLevel(src string) ([]caddyBlock, error) {
	var blocks []caddyBlock
	var pending []string
	var cur *caddyBlock
	depth := 0
	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if cur == nil {
			if trim == "" {
				pending = nil
				continue
			}
			if strings.HasPrefix(trim, "#") {
				pending = append(pending, line)
				continue
			}
			code := stripComment(trim)
			if strings.HasSuffix(code, "{") {
				cur = &caddyBlock{header: strings.TrimSpace(strings.TrimSuffix(code, "{")), comments: pending}
				pending = nil
				depth = 1
				continue
			}
			return nil, fmt.Errorf("line %d: 블록 밖의 지시어는 지원하지 않습니다: %q", ln, trim)
		}
		code := stripComment(trim)
		depth += strings.Count(code, "{") - strings.Count(code, "}")
		if depth == 0 {
			blocks = append(blocks, *cur)
			cur = nil
			continue
		}
		cur.body = append(cur.body, line)
	}
	if cur != nil {
		return nil, fmt.Errorf("닫히지 않은 블록: %q", cur.header)
	}
	return blocks, sc.Err()
}

// stripComment removes a trailing "# comment" (Caddy requires whitespace before #).
func stripComment(s string) string {
	if strings.HasPrefix(s, "#") {
		return ""
	}
	if i := strings.Index(s, " #"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	if i := strings.Index(s, "\t#"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func commentOf(s string) string {
	for _, sep := range []string{" #", "\t#"} {
		if i := strings.Index(s, sep); i >= 0 {
			return strings.TrimSpace(s[i+len(sep):])
		}
	}
	return ""
}

// isDecorative reports whether a comment is a section banner like "--- 공개 ---" or "=====".
func isDecorative(n string) bool {
	return n == "" || strings.HasPrefix(n, "---") || strings.HasPrefix(n, "===")
}

func dedent(line string) string {
	if strings.HasPrefix(line, "\t") {
		return line[1:]
	}
	for _, p := range []string{"    ", "  "} {
		if strings.HasPrefix(line, p) {
			return line[len(p):]
		}
	}
	return line
}

// ImportCaddyfile converts an existing Caddyfile into the base skeleton
// (global options + snippets) and a list of services.
func ImportCaddyfile(src string, st Settings) (base string, services []*Service, warnings []string, err error) {
	blocks, err := splitTopLevel(src)
	if err != nil {
		return "", nil, nil, err
	}
	var baseParts []string
	for _, b := range blocks {
		isGlobal := b.header == ""
		isSnippet := strings.HasPrefix(b.header, "(")
		if isManagedSnippet(b.header) {
			continue // regenerated from settings
		}
		if isGlobal || isSnippet {
			var sb strings.Builder
			for _, c := range b.comments {
				sb.WriteString(c + "\n")
			}
			sb.WriteString(b.header)
			if b.header != "" {
				sb.WriteString(" ")
			}
			sb.WriteString("{\n")
			for _, l := range b.body {
				sb.WriteString(l + "\n")
			}
			sb.WriteString("}")
			baseParts = append(baseParts, sb.String())
			continue
		}
		svc, warn := parseSite(b, st)
		warnings = append(warnings, warn...)
		if svc != nil {
			services = append(services, svc)
		}
	}
	return strings.Join(baseParts, "\n\n") + "\n", services, warnings, nil
}

func parseSite(b caddyBlock, st Settings) (*Service, []string) {
	var warns []string
	addrs := strings.FieldsFunc(b.header, func(r rune) bool { return r == ',' || r == ' ' })
	if len(addrs) == 0 {
		return nil, []string{"주소 없는 블록 무시"}
	}
	if len(addrs) > 1 {
		warns = append(warns, fmt.Sprintf("%s: 주소가 여러 개라 첫 번째만 사용합니다", b.header))
	}
	addr := strings.TrimPrefix(strings.TrimPrefix(addrs[0], "https://"), "http://")
	host, port := addr, 0
	if i := strings.LastIndex(addr, ":"); i > 0 {
		host = addr[:i]
		port, _ = strconv.Atoi(addr[i+1:])
	}
	sub := ""
	switch {
	case host == st.Domain:
		sub = "@"
	case strings.HasSuffix(host, "."+st.Domain):
		sub = strings.TrimSuffix(host, "."+st.Domain)
	default:
		return nil, []string{fmt.Sprintf("%s: 도메인(%s)과 맞지 않아 건너뜀", host, st.Domain)}
	}
	s := &Service{
		ID: newID(), Subdomain: sub, Exposure: ExposurePublic, Enabled: true, ManageDNS: true,
		Authelia: AutheliaOpts{Policy: "one_factor"},
	}
	if port != 0 {
		if port == st.TailscalePort {
			s.Exposure = ExposureTailscale
		} else {
			warns = append(warns, fmt.Sprintf("%s: 알 수 없는 포트 %d — 공개(443)로 가져옵니다", host, port))
		}
	}
	var notes []string
	for _, c := range b.comments {
		n := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(c), "#"))
		if isDecorative(n) {
			continue
		}
		notes = append(notes, n)
	}
	if c := commentOf(b.header + " "); c != "" {
		notes = append(notes, c)
	}
	var extra []string
	depth := 0
	codeAt := func(i int) string {
		if i < 0 || i >= len(b.body) {
			return ""
		}
		return stripComment(strings.TrimSpace(b.body[i]))
	}
	isRealIP := func(c string) bool { return strings.HasPrefix(c, "log_append "+realIPField+" ") }
	for i, raw := range b.body {
		line := dedent(raw)
		trim := strings.TrimSpace(raw)
		code := stripComment(trim)
		if depth == 0 {
			switch {
			case code == "import "+snippetWAFBlock, strings.HasPrefix(code, "import "+snippetWAFBlock+"_"):
				s.WAF = WAFBlock
				continue
			case code == "import "+snippetWAFDetect, strings.HasPrefix(code, "import "+snippetWAFDetect+"_"):
				s.WAF = WAFDetect
				continue
			case code == "import "+snippetGuard:
				s.Guard = true
				continue
			case strings.HasPrefix(code, "request_header "+proxyHeader+" "):
				continue // generated: Gilmok proxy secret
			case code == "log" && commentOf(trim) == "gilmok":
				continue // generated: dashboard / CrowdSec access log
			case isRealIP(code), code == "log" && isRealIP(codeAt(i+1)):
				continue // generated when CrowdSec is on (mTLS sites)
			case code == "import "+snippetMTLS:
				s.MTLS, s.Proxied = true, true
				continue
			case code == "import "+snippetAuthelia:
				s.Authelia.Enabled = true
				continue
			case strings.HasPrefix(code, "reverse_proxy ") && !strings.HasSuffix(code, "{") && s.Upstream == "":
				f := strings.Fields(code)
				if len(f) == 2 {
					s.Upstream = f[1]
					if c := commentOf(trim); c != "" {
						notes = append(notes, c)
					}
					continue
				}
			}
		}
		depth += strings.Count(code, "{") - strings.Count(code, "}")
		extra = append(extra, line)
	}
	s.Extra = strings.TrimRight(strings.Join(extra, "\n"), "\n ")
	s.Notes = strings.Join(notes, " / ")
	if s.Upstream == "" && s.Extra == "" {
		warns = append(warns, fmt.Sprintf("%s: 내용이 비어 있습니다", host))
	}
	return s, warns
}

// ---------------------------------------------------------------- generate

func GenerateCaddyfile(d Data) string {
	st := d.Settings
	var sb strings.Builder
	sb.WriteString(generatedBanner + "\n")
	sb.WriteString(strings.TrimRight(st.CaddyBase, "\n") + "\n")
	sb.WriteString(managedSnippets(d))

	svcs := append([]*Service(nil), d.Services...)
	sortServices(svcs)
	section := ""
	for _, s := range svcs {
		if !s.Enabled || s.DNSOnly {
			continue
		}
		title := "공개 서비스 (:443)"
		if s.Exposure == ExposureTailscale {
			title = fmt.Sprintf("Tailscale 전용 (:%d)", st.TailscalePort)
		}
		if title != section {
			section = title
			sb.WriteString("\n# =====================================================================\n# " + title + "\n# =====================================================================\n")
		}
		sb.WriteString("\n")
		if n := strings.TrimSpace(s.Notes); n != "" {
			for _, l := range strings.Split(n, "\n") {
				sb.WriteString("# " + strings.TrimSpace(l) + "\n")
			}
		}
		addr := st.FQDN(s.Subdomain)
		if s.Exposure == ExposureTailscale {
			addr += ":" + strconv.Itoa(st.TailscalePort)
		}
		sb.WriteString(addr + " {\n")
		if st.UseCloudflare && s.Exposure == ExposurePublic && s.Proxied && s.MTLS {
			sb.WriteString("\timport " + snippetMTLS + "\n")
		}
		if st.UseAuthelia && s.Authelia.Enabled {
			sb.WriteString("\timport " + snippetAuthelia + "\n")
		}
		if s.ID != "" && s.ID == st.SecSelfService && d.ProxySecret != "" {
			// lets Gilmok tell "through Caddy" from "another container on the network"
			sb.WriteString("\trequest_header " + proxyHeader + " \"" + d.ProxySecret + "\" # gilmok\n")
		}
		cs := crowdsecLogging(s, st)
		if (cs || st.DashLogs) && !extraHasLog(s.Extra) {
			sb.WriteString("\tlog # gilmok\n") // marker: recognized (and dropped) on import
		}
		if cs {
			sb.WriteString("\tlog_append " + realIPField + " {http.request.header.Cf-Connecting-Ip}\n")
		}
		if s.Guard && guardActive(d) {
			sb.WriteString("\timport " + snippetGuard + "\n")
		}
		if s.WAF == WAFBlock || s.WAF == WAFDetect {
			sb.WriteString("\timport " + wafSnippetFor(s) + "\n")
		}
		if e := strings.TrimRight(s.Extra, "\n "); e != "" {
			for _, l := range strings.Split(e, "\n") {
				if strings.TrimSpace(l) == "" {
					sb.WriteString("\n")
				} else {
					sb.WriteString("\t" + l + "\n")
				}
			}
		}
		if u := strings.TrimSpace(s.Upstream); u != "" {
			sb.WriteString("\treverse_proxy " + u + "\n")
		}
		sb.WriteString("}\n")
	}
	return sb.String()
}

// ---------------------------------------------------------------- validation of inputs

func validateService(s *Service, all []*Service, st Settings) error {
	s.Subdomain = strings.ToLower(strings.TrimSpace(s.Subdomain))
	s.Upstream = strings.TrimSpace(s.Upstream)
	if s.Subdomain == "" {
		return fmt.Errorf("서브도메인을 입력하세요")
	}
	if s.Subdomain != "@" {
		for _, r := range s.Subdomain {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
				return fmt.Errorf("서브도메인에는 영문 소문자, 숫자, -, . 만 쓸 수 있습니다")
			}
		}
	}
	if s.Exposure != ExposurePublic && s.Exposure != ExposureTailscale {
		return fmt.Errorf("노출 방식이 올바르지 않습니다")
	}
	if s.Exposure == ExposureTailscale {
		s.Proxied, s.MTLS = false, false
	}
	if !s.Proxied {
		s.MTLS = false
	}
	if s.WAF != WAFBlock && s.WAF != WAFDetect {
		s.WAF = WAFOff
	}
	if s.WAFParanoia < 0 || s.WAFParanoia > 4 {
		s.WAFParanoia = 0
	}
	if x, err := validateWafExclusions(s.WAFExclude); err != nil {
		return err
	} else {
		s.WAFExclude = x
	}
	if s.DNSOnly {
		s.Guard, s.WAFParanoia, s.WAFExclude = false, 0, nil
		s.Upstream, s.Extra, s.MTLS, s.WAF = "", "", false, WAFOff
		s.Authelia.Enabled = false
	} else if s.Upstream == "" && strings.TrimSpace(s.Extra) == "" {
		return fmt.Errorf("대상(upstream) 또는 추가 지시어 중 하나는 필요합니다")
	}
	if strings.ContainsAny(s.Upstream, " \t\r\n{}#\"'`") {
		return fmt.Errorf("대상(upstream)은 공백 없이 host:port 형식으로 입력하세요")
	}
	if s.Authelia.Policy != "one_factor" && s.Authelia.Policy != "two_factor" {
		s.Authelia.Policy = "two_factor"
	}
	// braces in extra must balance and never close the site block early (no escaping into a
	// new site / global block)
	if err := checkBraces(s.Extra); err != nil {
		return fmt.Errorf("추가 지시어: %v", err)
	}
	if strings.Contains(strings.ToLower(s.Extra), strings.ToLower(proxyHeader)) {
		return fmt.Errorf("추가 지시어에 %s 헤더를 쓸 수 없습니다 — 길목 사이트에만 길목이 자동으로 넣습니다 (설정 › 접근 보안)", proxyHeader)
	}
	for _, o := range all {
		if o.ID != s.ID && o.Subdomain == s.Subdomain {
			return fmt.Errorf("%s 는 이미 등록되어 있습니다", st.FQDN(s.Subdomain))
		}
	}
	return nil
}

var reSiteHost = regexp.MustCompile(`(?m)^(?:https?://)?([a-z0-9*][a-z0-9.*-]*\.[a-z]{2,})(?::\d+)?\s*(?:,|\{)`)

// inferDomain guesses the zone from the site addresses of a Caddyfile (most common
// registrable suffix: last two labels, three for e.g. example.co.kr). "" when unsure.
func inferDomain(caddyfile string) string {
	count := map[string]int{}
	for _, m := range reSiteHost.FindAllStringSubmatch(strings.ToLower(caddyfile), -1) {
		labels := strings.Split(strings.TrimPrefix(m[1], "*."), ".")
		if len(labels) < 2 {
			continue
		}
		n := 2
		if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && len(labels[len(labels)-2]) <= 3 {
			n = 3 // co.kr, or.jp, com.au …
		}
		if len(labels) < n {
			continue
		}
		count[strings.Join(labels[len(labels)-n:], ".")]++
	}
	best, bestN := "", 0
	for d, c := range count {
		if c > bestN || c == bestN && d < best {
			best, bestN = d, c
		}
	}
	return best
}

// checkBraces: "{" / "}" must balance and the running depth must never go below zero — a "}" that
// closes the surrounding block would let text escape into a new site or the global options.
func checkBraces(text string) error {
	depth := 0
	for i, line := range strings.Split(text, "\n") {
		for _, ch := range stripComment(line) {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					return fmt.Errorf("%d번째 줄의 } 가 바깥 블록을 닫습니다 — 블록 밖으로 나가는 지시어는 쓸 수 없습니다", i+1)
				}
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("중괄호 { } 개수가 맞지 않습니다")
	}
	return nil
}
