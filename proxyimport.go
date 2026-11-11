package main

// Bring services over from another reverse proxy's configuration — a Caddyfile of another Caddy,
// nginx (incl. Nginx Proxy Manager host files) or Traefik (dynamic YAML / TOML, docker-compose
// labels, or the labels of running containers). Unlike 「가져오기」 (which replaces the service list
// and the base configuration from Gilmok's own Caddyfile) this only ADDS the services you pick and,
// if you say so, updates the upstream of ones that already exist.
//
//	POST /api/import/sites        {format, files:[{name,content}]}                → preview
//	POST /api/import/sites/apply  {format, files, pick:[sub…], overwrite:[sub…]}  → merge
//
// The apply call parses the files again on the server; nothing the browser sends is trusted as a
// service definition.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type importFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// FoundSite: one host found in a foreign configuration.
type FoundSite struct {
	Host     string   `json:"host"`
	Sub      string   `json:"sub"`      // subdomain under Gilmok's domain
	Upstream string   `json:"upstream"` // host:port (https://… kept)
	Source   string   `json:"source"`   // file / container it came from
	Status   string   `json:"status"`   // new | exists | same | error
	Current  string   `json:"current,omitempty"`
	Notes    []string `json:"notes,omitempty"`
	Error    string   `json:"error,omitempty"`
	svc      *Service
}

type importResult struct {
	Format   string      `json:"format"`
	Sites    []FoundSite `json:"sites"`
	Warnings []string    `json:"warnings"`
}

var importFormats = map[string]string{"caddy": "Caddyfile", "nginx": "nginx", "traefik": "Traefik", "traefik-docker": "Traefik (컨테이너 라벨)"}

// detectFormat guesses a file's format from its name and content.
func detectFormat(name, content string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "caddyfile"):
		return "caddy"
	case strings.HasSuffix(n, ".conf") || strings.Contains(content, "server_name") || strings.Contains(content, "proxy_pass"):
		return "nginx"
	case strings.Contains(content, "traefik.") || strings.Contains(content, "routers") || strings.HasSuffix(n, ".toml"):
		return "traefik"
	case strings.Contains(content, "reverse_proxy"):
		return "caddy"
	}
	return ""
}

// ---------------------------------------------------------------- host → subdomain

func (a *App) hostToSub(host string, st Settings) (sub, note string, err error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, "*~^$()[]{}\\ ") {
		return "", "", fmt.Errorf("이름이 아닌 주소(%s)는 가져올 수 없습니다", host)
	}
	switch {
	case host == st.Domain:
		return "@", "", nil
	case strings.HasSuffix(host, "."+st.Domain):
		return strings.TrimSuffix(host, "."+st.Domain), "", nil
	}
	first := strings.SplitN(host, ".", 2)[0]
	if first == "" || first == host {
		return "", "", fmt.Errorf("%s: 서브도메인을 정할 수 없습니다", host)
	}
	return first, fmt.Sprintf("다른 도메인(%s) → %s.%s 로 가져옵니다", host, first, st.Domain), nil
}

// upstreamFromURL turns http://app:8080/path into app:8080 (https:// is kept, the path is dropped).
func upstreamFromURL(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	note := ""
	if p := strings.TrimRight(u.Path, "/"); p != "" {
		note = fmt.Sprintf("원래 대상 경로 %s 는 빠졌습니다 — 필요하면 추가 지시어로", u.Path)
	}
	port := u.Port()
	if u.Scheme == "https" {
		if port == "" || port == "443" {
			return "https://" + u.Hostname(), note
		}
		return "https://" + u.Hostname() + ":" + port, note
	}
	if port == "" {
		port = "80"
	}
	return u.Hostname() + ":" + port, note
}

// ---------------------------------------------------------------- Caddyfile (another Caddy)

func parseForeignCaddy(src string, st Settings) ([]FoundSite, []string) {
	blocks, err := splitTopLevel(src)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var out []FoundSite
	var warns []string
	for _, b := range blocks {
		if b.header == "" || strings.HasPrefix(b.header, "(") || isManagedSnippet(b.header) {
			continue
		}
		addrs := strings.FieldsFunc(b.header, func(r rune) bool { return r == ',' || r == ' ' })
		for _, addr := range addrs {
			addr = strings.TrimPrefix(strings.TrimPrefix(addr, "https://"), "http://")
			host := addr
			if i := strings.LastIndex(addr, ":"); i > 0 {
				host = addr[:i]
			}
			if host == "" || strings.HasPrefix(addr, ":") {
				continue // :80 { … } style catch-all
			}
			fs := FoundSite{Host: host}
			// parse the block as if Gilmok's domain were this host's parent
			st2 := st
			if host != st.Domain && !strings.HasSuffix(host, "."+st.Domain) {
				if p := strings.SplitN(host, ".", 2); len(p) == 2 {
					st2.Domain = p[1]
				}
			}
			b2 := b
			b2.header = addr
			svc, w := parseSite(b2, st2)
			if svc == nil {
				fs.Error = strings.Join(w, "; ")
				out = append(out, fs)
				continue
			}
			fs.svc, fs.Upstream = svc, svc.Upstream
			fs.Notes = append(fs.Notes, w...)
			for _, l := range strings.Split(svc.Extra, "\n") {
				if f := strings.Fields(stripComment(strings.TrimSpace(l))); len(f) > 1 && f[0] == "import" {
					fs.Notes = append(fs.Notes, fmt.Sprintf("스니펫 import %s 가 추가 지시어로 들어갑니다 — 길목의 기본 골격에 없으면 적용 때 검증에서 걸립니다", f[1]))
				}
			}
			out = append(out, fs)
		}
	}
	return out, warns
}

// ---------------------------------------------------------------- nginx

type ngxDirective struct {
	name  string
	args  []string
	block []*ngxDirective
}

func ngxTokens(src string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '#':
			flush()
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			flush()
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				return nil, errors.New("닫히지 않은 따옴표가 있습니다")
			}
			toks = append(toks, src[i+1:j])
			i = j
		case c == '{' || c == '}' || c == ';':
			flush()
			toks = append(toks, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return toks, nil
}

func ngxParse(toks []string, pos *int, depth int) ([]*ngxDirective, error) {
	var out []*ngxDirective
	var args []string
	for *pos < len(toks) {
		t := toks[*pos]
		*pos++
		switch t {
		case ";":
			if len(args) > 0 {
				out = append(out, &ngxDirective{name: args[0], args: args[1:]})
			}
			args = nil
		case "{":
			if len(args) == 0 {
				return nil, errors.New("이름 없는 블록이 있습니다")
			}
			d := &ngxDirective{name: args[0], args: args[1:]}
			args = nil
			kids, err := ngxParse(toks, pos, depth+1)
			if err != nil {
				return nil, err
			}
			d.block = kids
			out = append(out, d)
		case "}":
			if depth == 0 {
				return nil, errors.New("여는 { 없이 닫는 } 가 있습니다")
			}
			return out, nil
		default:
			args = append(args, t)
		}
	}
	if depth > 0 {
		return nil, errors.New("닫히지 않은 { 가 있습니다")
	}
	return out, nil
}

func ngxWalk(ds []*ngxDirective, fn func(d *ngxDirective)) {
	for _, d := range ds {
		fn(d)
		ngxWalk(d.block, fn)
	}
}

var reNgxVar = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

func parseNginx(src, file string) ([]FoundSite, []string) {
	toks, err := ngxTokens(src)
	if err != nil {
		return nil, []string{file + ": " + err.Error()}
	}
	pos := 0
	tree, err := ngxParse(toks, &pos, 0)
	if err != nil {
		return nil, []string{file + ": " + err.Error()}
	}
	upstreams := map[string]string{}
	ngxWalk(tree, func(d *ngxDirective) {
		if d.name == "upstream" && len(d.args) == 1 {
			for _, k := range d.block {
				if k.name == "server" && len(k.args) > 0 && upstreams[d.args[0]] == "" {
					upstreams[d.args[0]] = k.args[0]
				}
			}
		}
	})
	var out []FoundSite
	var warns []string
	ngxWalk(tree, func(d *ngxDirective) {
		if d.name != "server" || d.block == nil {
			return
		}
		vars := map[string]string{}
		var names []string
		pass, passRoot, auth := "", "", false
		ngxWalk(d.block, func(k *ngxDirective) {
			switch k.name {
			case "set":
				if len(k.args) == 2 && strings.HasPrefix(k.args[0], "$") {
					vars[strings.TrimPrefix(k.args[0], "$")] = k.args[1]
				}
			case "server_name":
				names = append(names, k.args...)
			case "auth_request", "auth_basic":
				auth = true
			}
		})
		// proxy_pass: the one in `location /` first, else the first one
		for _, k := range d.block {
			if k.name == "proxy_pass" && len(k.args) > 0 && pass == "" {
				pass = k.args[0]
			}
			if k.name == "location" && k.block != nil {
				for _, x := range k.block {
					if x.name == "proxy_pass" && len(x.args) > 0 {
						if strings.Join(k.args, " ") == "/" && passRoot == "" {
							passRoot = x.args[0]
						}
						if pass == "" {
							pass = x.args[0]
						}
					}
				}
			}
		}
		if passRoot != "" {
			pass = passRoot
		}
		// Nginx Proxy Manager host files: the proxy_pass is in an included file, the target in variables
		if pass == "" && vars["server"] != "" && vars["port"] != "" {
			scheme := vars["forward_scheme"]
			if scheme == "" {
				scheme = "http"
			}
			pass = scheme + "://" + vars["server"] + ":" + vars["port"]
		}
		if len(names) == 0 {
			return
		}
		up, note := "", ""
		if pass != "" {
			pass = reNgxVar.ReplaceAllStringFunc(pass, func(m string) string {
				k := reNgxVar.FindStringSubmatch(m)[1]
				if v, ok := vars[k]; ok {
					return v
				}
				if k == "request_uri" || k == "uri" || k == "is_args" || k == "args" {
					return ""
				}
				return m
			})
			if u, err := url.Parse(pass); err == nil && u.Port() == "" {
				if s, ok := upstreams[u.Hostname()]; ok {
					pass = u.Scheme + "://" + s
				}
			}
			if strings.Contains(pass, "$") {
				note = fmt.Sprintf("proxy_pass 에 풀 수 없는 변수가 있습니다: %s", pass)
			} else {
				up, note = upstreamFromURL(pass)
			}
		}
		for _, n := range names {
			if n == "_" || n == "localhost" || n == "" || strings.HasPrefix(n, "~") || strings.HasPrefix(n, "*") {
				continue
			}
			fs := FoundSite{Host: n, Upstream: up, Source: file}
			if note != "" {
				fs.Notes = append(fs.Notes, note)
			}
			if auth {
				fs.Notes = append(fs.Notes, "원래 인증(auth_request/auth_basic)이 걸려 있었습니다 — Authelia 관문을 확인하세요")
			}
			if up == "" {
				fs.Error = "proxy_pass 를 찾지 못했습니다 (리다이렉트·정적 사이트는 가져오지 않습니다)"
			}
			out = append(out, fs)
		}
	})
	return out, warns
}

// ---------------------------------------------------------------- Traefik

var reTraefikHost = regexp.MustCompile("Host(?:SNI)?\\(([^)]*)\\)")

func traefikHosts(rule string) []string {
	var out []string
	for _, m := range reTraefikHost.FindAllStringSubmatch(rule, -1) {
		for _, h := range strings.Split(m[1], ",") {
			h = strings.Trim(strings.TrimSpace(h), "`\"'")
			if h != "" {
				out = append(out, h)
			}
		}
	}
	return out
}

// tomlToMap: the subset of TOML Traefik dynamic files use ([a.b], [[a.b]], key = "value" / number / bool).
func tomlToMap(src string) (map[string]any, error) {
	root := map[string]any{}
	cur := root
	walk := func(path []string, array bool) (map[string]any, error) {
		m := root
		for i, p := range path {
			p = strings.Trim(strings.TrimSpace(p), `"`)
			last := i == len(path)-1
			if last && array {
				arr, _ := m[p].([]any)
				n := map[string]any{}
				m[p] = append(arr, n)
				return n, nil
			}
			switch v := m[p].(type) {
			case map[string]any:
				m = v
			case []any:
				if len(v) == 0 {
					return nil, fmt.Errorf("잘못된 표: %s", strings.Join(path, "."))
				}
				m = v[len(v)-1].(map[string]any)
			case nil:
				n := map[string]any{}
				m[p] = n
				m = n
			default:
				return nil, fmt.Errorf("잘못된 표: %s", strings.Join(path, "."))
			}
		}
		return m, nil
	}
	for n, line := range strings.Split(src, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		var err error
		switch {
		case strings.HasPrefix(l, "[["):
			cur, err = walk(strings.Split(strings.Trim(l, "[] "), "."), true)
		case strings.HasPrefix(l, "["):
			cur, err = walk(strings.Split(strings.Trim(l, "[] "), "."), false)
		default:
			i := strings.Index(l, "=")
			if i < 0 {
				return nil, fmt.Errorf("%d번째 줄을 읽지 못했습니다", n+1)
			}
			k := strings.Trim(strings.TrimSpace(l[:i]), `"`)
			v := strings.TrimSpace(l[i+1:])
			if j := strings.Index(v, " #"); j >= 0 && !strings.HasPrefix(v, `"`) {
				v = strings.TrimSpace(v[:j])
			}
			if strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'") {
				if uq, err := strconv.Unquote(v); err == nil {
					v = uq
				} else {
					v = strings.Trim(v, `"'`)
				}
			}
			if strings.HasPrefix(v, "[") { // inline array of strings
				var arr []any
				for _, x := range strings.Split(strings.Trim(v, "[]"), ",") {
					if x = strings.Trim(strings.TrimSpace(x), `"'`); x != "" {
						arr = append(arr, x)
					}
				}
				cur[k] = arr
			} else {
				cur[k] = v
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return root, nil
}

func mget(m any, path ...string) any {
	for _, p := range path {
		mm, ok := m.(map[string]any)
		if !ok {
			return nil
		}
		var found any
		for k, v := range mm { // Traefik keys are case-insensitive (loadBalancer / loadbalancer)
			if strings.EqualFold(k, p) {
				found = v
				break
			}
		}
		m = found
	}
	return m
}

func mstr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case float64:
		return strconv.Itoa(int(x))
	}
	return ""
}

// parseTraefikDynamic: http.routers / http.services of a file-provider config.
func parseTraefikDynamic(doc map[string]any, file string) []FoundSite {
	routers, _ := mget(doc, "http", "routers").(map[string]any)
	services, _ := mget(doc, "http", "services").(map[string]any)
	names := make([]string, 0, len(routers))
	for n := range routers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []FoundSite
	for _, rn := range names {
		r := routers[rn]
		rule := mstr(mget(r, "rule"))
		svcName := strings.SplitN(mstr(mget(r, "service")), "@", 2)[0]
		up, note := "", ""
		if s, ok := services[svcName]; ok {
			if srv, ok := mget(s, "loadBalancer", "servers").([]any); ok && len(srv) > 0 {
				up, note = upstreamFromURL(mstr(mget(srv[0], "url")))
			}
		}
		for _, h := range traefikHosts(rule) {
			fs := FoundSite{Host: h, Upstream: up, Source: file + " › " + rn}
			if note != "" {
				fs.Notes = append(fs.Notes, note)
			}
			if mw := mget(r, "middlewares"); mw != nil {
				fs.Notes = append(fs.Notes, "원래 미들웨어가 걸려 있었습니다 (인증이면 Authelia 관문을 확인하세요)")
			}
			if up == "" {
				fs.Error = fmt.Sprintf("서비스 %q 의 대상 주소를 찾지 못했습니다", svcName)
			}
			out = append(out, fs)
		}
	}
	return out
}

// traefikFromLabels: routers / services written as Docker labels on one container.
func traefikFromLabels(labels map[string]string, host, source string, ports []string) []FoundSite {
	if strings.EqualFold(labels["traefik.enable"], "false") {
		return nil
	}
	routers := map[string]map[string]string{}
	svcPort, svcScheme := map[string]string{}, map[string]string{}
	for k, v := range labels {
		lk := strings.ToLower(k)
		p := strings.Split(lk, ".")
		if len(p) < 5 || p[0] != "traefik" || p[1] != "http" {
			continue
		}
		switch {
		case p[2] == "routers":
			if routers[p[3]] == nil {
				routers[p[3]] = map[string]string{}
			}
			routers[p[3]][strings.Join(p[4:], ".")] = v
		case p[2] == "services" && strings.HasSuffix(lk, ".loadbalancer.server.port"):
			svcPort[p[3]] = v
		case p[2] == "services" && strings.HasSuffix(lk, ".loadbalancer.server.scheme"):
			svcScheme[p[3]] = v
		}
	}
	names := make([]string, 0, len(routers))
	for n := range routers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []FoundSite
	for _, rn := range names {
		r := routers[rn]
		sn := r["service"]
		if sn == "" {
			sn = rn
			if len(svcPort) == 1 {
				for k := range svcPort {
					sn = k
				}
			}
		}
		port := svcPort[sn]
		if port == "" && len(ports) == 1 {
			port = ports[0]
		}
		up := ""
		if port != "" {
			if svcScheme[sn] == "https" {
				up = "https://" + host + ":" + port
			} else {
				up = host + ":" + port
			}
		}
		for _, h := range traefikHosts(r["rule"]) {
			fs := FoundSite{Host: h, Upstream: up, Source: source}
			if r["middlewares"] != "" {
				fs.Notes = append(fs.Notes, fmt.Sprintf("원래 미들웨어(%s)가 걸려 있었습니다 — 인증이면 Authelia 관문을 확인하세요", r["middlewares"]))
			}
			if up == "" {
				fs.Error = "포트를 알 수 없습니다 (loadbalancer.server.port 라벨이 없고 열린 포트가 여러 개 또는 없음)"
			}
			out = append(out, fs)
		}
	}
	return out
}

// parseTraefikFile: a dynamic config (YAML / TOML) or a docker-compose file with traefik labels.
func parseTraefikFile(name, src string) ([]FoundSite, []string) {
	var doc map[string]any
	if strings.HasSuffix(strings.ToLower(name), ".toml") || (!strings.Contains(src, ":") && strings.Contains(src, "[http")) {
		m, err := tomlToMap(src)
		if err != nil {
			return nil, []string{name + ": " + err.Error()}
		}
		doc = m
	} else if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return nil, []string{fmt.Sprintf("%s: YAML을 읽지 못했습니다 — %v", name, err)}
	}
	if svcs, ok := mget(doc, "services").(map[string]any); ok && mget(doc, "http") == nil {
		// docker-compose: services.<name>.labels
		names := make([]string, 0, len(svcs))
		for n := range svcs {
			names = append(names, n)
		}
		sort.Strings(names)
		var out []FoundSite
		for _, n := range names {
			s := svcs[n]
			labels := map[string]string{}
			switch l := mget(s, "labels").(type) {
			case map[string]any:
				for k, v := range l {
					labels[k] = mstr(v)
				}
			case []any:
				for _, x := range l {
					if kv := strings.SplitN(mstr(x), "=", 2); len(kv) == 2 {
						labels[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
					}
				}
			}
			host := n
			if cn := mstr(mget(s, "container_name")); cn != "" {
				host = cn
			}
			var ports []string
			if ex, ok := mget(s, "expose").([]any); ok {
				for _, p := range ex {
					ports = append(ports, strings.SplitN(mstr(p), "/", 2)[0])
				}
			}
			out = append(out, traefikFromLabels(labels, host, name+" › "+n, ports)...)
		}
		return out, nil
	}
	return parseTraefikDynamic(doc, name), nil
}

// traefikFromContainers: the traefik.* labels of the containers on this Docker.
func traefikFromContainers(ctx context.Context) ([]FoundSite, []string) {
	ids, err := docker(ctx, nil, nil, "ps", "-q")
	if err != nil {
		return nil, []string{fmt.Sprintf("Docker 컨테이너 목록을 읽지 못했습니다: %s", oneLine(ids))}
	}
	if strings.TrimSpace(ids) == "" {
		return nil, nil
	}
	raw, err := docker(ctx, nil, nil, append([]string{"inspect"}, strings.Fields(ids)...)...)
	if err != nil {
		return nil, []string{fmt.Sprintf("docker inspect 실패: %s", oneLine(raw))}
	}
	var list []struct {
		Name   string
		Config struct {
			Labels       map[string]string
			ExposedPorts map[string]any
		}
	}
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, []string{"docker inspect 결과를 읽지 못했습니다"}
	}
	var out []FoundSite
	for _, c := range list {
		name := strings.TrimPrefix(c.Name, "/")
		has := false
		for k := range c.Config.Labels {
			if strings.HasPrefix(strings.ToLower(k), "traefik.http.routers.") {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		var ports []string
		for p := range c.Config.ExposedPorts {
			if strings.HasSuffix(p, "/tcp") {
				ports = append(ports, strings.TrimSuffix(p, "/tcp"))
			}
		}
		sort.Strings(ports)
		out = append(out, traefikFromLabels(c.Config.Labels, name, "컨테이너 "+name, ports)...)
	}
	return out, nil
}

// ---------------------------------------------------------------- preview / apply

func (a *App) importSites(ctx context.Context, format string, files []importFile) (importResult, error) {
	st := a.store.Snapshot().Settings
	res := importResult{Format: format, Sites: []FoundSite{}, Warnings: []string{}}
	if strings.TrimSpace(st.Domain) == "" {
		return res, errors.New("도메인이 정해져 있지 않습니다 — 설정 탭 › 도메인에서 먼저 정하세요")
	}
	if format != "traefik-docker" && len(files) == 0 {
		return res, errors.New("불러올 파일을 고르세요")
	}
	if len(files) > 200 {
		return res, errors.New("한 번에 200개 파일까지 불러올 수 있습니다")
	}
	var found []FoundSite
	if format == "traefik-docker" {
		f, w := traefikFromContainers(ctx)
		found, res.Warnings = f, append(res.Warnings, w...)
	}
	for _, f := range files {
		if len(f.Content) > 1<<20 || !utf8.ValidString(f.Content) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: 1MB 이하의 UTF-8 텍스트가 아니라 건너뜁니다", f.Name))
			continue
		}
		fm := format
		if fm == "" || fm == "auto" {
			fm = detectFormat(f.Name, f.Content)
			if res.Format == "" || res.Format == "auto" {
				res.Format = fm
			}
		}
		var got []FoundSite
		var w []string
		switch fm {
		case "caddy":
			got, w = parseForeignCaddy(f.Content, st)
		case "nginx":
			got, w = parseNginx(f.Content, f.Name)
		case "traefik":
			got, w = parseTraefikFile(f.Name, f.Content)
		default:
			w = []string{fmt.Sprintf("%s: 형식을 알아내지 못했습니다 — 형식을 직접 고르세요", f.Name)}
		}
		for i := range got {
			if got[i].Source == "" {
				got[i].Source = f.Name
			}
		}
		found = append(found, got...)
		res.Warnings = append(res.Warnings, w...)
	}
	cur := map[string]*Service{}
	for _, s := range a.store.Snapshot().Services {
		cur[s.Subdomain] = s
	}
	seen := map[string]bool{}
	for _, fs := range found {
		if fs.Error == "" {
			sub, note, err := a.hostToSub(fs.Host, st)
			if err != nil {
				fs.Error = err.Error()
			} else {
				fs.Sub = sub
				if note != "" {
					fs.Notes = append([]string{note}, fs.Notes...)
				}
			}
		}
		switch {
		case fs.Error != "":
			fs.Status = "error"
		case seen[fs.Sub]:
			fs.Status, fs.Error = "error", "같은 서브도메인이 앞에 이미 있습니다 — 첫 번째만 씁니다"
		default:
			seen[fs.Sub] = true
			fs.Status = "new"
			if c := cur[fs.Sub]; c != nil {
				fs.Current = c.Upstream
				fs.Status = "exists"
				if c.Upstream == fs.Upstream {
					fs.Status = "same"
				}
			}
		}
		res.Sites = append(res.Sites, fs)
	}
	return res, nil
}

func readImportReq(r *http.Request) (format string, files []importFile, pick, overwrite map[string]bool, err error) {
	var in struct {
		Format    string       `json:"format"`
		Files     []importFile `json:"files"`
		Pick      []string     `json:"pick"`
		Overwrite []string     `json:"overwrite"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 12<<20))
	if err = dec.Decode(&in); err != nil {
		return "", nil, nil, nil, errors.New("요청이 너무 크거나 올바르지 않습니다 (파일 합계 최대 약 10MB)")
	}
	if in.Format != "" && in.Format != "auto" && importFormats[in.Format] == "" {
		return "", nil, nil, nil, errors.New("알 수 없는 형식입니다")
	}
	pick, overwrite = map[string]bool{}, map[string]bool{}
	for _, s := range in.Pick {
		pick[s] = true
	}
	for _, s := range in.Overwrite {
		overwrite[s] = true
	}
	return in.Format, in.Files, pick, overwrite, nil
}

func (a *App) postImportSites(w http.ResponseWriter, r *http.Request) {
	format, files, _, _, err := readImportReq(r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := a.importSites(ctx, format, files)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *App) postImportSitesApply(w http.ResponseWriter, r *http.Request) {
	format, files, pick, overwrite, err := readImportReq(r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := a.importSites(ctx, format, files)
	if err != nil {
		fail(w, 400, err)
		return
	}
	added, updated := []string{}, []string{}
	var skipped []string
	err = a.store.Update(func(d *Data) error {
		for _, fs := range res.Sites {
			if !pick[fs.Sub] || fs.Status == "error" || fs.Status == "same" {
				continue
			}
			var existing *Service
			for _, s := range d.Services {
				if s.Subdomain == fs.Sub {
					existing = s
				}
			}
			if existing != nil {
				if !overwrite[fs.Sub] {
					continue
				}
				cp := *existing
				cp.Upstream = fs.Upstream
				if err := validateService(&cp, d.Services, d.Settings); err != nil {
					skipped = append(skipped, fs.Sub+": "+err.Error())
					continue
				}
				cp.Updated = time.Now()
				*existing = cp
				updated = append(updated, fs.Sub)
				continue
			}
			s := fs.svc
			if s == nil {
				s = &Service{Upstream: fs.Upstream, Exposure: ExposurePublic, Enabled: true, ManageDNS: true,
					Authelia: AutheliaOpts{Policy: "two_factor"}}
			}
			s.ID, s.Subdomain = newID(), fs.Sub
			s.Authelia.Groups = nil // groups are Gilmok's own (registered) list — pick them after importing
			if fs.Host != "" && s.Notes == "" {
				s.Notes = fmt.Sprintf("불러옴: %s", fs.Host)
			}
			if err := validateService(s, d.Services, d.Settings); err != nil {
				skipped = append(skipped, fs.Sub+": "+err.Error())
				continue
			}
			s.Updated = time.Now()
			d.Services = append(d.Services, s)
			added = append(added, fs.Sub)
		}
		if len(added)+len(updated) > 0 {
			d.markDirty(fmt.Sprintf("서비스 불러오기 (%s) — 추가 %d · 대상 변경 %d", importFormats[res.Format], len(added), len(updated)))
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.detectSelf()
	a.auth.audit(r, "audit", "warn", "서비스 불러오기", importFormats[res.Format],
		fmt.Sprintf("서비스 불러오기 (%s) — 추가 %d · 대상 변경 %d · 건너뜀 %d", importFormats[res.Format], len(added), len(updated), len(skipped)),
		map[string]any{"added": added, "updated": updated})
	writeJSON(w, 200, map[string]any{"added": added, "updated": updated, "skipped": skipped})
}
