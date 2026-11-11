package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------- request context

type ctxKey int

const (
	ctxAccess ctxKey = iota
	ctxSession
)

func withAccess(ctx context.Context, a access) context.Context {
	return context.WithValue(ctx, ctxAccess, a)
}
func accessOf(ctx context.Context) access {
	a, _ := ctx.Value(ctxAccess).(access)
	return a
}
func withSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxSession, s)
}
func sessionOf(ctx context.Context) *Session {
	s, _ := ctx.Value(ctxSession).(*Session)
	return s
}

// ---------------------------------------------------------------- audit middleware

// Every state-changing API call is written to the audit log: who, what, result, the request
// (secrets redacted) and, for settings / services, a field-level before→after diff.

type auditRoute struct {
	re     *regexp.Regexp
	method string
	label  string
	level  string
}

var auditRoutes = []auditRoute{
	{regexp.MustCompile(`^/api/groups$`), "POST", "Authelia 그룹 추가", "info"},
	{regexp.MustCompile(`^/api/services$`), "POST", "서비스 추가", "info"},
	{regexp.MustCompile(`^/api/services/[^/]+$`), "PUT", "서비스 수정", "info"},
	{regexp.MustCompile(`^/api/services/[^/]+$`), "DELETE", "서비스 삭제", "warn"},
	{regexp.MustCompile(`^/api/settings$`), "PUT", "설정 변경", "info"},
	{regexp.MustCompile(`^/api/import$`), "POST", "기존 설정 가져오기", "warn"},
	{regexp.MustCompile(`^/api/apply$`), "POST", "적용 (Caddy·Authelia·DNS)", "warn"},
	{regexp.MustCompile(`^/api/users$`), "POST", "Authelia 사용자 추가", "warn"},
	{regexp.MustCompile(`^/api/users/[^/]+$`), "PUT", "Authelia 사용자 수정", "warn"},
	{regexp.MustCompile(`^/api/users/[^/]+$`), "DELETE", "Authelia 사용자 삭제", "warn"},
	{regexp.MustCompile(`^/api/system/update$`), "POST", "이미지 업데이트", "warn"},
	{regexp.MustCompile(`^/api/dashboard$`), "PUT", "대시보드 배치 변경", "info"},
	{regexp.MustCompile(`^/api/dns/records$`), "POST", "DNS 레코드 직접 추가", "warn"},
	{regexp.MustCompile(`^/api/dns/records/[^/]+$`), "PUT", "DNS 레코드 직접 수정", "warn"},
	{regexp.MustCompile(`^/api/dns/records/[^/]+$`), "DELETE", "DNS 레코드 직접 삭제", "critical"},
	{regexp.MustCompile(`^/api/ddns/run$`), "POST", "DDNS Updater 지금 확인", "info"},
	{regexp.MustCompile(`^/api/waf/test$`), "POST", "WAF 시험 요청", "info"},
	{regexp.MustCompile(`^/api/cloudflare/token$`), "POST", "Cloudflare API 토큰 저장", "warn"},
	{regexp.MustCompile(`^/api/cloudflare/token$`), "DELETE", "Cloudflare API 토큰 삭제", "warn"},
	{regexp.MustCompile(`^/api/crowdsec/bouncer$`), "POST", "CrowdSec 바운서 키 만들기", "warn"},
	{regexp.MustCompile(`^/api/cfwaf/apply$`), "POST", "Cloudflare WAF 규칙 적용", "warn"},
	{regexp.MustCompile(`^/api/cfwaf/adopt$`), "POST", "Cloudflare 규칙 가져오기", "info"},
	{regexp.MustCompile(`^/api/crowdsec/decisions$`), "POST", "CrowdSec 수동 차단", "warn"},
	{regexp.MustCompile(`^/api/crowdsec/decisions/[^/]+$`), "DELETE", "CrowdSec 차단 해제", "warn"},
	{regexp.MustCompile(`^/api/crowdsec/sync$`), "POST", "CrowdSec 동기화", "info"},
	{regexp.MustCompile(`^/api/logs/delete$`), "POST", "로그 삭제", "critical"},
	{regexp.MustCompile(`^/api/dev/fault$`), "POST", "장애 주입 예약 (테스트)", "warn"},
	{regexp.MustCompile(`^/api/updates/check$`), "POST", "업데이트 확인", "info"},
}

var reSecretKey = regexp.MustCompile(`(?i)pass|secret|token|code|key|hash`)

func redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if reSecretKey.MatchString(k) {
				if s, ok := val.(string); ok && s != "" {
					x[k] = "***"
					continue
				}
			}
			x[k] = redact(val)
		}
	case []any:
		for i := range x {
			x[i] = redact(x[i])
		}
	}
	return v
}

type capture struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *capture) WriteHeader(s int) { c.status = s; c.ResponseWriter.WriteHeader(s) }
func (c *capture) Write(b []byte) (int, error) {
	if c.buf.Len() < 64<<10 {
		c.buf.Write(b)
	}
	return c.ResponseWriter.Write(b)
}

func (a *App) auditMW(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			h.ServeHTTP(w, r)
			return
		}
		var route *auditRoute
		for i := range auditRoutes {
			if auditRoutes[i].method == r.Method && auditRoutes[i].re.MatchString(r.URL.Path) {
				route = &auditRoutes[i]
				break
			}
		}
		if route == nil {
			h.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		r.Body = io.NopCloser(bytes.NewReader(body))
		before := a.store.Snapshot()
		cw := &capture{ResponseWriter: w, status: 200}
		h.ServeHTTP(cw, r)
		after := a.store.Snapshot()

		detail := map[string]any{"path": r.URL.Path}
		var req any
		if json.Unmarshal(body, &req) == nil && req != nil {
			detail["request"] = redact(req)
		}
		var resp map[string]any
		ok := cw.status < 400
		msg := route.label
		if json.Unmarshal(cw.buf.Bytes(), &resp) == nil {
			if e, _ := resp["error"].(string); e != "" {
				msg += " — 실패: " + truncate(e, 300)
			}
			if v, has := resp["ok"].(bool); has {
				ok = ok && v
			}
			if lines, has := resp["log"]; has {
				detail["log"] = lines
			}
		}
		if ok && !strings.Contains(msg, "실패") {
			msg += " — 완료"
		} else if !strings.Contains(msg, "실패") {
			msg += " — 실패"
		}
		target := ""
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/settings"):
			if ch := diffStruct(before.Settings, after.Settings); len(ch) > 0 {
				detail["changed"] = ch
				keys := make([]string, 0, len(ch))
				for k := range ch {
					keys = append(keys, k)
				}
				target = truncate(strings.Join(keys, ", "), 200)
			}
		case strings.HasPrefix(r.URL.Path, "/api/services"):
			b, af := serviceDiff(before, after)
			if b != nil || af != nil {
				if b != nil && af != nil {
					detail["changed"] = diffStruct(*b, *af)
				}
				detail["before"], detail["after"] = b, af
				if af != nil {
					target = after.Settings.FQDN(af.Subdomain)
				} else {
					target = before.Settings.FQDN(b.Subdomain)
				}
			}
		case strings.HasPrefix(r.URL.Path, "/api/users"):
			target = strings.TrimPrefix(r.URL.Path, "/api/users/")
		}
		level := route.level
		if !ok {
			level = "error"
		}
		e := Event{Cat: "audit", Level: level, Action: route.label, Target: target, Msg: msg, Actor: a.auth.actor(r), IP: clientIP(r)}
		if b, err := json.Marshal(detail); err == nil {
			e.Detail = truncate(string(b), 60000)
		}
		a.ldb.Event(e)
	})
}

// serviceDiff finds the service that was added / changed / removed between two snapshots.
func serviceDiff(before, after Data) (*Service, *Service) {
	bm := map[string]*Service{}
	for _, s := range before.Services {
		bm[s.ID] = s
	}
	am := map[string]*Service{}
	for _, s := range after.Services {
		am[s.ID] = s
	}
	for id, s := range am {
		if o, ok := bm[id]; !ok {
			return nil, s
		} else if !reflect.DeepEqual(stripUpdated(*o), stripUpdated(*s)) {
			return o, s
		}
	}
	for id, s := range bm {
		if _, ok := am[id]; !ok {
			return s, nil
		}
	}
	return nil, nil
}

func stripUpdated(s Service) Service { s.Updated = time.Time{}; return s }

// diffStruct returns {field: {from, to}} for differing JSON fields (long text summarized).
func diffStruct(a, b any) map[string]any {
	toMap := func(v any) map[string]any {
		var m map[string]any
		raw, _ := json.Marshal(v)
		_ = json.Unmarshal(raw, &m)
		return m
	}
	am, bm := toMap(a), toMap(b)
	out := map[string]any{}
	for k, bv := range bm {
		if k == "updated" {
			continue
		}
		av := am[k]
		if reflect.DeepEqual(av, bv) {
			continue
		}
		out[k] = map[string]any{"from": summarize(av), "to": summarize(bv)}
	}
	return out
}

func summarize(v any) any {
	if s, ok := v.(string); ok && len(s) > 200 {
		return fmt.Sprintf("(%d줄, %d자) %s…", strings.Count(s, "\n")+1, len(s), s[:120])
	}
	return v
}
