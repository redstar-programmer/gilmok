package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Access security. Gilmok controls the whole edge (proxy, SSO, DNS, WAF), so every layer applies:
//
//  1. access path  — only (a) the host-published port (the request comes from the container's
//     network gateway, or loopback when Gilmok runs natively) or (b) Caddy carrying the
//     per-install X-Gilmok-Proxy secret. Any other container on the shared Docker network that
//     tries gilmok:8080 directly is refused and logged.
//  2. SSO          — through Caddy, an Authelia user (Remote-User, optionally in given groups)
//  3. login        — admin password (argon2id) + optional TOTP; escalating lockout
//  4. session      — random 256-bit token, HttpOnly + SameSite=Strict (+Secure behind HTTPS),
//     idle and absolute timeout, list / revoke
//  5. step-up      — sensitive actions need a fresh password (+TOTP) within N minutes
//  6. CSRF         — custom header on writes + Origin check; strict CSP and security headers

const (
	sessionCookie = "gm_session"
	proxyHeader   = "X-Gilmok-Proxy"
)

type Session struct {
	ID       string    `json:"id"` // public id (not the token)
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"lastSeen"`
	Reauth   time.Time `json:"reauth"`
	IP       string    `json:"ip"`
	UA       string    `json:"ua"`
	Via      string    `json:"via"` // direct | proxy
	SSOUser  string    `json:"ssoUser,omitempty"`
	User     string    `json:"user"` // Gilmok account
	token    string
}

type Auth struct {
	app      *App
	store    *Store
	mu       sync.Mutex
	sessions map[string]*Session // token → session
	fails    map[string]*failState
	gwMu     sync.Mutex
	gateways []net.IP
	gwAt     time.Time
	denyLog  map[string]time.Time
}

type failState struct {
	n        int
	first    time.Time // start of the current counting window
	lockTill time.Time
	locks    int
}

func newAuth(app *App) *Auth {
	return &Auth{app: app, store: app.store, sessions: map[string]*Session{}, fails: map[string]*failState{}, denyLog: map[string]time.Time{}}
}

// clientIP: who is on the other end, for logs and per-client lockout. Through Gilmok's own Caddy
// site (verified by the proxy secret) the TCP peer is Caddy, so take the address Caddy appended
// to X-Forwarded-For (the last entry — earlier ones are client-supplied and can be forged).
func clientIP(r *http.Request) string {
	if accessOf(r.Context()).via == "proxy" {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	return peerIP(r)
}

// peerIP: the TCP peer — the only address the access-path check may trust.
func peerIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------------------------------------------------------------- access path

// gatewayIPs: gateways of this container's networks (host-published ports arrive from there).
func (a *Auth) gatewayIPs() []net.IP {
	a.gwMu.Lock()
	defer a.gwMu.Unlock()
	if time.Since(a.gwAt) < 5*time.Minute && a.gwAt.Year() > 2000 {
		return a.gateways
	}
	a.gwAt = time.Now()
	name, err := hostnameSelf()
	if err != nil || name == "" {
		return a.gateways
	}
	ctx, cancel := withTimeout(5 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{json .NetworkSettings.Networks}}", name)
	if err != nil {
		return a.gateways
	}
	var nets map[string]struct{ Gateway string }
	if json.Unmarshal([]byte(out), &nets) != nil {
		return a.gateways
	}
	var gws []net.IP
	for _, n := range nets {
		if ip := net.ParseIP(n.Gateway); ip != nil {
			gws = append(gws, ip)
		}
	}
	a.gateways = gws
	return gws
}

type access struct {
	ok      bool
	via     string // direct | proxy
	ssoUser string
	reason  string
}

func (a *Auth) checkAccess(r *http.Request) access {
	d := a.store.Snapshot()
	st := d.Settings
	ip := net.ParseIP(peerIP(r))
	if got := r.Header.Get(proxyHeader); got != "" {
		if d.ProxySecret == "" || subtle.ConstantTimeCompare([]byte(got), []byte(d.ProxySecret)) != 1 {
			return access{reason: "잘못된 프록시 비밀 헤더"}
		}
		if !st.SecAllowProxy {
			return access{reason: "Caddy 경유 접속이 꺼져 있습니다"}
		}
		user := strings.TrimSpace(r.Header.Get("Remote-User"))
		if st.SecRequireSSO && st.UseAuthelia {
			if user == "" {
				return access{reason: "Authelia 로그인이 필요합니다 (Remote-User 없음 — 길목 사이트에 Authelia를 켜세요)"}
			}
			if want := splitCSV(st.SecSSOGroups); len(want) > 0 {
				have := splitCSV(r.Header.Get("Remote-Groups"))
				if !intersects(want, have) {
					return access{reason: fmt.Sprintf("Authelia 사용자 %s 는 허용 그룹(%s)에 없습니다", user, strings.Join(want, ", "))}
				}
			}
		}
		return access{ok: true, via: "proxy", ssoUser: user}
	}
	if ip != nil && ip.IsLoopback() {
		if st.SecAllowDirect {
			return access{ok: true, via: "direct"}
		}
		return access{reason: "직접 접속이 꺼져 있습니다"}
	}
	for _, g := range a.gatewayIPs() {
		if ip != nil && g.Equal(ip) {
			if st.SecAllowDirect {
				return access{ok: true, via: "direct"}
			}
			return access{reason: "직접 접속(호스트 포트)이 꺼져 있습니다"}
		}
	}
	return access{reason: "허용되지 않은 경로 — 같은 네트워크의 다른 컨테이너에서 직접 접속한 것으로 보입니다"}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// guard wraps everything (UI + API).
func (a *Auth) guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" { // docker healthcheck from inside the container
			if ip := net.ParseIP(peerIP(r)); ip != nil && ip.IsLoopback() {
				w.Write([]byte("ok"))
				return
			}
		}
		acc := a.checkAccess(r)
		if !acc.ok {
			key := clientIP(r) + "|" + acc.reason
			a.mu.Lock()
			last := a.denyLog[key]
			if time.Since(last) > 10*time.Minute {
				a.denyLog[key] = time.Now()
			}
			a.mu.Unlock()
			if time.Since(last) > 10*time.Minute {
				a.app.ldb.Event(Event{Cat: "security", Level: "warn", Action: "access.denied", Target: r.URL.Path, Msg: acc.reason, IP: clientIP(r), Actor: "-"})
			}
			http.Error(w, "403 forbidden — "+acc.reason, http.StatusForbidden)
			return
		}
		// CSRF defence in depth: a cross-site Origin is never accepted on writes
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					http.Error(w, "403 cross-origin", http.StatusForbidden)
					return
				}
			}
		}
		h.ServeHTTP(w, r.WithContext(withAccess(r.Context(), acc)))
	})
}

// ---------------------------------------------------------------- sessions

func (a *Auth) policy() (idle, abs, reauth time.Duration) {
	st := a.store.Snapshot().Settings
	idle = time.Duration(max(st.SecIdleMin, 5)) * time.Minute
	abs = time.Duration(max(st.SecAbsHours, 1)) * time.Hour
	reauth = time.Duration(max(st.SecReauthMin, 1)) * time.Minute
	return
}

func (a *Auth) session(r *http.Request) *Session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	idle, abs, _ := a.policy()
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return nil
	}
	now := time.Now()
	if now.Sub(s.LastSeen) > idle || now.Sub(s.Created) > abs {
		delete(a.sessions, c.Value)
		return nil
	}
	s.LastSeen = now
	return s
}

func (a *Auth) newSession(w http.ResponseWriter, r *http.Request, fresh bool, user string) *Session {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	pid := make([]byte, 6)
	_, _ = rand.Read(pid)
	acc := accessOf(r.Context())
	now := time.Now()
	s := &Session{ID: hex.EncodeToString(pid), Created: now, LastSeen: now, IP: clientIP(r), UA: truncate(r.UserAgent(), 160), Via: acc.via, SSOUser: acc.ssoUser, token: tok, User: user}
	if fresh {
		s.Reauth = now
	}
	a.mu.Lock()
	a.sessions[tok] = s
	a.mu.Unlock()
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
	return s
}

// require: a live session of an existing, enabled account; then the account's gate (temporary
// password / mandatory 2FA enrolment) and the route's permission.
func (a *Auth) require(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := a.session(r)
		if s == nil {
			fail(w, 401, errors.New("로그인이 필요합니다"))
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-GM") != "1" {
			fail(w, 403, errors.New("잘못된 요청"))
			return
		}
		var gate string
		var perms map[string]bool
		alive := false
		a.store.Read(func(d *Data) {
			if acct := d.account(s.User); acct != nil && !acct.Disabled {
				alive, gate, perms = true, gateOf(d, acct), d.permsOf(acct)
			}
		})
		if !alive { // account deleted or disabled meanwhile
			a.revokeUser(s.User, nil)
			fail(w, 401, errors.New("계정이 사용 중지되었거나 삭제되었습니다 — 다시 로그인하세요"))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if gate != "" && !gateAllows(gate, r.Method, r.URL.Path) {
			msg := map[string]string{
				"bootstrap": "초기 계정입니다 — 먼저 진짜 관리자 계정을 만드세요",
				"password":  "임시 비밀번호입니다 — 먼저 새 비밀번호를 정하세요",
				"2fa":       "2단계 인증이 필수입니다 — 먼저 설정하세요",
			}[gate]
			writeJSON(w, 403, map[string]any{"error": msg, "gate": gate})
			return
		}
		if p := permFor(r.Method, r.URL.Path); p != "" && !perms[p] {
			a.audit(r.WithContext(withSession(r.Context(), s)), "security", "warn", "auth.forbidden", r.Method+" "+r.URL.Path,
				fmt.Sprintf("권한 없는 요청 거부 — 「%s」 권한 필요", permName(p)), nil)
			writeJSON(w, 403, map[string]any{"error": fmt.Sprintf("권한이 없습니다 — 「%s」 권한이 필요합니다 (설정 › 계정 관리)", permName(p)), "perm": p})
			return
		}
		ctx := withPerms(withSession(r.Context(), s), perms)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sensitive: step-up authentication for dangerous actions.
func (a *Auth) sensitive(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.recentlyVerified(r) {
			writeJSON(w, 403, map[string]any{"error": "중요한 작업입니다 — 비밀번호를 다시 확인해 주세요", "reauth": true})
			return
		}
		h(w, r)
	}
}

func (a *Auth) recentlyVerified(r *http.Request) bool {
	s := sessionOf(r.Context())
	_, _, win := a.policy()
	a.mu.Lock()
	defer a.mu.Unlock()
	return s != nil && time.Since(s.Reauth) <= win
}

// ---------------------------------------------------------------- brute force

func (a *Auth) lockedFor(key string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[key]
	if f == nil {
		return 0
	}
	return time.Until(f.lockTill)
}

func (a *Auth) noteFail(key string) (locked time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[key]
	if f == nil {
		f = &failState{}
		a.fails[key] = f
	}
	// the shared key (all clients) must not become a cheap way to lock everyone out: it needs many
	// more failures, locks briefly, and is never cleared by someone else's successful login
	limit, base, maxD := 5, 5*time.Minute, time.Hour
	if key == globalKey {
		limit, base, maxD = 30, time.Minute, 15*time.Minute
	}
	if time.Since(f.first) > 15*time.Minute {
		f.n, f.first = 0, time.Now()
	}
	f.n++
	if f.n >= limit {
		f.locks++
		d := time.Duration(math.Min(float64(base)*math.Pow(2, float64(f.locks-1)), float64(maxD)))
		f.lockTill, f.n = time.Now().Add(d), 0
		return d
	}
	return 0
}

func (a *Auth) noteOK(key string) {
	a.mu.Lock()
	delete(a.fails, key)
	a.mu.Unlock()
}

// gateAllows: while an account must first finish a gate (initial account, temporary password,
// required 2FA) only the calls that gate needs get through.
func gateAllows(gate, method, path string) bool {
	switch {
	case path == "/api/auth/reauth" && method == http.MethodPost:
		return true // the 2FA steps are step-up protected
	case gate == "bootstrap":
		return path == "/api/auth/bootstrap"
	case gate == "password":
		return path == "/api/auth/password"
	case gate == "2fa":
		return path == "/api/auth/totp/begin" || path == "/api/auth/totp/enable" || path == "/api/auth/recovery"
	}
	return false
}

// all login attempts share one key too: Docker Desktop hides client IPs, so a per-IP limit alone is weak
const globalKey = "*"

// ---------------------------------------------------------------- TOTP (RFC 6238, SHA1, 6 digits, 30 s)

func totpCode(secret string, t time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

func totpVerify(secret, code string) bool {
	return totpStep(secret, code) > 0
}

// totpStep: the 30-second step the code belongs to (now ±1), 0 if it matches none.
func totpStep(secret, code string) int64 {
	code = strings.TrimSpace(code)
	if secret == "" || len(code) != 6 {
		return 0
	}
	now := time.Now()
	for _, d := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		t := now.Add(d)
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, t)), []byte(code)) == 1 {
			return t.Unix() / 30
		}
	}
	return 0
}

func newTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// ---------------------------------------------------------------- handlers

// ensureProxySecret creates the per-install secret Caddy sends for Gilmok's own site.
func ensureProxySecret(s *Store) {
	if s.Snapshot().ProxySecret != "" {
		return
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	sum := sha256.Sum256(b)
	_ = s.Update(func(d *Data) error {
		if d.ProxySecret == "" {
			d.ProxySecret = hex.EncodeToString(sum[:])
		}
		return nil
	})
}
