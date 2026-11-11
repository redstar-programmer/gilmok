package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"rsc.io/qr"
)

// Gilmok accounts: several people, each with a role (set of permissions) and their own TOTP.
//
//   - Data.Accounts / Data.Roles live in gilmok.json (hashes and TOTP secrets never leave the server)
//   - every API request resolves the session's account again, so disabling / deleting an account
//     or changing its role takes effect immediately
//   - first run: a built-in account admin / admin (Bootstrap). Logging in with it only allows
//     creating a real admin account; that disables admin/admin for good (password scrambled)
//   - 2FA is each person's choice (내 계정); an account manager can require it per account
//     (Account.Require2FA, one by one or in bulk) — such an account can do nothing but enrol until done
//   - at least one enabled account with the 「accounts」 permission always remains

type Account struct {
	Name        string    `json:"name"`
	Display     string    `json:"display,omitempty"`
	Role        string    `json:"role"`
	Hash        string    `json:"hash"`                  // argon2id — never sent to the UI
	TOTP        string    `json:"totp,omitempty"`        // base32 secret — never sent
	TOTPLast    int64     `json:"totpLast,omitempty"`    // last accepted step — a code works once
	TOTPPending string    `json:"totpPending,omitempty"` //
	Recovery    []string  `json:"recovery,omitempty"`    // sha256 of unused recovery codes
	Disabled    bool      `json:"disabled,omitempty"`
	MustChange  bool      `json:"mustChange,omitempty"` // temporary password: change at next login
	Require2FA  bool      `json:"require2fa,omitempty"` // an account manager requires TOTP for this account
	Bootstrap   bool      `json:"bootstrap,omitempty"`  // the built-in admin/admin of a fresh install
	Created     time.Time `json:"created"`
	LastLogin   time.Time `json:"lastLogin,omitempty"`
	PwChanged   time.Time `json:"pwChanged,omitempty"`
}

type Role struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Perms   []string `json:"perms"`
	Builtin bool     `json:"builtin"`
}

type permDef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

var permCatalog = []permDef{
	{"config", "구성 변경", "서비스, Caddy·Authelia·Cloudflare·CrowdSec 설정, 대시보드 배치 저장 (실제 반영은 「적용」)"},
	{"apply", "적용·외부 반영", "적용, 이미지 업데이트, 기존 설정 가져오기, Cloudflare 규칙·DNS 레코드 직접 변경, DDNS·CrowdSec 동기화"},
	{"authelia_users", "Authelia 사용자", "Authelia 로그인 사용자 추가·수정·삭제"},
	{"security", "차단 관리", "CrowdSec 수동 차단·해제, WAF 시험 요청"},
	{"logs", "로그 관리", "로그 내보내기·삭제, 보존·디스크 설정"},
	{"accounts", "계정·접근 보안", "길목 계정·역할 관리, 2단계 인증 정책·접근 경로·세션 설정, 다른 사람 세션 종료"},
	{"system", "연결·시스템", "구성요소 사용 여부, 컨테이너 이름, 설정 파일·폴더 경로, Caddy 연결 방식(실행 파일·관리 API), CrowdSec 주소 변경"},
}

func allPermIDs() []string {
	out := make([]string, len(permCatalog))
	for i, p := range permCatalog {
		out[i] = p.ID
	}
	return out
}

func permName(id string) string {
	for _, p := range permCatalog {
		if p.ID == id {
			return p.Name
		}
	}
	return id
}

func defaultRoles() []*Role {
	return []*Role{
		{ID: "admin", Name: "관리자", Perms: allPermIDs(), Builtin: true},
		{ID: "operator", Name: "운영자", Perms: []string{"config", "apply", "authelia_users", "security"}, Builtin: true},
		{ID: "viewer", Name: "보기 전용", Perms: []string{}, Builtin: true},
	}
}

// migrateAccounts: the single admin of earlier versions becomes account "admin"; roles get defaults.
func migrateAccounts(d *Data) {
	if len(d.Roles) == 0 {
		d.Roles = defaultRoles()
	}
	for _, r := range d.Roles {
		if r.ID == "admin" {
			r.Perms, r.Builtin = allPermIDs(), true // the catalog may have grown
		}
	}
	if len(d.Accounts) == 0 && d.AdminHash != "" {
		d.Accounts = []*Account{{Name: "admin", Display: "관리자", Role: "admin", Hash: d.AdminHash, TOTP: d.TOTPSecret, Created: time.Now()}}
		d.AdminHash, d.TOTPSecret, d.TOTPPending = "", "", ""
	}
	if len(d.Accounts) == 0 { // fresh install: admin / admin, only good for creating the real admin
		h, _ := HashPassword(bootstrapPassword)
		d.Accounts = []*Account{{Name: "admin", Display: "초기 관리자", Role: "admin", Hash: h, Bootstrap: true, Created: time.Now()}}
	}
	if d.Settings.SecRequire2FA { // the old all-accounts switch becomes a per-account requirement
		for _, a := range d.Accounts {
			a.Require2FA = true
		}
		d.Settings.SecRequire2FA = false
	}
}

const bootstrapPassword = "admin"

func (d *Data) account(name string) *Account {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, a := range d.Accounts {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func (d *Data) role(id string) *Role {
	for _, r := range d.Roles {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (d *Data) permsOf(a *Account) map[string]bool {
	m := map[string]bool{}
	if a == nil {
		return m
	}
	if a.Role == "admin" {
		for _, p := range allPermIDs() {
			m[p] = true
		}
		return m
	}
	if r := d.role(a.Role); r != nil {
		for _, p := range r.Perms {
			m[p] = true
		}
	}
	return m
}

// adminsLeft: enabled accounts that can manage accounts, ignoring `skip`.
func (d *Data) adminsLeft(skip string) int {
	n := 0
	for _, a := range d.Accounts {
		if a.Name != skip && !a.Disabled && d.permsOf(a)["accounts"] {
			n++
		}
	}
	return n
}

var reAccountName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

func validatePassword(name, pw string) error {
	switch {
	case len(pw) < 12:
		return errors.New("비밀번호는 12자 이상이어야 합니다")
	case len(pw) > 200:
		return errors.New("비밀번호가 너무 깁니다")
	case strings.Contains(strings.ToLower(pw), strings.ToLower(name)) && len(name) >= 3:
		return errors.New("비밀번호에 아이디를 넣을 수 없습니다")
	}
	return nil
}

func randomPassword() string {
	const alpha = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = alpha[int(c)%len(alpha)]
	}
	return string(out[:4]) + "-" + string(out[4:8]) + "-" + string(out[8:12]) + "-" + string(out[12:])
}

func hashRecovery(code string) string {
	c := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte("gilmok-recovery:" + c))
	return hex.EncodeToString(sum[:])
}

func newRecoveryCodes() (plain, hashed []string) {
	for i := 0; i < 10; i++ {
		b := make([]byte, 5)
		_, _ = rand.Read(b)
		h := hex.EncodeToString(b)
		code := h[:5] + "-" + h[5:]
		plain = append(plain, code)
		hashed = append(hashed, hashRecovery(code))
	}
	return
}

// ---------------------------------------------------------------- route permissions

type permRoute struct {
	re     *regexp.Regexp
	writes bool // only for non-GET methods
	perm   string
}

var permRoutes = []permRoute{
	{regexp.MustCompile(`^/api/auth/`), false, ""}, // own account
	{regexp.MustCompile(`^/api/accounts`), false, "accounts"},
	{regexp.MustCompile(`^/api/roles`), false, "accounts"},
	{regexp.MustCompile(`^/api/logs/export$`), false, "logs"},
	{regexp.MustCompile(`^/api/logs/delete$`), true, "logs"},
	{regexp.MustCompile(`^/api/(apply|import)$`), true, "apply"},
	{regexp.MustCompile(`^/api/system/update$`), true, "apply"},
	{regexp.MustCompile(`^/api/cfwaf/(apply|adopt)$`), true, "apply"},
	{regexp.MustCompile(`^/api/dns/records`), true, "apply"},
	{regexp.MustCompile(`^/api/ddns/run$`), true, "apply"},
	{regexp.MustCompile(`^/api/crowdsec/sync$`), true, "apply"},
	{regexp.MustCompile(`^/api/crowdsec/bouncer$`), true, "system"},
	{regexp.MustCompile(`^/api/stacks/`), true, "system"},
	{regexp.MustCompile(`^/api/dev/fault$`), true, "apply"},
	{regexp.MustCompile(`^/api/crowdsec/decisions`), true, "security"},
	{regexp.MustCompile(`^/api/waf/test$`), true, "security"},
	{regexp.MustCompile(`^/api/config/export$`), false, "config"},
	{regexp.MustCompile(`^/api/users`), true, "authelia_users"},
	{regexp.MustCompile(`^/api/(updates/check|dash/data|validate)$`), true, ""}, // reads that use POST
}

func permFor(method, path string) string {
	write := method != http.MethodGet && method != http.MethodHead
	for _, r := range permRoutes {
		if r.re.MatchString(path) && (!r.writes || write) {
			return r.perm
		}
	}
	if write {
		return "config"
	}
	return ""
}

type permsKey struct{}

func withPerms(ctx context.Context, p map[string]bool) context.Context {
	return context.WithValue(ctx, permsKey{}, p)
}

func (a *Auth) can(r *http.Request, perm string) bool {
	p, _ := r.Context().Value(permsKey{}).(map[string]bool)
	return p[perm]
}

// gate: what the account must do before it may use the app ("" = nothing).
func gateOf(d *Data, acct *Account) string {
	switch {
	case acct.Bootstrap:
		return "bootstrap"
	case acct.MustChange:
		return "password"
	case acct.Require2FA && acct.TOTP == "":
		return "2fa"
	}
	return ""
}

// ---------------------------------------------------------------- views

type accountView struct {
	Name       string    `json:"name"`
	Display    string    `json:"display"`
	Role       string    `json:"role"`
	RoleName   string    `json:"roleName"`
	TOTP       bool      `json:"totp"`
	Recovery   int       `json:"recovery"` // unused recovery codes
	Disabled   bool      `json:"disabled"`
	MustChange bool      `json:"mustChange"`
	Require2FA bool      `json:"require2fa"`
	Bootstrap  bool      `json:"bootstrap"`
	Created    time.Time `json:"created"`
	LastLogin  time.Time `json:"lastLogin"`
	PwChanged  time.Time `json:"pwChanged"`
	Sessions   int       `json:"sessions"`
}

func (a *Auth) viewOf(d *Data, acct *Account) accountView {
	v := accountView{Name: acct.Name, Display: acct.Display, Role: acct.Role, TOTP: acct.TOTP != "", Recovery: len(acct.Recovery),
		Disabled: acct.Disabled, MustChange: acct.MustChange, Require2FA: acct.Require2FA, Bootstrap: acct.Bootstrap, Created: acct.Created, LastLogin: acct.LastLogin, PwChanged: acct.PwChanged}
	if r := d.role(acct.Role); r != nil {
		v.RoleName = r.Name
	}
	a.mu.Lock()
	for _, s := range a.sessions {
		if s.User == acct.Name {
			v.Sessions++
		}
	}
	a.mu.Unlock()
	return v
}

func (a *Auth) meView(d *Data, acct *Account) map[string]any {
	perms := []string{}
	for p, ok := range d.permsOf(acct) {
		if ok {
			perms = append(perms, p)
		}
	}
	sort.Strings(perms)
	v := a.viewOf(d, acct)
	return map[string]any{"name": v.Name, "display": v.Display, "role": v.Role, "roleName": v.RoleName, "perms": perms,
		"totp": v.TOTP, "recovery": v.Recovery, "gate": gateOf(d, acct), "require2fa": acct.Require2FA}
}

// ---------------------------------------------------------------- auth handlers (own account)

var dummyHash string // compared when the account does not exist, so timing does not reveal names

func (a *Auth) state(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	acc := accessOf(r.Context())
	firstRun := false
	for _, x := range d.Accounts {
		if x.Bootstrap && !x.Disabled {
			firstRun = true
		}
	}
	// before login: only what the login screen needs (firstRun = show the admin/admin hint)
	res := map[string]any{"setup": len(d.Accounts) == 0, "firstRun": firstRun, "loggedIn": false, "lang": d.Settings.Lang}
	if s := a.session(r); s != nil {
		if acct := d.account(s.User); acct != nil && !acct.Disabled {
			res["loggedIn"], res["me"] = true, a.meView(&d, acct)
			res["version"], res["via"], res["ssoUser"] = version, acc.via, acc.ssoUser
		}
	}
	writeJSON(w, 200, res)
}

func (a *Auth) audit(r *http.Request, cat, level, action, target, msg string, detail any) {
	a.auditAs(r, a.actor(r), cat, level, action, target, msg, detail)
}

func (a *Auth) auditAs(r *http.Request, actor, cat, level, action, target, msg string, detail any) {
	e := Event{Cat: cat, Level: level, Action: action, Target: target, Msg: msg, Actor: actor, IP: clientIP(r)}
	if detail != nil {
		e.Detail = truncate(mustJSON(detail), 20000)
	}
	a.app.ldb.Event(e)
}

func viaText(r *http.Request) string {
	acc := accessOf(r.Context())
	switch {
	case acc.ssoUser != "":
		return "Authelia: " + acc.ssoUser
	case acc.via == "direct":
		return "호스트 직접"
	}
	return "Caddy 경유"
}

func (a *Auth) actor(r *http.Request) string {
	if s := sessionOf(r.Context()); s != nil && s.User != "" {
		return s.User + " (" + viaText(r) + ")"
	}
	return "- (" + viaText(r) + ")"
}

func (a *Auth) setup(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Password string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if in.Name == "" {
		in.Name = "admin"
	}
	if !reAccountName.MatchString(in.Name) {
		fail(w, 400, errors.New("아이디는 영문 소문자·숫자·. _ - 로 2~32자입니다"))
		return
	}
	if err := validatePassword(in.Name, in.Password); err != nil {
		fail(w, 400, err)
		return
	}
	h, _ := HashPassword(in.Password)
	now := time.Now()
	err := a.store.Update(func(d *Data) error {
		if len(d.Accounts) > 0 {
			return errors.New("이미 설정되어 있습니다")
		}
		migrateAccounts(d)
		d.Accounts = []*Account{{Name: in.Name, Display: "관리자", Role: "admin", Hash: h, Created: now, PwChanged: now, LastLogin: now}}
		return nil
	})
	if err != nil {
		fail(w, 409, err)
		return
	}
	a.newSession(w, r, true, in.Name)
	a.auditAs(r, in.Name+" ("+viaText(r)+")", "audit", "warn", "auth.setup", in.Name, "첫 관리자 계정을 만들었습니다", nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// checkSecondFactor accepts a TOTP code or an unused recovery code (consumed).
func (a *Auth) checkSecondFactor(acct *Account, code string) (ok, usedRecovery bool) {
	code = strings.TrimSpace(code)
	if step := totpStep(acct.TOTP, code); step > 0 {
		ok := false // a code seen once (login, reauth) cannot be replayed within its 90 s window
		_ = a.store.Update(func(d *Data) error {
			if x := d.account(acct.Name); x != nil && x.TOTP == acct.TOTP && step > x.TOTPLast {
				x.TOTPLast, ok = step, true
			}
			return nil
		})
		return ok, false
	}
	if len(strings.ReplaceAll(code, "-", "")) == 10 {
		h := hashRecovery(code)
		used := false
		_ = a.store.Update(func(d *Data) error {
			x := d.account(acct.Name)
			if x == nil {
				return nil
			}
			for i, c := range x.Recovery {
				if c == h {
					x.Recovery = append(x.Recovery[:i], x.Recovery[i+1:]...)
					used = true
					break
				}
			}
			return nil
		})
		return used, used
	}
	return false, false
}

func (a *Auth) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Password, Code string }
	_ = readJSON(r, &in)
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if in.Name == "" {
		in.Name = "admin"
	}
	key := clientIP(r) + "|" + in.Name
	for _, k := range []string{key, globalKey} {
		if d := a.lockedFor(k); d > 0 {
			fail(w, 429, fmt.Errorf("로그인 시도가 너무 많습니다. %d분 뒤에 다시 시도하세요", int(d.Minutes())+1))
			return
		}
	}
	d := a.store.Snapshot()
	acct := d.account(in.Name)
	var pwOK bool
	if acct != nil && !acct.Disabled {
		pwOK = VerifyPassword(acct.Hash, in.Password)
	} else {
		VerifyPassword(dummyHash, in.Password) // same cost as a real check
	}
	if pwOK && acct.TOTP != "" && strings.TrimSpace(in.Code) == "" {
		writeJSON(w, 401, map[string]any{"error": "2단계 인증 코드를 입력하세요", "needCode": true})
		return
	}
	codeOK, usedRecovery := true, false
	if pwOK && acct.TOTP != "" {
		codeOK, usedRecovery = a.checkSecondFactor(acct, in.Code)
	}
	if !pwOK || !codeOK {
		time.Sleep(time.Second)
		lk := a.noteFail(key)
		if g := a.noteFail(globalKey); g > lk {
			lk = g
		}
		what := "아이디 또는 비밀번호 오류"
		if pwOK {
			what = "2단계 인증 코드 오류"
		} else if acct != nil && acct.Disabled {
			what = "사용 중지된 계정"
		}
		lvl, msg := "warn", "로그인 실패 ("+in.Name+"): "+what
		if lk > 0 {
			lvl, msg = "error", fmt.Sprintf("%s — 로그인을 %d분 잠갔습니다", msg, int(lk.Minutes()))
		}
		a.auditAs(r, in.Name+" ("+viaText(r)+")", "security", lvl, "auth.login.fail", in.Name, msg, map[string]any{"ua": truncate(r.UserAgent(), 160)})
		if pwOK {
			fail(w, 401, errors.New("2단계 인증 코드가 올바르지 않습니다"))
		} else {
			fail(w, 401, errors.New("아이디 또는 비밀번호가 올바르지 않습니다"))
		}
		return
	}
	a.noteOK(key)                                      // not globalKey: one valid login must not reset the counter for everyone else
	if c, err := r.Cookie(sessionCookie); err == nil { // rotate
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	a.newSession(w, r, true, acct.Name)
	_ = a.store.Update(func(x *Data) error {
		if y := x.account(acct.Name); y != nil {
			y.LastLogin = time.Now()
		}
		return nil
	})
	msg := "로그인"
	if usedRecovery {
		msg = "로그인 (복구 코드 사용 — 남은 코드 확인 필요)"
	}
	a.auditAs(r, acct.Name+" ("+viaText(r)+")", "audit", map[bool]string{true: "warn", false: "info"}[usedRecovery], "auth.login", acct.Name, msg, map[string]any{"ua": truncate(r.UserAgent(), 160), "totp": acct.TOTP != ""})
	writeJSON(w, 200, map[string]any{"ok": true, "usedRecovery": usedRecovery})
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	user := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		if s := a.sessions[c.Value]; s != nil {
			user = s.User
		}
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	a.auditAs(r, user+" ("+viaText(r)+")", "audit", "info", "auth.logout", user, "로그아웃", nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *Auth) me(r *http.Request) (*Data, *Account) {
	d := a.store.Snapshot()
	s := sessionOf(r.Context())
	if s == nil {
		return &d, nil
	}
	return &d, d.account(s.User)
}

func (a *Auth) reauth(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password, Code string }
	_ = readJSON(r, &in)
	if d := a.lockedFor(globalKey); d > 0 {
		fail(w, 429, fmt.Errorf("시도가 너무 많습니다. %d분 뒤에 다시 시도하세요", int(d.Minutes())+1))
		return
	}
	_, acct := a.me(r)
	if acct != nil {
		if d := a.lockedFor("step|" + acct.Name); d > 0 {
			fail(w, 429, fmt.Errorf("시도가 너무 많습니다. %d분 뒤에 다시 시도하세요", int(d.Minutes())+1))
			return
		}
	}
	ok := acct != nil && VerifyPassword(acct.Hash, in.Password)
	if ok && acct.TOTP != "" {
		ok, _ = a.checkSecondFactor(acct, in.Code)
	}
	if !ok {
		time.Sleep(time.Second)
		a.noteFail(globalKey)
		if acct != nil {
			a.stepFail(r, acct.Name)
		}
		a.audit(r, "security", "warn", "auth.reauth.fail", "", "재인증 실패", nil)
		fail(w, 401, errors.New("비밀번호 또는 코드가 올바르지 않습니다"))
		return
	}
	s := sessionOf(r.Context())
	a.mu.Lock()
	s.Reauth = time.Now()
	a.mu.Unlock()
	a.audit(r, "audit", "info", "auth.reauth", "", "재인증", nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// stepFail counts a wrong password inside a logged-in session (re-auth, password change) per
// account. Five in a row looks like a stolen session guessing: lock the key and end this session.
func (a *Auth) stepFail(r *http.Request, name string) {
	if d := a.noteFail("step|" + name); d > 0 {
		if c, err := r.Cookie(sessionCookie); err == nil {
			a.mu.Lock()
			delete(a.sessions, c.Value)
			a.mu.Unlock()
		}
		a.audit(r, "security", "critical", "auth.step.lock", name, fmt.Sprintf("로그인 상태에서 비밀번호를 연속으로 틀려 세션을 끝내고 %d분 잠갔습니다", int(d.Minutes())), nil)
	}
}

// revokeUser ends every session of an account except `keep`.
func (a *Auth) revokeUser(name string, keep *Session) int {
	n := 0
	a.mu.Lock()
	for k, s := range a.sessions {
		if s.User == name && s != keep {
			delete(a.sessions, k)
			n++
		}
	}
	a.mu.Unlock()
	return n
}

func (a *Auth) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Current, New string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	_, acct := a.me(r)
	if acct == nil {
		fail(w, 401, errors.New("로그인이 필요합니다"))
		return
	}
	if err := validatePassword(acct.Name, in.New); err != nil {
		fail(w, 400, err)
		return
	}
	if in.New == in.Current {
		fail(w, 400, errors.New("새 비밀번호가 지금 비밀번호와 같습니다"))
		return
	}
	if d := a.lockedFor("step|" + acct.Name); d > 0 {
		fail(w, 429, fmt.Errorf("시도가 너무 많습니다. %d분 뒤에 다시 시도하세요", int(d.Minutes())+1))
		return
	}
	if !VerifyPassword(acct.Hash, in.Current) {
		time.Sleep(time.Second)
		a.noteFail(globalKey)
		a.stepFail(r, acct.Name)
		a.audit(r, "security", "warn", "auth.password.fail", acct.Name, "비밀번호 변경 실패 (현재 비밀번호 틀림)", nil)
		fail(w, 400, errors.New("현재 비밀번호가 올바르지 않습니다"))
		return
	}
	h, err := HashPassword(in.New)
	if err != nil {
		fail(w, 500, err)
		return
	}
	_ = a.store.Update(func(d *Data) error {
		if x := d.account(acct.Name); x != nil {
			x.Hash, x.MustChange, x.PwChanged = h, false, time.Now()
		}
		return nil
	})
	n := a.revokeUser(acct.Name, sessionOf(r.Context()))
	a.audit(r, "audit", "warn", "auth.password", acct.Name, fmt.Sprintf("비밀번호 변경 — 이 계정의 다른 세션 %d개를 끊었습니다", n), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

type sessionOut struct {
	Session
	Current bool      `json:"current"`
	Expires time.Time `json:"expires"`
}

func (a *Auth) listSessions(w http.ResponseWriter, r *http.Request) {
	cur := sessionOf(r.Context())
	all := a.can(r, "accounts")
	idle, abs, _ := a.policy()
	a.mu.Lock()
	var list []sessionOut
	now := time.Now()
	for k, s := range a.sessions {
		if now.Sub(s.LastSeen) > idle || now.Sub(s.Created) > abs {
			delete(a.sessions, k)
			continue
		}
		if !all && s.User != cur.User {
			continue
		}
		exp := s.LastSeen.Add(idle)
		if e2 := s.Created.Add(abs); e2.Before(exp) {
			exp = e2
		}
		list = append(list, sessionOut{Session: *s, Current: s == cur, Expires: exp})
	}
	a.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].LastSeen.After(list[j].LastSeen) })
	_, acct := a.me(r)
	writeJSON(w, 200, map[string]any{"sessions": list, "all": all, "totp": acct != nil && acct.TOTP != ""})
}

// revokeSession: "others" = this account's other sessions; an id of someone else's session needs 「accounts」.
func (a *Auth) revokeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur := sessionOf(r.Context())
	all := a.can(r, "accounts")
	n, denied := 0, false
	a.mu.Lock()
	for k, s := range a.sessions {
		if s == cur {
			continue
		}
		switch {
		case id == "others" && s.User == cur.User:
		case s.ID == id && (s.User == cur.User || all):
		case s.ID == id:
			denied = true
			continue
		default:
			continue
		}
		delete(a.sessions, k)
		n++
	}
	a.mu.Unlock()
	if denied {
		fail(w, 403, errors.New("다른 사람의 세션은 「계정·접근 보안」 권한이 있어야 끊을 수 있습니다"))
		return
	}
	a.audit(r, "audit", "warn", "auth.session.revoke", id, fmt.Sprintf("세션 %d개 강제 종료", n), nil)
	writeJSON(w, 200, map[string]int{"revoked": n})
}

func totpURI(acct, domain, secret string) string {
	label := url.PathEscape("Gilmok:" + acct + "@" + domain)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=Gilmok&algorithm=SHA1&digits=6&period=30", label, secret)
}

func qrDataURL(text string) string {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return ""
	}
	c.Scale = 6
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG())
}

func (a *Auth) totpBegin(w http.ResponseWriter, r *http.Request) {
	_, acct := a.me(r)
	if acct == nil {
		fail(w, 401, errors.New("로그인이 필요합니다"))
		return
	}
	sec := newTOTPSecret()
	_ = a.store.Update(func(d *Data) error {
		if x := d.account(acct.Name); x != nil {
			x.TOTPPending = sec
		}
		return nil
	})
	uri := totpURI(acct.Name, a.store.Snapshot().Settings.Domain, sec)
	writeJSON(w, 200, map[string]string{"secret": sec, "uri": uri, "qr": qrDataURL(uri)})
}

func (a *Auth) totpEnable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	_ = readJSON(r, &in)
	_, acct := a.me(r)
	if acct == nil {
		fail(w, 401, errors.New("로그인이 필요합니다"))
		return
	}
	lkey := "totp|" + acct.Name
	if d := a.lockedFor(lkey); d > 0 {
		fail(w, 429, fmt.Errorf("시도가 너무 많습니다. %d분 뒤에 다시 시도하세요", int(d.Minutes())+1))
		return
	}
	step := totpStep(acct.TOTPPending, in.Code)
	if acct.TOTPPending == "" || step == 0 {
		time.Sleep(time.Second)
		a.noteFail(lkey)
		fail(w, 400, errors.New("코드가 올바르지 않습니다 — 앱에 지금 보이는 6자리 코드를 입력하세요 (PC와 휴대폰 시계가 맞는지도 확인)"))
		return
	}
	plain, hashed := newRecoveryCodes()
	replaced := acct.TOTP != ""
	_ = a.store.Update(func(d *Data) error {
		if x := d.account(acct.Name); x != nil {
			x.TOTP, x.TOTPPending, x.Recovery, x.TOTPLast = x.TOTPPending, "", hashed, step
		}
		return nil
	})
	msg := "2단계 인증(TOTP)을 켰습니다"
	if replaced {
		msg = "2단계 인증 기기를 바꿨습니다 (예전 코드·복구 코드는 무효)"
	}
	a.audit(r, "audit", "warn", "auth.totp.enable", acct.Name, msg, nil)
	writeJSON(w, 200, map[string]any{"ok": true, "recovery": plain})
}

func (a *Auth) totpDisable(w http.ResponseWriter, r *http.Request) {
	d, acct := a.me(r)
	if acct == nil {
		fail(w, 401, errors.New("로그인이 필요합니다"))
		return
	}
	if acct.Require2FA {
		fail(w, 400, errors.New("관리자가 이 계정에 2단계 인증을 요구하고 있어 끌 수 없습니다 — 기기를 바꾸려면 「다른 기기로 다시 설정」을 쓰세요"))
		return
	}
	_ = d
	_ = a.store.Update(func(x *Data) error {
		if y := x.account(acct.Name); y != nil {
			y.TOTP, y.TOTPPending, y.Recovery = "", "", nil
		}
		return nil
	})
	a.audit(r, "audit", "critical", "auth.totp.disable", acct.Name, "2단계 인증(TOTP)을 껐습니다", nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *Auth) recoveryRegen(w http.ResponseWriter, r *http.Request) {
	_, acct := a.me(r)
	if acct == nil || acct.TOTP == "" {
		fail(w, 400, errors.New("2단계 인증을 먼저 켜세요"))
		return
	}
	plain, hashed := newRecoveryCodes()
	_ = a.store.Update(func(d *Data) error {
		if x := d.account(acct.Name); x != nil {
			x.Recovery = hashed
		}
		return nil
	})
	a.audit(r, "audit", "warn", "auth.recovery", acct.Name, "복구 코드를 새로 만들었습니다 (예전 코드는 무효)", nil)
	writeJSON(w, 200, map[string]any{"recovery": plain})
}

// ---------------------------------------------------------------- account management (「accounts」)

func (a *Auth) listAccounts(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	out := []accountView{}
	for _, acct := range d.Accounts {
		out = append(out, a.viewOf(&d, acct))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	cur := ""
	if s := sessionOf(r.Context()); s != nil {
		cur = s.User
	}
	writeJSON(w, 200, map[string]any{"accounts": out, "roles": d.Roles, "perms": permCatalog, "me": cur})
}

func (a *Auth) createAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Display, Role, Password string
		Require2FA                    bool `json:"require2fa"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Display = strings.TrimSpace(in.Display)
	if !reAccountName.MatchString(in.Name) {
		fail(w, 400, errors.New("아이디는 영문 소문자·숫자로 시작하고 영문 소문자·숫자·. _ - 로 2~32자입니다"))
		return
	}
	if len(in.Display) > 40 {
		fail(w, 400, errors.New("이름은 40자 이하여야 합니다"))
		return
	}
	temp := ""
	if in.Password == "" {
		temp = randomPassword()
		in.Password = temp
	}
	if err := validatePassword(in.Name, in.Password); err != nil {
		fail(w, 400, err)
		return
	}
	h, err := HashPassword(in.Password)
	if err != nil {
		fail(w, 500, err)
		return
	}
	err = a.store.Update(func(d *Data) error {
		if d.account(in.Name) != nil {
			return fmt.Errorf("이미 있는 아이디입니다: %s", in.Name)
		}
		if d.role(in.Role) == nil {
			return errors.New("역할을 고르세요")
		}
		d.Accounts = append(d.Accounts, &Account{Name: in.Name, Display: in.Display, Role: in.Role, Hash: h, MustChange: true, Require2FA: in.Require2FA, Created: time.Now()})
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.audit(r, "audit", "warn", "account.create", in.Name, fmt.Sprintf("계정 추가: %s (역할 %s)", in.Name, in.Role), nil)
	writeJSON(w, 200, map[string]any{"ok": true, "tempPassword": temp})
}

func (a *Auth) updateAccount(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Display    string
		Role       string
		Disabled   bool
		Require2FA bool `json:"require2fa"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	var before Account
	err := a.store.Update(func(d *Data) error {
		x := d.account(name)
		if x == nil {
			return errors.New("계정을 찾을 수 없습니다")
		}
		if d.role(in.Role) == nil {
			return errors.New("역할을 고르세요")
		}
		if x.Bootstrap && !in.Disabled {
			return errors.New("초기 계정(admin/admin)은 다시 켤 수 없습니다 — 필요 없으면 삭제하세요")
		}
		if s := sessionOf(r.Context()); s != nil && s.User == x.Name {
			if in.Disabled {
				return errors.New("자기 계정은 사용 중지할 수 없습니다 — 다른 관리자에게 요청하세요")
			}
			had := d.role(x.Role) != nil && containsStr(d.role(x.Role).Perms, "accounts")
			if had && !containsStr(d.role(in.Role).Perms, "accounts") {
				return errors.New("자기 계정에서 「계정·접근 보안」 권한을 뺄 수 없습니다 — 다른 관리자에게 요청하세요")
			}
		}
		before = *x
		x.Display, x.Role, x.Disabled, x.Require2FA = strings.TrimSpace(in.Display), in.Role, in.Disabled, in.Require2FA
		if d.adminsLeft("") == 0 {
			*x = before
			return errors.New("「계정·접근 보안」 권한이 있는 사용 중 계정이 최소 하나는 있어야 합니다")
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	n := 0
	if in.Disabled && !before.Disabled {
		n = a.revokeUser(name, nil)
	}
	a.audit(r, "audit", "warn", "account.update", name, fmt.Sprintf("계정 수정: %s (역할 %s → %s, 사용 중지 %v → %v, 2단계 요구 %v → %v, 끊은 세션 %d)", name, before.Role, in.Role, before.Disabled, in.Disabled, before.Require2FA, in.Require2FA, n), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *Auth) resetAccountPassword(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s := sessionOf(r.Context()); s != nil && s.User == name {
		fail(w, 400, errors.New("내 비밀번호는 「내 계정」에서 바꾸세요"))
		return
	}
	temp := randomPassword()
	h, _ := HashPassword(temp)
	err := a.store.Update(func(d *Data) error {
		x := d.account(name)
		if x == nil {
			return errors.New("계정을 찾을 수 없습니다")
		}
		x.Hash, x.MustChange = h, true
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	n := a.revokeUser(name, nil)
	a.audit(r, "audit", "warn", "account.password.reset", name, fmt.Sprintf("임시 비밀번호 발급 (세션 %d개 종료)", n), nil)
	writeJSON(w, 200, map[string]any{"ok": true, "tempPassword": temp})
}

func (a *Auth) resetAccount2FA(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := a.store.Update(func(d *Data) error {
		x := d.account(name)
		if x == nil {
			return errors.New("계정을 찾을 수 없습니다")
		}
		x.TOTP, x.TOTPPending, x.Recovery = "", "", nil
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	n := 0
	if s := sessionOf(r.Context()); s == nil || s.User != name {
		n = a.revokeUser(name, nil)
	}
	a.audit(r, "audit", "critical", "account.2fa.reset", name, fmt.Sprintf("2단계 인증 초기화 — 다음 로그인 때 다시 설정 (세션 %d개 종료)", n), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *Auth) deleteAccount(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s := sessionOf(r.Context()); s != nil && s.User == name {
		fail(w, 400, errors.New("지금 로그인한 내 계정은 지울 수 없습니다"))
		return
	}
	err := a.store.Update(func(d *Data) error {
		if d.account(name) == nil {
			return errors.New("계정을 찾을 수 없습니다")
		}
		if d.adminsLeft(name) == 0 {
			return errors.New("「계정·접근 보안」 권한이 있는 마지막 계정은 지울 수 없습니다")
		}
		out := d.Accounts[:0]
		for _, x := range d.Accounts {
			if x.Name != name {
				out = append(out, x)
			}
		}
		d.Accounts = out
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	n := a.revokeUser(name, nil)
	a.audit(r, "audit", "critical", "account.delete", name, fmt.Sprintf("계정 삭제: %s (세션 %d개 종료)", name, n), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- roles

var reRoleID = regexp.MustCompile(`[^a-z0-9]+`)

func cleanPerms(ps []string) []string {
	ok := map[string]bool{}
	for _, p := range allPermIDs() {
		ok[p] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range ps {
		if ok[p] && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func (a *Auth) createRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name  string
		Perms []string
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if bad := unknownPerms(in.Perms); len(bad) > 0 {
		fail(w, 400, fmt.Errorf("없는 권한입니다: %s", strings.Join(bad, ", ")))
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 30 {
		fail(w, 400, errors.New("역할 이름은 1~30자입니다"))
		return
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	id := "r_" + hex.EncodeToString(b)
	err := a.store.Update(func(d *Data) error {
		for _, x := range d.Roles {
			if x.Name == in.Name {
				return fmt.Errorf("이미 있는 역할 이름입니다: %s", in.Name)
			}
		}
		d.Roles = append(d.Roles, &Role{ID: id, Name: in.Name, Perms: cleanPerms(in.Perms)})
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.audit(r, "audit", "warn", "role.create", in.Name, "역할 추가: "+in.Name, map[string]any{"perms": cleanPerms(in.Perms)})
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

func (a *Auth) updateRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name  string
		Perms []string
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if bad := unknownPerms(in.Perms); len(bad) > 0 {
		fail(w, 400, fmt.Errorf("없는 권한입니다: %s", strings.Join(bad, ", ")))
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 30 {
		fail(w, 400, errors.New("역할 이름은 1~30자입니다"))
		return
	}
	err := a.store.Update(func(d *Data) error {
		x := d.role(id)
		if x == nil {
			return errors.New("역할을 찾을 수 없습니다")
		}
		if x.ID == "admin" {
			return errors.New("「관리자」 역할은 항상 모든 권한을 가지며 바꿀 수 없습니다")
		}
		old := *x
		x.Name, x.Perms = in.Name, cleanPerms(in.Perms)
		if d.adminsLeft("") == 0 {
			*x = old
			return errors.New("이렇게 바꾸면 계정을 관리할 수 있는 사람이 없어집니다")
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.audit(r, "audit", "warn", "role.update", in.Name, "역할 수정: "+in.Name, map[string]any{"perms": cleanPerms(in.Perms)})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *Auth) deleteRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := ""
	err := a.store.Update(func(d *Data) error {
		x := d.role(id)
		if x == nil {
			return errors.New("역할을 찾을 수 없습니다")
		}
		if x.Builtin {
			return errors.New("기본 역할은 지울 수 없습니다")
		}
		for _, acct := range d.Accounts {
			if acct.Role == id {
				return fmt.Errorf("계정 %s 이(가) 이 역할을 쓰고 있습니다 — 먼저 다른 역할로 바꾸세요", acct.Name)
			}
		}
		name = x.Name
		out := d.Roles[:0]
		for _, y := range d.Roles {
			if y.ID != id {
				out = append(out, y)
			}
		}
		d.Roles = out
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.audit(r, "audit", "warn", "role.delete", name, "역할 삭제: "+name, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func init() {
	dummyHash, _ = HashPassword("gilmok-timing-equaliser")
}

// bootstrap: admin/admin creates the real admin account and is disabled for good.
func (a *Auth) bootstrap(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Display, Password string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	s := sessionOf(r.Context())
	_, cur := a.me(r)
	if cur == nil || !cur.Bootstrap || cur.Disabled {
		fail(w, 403, errors.New("초기 계정으로 로그인했을 때만 쓸 수 있습니다"))
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Display = strings.TrimSpace(in.Display)
	if !reAccountName.MatchString(in.Name) {
		fail(w, 400, errors.New("아이디는 영문 소문자·숫자로 시작하고 영문 소문자·숫자·. _ - 로 2~32자입니다"))
		return
	}
	if in.Name == cur.Name {
		fail(w, 400, errors.New("초기 계정과 다른 아이디를 쓰세요 (admin 말고 예: 본인 이름)"))
		return
	}
	if err := validatePassword(in.Name, in.Password); err != nil {
		fail(w, 400, err)
		return
	}
	if in.Password == bootstrapPassword {
		fail(w, 400, errors.New("초기 비밀번호를 그대로 쓸 수 없습니다"))
		return
	}
	h, err := HashPassword(in.Password)
	if err != nil {
		fail(w, 500, err)
		return
	}
	scrambled, _ := HashPassword(randomPassword() + randomPassword())
	now := time.Now()
	err = a.store.Update(func(d *Data) error {
		if d.account(in.Name) != nil {
			return fmt.Errorf("이미 있는 아이디입니다: %s", in.Name)
		}
		b := d.account(cur.Name)
		if b == nil || !b.Bootstrap {
			return errors.New("초기 계정을 찾을 수 없습니다")
		}
		d.Accounts = append(d.Accounts, &Account{Name: in.Name, Display: in.Display, Role: "admin", Hash: h, Created: now, PwChanged: now, LastLogin: now})
		b.Disabled, b.Hash, b.TOTP, b.TOTPPending, b.Recovery = true, scrambled, "", "", nil // admin/admin can never log in again
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.revokeUser(cur.Name, nil)
	a.newSession(w, r, true, in.Name)
	_ = s
	a.auditAs(r, in.Name+" ("+viaText(r)+")", "audit", "critical", "auth.bootstrap", in.Name,
		fmt.Sprintf("첫 관리자 계정 %s 를 만들고 초기 계정 admin/admin 을 비활성화했습니다", in.Name), nil)
	writeJSON(w, 200, map[string]any{"ok": true, "name": in.Name})
}

// requireTwoFactor: require (or stop requiring) TOTP for several accounts at once.
func (a *Auth) requireTwoFactor(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Names   []string `json:"names"`
		Require bool     `json:"require"`
	}
	if err := readJSON(r, &in); err != nil || len(in.Names) == 0 {
		fail(w, 400, errors.New("계정을 하나 이상 고르세요"))
		return
	}
	var changed, skipped []string
	_ = a.store.Update(func(d *Data) error {
		for _, n := range in.Names {
			x := d.account(n)
			switch {
			case x == nil:
				continue
			case x.Bootstrap:
				skipped = append(skipped, x.Name)
				continue
			case x.Require2FA == in.Require:
				continue
			}
			x.Require2FA = in.Require
			changed = append(changed, x.Name)
		}
		return nil
	})
	what := map[bool]string{true: "요구", false: "요구 해제"}[in.Require]
	if len(changed) > 0 {
		a.audit(r, "audit", "warn", "account.2fa.require", strings.Join(changed, ","), fmt.Sprintf("2단계 인증 %s: %s", what, strings.Join(changed, ", ")), nil)
	}
	writeJSON(w, 200, map[string]any{"changed": changed, "skipped": skipped})
}

// unknownPerms lists ids that are not in the permission catalog.
func unknownPerms(ps []string) []string {
	ok := map[string]bool{}
	for _, p := range allPermIDs() {
		ok[p] = true
	}
	var bad []string
	for _, p := range ps {
		if !ok[p] {
			bad = append(bad, p)
		}
	}
	return bad
}

// uiLangs: languages the UI has (web/i18n/<lang>.json; ko is the source text).
var uiLangs = map[string]bool{"ko": true, "en": true}

// chooseLang: the very first visit picks the UI language of this install, before any login exists
// to ask for. Allowed only while no language is set — afterwards it is a setting (설정 탭 › 화면 언어),
// changed with the usual permissions.
func (a *Auth) chooseLang(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Lang string `json:"lang"`
	}
	if err := readJSON(r, &in); err != nil || !uiLangs[in.Lang] {
		fail(w, 400, errors.New("화면 언어는 ko 또는 en 이어야 합니다"))
		return
	}
	err := a.store.Update(func(d *Data) error {
		if d.Settings.Lang != "" {
			return errLangChosen
		}
		d.Settings.Lang = in.Lang
		return nil
	})
	if errors.Is(err, errLangChosen) {
		fail(w, 409, errors.New("화면 언어는 이미 정해져 있습니다 — 설정 탭에서 바꾸세요"))
		return
	}
	if err != nil {
		fail(w, 500, err)
		return
	}
	a.auditAs(r, "("+viaText(r)+")", "audit", "info", "settings.lang", in.Lang, "첫 접속 화면 언어: "+in.Lang, nil)
	writeJSON(w, 200, map[string]string{"lang": in.Lang})
}

var errLangChosen = errors.New("language already chosen")
