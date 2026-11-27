package main

// Trusted devices and sessions that survive a restart.
//
// Trusted device: after a login with the second factor, "trust this device" leaves a long-lived
// cookie (one per account, HttpOnly, SameSite=Strict). The next login from that browser asks for
// the password only. The server keeps the SHA-256 of the cookie, never the cookie itself, and a
// "stamp" of the credentials it was made with — a new password, a new or reset second factor
// changes the stamp, so every trusted device of the account stops working at once. Devices are
// listed and revoked in 「내 계정」; account managers can revoke someone's devices.
//
// Sessions: the in-memory table is keyed by SHA-256 of the session cookie and written to
// <data>/sessions.json (0600) on every login / logout / revoke, so an update or restart does not
// log everyone out. A copied file holds no usable cookie. Idle / absolute expiry still apply.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

type TrustedDevice struct {
	ID       string    `json:"id"`
	Hash     string    `json:"hash"`  // sha256 of the cookie value — never sent to the UI
	Stamp    string    `json:"stamp"` // credentials it was made with (see credStamp)
	Label    string    `json:"label"` // browser · OS
	IP       string    `json:"ip"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed"`
	Expires  time.Time `json:"expires"`
}

const maxTrusted = 20

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// skey: the key of a session in the table (and in sessions.json) — never the cookie itself.
func skey(tok string) string { return sha("gm-session|" + tok) }

// credStamp: changes when the password or the second factor changes.
func credStamp(acct *Account) string { return sha(acct.Hash + "|" + acct.TOTP)[:24] }

func trustCookieName(account string) string { return "gm_trust_" + sha("acct|" + account)[:10] }

// trustDays: how long a trusted device lasts (0 = the feature is off).
func trustDays(st Settings) int {
	if st.SecTrustOff {
		return 0
	}
	if st.SecTrustDays <= 0 {
		return 30
	}
	return min(st.SecTrustDays, 90)
}

// uaLabel: "Chrome · Windows" from a User-Agent (for the device list only).
func uaLabel(ua string) string {
	l := strings.ToLower(ua)
	br := "브라우저"
	for _, x := range [][2]string{{"edg/", "Edge"}, {"opr/", "Opera"}, {"whale/", "Whale"}, {"samsungbrowser", "Samsung Internet"}, {"firefox/", "Firefox"}, {"chrome/", "Chrome"}, {"safari/", "Safari"}} {
		if strings.Contains(l, x[0]) {
			br = x[1]
			break
		}
	}
	osn := ""
	for _, x := range [][2]string{{"windows", "Windows"}, {"android", "Android"}, {"iphone", "iPhone"}, {"ipad", "iPad"}, {"mac os", "macOS"}, {"cros", "ChromeOS"}, {"linux", "Linux"}} {
		if strings.Contains(l, x[0]) {
			osn = x[1]
			break
		}
	}
	if osn == "" {
		return br
	}
	return br + " · " + osn
}

// trustedHere: the account's trusted device this request carries, if it is still valid.
func (a *Auth) trustedHere(r *http.Request, acct *Account) *TrustedDevice {
	if acct == nil || trustDays(a.store.Snapshot().Settings) == 0 {
		return nil
	}
	c, err := r.Cookie(trustCookieName(acct.Name))
	if err != nil || len(c.Value) < 32 {
		return nil
	}
	h, stamp, now := sha(c.Value), credStamp(acct), time.Now()
	for i := range acct.Trusted {
		t := &acct.Trusted[i]
		if t.Hash == h && t.Stamp == stamp && now.Before(t.Expires) {
			return t
		}
	}
	return nil
}

// trustDevice: remember this browser for the account (after a login with the second factor).
func (a *Auth) trustDevice(w http.ResponseWriter, r *http.Request, acct *Account) {
	days := trustDays(a.store.Snapshot().Settings)
	if days == 0 {
		return
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	id := make([]byte, 6)
	_, _ = rand.Read(id)
	now := time.Now()
	dev := TrustedDevice{ID: hex.EncodeToString(id), Hash: sha(tok), Stamp: credStamp(acct), Label: uaLabel(r.UserAgent()), IP: clientIP(r), Created: now, LastUsed: now, Expires: now.Add(time.Duration(days) * 24 * time.Hour)}
	_ = a.store.Update(func(d *Data) error {
		x := d.account(acct.Name)
		if x == nil {
			return nil
		}
		// replace this browser's earlier entry, drop dead ones, keep the newest maxTrusted
		keep := pruneTrusted(x.Trusted, credStamp(x), now)
		if c, err := r.Cookie(trustCookieName(acct.Name)); err == nil {
			old := sha(c.Value)
			keep = filterTrusted(keep, func(t TrustedDevice) bool { return t.Hash != old })
		}
		keep = append(keep, dev)
		if len(keep) > maxTrusted {
			sort.Slice(keep, func(i, j int) bool { return keep[i].LastUsed.After(keep[j].LastUsed) })
			keep = keep[:maxTrusted]
		}
		x.Trusted = keep
		return nil
	})
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: trustCookieName(acct.Name), Value: tok, Path: "/", MaxAge: days * 86400, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
}

func (a *Auth) touchTrusted(acct string, id, ip string) {
	_ = a.store.Update(func(d *Data) error {
		if x := d.account(acct); x != nil {
			for i := range x.Trusted {
				if x.Trusted[i].ID == id {
					x.Trusted[i].LastUsed, x.Trusted[i].IP = time.Now(), ip
				}
			}
		}
		return nil
	})
}

func pruneTrusted(list []TrustedDevice, stamp string, now time.Time) []TrustedDevice {
	return filterTrusted(list, func(t TrustedDevice) bool { return t.Stamp == stamp && now.Before(t.Expires) })
}

func filterTrusted(list []TrustedDevice, keep func(TrustedDevice) bool) []TrustedDevice {
	out := []TrustedDevice{}
	for _, t := range list {
		if keep(t) {
			out = append(out, t)
		}
	}
	return out
}

type trustedView struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	IP       string    `json:"ip"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed"`
	Expires  time.Time `json:"expires"`
	Current  bool      `json:"current"`
}

// GET /api/auth/devices: my trusted devices (valid ones only)
func (a *Auth) listDevices(w http.ResponseWriter, r *http.Request) {
	d, acct := a.me(r)
	if acct == nil {
		fail(w, 401, errors.New("로그인이 필요합니다"))
		return
	}
	cur := ""
	if c, err := r.Cookie(trustCookieName(acct.Name)); err == nil {
		cur = sha(c.Value)
	}
	out := []trustedView{}
	for _, t := range pruneTrusted(acct.Trusted, credStamp(acct), time.Now()) {
		out = append(out, trustedView{t.ID, t.Label, t.IP, t.Created, t.LastUsed, t.Expires, t.Hash == cur})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastUsed.After(out[j].LastUsed) })
	writeJSON(w, 200, map[string]any{"devices": out, "days": trustDays(d.Settings), "totp": acct.TOTP != ""})
}

// DELETE /api/auth/devices/{id} ("all" = every device of my account)
func (a *Auth) revokeDevice(w http.ResponseWriter, r *http.Request) {
	_, acct := a.me(r)
	if acct == nil {
		fail(w, 401, errors.New("로그인이 필요합니다"))
		return
	}
	id := r.PathValue("id")
	n := a.untrust(acct.Name, id)
	if c, err := r.Cookie(trustCookieName(acct.Name)); err == nil && (id == "all" || !a.stillTrusted(acct.Name, sha(c.Value))) {
		http.SetCookie(w, &http.Cookie{Name: trustCookieName(acct.Name), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	a.audit(r, "audit", "warn", "auth.trust.revoke", acct.Name, fmt.Sprintf("신뢰 기기 해제 %d개", n), nil)
	writeJSON(w, 200, map[string]int{"revoked": n})
}

// DELETE /api/accounts/{name}/devices: an account manager revokes someone's trusted devices
func (a *Auth) revokeAccountDevices(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	if d := a.store.Snapshot(); d.account(name) == nil {
		fail(w, 404, errors.New("계정이 없습니다"))
		return
	}
	n := a.untrust(name, "all")
	a.audit(r, "audit", "warn", "account.trust.revoke", name, fmt.Sprintf("%s 계정의 신뢰 기기 %d개 해제", name, n), nil)
	writeJSON(w, 200, map[string]int{"revoked": n})
}

func (a *Auth) untrust(name, id string) int {
	n := 0
	_ = a.store.Update(func(d *Data) error {
		if x := d.account(name); x != nil {
			before := len(x.Trusted)
			if id == "all" {
				x.Trusted = nil
			} else {
				x.Trusted = filterTrusted(x.Trusted, func(t TrustedDevice) bool { return t.ID != id })
			}
			n = before - len(x.Trusted)
		}
		return nil
	})
	return n
}

func (a *Auth) stillTrusted(name, hash string) bool {
	d := a.store.Snapshot()
	if x := d.account(name); x != nil {
		for _, t := range x.Trusted {
			if t.Hash == hash {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- sessions on disk

func (a *Auth) sessionsFile() string {
	if a.app == nil || a.app.dataDir == "" {
		return ""
	}
	return filepath.Join(a.app.dataDir, "sessions.json")
}

// saveSessionsLocked writes the session table (keys are hashes). Caller holds a.mu.
func (a *Auth) saveSessionsLocked() {
	p := a.sessionsFile()
	if p == "" {
		return
	}
	b, err := json.Marshal(a.sessions)
	if err != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

func (a *Auth) saveSessions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.saveSessionsLocked()
}

// loadSessions: the sessions saved before a restart, minus the expired ones.
func (a *Auth) loadSessions() {
	p := a.sessionsFile()
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var m map[string]*Session
	if json.Unmarshal(b, &m) != nil {
		return
	}
	idle, abs, _ := a.policy()
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, s := range m {
		if s == nil || len(k) != 64 || now.Sub(s.LastSeen) > idle || now.Sub(s.Created) > abs {
			continue
		}
		a.sessions[k] = s
	}
}

// sessionSaver: LastSeen changes on every request — written once a minute (logins / logouts are
// written at once).
func (a *Auth) sessionSaver() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		a.saveSessions()
	}
}
