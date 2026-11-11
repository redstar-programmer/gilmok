package main

// Factory reset (설정 탭 › 적용·백업 › 초기화) — Gilmok back to the state of a fresh install.
//
//   GET  /api/reset/plan                       what a reset would remove (counts only)
//   POST /api/reset {accounts, confirm}         step-up; confirm must be "초기화"
//
// Cleared: services, every setting (code defaults — the GM_* install hints from the environment
// are NOT re-applied), Authelia group list, dashboard, Cloudflare rule ids, managed-DNS lists,
// pending changes, DDNS / update status, the Cloudflare token entered in the UI, the whole log
// database (requests, metrics, audit, security, system), the dashboard's in-memory statistics
// (request ring, buckets, certificates, health, container stats, CrowdSec counts) and metrics.json.
// With accounts=true also every account and custom role (only admin/admin is left, all sessions end).
//
// Not touched: anything outside Gilmok — the Caddyfile, Authelia files, Cloudflare records/rules,
// containers — those change only with the next 「적용」. A token given to the container
// (GM_CF_TOKEN / GM_CF_TOKEN_FILE) cannot be removed from here. The proxy secret is kept so
// Caddy's existing header for Gilmok's own site keeps working. The data file is copied to
// backups/<ts>-reset/ first (the only thing a reset leaves behind on purpose).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const resetConfirmWord = "초기화"

type ResetPlan struct {
	Services   int    `json:"services"`
	Groups     int    `json:"groups"`
	Roles      int    `json:"roles"`    // custom (non built-in) roles
	Accounts   int    `json:"accounts"` // accounts that a reset with accounts would remove
	ManagedDNS int    `json:"managedDns"`
	CFRules    int    `json:"cfRules"`
	Pending    int    `json:"pending"`
	Domain     string `json:"domain"`
	Caddy      string `json:"caddy"` // current Caddy container (shown so the user sees it goes back)
	LogRows    int64  `json:"logRows"`
	CFTokenUI  bool   `json:"cfTokenUi"`  // a token entered in the UI will be deleted
	CFTokenCtr bool   `json:"cfTokenCtr"` // a token given to the container stays (cannot remove here)
	Backup     string `json:"backup,omitempty"`
}

func (a *App) resetPlanOf(d Data) ResetPlan {
	p := ResetPlan{Services: len(d.Services), Groups: len(d.AGroups), Accounts: len(d.Accounts),
		ManagedDNS: len(d.ManagedDNS) + len(d.ManagedDNS6), Pending: len(d.Pending), Domain: d.Settings.Domain,
		Caddy: d.Settings.CaddyContainer}
	for _, r := range d.Roles {
		if !r.Builtin {
			p.Roles++
		}
	}
	for _, id := range []string{d.CFWAF.AsnRuleID, d.CFWAF.CsRuleID, d.CFWAF.AllowRuleID, d.CFWAF.ThreatRuleID, d.CFWAF.CustomRuleID, d.CFWAF.RateRuleID} {
		if id != "" {
			p.CFRules++
		}
	}
	switch cfTokenSourceName() {
	case "ui":
		p.CFTokenUI = true
	case "container-file", "container-env":
		p.CFTokenCtr = true
	}
	if a.ldb != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		for _, c := range a.ldb.Counts(ctx) {
			p.LogRows += c.Rows
		}
		cancel()
	}
	return p
}

func (a *App) getResetPlan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.resetPlanOf(a.store.Snapshot()))
}

// resetData turns d into a fresh install. Only the proxy secret and this container's own name
// (detected at start) survive; accounts and roles too when accounts=false.
func resetData(d *Data, accounts bool) {
	keep := *d
	// managed stacks are containers outside Gilmok: a reset leaves them running and remembered
	*d = Data{Settings: baseSettings(), ProxySecret: keep.ProxySecret, SelfName: keep.SelfName, Stacks: keep.Stacks}
	if !accounts {
		d.Accounts, d.Roles = keep.Accounts, keep.Roles
	}
	migrateAccounts(d) // default roles; no accounts → the initial admin/admin
}

// resetRuntime drops everything Gilmok keeps in memory or beside the data file about the old setup.
// keepBackup: the backup just taken — every older backup goes.
func (a *App) resetRuntime(keepBackup string) error {
	root := filepath.Join(a.dataDir, "backups")
	if ents, err := os.ReadDir(root); err == nil {
		for _, e := range ents {
			if p := filepath.Join(root, e.Name()); p != filepath.Clean(keepBackup) {
				_ = os.RemoveAll(p)
			}
		}
	}
	if a.mon != nil {
		m := a.mon
		m.mu.Lock()
		m.reqs, m.pos = nil, 0
		m.fine, m.coarse = map[int64]*Slot{}, map[int64]*Slot{}
		m.waf = nil
		m.lastTs = time.Now().UnixMilli() // a reconnecting log stream must not replay old lines
		m.lines = 0
		m.ctr, m.ctrAt = map[string][]CtrPoint{}, time.Time{}
		m.health = map[string]*HealthState{}
		m.certs, m.certsAt = nil, time.Time{}
		m.csBans, m.csErr, m.csAt, m.csKnown = 0, "", time.Time{}, nil
		m.dirty = false
		m.mu.Unlock()
	}
	_ = os.Remove(a.metricsPath())
	a.cs.mu.Lock()
	a.cs.status = CSSyncStatus{}
	a.cs.mu.Unlock()
	a.topo.mu.Lock()
	a.topo.ip, a.topo.ipAt, a.topo.osName = "", time.Time{}, ""
	a.topo.mu.Unlock()
	if a.cf != nil {
		a.cf.mu.Lock()
		a.cf.zone, a.cf.zoneID = "", ""
		a.cf.mu.Unlock()
	}
	if cfTokenUIPath != "" {
		if err := os.Remove(cfTokenUIPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("화면에서 넣은 Cloudflare 토큰을 지우지 못했습니다: %v", err)
		}
	}
	a.caddyTokenChanged(nil) // a managed Caddy loses the deleted token too
	if csKeyUIPath != "" {
		_ = os.Remove(csKeyUIPath) // a bouncer key Gilmok made itself (the bouncer stays in CrowdSec)
	}
	if a.ldb != nil {
		for cat := range logTables {
			if _, err := a.ldb.deleteBefore(cat, 0); err != nil {
				return fmt.Errorf("로그 기록(%s)을 지우지 못했습니다: %v", cat, err)
			}
		}
		go a.ldb.vacuum()
	}
	return nil
}

func (a *App) postReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Accounts bool   `json:"accounts"`
		Confirm  string `json:"confirm"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	failAudit := func(code int, err error) {
		a.auth.audit(r, "audit", "error", "길목 초기화", "", "길목 초기화 — 실패: "+truncate(err.Error(), 300), nil)
		fail(w, code, err)
	}
	if in.Confirm != resetConfirmWord {
		failAudit(400, fmt.Errorf("확인 문구로 「%s」를 입력하세요", resetConfirmWord))
		return
	}
	// a reset changes every setting, system keys included; with accounts it also replaces logins
	need := []string{"config", "system"}
	if in.Accounts {
		need = append(need, "accounts")
	}
	for _, perm := range need {
		if !a.auth.can(r, perm) {
			a.auth.audit(r, "audit", "error", "길목 초기화", "", "길목 초기화 — 실패: 권한 없음 ("+perm+")", nil)
			writeJSON(w, 403, map[string]any{"error": fmt.Sprintf("초기화에 「%s」 권한이 필요합니다", permName(perm)), "perm": perm})
			return
		}
	}

	plan := a.resetPlanOf(a.store.Snapshot())
	dir, err := backup(a.dataDir, "reset", map[string]string{"gilmok.json": a.store.path})
	if err != nil {
		failAudit(500, fmt.Errorf("초기화 전 백업에 실패해 중단했습니다: %v", err))
		return
	}
	plan.Backup = dir

	if err := a.store.Update(func(d *Data) error { resetData(d, in.Accounts); return nil }); err != nil {
		failAudit(500, err)
		return
	}
	rtErr := a.resetRuntime(dir)
	// the log database is empty now: the reset is its first entry (written before sessions go away
	// so it names who did it)
	what := "서비스·설정·로그"
	if in.Accounts {
		what += "·계정"
	}
	msg := fmt.Sprintf("길목 초기화 (%s) — 서비스 %d · 그룹 %d · 사용자 역할 %d · 관리 DNS %d · 로그 %d건 정리, 이전 데이터 백업 %s",
		what, plan.Services, plan.Groups, plan.Roles, plan.ManagedDNS, plan.LogRows, dir)
	if rtErr != nil {
		msg += " — 일부 실패: " + rtErr.Error()
	}
	a.auth.audit(r, "audit", "warn", "길목 초기화", "", msg, map[string]any{"accounts": in.Accounts})

	if in.Accounts {
		a.auth.mu.Lock()
		a.auth.sessions = map[string]*Session{}
		a.auth.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	// the same start-up steps a fresh install gets
	a.seedGroups()
	a.inferComponents()
	a.detectSelf()
	a.applyLogPolicy(a.store.Snapshot().Settings)
	res := map[string]any{"ok": true, "plan": plan, "loggedOut": in.Accounts}
	if rtErr != nil {
		res["warning"] = rtErr.Error()
	}
	writeJSON(w, 200, res)
}
