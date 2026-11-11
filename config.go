package main

// Back up / restore Gilmok's own configuration as a JSON file.
//
//   GET  /api/config/export                 download gilmok-config-<date>.json (no secrets)
//   POST /api/config/import {data, dry}      dry=true → preview, dry=false → replace & 「적용 대기」
//
// The file holds what the user set up here — settings, services, Authelia groups, roles, the
// dashboard layout, Cloudflare rule ids and the managed-DNS lists. It deliberately leaves out
// everything secret or per-install: accounts and their password/TOTP/recovery hashes, the proxy
// secret, sessions, and runtime status. A restore therefore never changes who can log in.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const configFormat = "gilmok-config"

type ConfigFile struct {
	Format      string     `json:"format"`
	AppVersion  string     `json:"appVersion"`
	Exported    time.Time  `json:"exported"`
	Settings    Settings   `json:"settings"`
	Services    []*Service `json:"services"`
	Groups      []AGroup   `json:"autheliaGroups"`
	Roles       []*Role    `json:"roles"`
	Dashboard   []Widget   `json:"dashboard,omitempty"`
	CFWAF       CFWAFState `json:"cfWaf"`
	ManagedDNS  []string   `json:"managedDns,omitempty"`
	ManagedDNS6 []string   `json:"managedDns6,omitempty"`
}

func configFrom(d Data) ConfigFile {
	return ConfigFile{
		Format: configFormat, AppVersion: version, Exported: time.Now(),
		Settings: d.Settings, Services: d.Services, Groups: d.AGroups, Roles: d.Roles,
		Dashboard: d.Dashboard, CFWAF: d.CFWAF, ManagedDNS: d.ManagedDNS, ManagedDNS6: d.ManagedDNS6,
	}
}

func (a *App) getConfigExport(w http.ResponseWriter, r *http.Request) {
	cfg := configFrom(a.store.Snapshot())
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fail(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="gilmok-config-`+time.Now().Format("20060102")+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
	a.auth.audit(r, "audit", "info", "설정 내보내기", "", fmt.Sprintf("설정 파일 내보내기 (서비스 %d · 그룹 %d · 역할 %d)", len(cfg.Services), len(cfg.Groups), len(cfg.Roles)), nil)
}

// settingsPerms: the permissions beyond 「구성 변경」 that changing cur→in would need, and whether a
// fresh password (step-up) is required. Mirrors the per-key rules in saveSettings (main.go) — keep
// the two in step.
func settingsPerms(cur, in Settings) (need map[string]bool, stepUp bool) {
	need = map[string]bool{}
	internal := map[string]bool{"useInit": true, "useTsInit": true, "logInit": true, "secInit": true, "secV2": true, "wafV2": true}
	for k := range diffStruct(cur, in) {
		if internal[k] { // one-time migration markers, not something the user sets
			continue
		}
		switch {
		case systemSettingKey(k):
			need["system"] = true
		case strings.HasPrefix(k, "sec"):
			need["accounts"] = true
		case strings.HasPrefix(k, "log"), strings.HasPrefix(k, "disk"):
			need["logs"] = true
		}
		if systemSettingKey(k) || strings.HasPrefix(k, "sec") || strings.HasPrefix(k, "log") || strings.HasPrefix(k, "disk") || k == "updateCheck" {
			stepUp = true
		}
	}
	return
}

type ImportPlan struct {
	ServicesAdd    []string `json:"servicesAdd"`
	ServicesUpdate []string `json:"servicesUpdate"`
	ServicesRemove []string `json:"servicesRemove"`
	SettingsKeys   []string `json:"settingsKeys"`
	Groups         int      `json:"groups"`
	Roles          int      `json:"roles"`
	Dashboard      bool     `json:"dashboard"`
	NeedPerms      []string `json:"needPerms,omitempty"`
}

// validateConfig checks an imported file is safe to apply (same gates as saving each piece by hand).
func (a *App) validateConfig(cfg *ConfigFile, cur Settings) error {
	if cfg.Format != configFormat {
		return errors.New("길목 설정 파일이 아닙니다 (format 불일치) — 「설정 내보내기」로 받은 파일을 올리세요")
	}
	// the same checks and normalization as the settings form (SecLang, IP lists, thresholds …)
	if err := normalizeSettings(&cfg.Settings); err != nil {
		return err
	}
	if err := a.checkSystemSettings(cur, cfg.Settings); err != nil {
		return err
	}
	known := map[string]bool{}
	for _, id := range allPermIDs() {
		known[id] = true
	}
	for _, r := range cfg.Roles {
		if r == nil {
			continue
		}
		for _, p := range r.Perms {
			if !known[p] {
				return fmt.Errorf("역할 %q 의 권한 %q 를 알 수 없습니다", r.Name, p)
			}
		}
	}
	// services must be valid and self-consistent on their own group list
	known = map[string]bool{}
	for _, g := range cfg.Groups {
		if err := validGroupName(g.Name); err != nil {
			return fmt.Errorf("그룹 %q: %v", g.Name, err)
		}
		known[g.Name] = true
	}
	seen := map[string]bool{}
	svcs := make([]*Service, 0, len(cfg.Services))
	for _, s := range cfg.Services {
		c := *s
		if err := validateService(&c, svcs, cfg.Settings); err != nil {
			return fmt.Errorf("서비스 %s: %v", s.Subdomain, err)
		}
		if c.ID == "" || seen[c.ID] {
			c.ID = newID()
		}
		seen[c.ID] = true
		for _, g := range c.Authelia.Groups {
			if !known[g] {
				return fmt.Errorf("서비스 %s 의 허용 그룹 %q 가 파일의 그룹 목록에 없습니다", s.Subdomain, g)
			}
		}
		nc := c
		svcs = append(svcs, &nc)
	}
	cfg.Services = svcs
	return nil
}

func (a *App) postConfigImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Data string `json:"data"`
		Dry  bool   `json:"dry"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, errors.New("파일이 너무 큽니다 (최대 약 1.4 MB)"))
		return
	}
	raw, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil || len(raw) == 0 {
		fail(w, 400, errors.New("파일을 읽지 못했습니다"))
		return
	}
	fail400 := func(err error) {
		a.auth.audit(r, "audit", "error", "설정 복원", truncate(in.Name, 80), "설정 복원 — 실패: "+truncate(err.Error(), 300), nil)
		fail(w, 400, err)
	}
	var cfg ConfigFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		// a field we do not know is not fatal — retry leniently, format check still guards it
		if err2 := json.Unmarshal(raw, &cfg); err2 != nil {
			fail(w, 400, fmt.Errorf("설정 파일을 해석하지 못했습니다: %v", err2))
			return
		}
	}
	cur := a.store.Snapshot()
	if err := a.validateConfig(&cfg, cur.Settings); err != nil {
		if !in.Dry {
			fail400(err)
		} else {
			fail(w, 400, err)
		}
		return
	}

	// permissions: 「구성 변경」 plus whatever the settings diff needs; the route is wrapped with S()
	// so the fresh-password requirement is already enforced for the whole restore.
	need, _ := settingsPerms(cur.Settings, cfg.Settings)
	if !a.auth.can(r, "config") {
		need["config"] = true
	}
	// roles decide who may do what: changing them is account management, not configuration
	roles := safeRoles(cfg.Roles, cur)
	if !sameRoles(cur.Roles, roles) {
		need["accounts"] = true
	}
	// never leave nobody able to manage accounts
	{
		after := cur
		after.Roles = roles
		if after.adminsLeft("") == 0 {
			err := errors.New("이 파일의 역할로 바꾸면 계정을 관리할 수 있는 계정이 하나도 남지 않습니다 — 역할 권한을 확인하세요")
			if !in.Dry {
				fail400(err)
			} else {
				fail(w, 400, err)
			}
			return
		}
	}
	for perm := range need {
		if !a.auth.can(r, perm) {
			if !in.Dry {
				a.auth.audit(r, "audit", "error", "설정 복원", truncate(in.Name, 80), "설정 복원 — 실패: 권한 없음 ("+perm+")", nil)
			}
			writeJSON(w, 403, map[string]any{"error": fmt.Sprintf("설정 복원에 「%s」 권한이 필요합니다", permName(perm)), "perm": perm})
			return
		}
	}

	plan := planImport(cur, cfg)
	if in.Dry {
		writeJSON(w, 200, plan)
		return
	}

	err = a.store.Update(func(d *Data) error {
		d.Settings = cfg.Settings
		d.Settings.SecV2, d.Settings.WafV2, d.Settings.SecInit, d.Settings.LogInit, d.Settings.UseInit, d.Settings.UseTSInit = true, true, true, true, true, true
		d.Services = cfg.Services
		d.AGroups, d.AGroupsInit = cfg.Groups, true
		d.Roles = roles
		d.Dashboard = cfg.Dashboard
		d.CFWAF = cfg.CFWAF
		d.ManagedDNS, d.ManagedDNS6 = cfg.ManagedDNS, cfg.ManagedDNS6
		d.markDirty("설정 복원 (파일에서 가져옴)")
		return nil
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	a.detectSelf()
	a.applyLogPolicy(cfg.Settings)
	a.auth.audit(r, "audit", "warn", "설정 복원", truncate(in.Name, 80),
		fmt.Sprintf("설정 파일 복원 — 서비스 추가 %d·수정 %d·삭제 %d, 설정 키 %d개, 그룹 %d, 역할 %d (적용 대기)",
			len(plan.ServicesAdd), len(plan.ServicesUpdate), len(plan.ServicesRemove), len(plan.SettingsKeys), plan.Groups, plan.Roles),
		map[string]any{"settingsKeys": plan.SettingsKeys})
	writeJSON(w, 200, plan)
}

func planImport(cur Data, cfg ConfigFile) ImportPlan {
	p := ImportPlan{Groups: len(cfg.Groups), Roles: len(cfg.Roles), Dashboard: cfg.Dashboard != nil}
	curByID := map[string]*Service{}
	for _, s := range cur.Services {
		curByID[s.ID] = s
	}
	newByID := map[string]bool{}
	for _, s := range cfg.Services {
		newByID[s.ID] = true
		if old, ok := curByID[s.ID]; !ok {
			p.ServicesAdd = append(p.ServicesAdd, s.Subdomain)
		} else if !sameService(old, s) {
			p.ServicesUpdate = append(p.ServicesUpdate, s.Subdomain)
		}
	}
	for _, s := range cur.Services {
		if !newByID[s.ID] {
			p.ServicesRemove = append(p.ServicesRemove, s.Subdomain)
		}
	}
	for k := range diffStruct(cur.Settings, cfg.Settings) {
		p.SettingsKeys = append(p.SettingsKeys, k)
	}
	return p
}

func sameService(a, b *Service) bool {
	x, y := *a, *b
	x.Updated, y.Updated = time.Time{}, time.Time{}
	ax, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return string(ax) == string(by)
}

// safeRoles: use the imported roles, but never drop a built-in role or one an existing account
// still uses — otherwise a restore could lock everyone out of their own account.
func safeRoles(imported []*Role, cur Data) []*Role {
	have := map[string]bool{}
	out := make([]*Role, 0, len(imported))
	for _, r := range imported {
		if r != nil && r.ID != "" && !have[r.ID] {
			have[r.ID] = true
			out = append(out, r)
		}
	}
	add := func(r *Role) {
		if r != nil && !have[r.ID] {
			have[r.ID] = true
			out = append(out, r)
		}
	}
	for _, r := range defaultRoles() {
		add(r)
	}
	curByID := map[string]*Role{}
	for _, r := range cur.Roles {
		curByID[r.ID] = r
	}
	for _, acc := range cur.Accounts {
		if !have[acc.Role] {
			if r := curByID[acc.Role]; r != nil {
				add(r)
			}
		}
	}
	// the admin role always has every permission (the catalog may have grown)
	for _, r := range out {
		if r.ID == "admin" {
			r.Perms, r.Builtin = allPermIDs(), true
		}
	}
	return out
}

// sameRoles: same role ids, names and permission sets (order does not matter).
func sameRoles(a, b []*Role) bool {
	key := func(list []*Role) map[string]string {
		m := map[string]string{}
		for _, r := range list {
			if r == nil {
				continue
			}
			p := append([]string{}, r.Perms...)
			sort.Strings(p)
			m[r.ID] = r.Name + "|" + strings.Join(p, ",")
		}
		return m
	}
	x, y := key(a), key(b)
	if len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if y[k] != v {
			return false
		}
	}
	return true
}
