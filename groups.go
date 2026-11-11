package main

// Authelia groups, defined ahead of time.
//
// Authelia itself has no group list — a group exists because a user in users_database.yml has it
// and a rule in access_control allows it. Gilmok keeps a list of named groups with a description
// (Data.AGroups) so services and users pick from the same names, and renames / deletes reach
// every place the name is used:
//   - services' allowed groups → changed in the DB, 「적용 대기」 (access_control is regenerated)
//   - users' groups            → users_database.yml rewritten right away (Authelia restarts)
//
//   GET    /api/groups                     list (defined + in use) with where each is used
//   POST   /api/groups {name, desc}        define
//   PUT    /api/groups/{name} {name, desc} change description / rename everywhere
//   DELETE /api/groups/{name}[?purge=1]    remove the definition (purge: also from services and users)

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type AGroup struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type groupView struct {
	Name     string   `json:"name"`
	Desc     string   `json:"desc"`
	Defined  bool     `json:"defined"`
	Users    []string `json:"users"`
	Services []string `json:"services"` // subdomains
}

func validGroupName(g string) error {
	if g == "" {
		return errors.New("그룹 이름을 입력하세요")
	}
	if len(g) > 64 || !validUsername(g) {
		return fmt.Errorf("그룹 이름 %q 에는 영문/숫자/-_. 만 쓸 수 있습니다 (64자 이하)", g)
	}
	return nil
}

// ensureGroups adds names used by a service or user to the defined list (no description).
func (d *Data) ensureGroups(names []string) {
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || validGroupName(n) != nil {
			continue
		}
		found := false
		for _, g := range d.AGroups {
			if g.Name == n {
				found = true
				break
			}
		}
		if !found {
			d.AGroups = append(d.AGroups, AGroup{Name: n})
		}
	}
	sort.Slice(d.AGroups, func(i, j int) bool { return d.AGroups[i].Name < d.AGroups[j].Name })
}

// seedGroups: the first time, every group already used by services or users becomes defined.
func (a *App) seedGroups() {
	d := a.store.Snapshot()
	if d.AGroupsInit {
		return
	}
	var names []string
	for _, s := range d.Services {
		names = append(names, s.Authelia.Groups...)
	}
	if d.Settings.UseAuthelia {
		if users, err := LoadUsers(d.Settings.AutheliaUsers); err == nil {
			for _, u := range users {
				names = append(names, u.Groups...)
			}
		}
	}
	_ = a.store.Update(func(x *Data) error {
		if x.AGroupsInit {
			return nil
		}
		x.ensureGroups(names)
		x.AGroupsInit = true
		return nil
	})
}

func (a *App) groupViews() ([]groupView, error) {
	a.seedGroups()
	d := a.store.Snapshot()
	m := map[string]*groupView{}
	get := func(n string) *groupView {
		if m[n] == nil {
			m[n] = &groupView{Name: n, Users: []string{}, Services: []string{}}
		}
		return m[n]
	}
	for _, g := range d.AGroups {
		v := get(g.Name)
		v.Desc, v.Defined = g.Desc, true
	}
	for _, s := range d.Services {
		for _, g := range s.Authelia.Groups {
			v := get(g)
			v.Services = append(v.Services, s.Subdomain)
		}
	}
	var uerr error
	if d.Settings.UseAuthelia {
		users, err := LoadUsers(d.Settings.AutheliaUsers)
		if err != nil {
			uerr = err
		}
		for name, u := range users {
			for _, g := range u.Groups {
				v := get(g)
				v.Users = append(v.Users, name)
			}
		}
	}
	out := make([]groupView, 0, len(m))
	for _, v := range m {
		sort.Strings(v.Users)
		sort.Strings(v.Services)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, uerr
}

func (a *App) getGroups(w http.ResponseWriter, r *http.Request) {
	list, err := a.groupViews()
	res := map[string]any{"groups": list}
	if err != nil {
		res["usersError"] = "users_database.yml 을 읽지 못해 사용자 쪽 사용 현황은 빠졌습니다: " + err.Error()
	}
	writeJSON(w, 200, res)
}

func (a *App) postGroup(w http.ResponseWriter, r *http.Request) {
	var in AGroup
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Name, in.Desc = strings.TrimSpace(in.Name), strings.TrimSpace(in.Desc)
	if err := validGroupName(in.Name); err != nil {
		fail(w, 400, err)
		return
	}
	a.seedGroups()
	err := a.store.Update(func(d *Data) error {
		for _, g := range d.AGroups {
			if g.Name == in.Name {
				return fmt.Errorf("그룹 %s 는 이미 있습니다", in.Name)
			}
		}
		d.AGroups = append(d.AGroups, AGroup{Name: in.Name, Desc: truncate(in.Desc, 200)})
		sort.Slice(d.AGroups, func(i, j int) bool { return d.AGroups[i].Name < d.AGroups[j].Name })
		return nil
	})
	if err != nil {
		fail(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// replaceGroup renames (to != "") or removes (to == "") a group in a list.
func replaceGroup(list []string, from, to string) ([]string, bool) {
	out := make([]string, 0, len(list))
	changed := false
	for _, g := range list {
		if g == from {
			changed = true
			if to != "" && !containsStr(out, to) && !containsStr(list, to) {
				out = append(out, to)
			}
			continue
		}
		out = append(out, g)
	}
	return out, changed
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// errNeedReauth: the change would rewrite users_database.yml, which /api/users* only allows after
// a fresh password check (step-up) — ask for it before touching anything.
var errNeedReauth = errors.New("사용자 파일(users_database.yml)도 바뀌는 작업입니다 — 비밀번호를 다시 확인해 주세요")

// changeGroupEverywhere renames or removes a group in services (pending) and users (written now).
func (a *App) changeGroupEverywhere(r *http.Request, from, to string) (svcN, userN int, log []string, err error) {
	d := a.store.Snapshot()
	// users first: if writing users_database.yml fails, nothing else changes
	if d.Settings.UseAuthelia {
		a.usersMu.Lock()
		defer a.usersMu.Unlock()
		users, lerr := LoadUsers(d.Settings.AutheliaUsers)
		if lerr == nil {
			for _, u := range users {
				if g, ch := replaceGroup(u.Groups, from, to); ch {
					u.Groups = g
					userN++
				}
			}
			if userN > 0 {
				if !a.auth.recentlyVerified(r) {
					return 0, 0, nil, errNeedReauth
				}
				if !a.auth.can(r, "authelia_users") {
					return 0, 0, nil, fmt.Errorf("사용자 %d명의 그룹도 바뀌어야 하는데 「%s」 권한이 없습니다", userN, permName("authelia_users"))
				}
				lines, aerr := a.ApplyUsers(users)
				log = lines
				if aerr != nil {
					return 0, 0, log, fmt.Errorf("users_database.yml 반영 실패 (되돌렸습니다): %v", aerr)
				}
			}
		} else {
			// cannot see the users: refuse rather than leave them with a stale group name
			return 0, 0, nil, fmt.Errorf("users_database.yml 을 읽지 못해 사용자 쪽 그룹을 바꿀 수 없습니다 — Authelia 탭 › 컨테이너 연결을 확인하세요 (%v)", lerr)
		}
	}
	err = a.store.Update(func(x *Data) error {
		for _, s := range x.Services {
			if g, ch := replaceGroup(s.Authelia.Groups, from, to); ch {
				s.Authelia.Groups = g
				svcN++
			}
		}
		if svcN > 0 {
			if to == "" {
				x.markDirty("허용 그룹 삭제: " + from)
			} else {
				x.markDirty("허용 그룹 이름 변경: " + from + " → " + to)
			}
		}
		return nil
	})
	return
}

func (a *App) putGroup(w http.ResponseWriter, r *http.Request) {
	from := r.PathValue("name")
	var in AGroup
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Name, in.Desc = strings.TrimSpace(in.Name), strings.TrimSpace(in.Desc)
	if in.Name == "" {
		in.Name = from
	}
	if err := validGroupName(in.Name); err != nil {
		fail(w, 400, err)
		return
	}
	a.seedGroups()
	d := a.store.Snapshot()
	for _, g := range d.AGroups {
		if g.Name == in.Name && in.Name != from {
			fail(w, 409, fmt.Errorf("그룹 %s 는 이미 있습니다 — 합치려면 이 그룹을 지우고 사용처에 %s 를 넣으세요", in.Name, in.Name))
			return
		}
	}
	var svcN, userN int
	var log []string
	if in.Name != from {
		var err error
		svcN, userN, log, err = a.changeGroupEverywhere(r, from, in.Name)
		if err != nil {
			a.groupFail(w, r, "Authelia 그룹 이름 변경", from+" → "+in.Name, err, log)
			return
		}
	}
	_ = a.store.Update(func(x *Data) error {
		kept := x.AGroups[:0]
		for _, g := range x.AGroups {
			if g.Name != from {
				kept = append(kept, g)
			}
		}
		x.AGroups = append(kept, AGroup{Name: in.Name, Desc: truncate(in.Desc, 200)})
		sort.Slice(x.AGroups, func(i, j int) bool { return x.AGroups[i].Name < x.AGroups[j].Name })
		return nil
	})
	if in.Name != from {
		a.auth.audit(r, "audit", "warn", "Authelia 그룹 이름 변경", from+" → "+in.Name,
			fmt.Sprintf("그룹 이름 변경 %s → %s (서비스 %d개 · 사용자 %d명)", from, in.Name, svcN, userN), nil)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "services": svcN, "users": userN, "log": log})
}

func (a *App) deleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	purge := r.URL.Query().Get("purge") == "1"
	list, _ := a.groupViews()
	var v *groupView
	for i := range list {
		if list[i].Name == name {
			v = &list[i]
		}
	}
	if v == nil {
		fail(w, 404, errors.New("그룹을 찾을 수 없습니다"))
		return
	}
	if !purge && (len(v.Services) > 0 || len(v.Users) > 0) {
		a.auth.audit(r, "audit", "error", "Authelia 그룹 삭제", name, "그룹 삭제 — 실패: 사용 중 (purge 없이 요청)", nil)
		writeJSON(w, 409, map[string]any{"error": fmt.Sprintf("그룹 %s 는 서비스 %d개 · 사용자 %d명이 쓰고 있습니다", name, len(v.Services), len(v.Users)), "inUse": v})
		return
	}
	var svcN, userN int
	var log []string
	if purge {
		var err error
		svcN, userN, log, err = a.changeGroupEverywhere(r, name, "")
		if err != nil {
			a.groupFail(w, r, "Authelia 그룹 삭제", name, err, log)
			return
		}
	}
	_ = a.store.Update(func(x *Data) error {
		kept := x.AGroups[:0]
		for _, g := range x.AGroups {
			if g.Name != name {
				kept = append(kept, g)
			}
		}
		x.AGroups = kept
		return nil
	})
	a.auth.audit(r, "audit", "warn", "Authelia 그룹 삭제", name, fmt.Sprintf("그룹 %s 삭제 (서비스 %d개 · 사용자 %d명에서 뺌)", name, svcN, userN), nil)
	writeJSON(w, 200, map[string]any{"ok": true, "services": svcN, "users": userN, "log": log})
}

// groupSet: the registered group names (never nil — an empty set means "nothing registered").
func (d *Data) groupSet() map[string]bool {
	m := map[string]bool{}
	for _, g := range d.AGroups {
		m[g.Name] = true
	}
	return m
}

// checkNewGroups: groups added compared to `before` must be registered (no free typing).
// Groups that were already there stay allowed so an unrelated edit never fails.
func checkNewGroups(known map[string]bool, before, after []string) error {
	had := map[string]bool{}
	for _, g := range before {
		had[g] = true
	}
	var bad []string
	for _, g := range after {
		if !had[g] && !known[g] {
			bad = append(bad, g)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("등록되지 않은 그룹입니다: %s — Authelia 탭 › 사용자 · 그룹 › 그룹에서 먼저 추가하세요", strings.Join(bad, ", "))
	}
	return nil
}

// groupFail answers a failed rename / purge and records it (a refused step-up is not audited as a
// failure — the UI asks for the password and retries).
func (a *App) groupFail(w http.ResponseWriter, r *http.Request, action, target string, err error, log []string) {
	if errors.Is(err, errNeedReauth) {
		writeJSON(w, 403, map[string]any{"error": err.Error(), "reauth": true})
		return
	}
	a.auth.audit(r, "audit", "error", action, target, action+" — 실패: "+truncate(err.Error(), 300), map[string]any{"log": log})
	writeJSON(w, 400, map[string]any{"error": err.Error(), "log": log})
}
