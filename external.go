package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Authelia and CrowdSec outside Docker ("external" mode: installed on the PC, another host, …).
// Gilmok cannot docker exec / restart / read docker logs there, so:
//
//	Authelia — validation = YAML syntax + the access_control shape (no Authelia binary to run);
//	           apply writes the file and leaves a "restart Authelia" notice (Data.AutheliaRestart):
//	           the user restarts it, presses 「다시 시작했어요」, Gilmok checks GET <url>/api/health
//	           and offers to put the previous file back when Authelia does not come up. User changes
//	           need no restart when the file backend watches the file (watch: true). Security events
//	           come from Authelia's log file (log.file_path) when one is set.
//	CrowdSec — the LAPI does everything: decisions to Cloudflare with the bouncer key (as before),
//	           manual block / unblock with a machine (watcher) account, the bouncer key pasted in.

func autheliaInDocker(st Settings) bool { return st.AutheliaMode != "external" }
func crowdsecInDocker(st Settings) bool { return st.CrowdSecMode != "external" }

// AutheliaRestart: a change written to an Authelia outside Docker that takes effect once Authelia
// is restarted (by the user).
type AutheliaRestart struct {
	At     time.Time `json:"at"`
	What   string    `json:"what"`   // access_control | users | restore
	File   string    `json:"file"`   // the file that changed
	Backup string    `json:"backup"` // its previous content (a file in Gilmok's backups)
	// users with authentication_backend.file.watch: Authelia normally reloads by itself, but not
	// when the folder is shared in a way that sends no change events (Docker Desktop's Windows
	// folders, SMB, NFS — seen in testing), so the notice stays, worded as "probably already in".
	Watch bool `json:"watch,omitempty"`
}

// validateAutheliaYAML: what Gilmok can check without the Authelia binary — the file parses and
// access_control is a mapping with a valid default policy and a rules list.
func validateAutheliaYAML(content string) error {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return fmt.Errorf("Authelia 설정 검증 실패 (YAML): %v", err)
	}
	ac, ok := doc["access_control"].(map[string]any)
	if !ok {
		return errors.New("Authelia 설정 검증 실패: access_control 블록이 없습니다")
	}
	switch fmt.Sprint(ac["default_policy"]) {
	case "deny", "bypass", "one_factor", "two_factor":
	default:
		return fmt.Errorf("Authelia 설정 검증 실패: default_policy %v", ac["default_policy"])
	}
	if r, ok := ac["rules"]; ok && r != nil {
		if _, ok := r.([]any); !ok {
			return errors.New("Authelia 설정 검증 실패: rules 가 목록이 아닙니다")
		}
	}
	return nil
}

// autheliaWatchesUsers: authentication_backend.file.watch — Authelia reloads users_database.yml
// by itself, so user changes need no restart.
func autheliaWatchesUsers(st Settings) bool {
	b, err := os.ReadFile(st.AutheliaConfig)
	if err != nil {
		return false
	}
	var doc struct {
		Auth struct {
			File struct {
				Watch bool `yaml:"watch"`
			} `yaml:"file"`
		} `yaml:"authentication_backend"`
	}
	return yaml.Unmarshal(b, &doc) == nil && doc.Auth.File.Watch
}

var autheliaHTTP = &http.Client{Timeout: 8 * time.Second}

// autheliaHealth: GET <AutheliaURL>/api/health → 200 once Authelia has started.
func autheliaHealth(ctx context.Context, st Settings) error {
	if st.AutheliaURL == "" {
		return errors.New("Authelia 주소가 없습니다 — Authelia 탭 › 연결에서 정하면 길목이 정상 시작을 확인합니다")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(st.AutheliaURL, "/")+"/api/health", nil)
	if err != nil {
		return err
	}
	res, err := autheliaHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("Authelia(%s)에 연결하지 못했습니다: %v", st.AutheliaURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("Authelia 상태 확인 HTTP %d", res.StatusCode)
	}
	return nil
}

// markAutheliaRestart records a change that waits for the user to restart Authelia.
func (a *App) markAutheliaRestart(what, file, backup string) {
	a.markAutheliaRestartW(what, file, backup, false)
}

func (a *App) markAutheliaRestartW(what, file, backup string, watch bool) {
	_ = a.store.Update(func(d *Data) error {
		d.AutheliaRestart = &AutheliaRestart{At: time.Now(), What: what, File: file, Backup: backup, Watch: watch}
		return nil
	})
}

// clearAutheliaRestart drops the notice when it is about the given file (a rollback wrote the
// previous content back before Authelia was restarted).
func (a *App) clearAutheliaRestart(file string) {
	_ = a.store.Update(func(d *Data) error {
		if d.AutheliaRestart != nil && d.AutheliaRestart.File == file {
			d.AutheliaRestart = nil
		}
		return nil
	})
}

// POST /api/authelia/restarted — the user restarted Authelia: check that it answers, clear the notice.
func (a *App) postAutheliaRestarted(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	pend := d.AutheliaRestart
	if pend == nil {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	checked := d.Settings.AutheliaURL != ""
	if checked {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := autheliaHealth(ctx, d.Settings); err != nil {
			writeJSON(w, 502, map[string]any{"error": err.Error() + " — Authelia가 시작되지 않았으면 「이전 설정으로 되돌리기」 후 다시 시작하세요", "canRestore": pend.Backup != ""})
			return
		}
	}
	a.clearAutheliaRestart(pend.File)
	a.logEvent("system", "info", "authelia.restarted", pend.File, "Authelia 재시작 확인 — 변경이 반영됐습니다", nil)
	writeJSON(w, 200, map[string]any{"ok": true, "checked": checked})
}

// POST /api/authelia/restore — put back the file the pending change replaced (Authelia did not
// start with it); Authelia still has to be restarted to load it.
func (a *App) postAutheliaRestore(w http.ResponseWriter, r *http.Request) {
	pend := a.store.Snapshot().AutheliaRestart
	if pend == nil || pend.Backup == "" {
		fail(w, 400, errors.New("되돌릴 변경이 없습니다"))
		return
	}
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	old, err := os.ReadFile(pend.Backup)
	if err != nil {
		fail(w, 500, fmt.Errorf("백업을 읽지 못했습니다: %v", err))
		return
	}
	if err := writeInPlace(pend.File, old); err != nil {
		fail(w, 500, err)
		return
	}
	a.markAutheliaRestart("restore", pend.File, "")
	a.logEvent("system", "warn", "authelia.restore", pend.File, "Authelia 파일을 이전 내용으로 되돌렸습니다 — Authelia를 다시 시작하세요", nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- CrowdSec through the LAPI

var reCSMachine = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var csMachinePath string // <data>/secrets/crowdsec_machine (password of the machine account)

func csMachinePassword() string {
	if csMachinePath == "" {
		return ""
	}
	b, _ := os.ReadFile(csMachinePath)
	return strings.TrimSpace(string(b))
}

var csJWT struct {
	sync.Mutex
	key, token string
	exp        time.Time
}

// csWatcherToken logs the machine account in (POST /v1/watchers/login) — cached until near expiry.
func csWatcherToken(ctx context.Context, st Settings) (string, error) {
	pw := csMachinePassword()
	if st.CrowdSecMachine == "" || pw == "" {
		return "", errors.New("CrowdSec 머신 계정이 없습니다 — CrowdSec 탭 › 연결에서 「머신 계정」을 넣으세요 (cscli machines add)")
	}
	key := st.CrowdSecLAPI + "|" + st.CrowdSecMachine + "|" + pw
	csJWT.Lock()
	defer csJWT.Unlock()
	if csJWT.key == key && time.Until(csJWT.exp) > time.Minute {
		return csJWT.token, nil
	}
	body, _ := json.Marshal(map[string]string{"machine_id": st.CrowdSecMachine, "password": pw})
	var out struct {
		Token  string    `json:"token"`
		Expire time.Time `json:"expire"`
	}
	if err := lapiCall(ctx, st, "POST", "/v1/watchers/login", "", body, &out); err != nil {
		return "", fmt.Errorf("CrowdSec 머신 계정 로그인 실패: %v", err)
	}
	csJWT.key, csJWT.token, csJWT.exp = key, out.Token, out.Expire
	if csJWT.exp.IsZero() {
		csJWT.exp = time.Now().Add(30 * time.Minute)
	}
	return out.Token, nil
}

func lapiCall(ctx context.Context, st Settings, method, path, token string, body []byte, out any) error {
	base := strings.TrimRight(st.CrowdSecLAPI, "/")
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "gilmok/"+version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := lapiHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("CrowdSec LAPI(%s)에 연결하지 못했습니다: %v", base, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(b))
		}
		return fmt.Errorf("HTTP %d %s", res.StatusCode, truncate(e.Message, 200))
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

// csAddDecisionLAPI: a manual ban the way cscli makes one — an alert carrying the decision.
func csAddDecisionLAPI(ctx context.Context, st Settings, value string, isRange bool, dur, reason string) error {
	tok, err := csWatcherToken(ctx, st)
	if err != nil {
		return err
	}
	scope := "Ip"
	if isRange {
		scope = "Range"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	alert := []map[string]any{{
		"scenario": reason, "scenario_hash": "", "scenario_version": "", "message": reason,
		"events_count": 1, "events": []any{}, "start_at": now, "stop_at": now, "capacity": 0, "leakspeed": "0", "simulated": false,
		"source":    map[string]any{"scope": scope, "value": value},
		"decisions": []map[string]any{{"duration": dur, "origin": "cscli", "scenario": reason, "scope": scope, "type": "ban", "value": value}},
	}}
	b, _ := json.Marshal(alert)
	return lapiCall(ctx, st, "POST", "/v1/alerts", tok, b, nil)
}

func csDeleteDecisionLAPI(ctx context.Context, st Settings, id int64) error {
	tok, err := csWatcherToken(ctx, st)
	if err != nil {
		return err
	}
	return lapiCall(ctx, st, "DELETE", "/v1/decisions/"+strconv.FormatInt(id, 10), tok, nil, nil)
}

// POST /api/crowdsec/machine {id, password} — the machine account for manual decisions; checked by
// logging in before it is kept. The password goes to a 0600 file, never into the settings.
func (a *App) postCSMachine(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Password string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	in.ID = strings.TrimSpace(in.ID)
	if in.ID == "" && in.Password == "" { // remove
		_ = os.Remove(csMachinePath)
		_ = a.store.Update(func(d *Data) error { d.Settings.CrowdSecMachine = ""; return nil })
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if !reCSMachine.MatchString(in.ID) || len(in.Password) < 8 || strings.ContainsAny(in.Password, "\r\n") {
		fail(w, 400, errors.New("머신 이름(글자·숫자·._-)과 비밀번호(8자 이상)를 넣으세요"))
		return
	}
	st := a.store.Snapshot().Settings
	st.CrowdSecMachine = in.ID
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"machine_id": in.ID, "password": in.Password})
	if err := lapiCall(ctx, st, "POST", "/v1/watchers/login", "", body, nil); err != nil {
		fail(w, 400, fmt.Errorf("CrowdSec 머신 계정 로그인 실패 — 저장하지 않았습니다: %v", err))
		return
	}
	if err := os.MkdirAll(filepath.Dir(csMachinePath), 0o700); err != nil {
		fail(w, 500, err)
		return
	}
	if err := os.WriteFile(csMachinePath, []byte(in.Password), 0o600); err != nil {
		fail(w, 500, err)
		return
	}
	_ = a.store.Update(func(d *Data) error { d.Settings.CrowdSecMachine = in.ID; return nil })
	writeJSON(w, 200, map[string]any{"ok": true})
}

// csDecisionsWithKey: the bouncer's view with a key that is not saved yet (checking a pasted key).
func csDecisionsWithKey(ctx context.Context, st Settings, key string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(st.CrowdSecLAPI, "/")+"/v1/decisions?origins=crowdsec,cscli", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", key)
	res, err := lapiHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("CrowdSec LAPI(%s)에 연결하지 못했습니다: %v", st.CrowdSecLAPI, err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("CrowdSec이 바운서 키를 거부했습니다 (HTTP %d)", res.StatusCode)
	}
	return nil
}
