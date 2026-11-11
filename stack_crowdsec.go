package main

// Managed CrowdSec (docs/DESIGN_MANAGED_STACKS.md 4.3).
//
//   <data>/stacks/crowdsec/
//     compose.yml  .env (0600, CROWDSEC_BOUNCER_KEY)
//     acquis.d/  → /etc/crowdsec/acquis.d (read-only)   gilmok-caddy.yaml: the Caddy container's logs
//     parsers/   → /etc/crowdsec/parsers/s01-parse/gilmok-caddy-logs.yaml (read-only)
//     config/    → /etc/crowdsec        data/ → /var/lib/crowdsec/data
//
// The bouncer "gilmok" is registered by the image at start (BOUNCER_KEY_gilmok) with a key Gilmok
// generates and also keeps in <data>/secrets/crowdsec_key, so the LAPI calls work right away.
// The Docker socket is mounted read-only: CrowdSec reads the Caddy container's logs through it.
// No port is published — Gilmok reaches the LAPI on the shared network.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const gilmokCaddyParser = `# Based on crowdsecurity/caddy-logs. Differences:
#   - only lines labelled type=gmcaddy (see acquis.yaml), so the stock parser does not double count
#   - source IP = gm_real_ip (Cf-Connecting-Ip, written by Gilmok on mTLS sites only — those can
#     only be reached through Cloudflare, so the header cannot be forged). Docker Desktop rewrites
#     the TCP peer to the bridge gateway, which crowdsecurity/whitelists drops anyway.
filter: |
  evt.Parsed.program == 'gmcaddy' &&
  UnmarshalJSON(evt.Parsed.message, evt.Unmarshaled, 'caddy') in ['', nil] &&
  (evt.Unmarshaled.caddy.logger == nil || evt.Unmarshaled.caddy.logger != 'http.handlers.waf') &&
  evt.Unmarshaled.caddy.request != nil
onsuccess: next_stage
name: gilmok/caddy-logs
description: "Parse caddy access logs written by Gilmok (real client IP behind Cloudflare)"
statics:
  - meta: log_type
    value: http_access-log
  - target: evt.StrTime
    expression: |
      Sprintf("%v", evt.Unmarshaled.caddy.ts) matches '^[0-9e\\.\\+]+$' ? int(evt.Unmarshaled.caddy.ts) : evt.Unmarshaled.caddy.ts
  - meta: service
    value: http
  - parsed: remote_ip
    expression: "evt.Unmarshaled.caddy.gm_real_ip not in [nil, ''] ? evt.Unmarshaled.caddy.gm_real_ip : evt.Unmarshaled.caddy.request.client_ip"
  - parsed: http_version
    expression: "Split(evt.Unmarshaled.caddy.request.proto, '/')[1]"
  - meta: source_ip
    expression: evt.Parsed.remote_ip
  - meta: http_status
    expression: "evt.Unmarshaled.caddy.status != nil ? int(evt.Unmarshaled.caddy.status) : nil"
  - meta: http_path
    expression: "evt.Unmarshaled.caddy.request.uri"
  - parsed: request
    expression: "evt.Unmarshaled.caddy.request.uri"
  - parsed: verb
    expression: "evt.Unmarshaled.caddy.request.method"
  - meta: http_verb
    expression: "evt.Unmarshaled.caddy.request.method"
  - parsed: http_user_agent
    expression: "get(evt.Unmarshaled.caddy.request.headers, 'User-Agent') != nil ? evt.Unmarshaled.caddy.request.headers['User-Agent'][0] : nil"
  - meta: http_user_agent
    expression: evt.Parsed.http_user_agent
  - meta: target_fqdn
    expression: "evt.Unmarshaled.caddy.request.host"
  - meta: sub_type
    expression: "evt.Meta.http_status == '401' && get(evt.Unmarshaled.caddy.resp_headers, 'Www-Authenticate') != nil && any(get(evt.Unmarshaled.caddy.resp_headers, 'Www-Authenticate'), { # startsWith 'Basic' }) ? 'auth_fail' : nil"
`

func init() {
	stackKinds["crowdsec"] = &stackKind{
		Label: "CrowdSec", DefaultName: "gilmok-crowdsec", Project: "gilmok-crowdsec", Service: "crowdsec",
		ports:  func(*App, map[string]string) []string { return nil },
		render: renderCrowdSecStack, verify: verifyCrowdSecStack, adopt: adoptCrowdSecStack, check: checkCrowdSecOptions,
	}
}

func checkCrowdSecOptions(a *App, o map[string]string) error {
	st := a.store.Snapshot().Settings
	if o["caddyCtr"] == "" {
		o["caddyCtr"] = st.CaddyContainer
	}
	if !reStackCtr.MatchString(o["caddyCtr"]) {
		return errors.New("로그를 읽을 Caddy 컨테이너 이름이 올바르지 않습니다")
	}
	return nil
}

func crowdSecAcquis(caddyCtr string) string {
	return "# 길목이 관리합니다 — Caddy 컨테이너가 바뀌면 다시 써집니다.\n" +
		"# 길목은 mTLS(Proxied) 사이트에만 실제 IP(gm_real_ip)가 든 접근 로그를 남깁니다.\n" +
		"source: docker\ncontainer_name:\n  - " + caddyCtr + "\nlabels:\n  type: gmcaddy\n"
}

func renderCrowdSecStack(a *App, o map[string]string, dir, host, network, ctr string, log func(string, ...any)) error {
	for _, sub := range []string{"acquis.d", "parsers", "config", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "acquis.d", "gilmok-caddy.yaml"), []byte(crowdSecAcquis(o["caddyCtr"])), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "parsers", "gilmok-caddy-logs.yaml"), []byte(gilmokCaddyParser), 0o644); err != nil {
		return err
	}
	log("  수집 대상: %s 컨테이너 로그 (gilmok/caddy-logs 파서)", o["caddyCtr"])
	// bouncer key: the deployment's if it handed one in, otherwise Gilmok's own (made once)
	key := csKey()
	if key == "" {
		k, err := randHex(24)
		if err != nil {
			return err
		}
		key = k
		if err := os.MkdirAll(filepath.Dir(csKeyUIPath), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(csKeyUIPath, []byte(key), 0o600); err != nil {
			return err
		}
		log("  바운서 키를 새로 만들었습니다 (길목 secrets/crowdsec_key)")
	}
	envp := filepath.Join(dir, ".env")
	if err := os.WriteFile(envp+".tmp", []byte("# 길목이 관리합니다\nCROWDSEC_BOUNCER_KEY="+key+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(envp+".tmp", envp); err != nil {
		return err
	}
	compose := `# 길목이 만든 파일입니다 (관리형 CrowdSec). 직접 고치면 다시 설치할 때 덮어써집니다.
name: ` + stackProject(ctr) + `
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: ` + ctr + `
    restart: unless-stopped
    labels:
      gilmok.managed: crowdsec
    environment:
      COLLECTIONS: "crowdsecurity/caddy crowdsecurity/http-cve crowdsecurity/whitelist-good-actors"
      BOUNCER_KEY_gilmok: ${CROWDSEC_BOUNCER_KEY:-}
    volumes:
      - ` + yq(host+"/acquis.d:/etc/crowdsec/acquis.d:ro") + `
      - ` + yq(host+"/parsers/gilmok-caddy-logs.yaml:/etc/crowdsec/parsers/s01-parse/gilmok-caddy-logs.yaml:ro") + `
      - ` + yq(host+"/config:/etc/crowdsec") + `
      - ` + yq(host+"/data:/var/lib/crowdsec/data") + `
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
    logging:
      options: { max-size: "10m", max-file: "3" }
    networks: [edge]
networks:
  edge:
    name: ` + network + `
    external: true
`
	return os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(compose), 0o644)
}

// verifyCrowdSecStack: the first start installs the hub collections (needs the internet, ~1 min);
// done when the bouncer "gilmok" exists.
func verifyCrowdSecStack(a *App, ctr string) error {
	deadline := time.Now().Add(3 * time.Minute)
	last := ""
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		out, err := docker(ctx, nil, nil, "exec", ctr, "cscli", "bouncers", "list", "-o", "raw")
		cancel()
		if err == nil && strings.Contains(out, "gilmok") {
			// the bouncer is registered a moment before the LAPI listens: wait for that too
			since := time.Now().Add(-5 * time.Minute)
			if t, ok := ctrStartedAt(ctr); ok {
				since = t
			}
			if err := waitHealthy(ctr, since, "Local API listening", time.Until(deadline)); err != nil {
				return fmt.Errorf("CrowdSec LAPI가 준비되지 않았습니다: %v", err)
			}
			return reRegisterBouncer(ctr)
		}
		last = oneLine(lastLines(out, 2))
		if st, _ := ctrStateOf(context.Background(), ctr); st != "running" {
			logs, _ := docker(context.Background(), nil, nil, "logs", "--tail", "10", ctr)
			return fmt.Errorf("CrowdSec이 멈췄습니다 (%s): %s", st, oneLine(lastLines(logs, 3)))
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("CrowdSec이 3분 안에 준비되지 않았습니다 (바운서 gilmok 없음): %s", last)
}

// reRegisterBouncer makes the bouncer "gilmok" use Gilmok's current key. The image registers
// BOUNCER_KEY_gilmok only when the bouncer does not exist yet, so a CrowdSec database kept from an
// earlier install (e.g. after Gilmok's reset made a new key) would keep rejecting the new key.
func reRegisterBouncer(ctr string) error {
	key := csKey()
	if key == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = docker(ctx, nil, nil, "exec", ctr, "cscli", "bouncers", "delete", "gilmok")
	if out, err := docker(ctx, nil, nil, "exec", ctr, "cscli", "bouncers", "add", "gilmok", "-k", key); err != nil {
		return fmt.Errorf("바운서 gilmok 를 길목의 키로 다시 등록하지 못했습니다: %s", oneLine(lastLines(strings.ReplaceAll(out, key, "***"), 2)))
	}
	return nil
}

func adoptCrowdSecStack(d *Data, rec *ManagedStack) {
	st := &d.Settings
	st.UseCrowdSec, st.CrowdSecContainer = true, rec.Container
	st.CrowdSecLAPI = "http://" + rec.Container + ":8080"
	if !st.CrowdSecEnabled {
		st.CrowdSecEnabled = true // mTLS sites get the access log with the real client IP
		d.markDirty("CrowdSec 접근 로그 켬 (mTLS 사이트)")
	}
	st.CrowdSecSync = st.UseCloudflare
}

// syncCrowdSecAcquis: a managed CrowdSec follows the Caddy container — rewrite its acquisition and
// restart it when Caddy's name changed (a managed Caddy installed later, or the setting edited).
func (a *App) syncCrowdSecAcquis() {
	d := a.store.Snapshot()
	rec := d.Stacks["crowdsec"]
	if rec == nil || d.Settings.CaddyContainer == "" || rec.Options["caddyCtr"] == d.Settings.CaddyContainer {
		return
	}
	caddy := d.Settings.CaddyContainer
	if err := os.WriteFile(filepath.Join(rec.Dir, "acquis.d", "gilmok-caddy.yaml"), []byte(crowdSecAcquis(caddy)), 0o644); err != nil {
		a.logEvent("system", "error", "stack.crowdsec", "crowdsec", "관리형 CrowdSec 수집 대상을 바꾸지 못했습니다: "+err.Error(), nil)
		return
	}
	_ = a.store.Update(func(x *Data) error {
		if r := x.Stacks["crowdsec"]; r != nil {
			if r.Options == nil {
				r.Options = map[string]string{}
			}
			r.Options["caddyCtr"] = caddy
		}
		return nil
	})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if out, err := stackCompose(ctx, stackKinds["crowdsec"], rec.Dir, nil, "restart"); err != nil {
			a.logEvent("system", "error", "stack.crowdsec", "crowdsec", "관리형 CrowdSec 재시작 실패: "+oneLine(lastLines(out, 2)), nil)
		} else {
			a.logEvent("system", "info", "stack.crowdsec", "crowdsec", "관리형 CrowdSec이 이제 "+caddy+" 의 로그를 읽습니다", nil)
		}
	}()
}
