package main

// Managed Authelia (docs/DESIGN_MANAGED_STACKS.md 4.2) — v4.38+ configuration.
//
//   <data>/stacks/authelia/
//     compose.yml
//     config/  → /config   configuration.yml (access_control block managed by Gilmok as usual),
//                          users_database.yml (first admin)
//     secrets/ → /secrets  jwt, session, storage (random, 0600) — read through *_FILE variables
//     data/    → /data     db.sqlite3, notification.txt (filesystem notifier)
//
// No port is published: Caddy reaches it on the shared network (<container>:9091). Secrets and the
// first password never appear in responses, logs or the stack record.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func init() {
	stackKinds["authelia"] = &stackKind{
		Label: "Authelia", DefaultName: "gilmok-authelia", Project: "gilmok-authelia", Service: "authelia",
		ports: func(*App, map[string]string) []string { return nil }, // reached over the Docker network only
		render: renderAutheliaStack, verify: verifyAutheliaStack, adopt: adoptAutheliaStack, check: checkAutheliaOptions,
	}
}

var reSubdomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func checkAutheliaOptions(a *App, o map[string]string) error {
	st := a.store.Snapshot().Settings
	if st.Domain == "" {
		return errors.New("먼저 도메인을 정하세요 (설정 탭 › 도메인) — Authelia 로그인 쿠키와 포털 주소의 기준입니다")
	}
	if o["portal"] == "" {
		o["portal"] = "auth"
	}
	o["portal"] = strings.ToLower(o["portal"])
	if !reSubdomain.MatchString(o["portal"]) {
		return errors.New("포털 서브도메인은 영문 소문자·숫자·- 만 쓸 수 있습니다 (예: auth)")
	}
	if o["addPortal"] != "0" {
		o["addPortal"] = "1"
	}
	if !validUsername(o["adminUser"]) {
		return errors.New("Authelia 관리자 아이디는 영문·숫자·-_. 로 1~64자입니다")
	}
	// a reinstall over existing files keeps the users file: the password is only needed the first time
	if rec := a.store.Snapshot().Stacks["authelia"]; rec == nil || o["secretPassword"] != "" {
		if len(o["secretPassword"]) < 10 {
			return errors.New("Authelia 관리자 비밀번호는 10자 이상이어야 합니다")
		}
	}
	return nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// autheliaConfig: the v4.38+ configuration. The access_control block comes from Gilmok's generator,
// so later applies replace it the same way as for any other Authelia.
func autheliaConfig(d Data, portal string) string {
	dom := d.Settings.Domain
	return `# 길목이 만든 Authelia 설정입니다 (관리형). access_control 블록은 길목이 관리하고,
# 나머지는 직접 고쳐도 됩니다 (다시 설치하면 이 파일을 새로 만들지 않고 그대로 둡니다).
# 비밀값은 이 파일에 없습니다 — /secrets 의 파일을 *_FILE 환경변수로 읽습니다.
theme: 'dark'
server:
  address: 'tcp://:9091'
log:
  level: 'info'
ntp:
  disable_failure: true
totp:
  issuer: ` + q(dom) + `
authentication_backend:
  file:
    path: '/config/users_database.yml'
    password:
      algorithm: 'argon2'
session:
  cookies:
    - domain: ` + q(dom) + `
      authelia_url: ` + q("https://"+portal+"."+dom) + `
storage:
  local:
    path: '/data/db.sqlite3'
notifier:
  filesystem:
    filename: '/data/notification.txt'
` + GenerateAccessControl(d)
}

func renderAutheliaStack(a *App, o map[string]string, dir, host, network, ctr string, log func(string, ...any)) error {
	for _, sub := range []string{"config", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		return err
	}
	// secrets: made once, kept on reinstall (changing them would log everyone out / lose the DB)
	for _, name := range []string{"jwt", "session", "storage"} {
		p := filepath.Join(dir, "secrets", name)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		v, err := randHex(32)
		if err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			return err
		}
	}
	log("  비밀값 3개 (jwt·session·storage) 준비")
	d := a.store.Snapshot()
	cfg := filepath.Join(dir, "config", "configuration.yml")
	if _, err := os.Stat(cfg); err != nil {
		if err := os.WriteFile(cfg, []byte(autheliaConfig(d, o["portal"])), 0o644); err != nil {
			return err
		}
		log("  configuration.yml 생성 (도메인 %s, 포털 %s.%s)", d.Settings.Domain, o["portal"], d.Settings.Domain)
	} else {
		log("  configuration.yml 이 이미 있어 그대로 둡니다")
	}
	users := filepath.Join(dir, "config", "users_database.yml")
	list := map[string]*AUser{}
	if old, err := LoadUsers(users); err == nil {
		list = old
	}
	if pw := o["secretPassword"]; pw != "" {
		hash, err := HashPassword(pw)
		if err != nil {
			return err
		}
		name := o["adminUser"]
		u := list[name]
		if u == nil {
			u = &AUser{DisplayName: name, Email: name + "@" + d.Settings.Domain}
			list[name] = u
		}
		u.Password, u.Disabled = hash, false
		if !contains(u.Groups, "admins") {
			u.Groups = append(u.Groups, "admins")
		}
		b, err := MarshalUsers(list)
		if err != nil {
			return err
		}
		if err := os.WriteFile(users, b, 0o600); err != nil {
			return err
		}
		log("  관리자 %s (그룹 admins) 저장", name)
	}
	compose := `# 길목이 만든 파일입니다 (관리형 Authelia). 직접 고치면 다시 설치할 때 덮어써집니다.
name: ` + stackProject(ctr) + `
services:
  authelia:
    image: authelia/authelia:latest
    container_name: ` + ctr + `
    restart: unless-stopped
    labels:
      gilmok.managed: authelia
    environment:
      AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE: /secrets/jwt
      AUTHELIA_SESSION_SECRET_FILE: /secrets/session
      AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE: /secrets/storage
    volumes:
      - ` + yq(host+"/config:/config") + `
      - ` + yq(host+"/secrets:/secrets:ro") + `
      - ` + yq(host+"/data:/data") + `
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

func verifyAutheliaStack(a *App, ctr string) error {
	since := time.Now().Add(-2 * time.Minute)
	if t, ok := ctrStartedAt(ctr); ok {
		since = t
	}
	if err := waitHealthy(ctr, since, "Startup complete", 60*time.Second); err != nil {
		return fmt.Errorf("Authelia가 시작되지 않았습니다: %v", err)
	}
	return nil
}

var reForwardAuth = regexp.MustCompile(`(forward_auth\s+)([A-Za-z0-9_.-]+)(:9091)`)

func adoptAutheliaStack(d *Data, rec *ManagedStack) {
	st := &d.Settings
	old := st.AutheliaCtr
	st.UseAuthelia, st.AutheliaCtr = true, rec.Container
	st.AutheliaConfig = filepath.Join(rec.Dir, "config", "configuration.yml")
	st.AutheliaUsers = filepath.Join(rec.Dir, "config", "users_database.yml")
	st.AutheliaCtrDir, st.AutheliaStackDir, st.AutheliaService = "/config", "", "authelia"
	// the first admin is in group admins: register it so it can be picked like any other group
	found := false
	for _, g := range d.AGroups {
		if g.Name == "admins" {
			found = true
		}
	}
	if !found {
		d.AGroups = append(d.AGroups, AGroup{Name: "admins", Desc: "Authelia 관리자 (설치 때 길목이 만듦)"})
		d.AGroupsInit = true
	}
	// the Caddy snippet that sent logins to the old address now points at this container
	if m := reForwardAuth.FindStringSubmatch(st.CaddyBase); m != nil && m[2] != rec.Container && (m[2] == old || m[2] == "authelia") {
		st.CaddyBase = reForwardAuth.ReplaceAllString(st.CaddyBase, "${1}"+rec.Container+"${3}")
		d.markDirty("Authelia 주소 변경 (forward_auth → " + rec.Container + ")")
	}
	// sites that pointed at the old Authelia (an imported portal, typically) now reach this one —
	// otherwise logins go to the new Authelia while the portal still shows the old
	newUp := rec.Container + ":9091"
	hasPortal := false
	for _, s := range d.Services {
		up := strings.TrimPrefix(strings.TrimPrefix(s.Upstream, "http://"), "https://")
		if up != newUp && (up == old+":9091" || up == "authelia:9091") {
			s.Upstream, s.Updated = newUp, time.Now()
			d.markDirty("서비스 수정: " + s.Subdomain + " → " + newUp + " (새 Authelia)")
		}
		if strings.HasSuffix(s.Upstream, newUp) {
			hasPortal = true
		}
	}
	// the login portal itself: a public site without the login gate (gating it would loop)
	portal := rec.Options["portal"]
	if rec.Options["addPortal"] == "1" && portal != "" && !hasPortal {
		for _, s := range d.Services {
			if s.Subdomain == portal {
				return // that name is taken by another site — leave it as the user set it
			}
		}
		d.Services = append(d.Services, &Service{
			ID: newID(), Subdomain: portal, Upstream: rec.Container + ":9091", Exposure: ExposurePublic,
			Proxied: st.UseCloudflare, Enabled: true, ManageDNS: st.UseCloudflare,
			Notes: "Authelia 로그인 포털 (길목이 추가) — Authelia 관문을 켜지 마세요", Updated: time.Now(),
		})
		d.markDirty("서비스 추가: " + portal + " (Authelia 포털)")
	}
}
