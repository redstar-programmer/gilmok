package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type App struct {
	store   *Store
	cf      *CF
	dataDir string
	applyMu sync.Mutex // one apply/update at a time
	usersMu sync.Mutex // Authelia users: read-modify-write of users_database.yml
	cfwafMu sync.Mutex // Cloudflare WAF rules apply
	csMu    sync.Mutex // CrowdSec → Cloudflare list sync
	faultMu sync.Mutex
	fault   string // one-shot fault injection (GM_DEV_FAULTS=1 only)
	cs      csState
	topo    topoCache
	mon     *Monitor
	ldb     *LogDB
	auth    *Auth
	stk     stackMgr // managed stack jobs (stacks.go)
}

type Plan struct {
	CaddyCurrent    string          `json:"caddyCurrent"`
	CaddyNext       string          `json:"caddyNext"`
	AutheliaCurrent string          `json:"autheliaCurrent"`
	AutheliaNext    string          `json:"autheliaNext"`
	DNS             []DNSAction     `json:"dns"`
	DNSError        string          `json:"dnsError,omitempty"`
	PublicIP        string          `json:"publicIp"`
	PublicIP6       string          `json:"publicIp6,omitempty"`
	Warnings        []string        `json:"warnings"`
	Use             map[string]bool `json:"use"`
}

func (a *App) plan(ctx context.Context, d Data, withDNS bool) Plan {
	st := d.Settings
	p := Plan{Use: map[string]bool{"caddy": st.UseCaddy, "authelia": st.UseAuthelia, "cloudflare": st.UseCloudflare}}
	if st.UseCaddy {
		gen, heldMTLS := a.caddyGenData(d)
		p.CaddyNext = GenerateCaddyfile(gen)
		if len(heldMTLS) > 0 {
			p.Warnings = append(p.Warnings, mtlsHeldText(heldMTLS))
		}
		if b, err := os.ReadFile(st.CaddyfilePath); err == nil {
			p.CaddyCurrent = string(b)
		} else {
			p.Warnings = append(p.Warnings, "현재 Caddyfile을 읽지 못했습니다: "+err.Error())
		}
		if strings.TrimSpace(st.CaddyBase) == "" {
			p.Warnings = append(p.Warnings, "Caddy 기본 골격이 비어 있습니다. 먼저 '기존 설정 가져오기'를 실행하세요.")
		}
	}
	if st.UseAuthelia {
		if b, err := os.ReadFile(st.AutheliaConfig); err == nil {
			p.AutheliaCurrent = ExtractAccessControl(string(b))
		} else {
			p.Warnings = append(p.Warnings, "Authelia 설정을 읽지 못했습니다: "+err.Error())
		}
		p.AutheliaNext = strings.TrimRight(GenerateAccessControl(d), "\n")
	}
	needsTS := false
	for _, s := range d.Services {
		if s.Enabled && s.Exposure == ExposureTailscale {
			needsTS = true
		}
	}
	if needsTS && st.UseCloudflare && st.TailscaleIP == "" {
		p.Warnings = append(p.Warnings, "Tailscale 전용 서비스가 있지만 설정에 Tailscale IP가 없습니다.")
	}
	if !st.UseCloudflare {
		p.DNSError = "Cloudflare를 쓰지 않습니다"
	} else if !withDNS {
		p.DNSError = "DNS 계획은 생략했습니다"
	} else if a.cf.Configured() {
		ip, err := PublicIP(ctx)
		if err != nil {
			p.DNSError = err.Error()
		}
		p.PublicIP = ip
		ip6 := ""
		if st.DDNSIPv6 {
			if ip6, err = PublicIP6(ctx); err != nil {
				p.Warnings = append(p.Warnings, err.Error()+" — AAAA 레코드는 이번에 건너뜁니다")
			}
			p.PublicIP6 = ip6
		}
		recs, err := a.cf.Records(ctx, st.Domain)
		if err != nil {
			p.DNSError = err.Error()
		} else if ip != "" {
			p.DNS = PlanDNS(d, recs, ip, ip6, d.ManagedDNS, d.ManagedDNS6)
			n := 0
			for _, x := range p.DNS {
				if x.IPChange {
					n++
				}
			}
			if n > 0 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("공개 레코드 %d개의 주소가 지금 길목이 본 공인 IP(%s)와 다릅니다. 길목이 웹 서버와 다른 네트워크(예: 테스트 PC)에서 실행 중이면 이 주소는 틀린 값입니다 — 기본으로는 주소를 바꾸지 않고, 「공인 IP 변경 반영」을 체크했을 때만 바꿉니다.", n, ip))
			}
		}
	} else {
		p.DNSError = "Cloudflare 토큰이 없어 DNS는 건너뜁니다"
	}
	return p
}

type logger struct {
	mu    sync.Mutex
	lines []string
}

func (l *logger) f(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// backupKeep: how many backups stay (the oldest are removed after each new one).
const backupKeep = 30

func backup(dataDir, label string, files map[string]string) (string, error) {
	root := filepath.Join(dataDir, "backups")
	base := filepath.Join(root, time.Now().Format("20060102-150405")+"-"+label)
	dir := base
	// two backups in the same second must not overwrite each other
	for i := 2; ; i++ {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			break
		}
		dir = fmt.Sprintf("%s-%d", base, i)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	defer pruneBackups(root, backupKeep)
	for name, src := range files {
		b, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// writeInPlace keeps the inode so single-file bind mounts (./Caddyfile:/etc/caddy/Caddyfile) see the change.
func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// validateAutheliaConfig writes a candidate next to the real file (the config dir is
// mounted in both containers) and runs Authelia's own validator inside its container,
// where the secret files/env are available.
func validateAutheliaConfig(st Settings, content string) error {
	rb := make([]byte, 6) // unique: two validations at once must not overwrite each other's file
	_, _ = rand.Read(rb)
	name := ".gilmok-candidate-" + hex.EncodeToString(rb) + ".yml"
	local := filepath.Join(filepath.Dir(st.AutheliaConfig), name)
	if err := os.WriteFile(local, []byte(content), 0o600); err != nil {
		return err
	}
	defer os.Remove(local)
	inCtr := strings.TrimRight(st.AutheliaCtrDir, "/") + "/" + name
	out, err := ctrExec(st.AutheliaCtr, nil, "authelia", "config", "validate", "--config", inCtr)
	if err != nil && (strings.Contains(out, "unknown command") || strings.Contains(out, "unknown flag")) {
		out, err = ctrExec(st.AutheliaCtr, nil, "authelia", "validate-config", "--config", inCtr)
	}
	if err != nil || strings.Contains(out, "with errors") {
		// on failure the CLI appends its cobra usage text after the real errors — drop it
		if i := strings.Index(out, "\nUsage:"); i >= 0 {
			out = out[:i]
		}
		return fmt.Errorf("Authelia 설정 검증 실패:\n%s", lastLines(strings.TrimSpace(out), 12))
	}
	return nil
}

func restartAuthelia(st Settings) error {
	since := time.Now().Add(-1 * time.Second)
	if err := ctrRestart(st.AutheliaCtr); err != nil {
		return err
	}
	// Read logs only from the run that `docker restart` just started. A fixed "now - 1s"
	// window can include fatal lines from the previous (crash-looping) run and report a
	// healthy restart as failed — seen when rolling back a broken users_database.yml.
	if t, ok := ctrStartedAt(st.AutheliaCtr); ok {
		since = t
	}
	return waitHealthy(st.AutheliaCtr, since, "Startup complete", 40*time.Second)
}

// Fault injection (dev/test only, GM_DEV_FAULTS=1): a one-shot fault makes the next
// apply write a deliberately broken file *after* validation, so the real failure
// detection + rollback paths run against the real containers.
const (
	FaultAutheliaStart = "authelia-start" // configuration.yml broken → Authelia fails to start
	FaultCaddyReload   = "caddy-reload"   // Caddyfile broken → caddy reload fails (Authelia must be rolled back too)
	FaultUsersStart    = "users-start"    // users_database.yml broken → Authelia fails to start
)

func faultsEnabled() bool { return os.Getenv("GM_DEV_FAULTS") == "1" }

func (a *App) takeFault(kind string) bool {
	a.faultMu.Lock()
	defer a.faultMu.Unlock()
	if kind != "" && a.fault == kind {
		a.fault = ""
		return true
	}
	return false
}

func (a *App) peekFault() string {
	a.faultMu.Lock()
	defer a.faultMu.Unlock()
	return a.fault
}

const brokenYAML = "\n# gilmok fault injection\ngilmok_fault_injection: [unclosed\n"
const brokenCaddy = "\n# gilmok fault injection\ngilmok-fault.invalid {\n\tthis_directive_does_not_exist\n}\n"

// restoreAuthelia writes back the previous file and waits for a healthy start.
func restoreAuthelia(L *logger, st Settings, path string, old []byte) {
	L.f("  ↺ Authelia: 이전 파일로 복구 중…")
	if err := writeInPlace(path, old); err != nil {
		L.f("  ✗ 복구 쓰기 실패: %v — 백업 폴더에서 수동 복구가 필요합니다", err)
		return
	}
	if err := restartAuthelia(st); err != nil {
		L.f("  ✗ 복구 후에도 시작 실패: %v", err)
		return
	}
	L.f("  ✓ Authelia 이전 상태로 정상 시작")
}

// Apply generates, validates and applies everything, rolling back on failure.
// Order: validate both → backup → Authelia (restart) → Caddy (reload) → DNS.
// A Caddy failure rolls Authelia back too, so both stay on the same generation.
func (a *App) Apply(allowIPChange bool) ([]string, error) {
	if strings.TrimSpace(a.store.Snapshot().Settings.Domain) == "" {
		return nil, errors.New("도메인이 정해져 있지 않습니다 — 설정 탭 › 도메인에서 먼저 정하세요")
	}
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	L := &logger{}
	d := a.store.Snapshot()
	st := d.Settings
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if !st.UseCaddy && !st.UseAuthelia && !st.UseCloudflare {
		return L.lines, fmt.Errorf("적용할 구성요소가 없습니다 — 설정 탭 › 구성요소에서 쓰는 것을 켜세요")
	}
	var caddyNext string
	var caddyCur, authRaw []byte
	var authNext string
	var err error
	var heldMTLS []string // mTLS sites left out of this apply (no CA yet) — stay pending
	if st.UseCaddy {
		if strings.TrimSpace(st.CaddyBase) == "" {
			return L.lines, fmt.Errorf("Caddy 기본 골격이 비어 있습니다. 먼저 기존 설정을 가져오세요")
		}
		// mTLS sites of a Caddy without its CA file are held back (not served at all — never served
		// without the client-certificate check); everything else is applied
		var gen Data
		gen, heldMTLS = a.caddyGenData(d)
		if len(heldMTLS) > 0 {
			L.f("• %s", mtlsHeldText(heldMTLS))
		}
		caddyNext = GenerateCaddyfile(gen)
		if caddyCur, err = os.ReadFile(st.CaddyfilePath); err != nil {
			return L.lines, fmt.Errorf("현재 Caddyfile을 읽지 못했습니다 (되돌릴 원본이 없어 중단): %w", err)
		}
	} else {
		L.f("• Caddy: 사용 안 함")
	}
	if st.UseAuthelia {
		if authRaw, err = os.ReadFile(st.AutheliaConfig); err != nil {
			return L.lines, fmt.Errorf("Authelia 설정을 읽지 못했습니다: %w", err)
		}
		authNext = ReplaceAccessControl(string(authRaw), GenerateAccessControl(d))
	} else {
		L.f("• Authelia: 사용 안 함")
	}
	faultAuth := a.takeFault(FaultAutheliaStart)
	faultCaddy := a.takeFault(FaultCaddyReload)
	caddyChanged := st.UseCaddy && (string(caddyCur) != caddyNext || faultCaddy)
	authChanged := st.UseAuthelia && (string(authRaw) != authNext || faultAuth)
	if faultAuth {
		L.f("⚠ 장애 주입: %s (검증 후 깨진 configuration.yml을 씁니다)", FaultAutheliaStart)
	}
	if faultCaddy {
		L.f("⚠ 장애 주입: %s (검증 후 깨진 Caddyfile을 씁니다)", FaultCaddyReload)
	}

	// 1) validate both before touching anything
	if caddyChanged {
		L.f("▶ Caddyfile 검증")
		if err := validateCaddy(st, caddyNext); err != nil {
			return L.lines, err
		}
		L.f("  ✓ 문법/모듈 검증 통과")
	} else if st.UseCaddy {
		L.f("• Caddyfile 변경 없음")
	}
	if authChanged {
		L.f("▶ Authelia 설정 검증")
		if err := validateAutheliaConfig(st, authNext); err != nil {
			return L.lines, err
		}
		L.f("  ✓ 검증 통과")
	} else if st.UseAuthelia {
		L.f("• Authelia access_control 변경 없음")
	}

	// 2) backup
	if caddyChanged || authChanged {
		files := map[string]string{}
		if st.UseCaddy {
			files["Caddyfile"] = st.CaddyfilePath
		}
		if st.UseAuthelia {
			files["configuration.yml"] = st.AutheliaConfig
		}
		dir, err := backup(a.dataDir, "apply", files)
		if err != nil {
			return L.lines, fmt.Errorf("백업 실패: %w", err)
		}
		L.f("• 백업: %s", dir)
	}

	// 3) Authelia first (Caddy's forward_auth depends on it)
	if authChanged {
		L.f("▶ Authelia 적용 (재시작)")
		write := authNext
		if faultAuth {
			write += brokenYAML
		}
		if err := writeInPlace(st.AutheliaConfig, []byte(write)); err != nil {
			L.f("  ✗ 쓰기 실패: %v", err)
			restoreAuthelia(L, st, st.AutheliaConfig, authRaw)
			return L.lines, fmt.Errorf("Authelia 설정 쓰기 실패 — 되돌렸습니다")
		}
		if err := restartAuthelia(st); err != nil {
			L.f("  ✗ %v", err)
			restoreAuthelia(L, st, st.AutheliaConfig, authRaw)
			return L.lines, fmt.Errorf("Authelia 적용 실패 — 이전 상태로 되돌렸습니다")
		}
		L.f("  ✓ Authelia 정상 시작")
	}

	// 4) Caddy
	if caddyChanged {
		L.f("▶ Caddy 적용 (무중단 reload)")
		write := caddyNext
		if faultCaddy {
			write += brokenCaddy
		}
		err := writeInPlace(st.CaddyfilePath, []byte(write))
		if err == nil {
			err = reloadCaddy(st)
		}
		if err != nil {
			L.f("  ✗ %v", err)
			L.f("  ↺ Caddy: 이전 Caddyfile로 복구 중…")
			if e := writeInPlace(st.CaddyfilePath, caddyCur); e != nil {
				L.f("  ✗ 복구 쓰기 실패: %v — 백업 폴더에서 수동 복구가 필요합니다", e)
			} else if e := reloadCaddy(st); e != nil {
				// a failed reload keeps the old config running, so this is mostly cosmetic
				L.f("  ✗ 복구 reload 실패: %v", e)
			} else {
				L.f("  ✓ Caddy 이전 설정으로 복구됨")
			}
			if authChanged {
				restoreAuthelia(L, st, st.AutheliaConfig, authRaw)
			}
			return L.lines, fmt.Errorf("Caddy 적용 실패 — 이전 상태로 되돌렸습니다")
		}
		L.f("  ✓ Caddy reload 완료")
	}

	// 5) DNS
	var managed, managed6 []string
	if st.UseCloudflare && a.cf.Configured() {
		L.f("▶ Cloudflare DNS 동기화")
		ip, err := PublicIP(ctx)
		ip6 := ""
		if st.DDNSIPv6 {
			var e6 error
			if ip6, e6 = PublicIP6(ctx); e6 != nil {
				L.f("  ! %v — AAAA 레코드는 건너뜁니다 (기존 AAAA는 그대로)", e6)
			}
		}
		recs, err2 := a.cf.Records(ctx, st.Domain)
		switch {
		case err != nil:
			L.f("  ✗ %v (DNS 건너뜀)", err)
		case err2 != nil:
			L.f("  ✗ %v (DNS 건너뜀)", err2)
		default:
			acts := PlanDNS(d, recs, ip, ip6, d.ManagedDNS, d.ManagedDNS6)
			var held []string
			if !allowIPChange {
				if acts, held = holdIPChanges(acts); len(held) > 0 {
					L.f("  ! 공인 IP가 레코드와 달라 주소는 바꾸지 않았습니다 (%d개) — 길목이 웹 서버와 다른 네트워크에서 실행 중일 수 있습니다", len(held))
					for _, x := range held {
						L.f("    · %s", x)
					}
					L.f("    맞는 변경이면 적용 화면에서 「공인 IP 변경 반영」을 체크하고 다시 적용하세요")
				}
			}
			n := 0
			for _, x := range acts {
				if x.Action != "ok" && x.Action != "skip" {
					n++
				}
			}
			if n == 0 {
				L.f("  • 변경 없음")
			}
			done := map[string]bool{}
			for _, k := range a.cf.Execute(ctx, st.Domain, acts, L.f) {
				done[k] = true
			}
			want := desiredDNS(d, ip, ip6)
			managed = append([]string{}, managedNames(want, "A")...)
			managed6 = append([]string{}, managedNames(want, "AAAA")...)
			// a delete that failed keeps the record owned, so the next apply retries it (no orphans)
			for _, x := range acts {
				if x.Action == "delete" && !done[x.Type+" "+x.Name] {
					if x.Type == "AAAA" {
						managed6 = append(managed6, x.Name)
					} else {
						managed = append(managed, x.Name)
					}
					L.f("    · %s %s 삭제 실패 — 다음 적용 때 다시 시도합니다", x.Type, x.Name)
				}
			}
			// the WAN address is "known" only when the records were actually moved to it; when the
			// change was held back, DDNS must still see it as a change later
			if len(held) == 0 {
				_ = a.store.Update(func(x *Data) error {
					x.LastPublicIP = ip
					if ip6 != "" {
						x.LastPublicIP6 = ip6
					}
					return nil
				})
			}
		}
	}

	_ = a.store.Update(func(x *Data) error {
		x.Dirty = false
		x.Pending = nil
		x.LastApplied = time.Now()
		x.SetupDone = true // set up through the tabs and applied: stop offering the setup wizard
		if len(heldMTLS) > 0 {
			x.markDirty(mtlsHeldText(heldMTLS))
		}
		if managed != nil {
			x.ManagedDNS = managed
			x.ManagedDNS6 = managed6
		}
		return nil
	})
	L.f("✔ 완료")
	return L.lines, nil
}

// ApplyUsers writes users_database.yml and restarts Authelia with rollback.
func (a *App) ApplyUsers(users map[string]*AUser) ([]string, error) {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	L := &logger{}
	st := a.store.Snapshot().Settings
	b, err := MarshalUsers(users)
	if err != nil {
		return nil, err
	}
	old, err := os.ReadFile(st.AutheliaUsers)
	if err != nil {
		return nil, fmt.Errorf("현재 사용자 파일을 읽지 못했습니다 (되돌릴 원본이 없어 중단): %w", err)
	}
	dir, err := backup(a.dataDir, "users", map[string]string{"users_database.yml": st.AutheliaUsers})
	if err != nil {
		return nil, err
	}
	L.f("• 백업: %s", dir)
	if a.takeFault(FaultUsersStart) {
		L.f("⚠ 장애 주입: %s (깨진 users_database.yml을 씁니다)", FaultUsersStart)
		b = append(b, []byte(brokenYAML)...)
	}
	if err := writeInPlace(st.AutheliaUsers, b); err != nil {
		L.f("  ✗ 쓰기 실패: %v", err)
		restoreAuthelia(L, st, st.AutheliaUsers, old)
		return L.lines, fmt.Errorf("사용자 파일 쓰기 실패 — 되돌렸습니다")
	}
	L.f("▶ Authelia 재시작")
	if err := restartAuthelia(st); err != nil {
		L.f("  ✗ %v", err)
		restoreAuthelia(L, st, st.AutheliaUsers, old)
		return L.lines, fmt.Errorf("사용자 적용 실패 — 되돌렸습니다")
	}
	L.f("  ✓ 정상 시작")
	return L.lines, nil
}

// pruneBackups keeps the newest `keep` backup folders (names start with the timestamp).
func pruneBackups(root string, keep int) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	for i := 0; i < len(dirs)-keep; i++ {
		_ = os.RemoveAll(filepath.Join(root, dirs[i]))
	}
}

// caddyGenData: the data the Caddyfile is generated from. Sites that would make Caddy refuse the
// WHOLE configuration are left out (held) so the rest can still be applied:
//   - a site needs a snippet the base configuration does not define (cf_only for mTLS, authelia for
//     the login gate, or an `import x` in its extra directives) — typical after importing a
//     Caddyfile from another Caddy
//   - an mTLS site on a Caddy Gilmok installed that has no CA file yet
//
// Held sites are never served half-configured (e.g. without the mTLS check). Returns "sub (reason)".
func (a *App) caddyGenData(d Data) (Data, []string) {
	defined := map[string]bool{}
	for _, m := range reSnippetDef.FindAllStringSubmatch(d.Settings.CaddyBase, -1) {
		defined[m[1]] = true
	}
	caMissing := false
	if ca := a.caddyCAFile(); ca != "" {
		if _, err := os.Stat(ca); err != nil {
			caMissing = true
		}
	}
	var held []string
	svcs := make([]*Service, 0, len(d.Services))
	for _, s := range d.Services {
		if !s.Enabled || s.DNSOnly {
			svcs = append(svcs, s)
			continue
		}
		var need []string
		mtls := s.Exposure == ExposurePublic && s.Proxied && s.MTLS && d.Settings.UseCloudflare
		if mtls {
			need = append(need, snippetMTLS)
		}
		if s.Authelia.Enabled && d.Settings.UseAuthelia {
			need = append(need, snippetAuthelia)
		}
		for _, l := range strings.Split(s.Extra, "\n") {
			if f := strings.Fields(stripComment(strings.TrimSpace(l))); len(f) >= 2 && f[0] == "import" && !strings.ContainsAny(f[1], "/.*") {
				need = append(need, f[1])
			}
		}
		reason := ""
		for _, n := range need {
			if !defined[n] && !strings.HasPrefix(n, "gm_") { // gm_* snippets are generated by Gilmok
				reason = fmt.Sprintf("기본 골격에 스니펫 (%s) 없음", n)
				break
			}
		}
		if reason == "" && mtls && caMissing {
			reason = "mTLS CA 없음"
		}
		if reason == "" {
			svcs = append(svcs, s)
			continue
		}
		cp := *s
		cp.Enabled = false
		svcs = append(svcs, &cp)
		held = append(held, fmt.Sprintf("%s (%s)", s.Subdomain, reason))
	}
	if len(held) == 0 {
		return d, nil
	}
	d.Services = svcs
	return d, held
}

var reSnippetDef = regexp.MustCompile(`(?m)^\s*\(([^)\s]+)\)\s*\{`)

func mtlsHeldText(held []string) string {
	return fmt.Sprintf("사이트 %d개 보류: %s — 이 사이트만 이번 적용에서 뺐습니다(나머지는 적용). mTLS CA는 Caddy 탭 › 연결의 「mTLS CA…」, 스니펫은 Caddy 탭 › 전역 설정 › 기본 골격에서 채운 뒤 다시 적용하세요", len(held), strings.Join(held, ", "))
}
