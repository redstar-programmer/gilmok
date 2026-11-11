package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

//go:embed web
var webFS embed.FS

var version = "0.1.2"

func main() {
	dataDir := env("GM_DATA", "/data")
	store, err := OpenStore(filepath.Join(dataDir, "gilmok.json"))
	if err != nil {
		log.Fatalf("data: %v", err)
	}
	cfTokenUIPath = filepath.Join(dataDir, "secrets", "cf_token")
	csKeyUIPath = filepath.Join(dataDir, "secrets", "crowdsec_key")
	app := &App{store: store, cf: NewCF(), dataDir: dataDir}
	ldb, err := openLogDB(filepath.Join(dataDir, "gilmok-logs.db"))
	if err != nil {
		log.Fatalf("log db: %v", err)
	}
	app.ldb = ldb
	app.applyLogPolicy(store.Snapshot().Settings)
	ensureProxySecret(store)
	app.detectSelf()
	app.seedGroups() // groups already used by services / users become the registered list (once)
	app.inferComponents()
	app.logEvent("system", "info", "gilmok.start", "", "길목 시작 v"+version, nil)
	app.cs.kick = make(chan struct{}, 1)
	app.mon = newMonitor()
	go app.monitorLoop()
	go app.diskGuardLoop()
	go app.metricsFlushLoop()
	go app.autheliaStreamLoop()
	go app.updatesLoop()
	// docker stop → SIGTERM: keep the dashboard history
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-sig
		app.saveMetrics()
		app.logEvent("system", "info", "gilmok.stop", "", "길목 종료", nil)
		time.Sleep(1500 * time.Millisecond) // let the log writer flush
		os.Exit(0)
	}()
	go app.ddnsLoop()
	go app.crowdsecLoop()

	handler := app.handler()

	addr := env("GM_LISTEN", ":8080")
	log.Printf("Gilmok %s listening on %s", version, addr)
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	log.Fatal(srv.ListenAndServe())
}

// handler builds every route (also used by the tests, so they exercise the real router).
func (app *App) handler() http.Handler {
	mux := http.NewServeMux()
	auth := newAuth(app)
	app.auth = auth

	// auth (no session yet)
	mux.HandleFunc("GET /api/auth/state", auth.state)
	mux.HandleFunc("POST /api/auth/setup", auth.setup)
	mux.HandleFunc("POST /api/auth/login", auth.login)
	mux.HandleFunc("POST /api/auth/logout", auth.logout)
	mux.HandleFunc("POST /api/auth/lang", auth.chooseLang) // first visit only (language not chosen yet)

	S := auth.sensitive // step-up: fresh password (+TOTP) required
	api := http.NewServeMux()
	api.HandleFunc("GET /api/state", app.getState)
	api.HandleFunc("POST /api/services", app.saveService)
	api.HandleFunc("PUT /api/services/{id}", app.saveService)
	api.HandleFunc("DELETE /api/services/{id}", app.deleteService)
	api.HandleFunc("POST /api/services/bulk", app.postServicesBulk)
	api.HandleFunc("GET /api/groups", app.getGroups)
	api.HandleFunc("POST /api/groups", app.postGroup)
	api.HandleFunc("PUT /api/groups/{name}", app.putGroup)
	api.HandleFunc("DELETE /api/groups/{name}", app.deleteGroup)
	api.HandleFunc("GET /api/services/export.xlsx", app.getServicesExport)
	api.HandleFunc("PUT /api/settings", app.saveSettings) // step-up checked inside for security fields
	api.HandleFunc("POST /api/import", S(app.importExisting))
	api.HandleFunc("GET /api/fs/browse", app.getFSBrowse)
	api.HandleFunc("GET /api/plan", app.getPlan)
	api.HandleFunc("POST /api/apply", S(app.postApply))
	api.HandleFunc("GET /api/dns", app.getDNS)
	api.HandleFunc("POST /api/dns/records", S(app.postDNSRecord))
	api.HandleFunc("PUT /api/dns/records/{id}", S(app.putDNSRecord))
	api.HandleFunc("DELETE /api/dns/records/{id}", S(app.deleteDNSRecord))
	api.HandleFunc("GET /api/users", app.listUsers)
	api.HandleFunc("POST /api/users", S(app.saveUser))
	api.HandleFunc("PUT /api/users/{name}", S(app.saveUser))
	api.HandleFunc("DELETE /api/users/{name}", S(app.deleteUser))
	api.HandleFunc("GET /api/system", app.getSystem)
	api.HandleFunc("POST /api/system/update", S(app.postUpdate))
	api.HandleFunc("GET /api/backups", app.listBackups)
	api.HandleFunc("GET /api/config/export", app.getConfigExport)
	api.HandleFunc("POST /api/config/import", S(app.postConfigImport))
	api.HandleFunc("GET /api/reset/plan", app.getResetPlan)
	api.HandleFunc("GET /api/setup/detect", app.getSetupDetect)
	api.HandleFunc("POST /api/setup/done", app.postSetupDone)
	api.HandleFunc("GET /api/tailscale/detect", app.getTailscaleDetect)
	api.HandleFunc("GET /api/stacks", app.getStacks)
	api.HandleFunc("POST /api/stacks/{name}/preflight", app.postStackPreflight)
	api.HandleFunc("GET /api/stacks/{name}/compose", app.getStackCompose)
	api.HandleFunc("PUT /api/stacks/{name}/compose", S(app.putStackCompose))
	api.HandleFunc("POST /api/stacks/{name}/compose-check", app.postStackComposeCheck)
	api.HandleFunc("POST /api/stacks/{name}/compose-reset", S(app.postStackComposeReset))
	api.HandleFunc("GET /api/docker/networks", app.getDockerNetworks)
	api.HandleFunc("POST /api/stacks/{name}/{action}", S(app.postStackAction))
	api.HandleFunc("POST /api/crowdsec/bouncer", S(app.postCSBouncer))
	api.HandleFunc("POST /api/reset", S(app.postReset))
	api.HandleFunc("GET /api/check/{target}", app.getCheck)
	api.HandleFunc("POST /api/validate", app.postValidate)
	api.HandleFunc("POST /api/auth/password", auth.changePassword)
	api.HandleFunc("POST /api/auth/reauth", auth.reauth)
	api.HandleFunc("GET /api/auth/sessions", auth.listSessions)
	api.HandleFunc("DELETE /api/auth/sessions/{id}", S(auth.revokeSession))
	api.HandleFunc("POST /api/auth/totp/begin", S(auth.totpBegin))
	api.HandleFunc("POST /api/auth/totp/enable", S(auth.totpEnable))
	api.HandleFunc("POST /api/auth/totp/disable", S(auth.totpDisable))
	api.HandleFunc("POST /api/auth/recovery", S(auth.recoveryRegen))
	api.HandleFunc("POST /api/auth/bootstrap", auth.bootstrap)
	api.HandleFunc("GET /api/accounts", auth.listAccounts)
	api.HandleFunc("POST /api/accounts/require-2fa", S(auth.requireTwoFactor))
	api.HandleFunc("POST /api/accounts", S(auth.createAccount))
	api.HandleFunc("PUT /api/accounts/{name}", S(auth.updateAccount))
	api.HandleFunc("POST /api/accounts/{name}/password", S(auth.resetAccountPassword))
	api.HandleFunc("POST /api/accounts/{name}/reset-2fa", S(auth.resetAccount2FA))
	api.HandleFunc("DELETE /api/accounts/{name}", S(auth.deleteAccount))
	api.HandleFunc("POST /api/roles", S(auth.createRole))
	api.HandleFunc("PUT /api/roles/{id}", S(auth.updateRole))
	api.HandleFunc("DELETE /api/roles/{id}", S(auth.deleteRole))
	api.HandleFunc("GET /api/waf/events", app.getWAFEvents)
	api.HandleFunc("GET /api/waf/meta", app.getWAFMeta)
	api.HandleFunc("POST /api/waf/test", app.postWAFTest)
	api.HandleFunc("GET /api/cfwaf/events", app.getCFEvents)
	api.HandleFunc("GET /api/topology", app.getTopology)
	api.HandleFunc("GET /api/dashboard", app.getDashboard)
	api.HandleFunc("PUT /api/dashboard", app.putDashboard)
	api.HandleFunc("POST /api/dash/data", app.postDashData)
	api.HandleFunc("GET /api/dash/requests", app.getDashRequests)
	api.HandleFunc("GET /api/health", app.getHealth)
	api.HandleFunc("POST /api/ddns/run", app.postDDNSRun)
	api.HandleFunc("GET /api/cloudflare/token", app.getCFToken)
	api.HandleFunc("POST /api/cloudflare/token", S(app.postCFToken))
	api.HandleFunc("DELETE /api/cloudflare/token", S(app.deleteCFToken))
	api.HandleFunc("GET /api/cfwaf", app.getCFWAF)
	api.HandleFunc("POST /api/cfwaf/apply", S(app.postCFWAFApply))
	api.HandleFunc("POST /api/cfwaf/adopt", S(app.postCFWAFAdopt))
	api.HandleFunc("GET /api/crowdsec", app.getCrowdSec)
	api.HandleFunc("POST /api/crowdsec/decisions", S(app.postCSDecision))
	api.HandleFunc("DELETE /api/crowdsec/decisions/{id}", S(app.deleteCSDecision))
	api.HandleFunc("POST /api/crowdsec/sync", app.postCSSync)
	api.HandleFunc("GET /api/logs/status", app.getLogStatus)
	api.HandleFunc("GET /api/logs/events", app.getLogEvents)
	api.HandleFunc("GET /api/logs/requests", app.getLogRequests)
	api.HandleFunc("GET /api/logs/export", app.getLogExport)
	api.HandleFunc("POST /api/logs/delete", S(app.postLogDelete))
	api.HandleFunc("GET /api/docker/containers", app.getContainers)
	api.HandleFunc("GET /api/docker/upstreams", app.getUpstreams)
	api.HandleFunc("GET /api/updates", app.getUpdates)
	api.HandleFunc("POST /api/updates/check", app.postUpdatesCheck)
	if faultsEnabled() {
		log.Printf("WARNING: GM_DEV_FAULTS=1 — fault injection API enabled (test only)")
		api.HandleFunc("POST /api/dev/fault", S(app.postFault))
	}
	mux.Handle("/api/", auth.require(app.auditMW(api)))

	sub, _ := fs.Sub(webFS, "web")
	webBuild = hashFS(sub)
	mux.Handle("/", noCache(http.FileServer(http.FS(sub))))
	return secHeaders(app.auth.guard(mux))
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 2<<20))
	return dec.Decode(v)
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		if webBuild != "" {
			w.Header().Set("X-GM-Build", webBuild)
		}
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

// webBuild identifies the embedded UI; every response carries it (X-GM-Build) so an
// open page notices a new version after an update and offers to reload.
var webBuild string

func hashFS(f fs.FS) string {
	h := sha256.New()
	_ = fs.WalkDir(f, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := fs.ReadFile(f, p)
		h.Write([]byte(p))
		h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- services / settings

func (a *App) getState(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	sortServices(d.Services)
	writeJSON(w, 200, map[string]any{
		"settings": d.Settings, "services": d.Services, "dirty": d.Dirty,
		"lastApplied": d.LastApplied, "lastPublicIp": d.LastPublicIP,
		"cfConfigured": a.cf.Configured(), "cfTokenSource": cfTokenSourceName(), "version": version,
		"pending": d.Pending, "managedDns": d.ManagedDNS, "managedDns6": d.ManagedDNS6,
		"lastPublicIp6": d.LastPublicIP6, "ddns": d.DDNS, "autheliaGroups": d.AGroups,
		"faultInjection": faultsEnabled(), "fault": a.peekFault(),
		"csConfigured": csKey() != "", "cfWafIds": d.CFWAF, "setupDone": d.SetupDone,
		"disk": a.diskSummary(), "updates": map[string]any{"count": d.Updates.count(), "checked": d.Updates.Checked, "items": d.Updates.Items},
		"me":       a.meOf(r, &d),
		"security": map[string]any{"totp": myTOTP(a, r, &d), "selfName": d.SelfName, "via": accessOf(r.Context()).via, "ssoUser": accessOf(r.Context()).ssoUser},
	})
}

func (a *App) postFault(w http.ResponseWriter, r *http.Request) {
	var in struct{ Kind string }
	_ = readJSON(r, &in)
	switch in.Kind {
	case "", FaultAutheliaStart, FaultCaddyReload, FaultUsersStart:
	default:
		fail(w, 400, errors.New("알 수 없는 장애 종류"))
		return
	}
	a.faultMu.Lock()
	a.fault = in.Kind
	a.faultMu.Unlock()
	writeJSON(w, 200, map[string]string{"fault": in.Kind})
}

func (a *App) saveService(w http.ResponseWriter, r *http.Request) {
	var in Service
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	id := r.PathValue("id")
	if id != "" {
		in.ID = id // the path names the service; the body may omit (or misstate) the id
	}
	err := a.store.Update(func(d *Data) error {
		if err := validateService(&in, d.Services, d.Settings); err != nil {
			return err
		}
		var before []string
		for _, s := range d.Services {
			if s.ID == id && id != "" {
				before = s.Authelia.Groups
			}
		}
		if err := checkNewGroups(d.groupSet(), before, in.Authelia.Groups); err != nil {
			return err
		}
		in.Updated = time.Now()
		fq := d.Settings.FQDN(in.Subdomain)
		if id == "" {
			d.markDirty("서비스 추가: " + fq)
			in.ID = newID()
			d.Services = append(d.Services, &in)
		} else {
			found := false
			for i, s := range d.Services {
				if s.ID == id {
					in.ID = id
					d.Services[i] = &in
					d.markDirty("서비스 수정: " + fq)
					found = true
				}
			}
			if !found {
				return errors.New("서비스를 찾을 수 없습니다")
			}
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.detectSelf() // a site whose upstream is this container becomes 「길목 사이트」 (proxy header)
	writeJSON(w, 200, in)
}

func (a *App) deleteService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.store.Update(func(d *Data) error {
		for i, s := range d.Services {
			if s.ID == id {
				d.Services = append(d.Services[:i], d.Services[i+1:]...)
				d.markDirty("서비스 삭제: " + d.Settings.FQDN(s.Subdomain))
				return nil
			}
		}
		return errors.New("서비스를 찾을 수 없습니다")
	})
	if err != nil {
		fail(w, 404, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	// security / logging / connection settings need a fresh password (step-up)
	cur := a.store.Snapshot().Settings
	// key-level permissions on top of 「구성 변경」: access security → 「계정·접근 보안」, logging → 「로그 관리」
	for k := range diffStruct(cur, in) {
		need := ""
		switch {
		case strings.HasPrefix(k, "sec"):
			need = "accounts"
		case strings.HasPrefix(k, "log"), strings.HasPrefix(k, "disk"):
			need = "logs"
		}
		if need != "" && !a.auth.can(r, need) {
			writeJSON(w, 403, map[string]any{"error": fmt.Sprintf("권한이 없습니다 — 이 설정(%s)을 바꾸려면 「%s」 권한이 필요합니다", k, permName(need)), "perm": need})
			return
		}
	}
	in.SecV2, in.WafV2 = true, true
	changed := diffStruct(cur, in)
	for k := range changed {
		if systemSettingKey(k) && !a.auth.can(r, "system") {
			writeJSON(w, 403, map[string]any{"error": fmt.Sprintf("권한이 없습니다 — 이 설정(%s)을 바꾸려면 「%s」 권한이 필요합니다", k, permName("system")), "perm": "system"})
			return
		}
	}
	if err := a.checkSystemSettings(cur, in); err != nil {
		fail(w, 400, err)
		return
	}
	for k := range changed {
		if systemSettingKey(k) || strings.HasPrefix(k, "sec") || strings.HasPrefix(k, "log") || strings.HasPrefix(k, "disk") || k == "updateCheck" {
			if !a.auth.recentlyVerified(r) {
				writeJSON(w, 403, map[string]any{"error": "보안·로그 설정은 비밀번호를 다시 확인해야 바꿀 수 있습니다", "reauth": true})
				return
			}
			break
		}
	}
	if err := normalizeSettings(&in); err != nil {
		fail(w, 400, err)
		return
	}
	affects := false
	_ = a.store.Update(func(d *Data) error {
		// only settings that change the generated files/DNS make the state "pending"
		before := d.Settings
		after := *d
		after.Settings = in
		changes := []string{}
		if GenerateCaddyfile(*d) != GenerateCaddyfile(after) {
			changes = append(changes, "Caddy 설정 변경")
		}
		if GenerateAccessControl(*d) != GenerateAccessControl(after) {
			changes = append(changes, "Authelia 정책 변경")
		}
		if before.Domain != in.Domain || before.TailscaleIP != in.TailscaleIP {
			changes = append(changes, "도메인/Tailscale IP 변경")
		}
		if before.DDNSIPv6 != in.DDNSIPv6 && in.UseCloudflare {
			if in.DDNSIPv6 {
				changes = append(changes, "IPv6(AAAA) 레코드 관리 켬")
			} else {
				changes = append(changes, "IPv6(AAAA) 레코드 관리 끔 — 길목이 만든 AAAA 삭제")
			}
		}
		d.Settings = in
		for _, c := range changes {
			d.markDirty(c)
		}
		affects = len(changes) > 0
		return nil
	})
	a.crowdsecSyncNow()
	a.applyLogPolicy(in)
	if _, ok := changed["caddyContainer"]; ok {
		a.syncCrowdSecAcquis() // a managed CrowdSec reads the new Caddy's logs
	}
	writeJSON(w, 200, map[string]any{"settings": in, "pending": affects})
}

func (a *App) importExisting(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	st := d.Settings
	if !st.UseCaddy {
		fail(w, 400, errors.New("Caddy를 쓰지 않는 구성이라 가져올 Caddyfile이 없습니다 — 서비스 탭에서 직접 추가하세요"))
		return
	}
	// optional body {name, content}: a Caddyfile chosen on the user's PC — read only, nothing is written
	var up struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if r.ContentLength != 0 && r.Body != nil {
		if err := readJSON(r, &up); err != nil && !errors.Is(err, io.EOF) {
			fail(w, 400, err)
			return
		}
	}
	var src []byte
	if up.Content != "" {
		if len(up.Content) > 1<<20 || !utf8.ValidString(up.Content) {
			fail(w, 400, errors.New("Caddyfile은 1MB 이하의 UTF-8 텍스트여야 합니다"))
			return
		}
		src = []byte(up.Content)
	} else {
		var err error
		if src, err = os.ReadFile(st.CaddyfilePath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				err = fmt.Errorf("Caddyfile을 찾지 못했습니다 (%s) — 길목 컨테이너에 Caddy 폴더가 마운트돼 있는지, Caddy 단계의 경로가 맞는지 확인하세요. PC에 있는 파일을 직접 골라 가져올 수도 있습니다", st.CaddyfilePath)
			}
			fail(w, 400, err)
			return
		}
	}
	inferred := ""
	if strings.TrimSpace(st.Domain) == "" {
		if st.Domain = inferDomain(string(src)); st.Domain == "" {
			fail(w, 400, errors.New("도메인이 정해져 있지 않고 Caddyfile에서도 알아낼 수 없습니다 — 설정 탭 › 도메인에서 먼저 정하세요"))
			return
		}
		inferred = st.Domain
	}
	base, svcs, warns, err := ImportCaddyfile(string(src), st)
	if inferred != "" {
		warns = append([]string{"도메인이 비어 있어 Caddyfile의 사이트 주소에서 " + inferred + " 로 정했습니다 — 다르면 설정 탭 › 도메인에서 고치세요"}, warns...)
	}
	if err != nil {
		fail(w, 400, err)
		return
	}
	if !st.UseAuthelia {
		// nothing to read
	} else if cfg, err := os.ReadFile(st.AutheliaConfig); err == nil {
		if def, err := ApplyAccessControlToImport(string(cfg), svcs, st); err != nil {
			warns = append(warns, err.Error())
		} else if def != "" {
			st.DefaultPolicy = def
		}
	} else {
		warns = append(warns, "Authelia 설정을 읽지 못했습니다: "+err.Error())
	}
	var managed []string
	if st.UseCloudflare && a.cf.Configured() {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		recs, err := a.cf.Records(ctx, st.Domain)
		if err != nil {
			warns = append(warns, "DNS 조회 실패: "+err.Error())
		} else {
			byName := map[string]DNSRecord{}
			for _, rec := range recs {
				if rec.Type == "A" {
					byName[rec.Name] = rec
				}
			}
			have := map[string]bool{}
			for _, s := range svcs {
				name := st.FQDN(s.Subdomain)
				have[name] = true
				rec, ok := byName[name]
				if !ok {
					warns = append(warns, name+": DNS 레코드가 없습니다 (적용 시 생성)")
					continue
				}
				managed = append(managed, name)
				if s.Exposure == ExposurePublic {
					s.Proxied = rec.Proxied
					if rec.Proxied && !s.MTLS {
						warns = append(warns, name+": Proxied인데 mTLS(cf_only)가 꺼져 있습니다")
					}
				} else if st.TailscaleIP == "" && strings.HasPrefix(rec.Content, "100.") {
					st.TailscaleIP = rec.Content
				}
			}
			// DNS-only records pointing at the Tailscale IP (e.g. sftpgo) become DNS-only services
			for _, rec := range recs {
				if rec.Type != "A" || have[rec.Name] || st.TailscaleIP == "" || rec.Content != st.TailscaleIP {
					continue
				}
				sub := strings.TrimSuffix(rec.Name, "."+st.Domain)
				svcs = append(svcs, &Service{ID: newID(), Subdomain: sub, Exposure: ExposureTailscale, DNSOnly: true,
					Enabled: true, ManageDNS: true, Notes: "DNS 전용 (Caddy 사이트 없음)", Authelia: AutheliaOpts{Policy: "two_factor"}})
				managed = append(managed, rec.Name)
			}
		}
	}
	err = a.store.Update(func(x *Data) error {
		x.Settings = st
		x.Settings.CaddyBase = base
		x.Services = svcs
		x.ManagedDNS = managed
		x.Pending = nil
		x.markDirty(fmt.Sprintf("기존 설정 가져오기 (서비스 %d개)", len(svcs)))
		return nil
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"imported": len(svcs), "warnings": warns})
}

func (a *App) getPlan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	d := a.store.Snapshot()
	p := a.plan(ctx, d, r.URL.Query().Get("dns") != "0")
	p.CaddyNext, p.CaddyCurrent = maskProxySecret(p.CaddyNext, d.ProxySecret), maskProxySecret(p.CaddyCurrent, d.ProxySecret)
	writeJSON(w, 200, p)
}

func (a *App) postApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AllowIPChange bool `json:"allowIpChange"`
	}
	_ = readJSON(r, &in) // empty body = defaults
	lines, err := a.Apply(in.AllowIPChange)
	res := map[string]any{"log": lines, "ok": err == nil}
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, 200, res)
}

// ---------------------------------------------------------------- DNS view

// ---------------------------------------------------------------- users

type userView struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayname"`
	Email       string   `json:"email"`
	Groups      []string `json:"groups"`
	Disabled    bool     `json:"disabled"`
}

func (a *App) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := LoadUsers(a.store.Snapshot().Settings.AutheliaUsers)
	if err != nil {
		fail(w, 500, err)
		return
	}
	var out []userView
	for n, u := range users {
		out = append(out, userView{n, u.DisplayName, u.Email, u.Groups, u.Disabled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	writeJSON(w, 200, out)
}

func (a *App) saveUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		userView
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	a.usersMu.Lock() // load → change → write must not interleave with another user change
	defer a.usersMu.Unlock()
	path := a.store.Snapshot().Settings.AutheliaUsers
	users, err := LoadUsers(path)
	if err != nil {
		fail(w, 500, err)
		return
	}
	name := r.PathValue("name")
	creating := name == ""
	if creating {
		name = strings.TrimSpace(in.Username)
		if !validUsername(name) {
			fail(w, 400, errors.New("아이디는 영문/숫자/-_. 만 사용할 수 있습니다"))
			return
		}
		if _, ok := users[name]; ok {
			fail(w, 400, errors.New("이미 있는 아이디입니다"))
			return
		}
		if len(in.Password) < 10 {
			fail(w, 400, errors.New("비밀번호는 10자 이상이어야 합니다"))
			return
		}
		users[name] = &AUser{}
	}
	u, ok := users[name]
	if !ok {
		fail(w, 404, errors.New("사용자를 찾을 수 없습니다"))
		return
	}
	u.DisplayName = strings.TrimSpace(in.DisplayName)
	u.Email = strings.TrimSpace(in.Email)
	u.Disabled = in.Disabled
	newGroups := []string{}
	for _, g := range in.Groups {
		if g = strings.TrimSpace(g); g != "" {
			newGroups = append(newGroups, g)
		}
	}
	snap := a.store.Snapshot()
	if err := checkNewGroups(snap.groupSet(), u.Groups, newGroups); err != nil {
		fail(w, 400, err)
		return
	}
	u.Groups = newGroups
	if in.Password != "" {
		if len(in.Password) < 10 {
			fail(w, 400, errors.New("비밀번호는 10자 이상이어야 합니다"))
			return
		}
		h, err := HashPassword(in.Password)
		if err != nil {
			fail(w, 500, err)
			return
		}
		u.Password = h
	}
	lines, err := a.ApplyUsers(users)
	res := map[string]any{"log": lines, "ok": err == nil}
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, 200, res)
}

func (a *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	a.usersMu.Lock()
	defer a.usersMu.Unlock()
	path := a.store.Snapshot().Settings.AutheliaUsers
	users, err := LoadUsers(path)
	if err != nil {
		fail(w, 500, err)
		return
	}
	name := r.PathValue("name")
	if _, ok := users[name]; !ok {
		fail(w, 404, errors.New("사용자를 찾을 수 없습니다"))
		return
	}
	if len(users) == 1 {
		fail(w, 400, errors.New("마지막 사용자는 삭제할 수 없습니다"))
		return
	}
	delete(users, name)
	lines, err := a.ApplyUsers(users)
	res := map[string]any{"log": lines, "ok": err == nil}
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, 200, res)
}

// ---------------------------------------------------------------- system / updates

func (a *App) getSystem(w http.ResponseWriter, r *http.Request) {
	st := a.store.Snapshot().Settings
	caddy := CtrStatus{Name: st.CaddyContainer}
	if caddyMode(st) == "docker" {
		caddy = ctrStatus(st.CaddyContainer)
	} else {
		caddy.Exists, caddy.State = true, caddyMode(st)
	}
	if caddy.Exists {
		if v, err := caddyVersion(st); err == nil {
			caddy.Version = v
		}
	}
	auth := ctrStatus(st.AutheliaCtr)
	if auth.Exists {
		if v, err := ctrExec(st.AutheliaCtr, nil, "authelia", "--version"); err == nil {
			auth.Version = strings.TrimSpace(strings.TrimPrefix(v, "authelia version "))
		}
	}
	writeJSON(w, 200, map[string]any{
		"caddy": caddy, "authelia": auth, "version": version,
	})
}

func (a *App) postUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Target string }
	_ = readJSON(r, &in)
	st := a.store.Snapshot().Settings
	L := &logger{}
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	err := a.update(in.Target, st, L)
	res := map[string]any{}
	if err == nil {
		// record the new bases and re-check now, so the answer already carries the new state
		res["updates"] = a.resetBaselines(in.Target)
	}
	res["log"], res["ok"] = L.lines, err == nil
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, 200, res)
}

func (a *App) update(target string, st Settings, L *logger) error {
	var ctr, dir, svc string
	var env []string
	switch target {
	case "caddy":
		ctr, dir, svc, env = st.CaddyContainer, st.CaddyStackDir, st.CaddyService, caddyComposeEnv()
	case "authelia":
		ctr, dir, svc = st.AutheliaCtr, st.AutheliaStackDir, st.AutheliaService
	default:
		return errors.New("알 수 없는 대상")
	}
	t, err := resolveCompose(ctr, dir, svc)
	if err != nil {
		return err
	}
	if target == "caddy" && env == nil && composeUsesVar(t, "CLOUDFLARE_API_TOKEN") {
		// without our token compose would fall back to the stack's .env (wrong in production)
		// and the recreated Caddy could no longer solve DNS challenges
		return errors.New("Cloudflare 토큰이 길목에 없어 Caddy 업데이트를 중단합니다 (compose 파일이 ${CLOUDFLARE_API_TOKEN}을 씁니다)")
	}
	before := ctrID(ctr)
	since := time.Now()
	if err := composeUpdate(t, env, L.f); err != nil {
		return err
	}
	if after := ctrID(ctr); after == before && before != "" {
		L.f("✓ 이미 최신 이미지 — 컨테이너를 다시 만들지 않았습니다")
		return nil
	}
	switch target {
	case "caddy":
		time.Sleep(3 * time.Second)
		if v, e := ctrExec(ctr, nil, "caddy", "version"); e == nil {
			L.f("✓ Caddy %s", strings.Fields(v + " ")[0])
		} else {
			return fmt.Errorf("새 Caddy 컨테이너 확인 실패: %s", oneLine(v))
		}
	case "authelia":
		if err := waitHealthy(ctr, since, "Startup complete", 60*time.Second); err != nil {
			return err
		}
		L.f("✓ Authelia 정상 시작")
	}
	return nil
}

func composeUsesVar(t ComposeTarget, name string) bool {
	for _, f := range t.DaemonFiles {
		if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), "${"+name) {
			return true
		}
	}
	return false
}

func (a *App) listBackups(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(filepath.Join(a.dataDir, "backups"))
	var names []string
	for i := len(entries) - 1; i >= 0 && len(names) < 30; i-- {
		names = append(names, entries[i].Name())
	}
	writeJSON(w, 200, names)
}

// myTOTP: does the logged-in account have 2FA on?
func myTOTP(a *App, r *http.Request, d *Data) bool {
	if s := sessionOf(r.Context()); s != nil {
		if acct := d.account(s.User); acct != nil {
			return acct.TOTP != ""
		}
	}
	return false
}

func (a *App) meOf(r *http.Request, d *Data) map[string]any {
	if s := sessionOf(r.Context()); s != nil {
		if acct := d.account(s.User); acct != nil {
			return a.auth.meView(d, acct)
		}
	}
	return nil
}

// systemSettingKey: settings that say where files are, which containers to talk to and how Caddy is
// run. Changing them can make Gilmok read other files or run another program, so they need the
// 「연결·시스템」 permission and a fresh password.
func systemSettingKey(k string) bool {
	switch k {
	case "caddyfilePath", "caddyfileInCtr", "caddyContainer", "autheliaContainer", "autheliaConfig", "autheliaUsers",
		"autheliaCtrDir", "caddyStackDir", "autheliaStackDir", "caddyService", "autheliaService",
		"crowdsecContainer", "crowdsecLapi", "caddyMode", "caddyBin", "caddyAdmin":
		return true
	}
	return strings.HasPrefix(k, "use")
}

// checkSystemSettings: config file paths must not point into Gilmok's own data / secrets or system
// folders, and the native Caddy binary must be a caddy binary.
func (a *App) checkSystemSettings(cur, in Settings) error {
	deny := []string{a.dataDir, "/run/secrets", "/proc", "/sys", "/dev", "/etc", "/root", "/var/run", "/run/desktop"}
	for _, f := range []struct{ name, now, was string }{
		{"Caddyfile 경로", in.CaddyfilePath, cur.CaddyfilePath},
		{"configuration.yml 경로", in.AutheliaConfig, cur.AutheliaConfig},
		{"users_database.yml 경로", in.AutheliaUsers, cur.AutheliaUsers},
	} {
		if f.now == f.was || f.now == "" {
			continue
		}
		p := filepath.Clean(f.now)
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s 는 절대 경로여야 합니다", f.name)
		}
		// the config folders of stacks Gilmok installed itself live in its data folder (stacks.go)
		managedOK := false
		for _, sub := range []string{filepath.Join(a.dataDir, "stacks", "caddy", "conf"), filepath.Join(a.dataDir, "stacks", "authelia", "config")} {
			if strings.HasPrefix(p, filepath.Clean(sub)+string(filepath.Separator)) {
				managedOK = true
			}
		}
		if managedOK {
			continue
		}
		for _, d := range deny {
			if d == "" {
				continue
			}
			d = filepath.Clean(d)
			if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) {
				return fmt.Errorf("%s 로 %s 를 쓸 수 없습니다 — 길목 데이터·비밀값·시스템 폴더는 가리킬 수 없습니다", f.name, d)
			}
		}
	}
	if in.CaddyBin != cur.CaddyBin && in.CaddyBin != "" {
		if b := strings.ToLower(filepath.Base(strings.ReplaceAll(in.CaddyBin, "\\", "/"))); b != "caddy" && b != "caddy.exe" {
			return errors.New("Caddy 실행 파일은 caddy 또는 caddy.exe 여야 합니다")
		}
	}
	return nil
}

// maskProxySecret hides the per-install proxy secret in text shown to users (plan / diff).
func maskProxySecret(text, secret string) string {
	if len(secret) < 8 {
		return text
	}
	return strings.ReplaceAll(text, secret, "•••(길목 비밀 — 숨김)•••")
}

var topoHopKinds = map[string]bool{"router": true, "firewall": true, "lb": true, "proxy": true, "tunnel": true, "other": true}

// checkTopoHops validates the front-device chain drawn on the topology map.
func checkTopoHops(hops []TopoHop) error {
	if len(hops) > 8 {
		return errors.New("앞단 장비는 8개까지 그릴 수 있습니다")
	}
	for i := range hops {
		h := &hops[i]
		if !topoHopKinds[h.Kind] {
			return fmt.Errorf("앞단 장비 종류 %q 를 알 수 없습니다", h.Kind)
		}
		h.Name, h.Note = strings.TrimSpace(h.Name), strings.TrimSpace(h.Note)
		if len([]rune(h.Name)) > 40 || len([]rune(h.Note)) > 80 {
			return errors.New("앞단 장비 이름은 40자, 메모는 80자까지입니다")
		}
		if h.ExtPort < 0 || h.ExtPort > 65535 || h.FwdPort < 0 || h.FwdPort > 65535 {
			return errors.New("포트는 1~65535 사이여야 합니다")
		}
	}
	return nil
}

// normalizeSettings validates and normalizes a whole Settings value. Every way settings get in —
// the settings form (saveSettings) and a restored config file (config.go) — goes through it, so a
// file cannot carry values the form would refuse (SecLang, IP lists, thresholds …).
func normalizeSettings(p *Settings) error {
	in := *p
	defer func() { *p = in }()
	in.LogInit, in.SecInit, in.UseInit, in.UseTSInit = true, true, true, true
	if !in.UseCloudflare {
		in.CrowdSecSync = false // bans are pushed to Cloudflare; without it CrowdSec only decides
	}
	if in.Lang != "" && !uiLangs[in.Lang] {
		return errors.New("화면 언어는 ko 또는 en 이어야 합니다")
	}
	in.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Domain)), ".")
	if in.Domain != "" && !reHostname.MatchString(in.Domain) { // empty = not chosen yet (설정 탭 › 도메인)
		return errors.New("도메인 형식이 아닙니다 (예: example.com)")
	}
	if in.DefaultPolicy != "deny" && in.DefaultPolicy != "one_factor" && in.DefaultPolicy != "two_factor" {
		in.DefaultPolicy = "deny"
	}
	if err := checkBraces(in.CaddyBase); err != nil {
		return fmt.Errorf("기본 골격: %v", err)
	}
	if in.WafParanoia < 1 || in.WafParanoia > 4 {
		in.WafParanoia = 1
	}
	if err := validateWAFDirectives(in.WafDirectives); err != nil {
		return err
	}
	if _, err := parseASNs(in.CfAsnList); err != nil {
		return err
	}
	if _, ok := cfAsnActions[in.CfAsnAction]; !ok {
		in.CfAsnAction = "managed_challenge"
	}
	clamp := func(v *int, lo, hi, def int) {
		if *v < lo || *v > hi {
			*v = def
		}
	}
	// WAF / basic blocking / Cloudflare edge rules
	if in.WafDetectPL != 0 {
		clamp(&in.WafDetectPL, in.WafParanoia, 4, 0)
	}
	clamp(&in.WafInbound, 1, 1000, 5)
	clamp(&in.WafOutbound, 1, 1000, 4)
	clamp(&in.WafBodyLimitMB, 0, 1024, 0)
	in.WafMethods = strings.Join(strings.Fields(strings.ToUpper(in.WafMethods)), " ")
	if in.WafMethods != "" && !reMethods.MatchString(in.WafMethods) {
		return errors.New("허용 메서드는 영문 대문자 단어를 공백으로 나눠 적으세요 (예: GET HEAD POST)")
	}
	in.WafGroupsOff = validWafGroups(in.WafGroupsOff)
	if x, err := validateWafExclusions(in.WafExclude); err != nil {
		return err
	} else {
		in.WafExclude = x
	}
	if err := validateGuardLists(in); err != nil {
		return err
	}
	for _, chk := range []struct {
		s    string
		name string
	}{{in.CfAllowIPs, "신뢰 IP"}, {in.CfDenyIPs, "차단 IP"}} {
		if _, err := parseIPList(chk.s); err != nil {
			return fmt.Errorf("%s: %v", chk.name, err)
		}
	}
	if _, err := parseCountries(in.CfGeoCountries); err != nil {
		return err
	}
	if in.CfGeoMode != "block" {
		in.CfGeoMode = "allow"
	}
	in.CfThreatAction = cfAction(in.CfThreatAction, "block")
	in.CfCustomAction = cfAction(in.CfCustomAction, "managed_challenge")
	if in.CfRateAction != "managed_challenge" {
		in.CfRateAction = "block"
	}
	clamp(&in.CfRateRequests, 1, 100000, 30)
	clamp(&in.CfRatePeriod, 10, 86400, 10)
	clamp(&in.CfRateTimeout, 10, 86400, 10)
	if len(in.CfCustomExpr) > cfExprMax {
		return fmt.Errorf("사용자 규칙 식은 %d자 이하여야 합니다", cfExprMax)
	}
	clamp(&in.DiskWarnPct, 2, 90, 20)
	clamp(&in.DiskCritPct, 1, 80, 10)
	clamp(&in.DiskStopPct, 1, 50, 5)
	if !(in.DiskStopPct < in.DiskCritPct && in.DiskCritPct < in.DiskWarnPct) {
		return errors.New("디스크 기준은 경고 > 강력 경고 > 중단 순서여야 합니다 (예: 20 / 10 / 5)")
	}
	for _, p := range []*int{&in.LogRetReqDays, &in.LogRetMetricDays, &in.LogRetAuditDays, &in.LogRetSecurityDays, &in.LogRetSystemDays} {
		clamp(p, 1, 3650, 30)
	}
	clamp(&in.LogMaxDBMB, 50, 1<<20, 2048)
	clamp(&in.SecIdleMin, 5, 1440, 30)
	clamp(&in.SecAbsHours, 1, 720, 12)
	clamp(&in.SecReauthMin, 1, 120, 10)
	if !in.SecAllowDirect && !in.SecAllowProxy {
		return errors.New("직접 접속과 Caddy 경유 접속을 모두 끌 수는 없습니다 (길목에 들어올 길이 없어집니다)")
	}
	switch in.CaddyMode {
	case "docker", "native", "api":
	default:
		in.CaddyMode = "docker"
	}
	in.CaddyAdmin = strings.TrimRight(strings.TrimSpace(in.CaddyAdmin), "/")
	if in.CaddyMode == "api" && !strings.HasPrefix(in.CaddyAdmin, "http://") && !strings.HasPrefix(in.CaddyAdmin, "https://") {
		return errors.New("Caddy 관리 API 주소는 http:// 로 시작해야 합니다 (예: http://host.docker.internal:2019)")
	}
	if err := checkServiceURL("Caddy 관리 API 주소", in.CaddyAdmin); err != nil {
		return err
	}
	switch in.TopoEdgeKind {
	case "", "router", "direct", "tunnel", "proxy":
	default:
		in.TopoEdgeKind = ""
	}
	if err := checkTopoHops(in.TopoHops); err != nil {
		return err
	}
	switch in.TopoPrivKind {
	case "", "ts_serve", "ts_direct", "vpn":
	default:
		in.TopoPrivKind = ""
	}
	if in.TopoEdgeExtPort < 0 || in.TopoEdgeExtPort > 65535 || in.TopoEdgeFwdPort < 0 || in.TopoEdgeFwdPort > 65535 {
		return errors.New("포트는 1~65535 사이여야 합니다")
	}
	if in.CrowdSecInterval < 15 {
		in.CrowdSecInterval = 60
	}
	in.CrowdSecLAPI = strings.TrimRight(strings.TrimSpace(in.CrowdSecLAPI), "/")
	if in.CrowdSecLAPI != "" && !strings.HasPrefix(in.CrowdSecLAPI, "http://") && !strings.HasPrefix(in.CrowdSecLAPI, "https://") {
		return errors.New("CrowdSec LAPI 주소는 http:// 또는 https:// 로 시작해야 합니다")
	}
	if err := checkServiceURL("CrowdSec LAPI 주소", in.CrowdSecLAPI); err != nil {
		return err
	}
	return nil
}

// checkServiceURL: a URL Gilmok itself will call (Caddy admin API, CrowdSec LAPI) must be a plain
// http(s) URL with a host, and never a link-local / cloud-metadata address.
func checkServiceURL(label, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("%s 형식이 아닙니다 (예: http://host:port)", label)
	}
	if blockedHost(u.Hostname()) {
		return fmt.Errorf("%s 로 링크 로컬·메타데이터 주소(%s)는 쓸 수 없습니다", label, u.Hostname())
	}
	return nil
}

// blockedHost: link-local (169.254/16, fe80::/10 — cloud metadata lives there) and metadata names.
func blockedHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "metadata.google.internal" || h == "metadata" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
	}
	return false
}
