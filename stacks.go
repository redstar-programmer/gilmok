package main

// Managed stacks — Caddy / Authelia / CrowdSec that Gilmok installs and runs itself as separate
// containers next to it (docs/DESIGN_MANAGED_STACKS.md). Connecting to containers the user runs
// stays as it is; a managed stack is just one Gilmok created.
//
//   GET  /api/stacks                         records, container state, current/last jobs
//   POST /api/stacks/{name}/preflight {opts} checks only (ports, names, paths, docker)
//   POST /api/stacks/{name}/{action} {opts}  install | start | stop | restart | remove → 202 + job
//
// Files live in <data>/stacks/<name>/ and compose runs from there, with absolute bind sources
// that the Docker daemon understands (Docker Desktop paths, named volumes — see stackPaths).
// Long work (an image build takes minutes) runs as a background job the UI polls.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type ManagedStack struct {
	Name      string            `json:"name"`      // caddy | authelia | crowdsec
	Container string            `json:"container"` // e.g. gilmok-caddy
	Network   string            `json:"network"`
	Dir       string            `json:"dir"`     // inside Gilmok: <data>/stacks/<name>
	HostDir   string            `json:"hostDir"` // the same folder as the Docker daemon sees it
	Options   map[string]string `json:"options,omitempty"`
	Installed time.Time         `json:"installed"`
}

// stackKinds: what can be installed (filled by stack_*.go).
var stackKinds = map[string]*stackKind{}

type stackKind struct {
	Label       string
	DefaultName string
	Project     string // compose project name
	Service     string // compose service name
	// ports the stack will publish for these options: "ip:port" ("" ip = all interfaces)
	ports func(a *App, o map[string]string) []string
	// render writes the stack's files into dir (hostDir = the same folder for the daemon)
	render func(a *App, o map[string]string, dir, hostDir, network, ctr string, log func(string, ...any)) error
	// build: optional image build (compose build) before start
	build bool
	// check runs inside the started container (e.g. caddy validate); "" when fine
	verify func(a *App, ctr string) error
	// adopt points Gilmok's settings at the installed stack
	adopt func(d *Data, rec *ManagedStack)
	// check validates install options before the job starts (nil = none)
	check func(a *App, o map[string]string) error
}

var reStackCtr = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// stackProject: the compose project name for a managed container (gilmok-caddy → gilmok-caddy).
func stackProject(ctr string) string {
	p := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return '-'
	}, ctr)
	if p == "" {
		return "gilmok-stack"
	}
	return p
}

// ---------------------------------------------------------------- jobs

type StackJob struct {
	ID      string    `json:"id"`
	Stack   string    `json:"stack"`
	Action  string    `json:"action"`
	State   string    `json:"state"` // running | ok | fail
	Log     []string  `json:"log"`
	Err     string    `json:"error,omitempty"`
	Started time.Time `json:"started"`
	Updated time.Time `json:"updated"` // last log line — the UI shows "last output N s ago"
	Ended   time.Time `json:"ended,omitempty"`
}

type stackMgr struct {
	mu   sync.Mutex
	cur  *StackJob
	last map[string]*StackJob // by stack name
}

func (m *stackMgr) logf(j *StackJob, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	m.mu.Lock()
	defer m.mu.Unlock()
	j.Updated = time.Now()
	for _, l := range strings.Split(strings.TrimRight(line, "\n"), "\n") {
		j.Log = append(j.Log, l)
	}
	if len(j.Log) > 400 {
		j.Log = j.Log[len(j.Log)-400:]
	}
}

func (m *stackMgr) snapshot(j *StackJob) *StackJob {
	if j == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *j
	c.Log = append([]string{}, j.Log...)
	return &c
}

// startJob runs fn in the background; one stack job at a time.
func (a *App) startStackJob(r *http.Request, name, action string, fn func(log func(string, ...any)) error) (*StackJob, error) {
	m := &a.stk
	m.mu.Lock()
	if m.cur != nil && m.cur.State == "running" {
		busy := m.cur.Stack + " " + m.cur.Action
		m.mu.Unlock()
		return nil, fmt.Errorf("다른 작업(%s)이 진행 중입니다 — 끝난 뒤 다시 시도하세요", busy)
	}
	j := &StackJob{ID: newID(), Stack: name, Action: action, State: "running", Started: time.Now()}
	j.Updated = j.Started
	m.cur = j
	if m.last == nil {
		m.last = map[string]*StackJob{}
	}
	m.last[name] = j
	m.mu.Unlock()
	actor, ip := a.auth.actor(r), clientIP(r)
	label := stackKinds[name].Label + " " + stackActionText[action]
	go func() {
		err := fn(func(f string, args ...any) { m.logf(j, f, args...) })
		m.mu.Lock()
		j.Ended = time.Now()
		if err != nil {
			j.State, j.Err = "fail", err.Error()
		} else {
			j.State = "ok"
		}
		m.mu.Unlock()
		lvl, msg := "info", label+" — 완료"
		if err != nil {
			lvl, msg = "error", label+" — 실패: "+truncate(err.Error(), 300)
			a.logEvent("system", "error", "stack."+action, name, msg, nil)
		}
		if a.ldb != nil {
			a.ldb.Event(Event{Ts: time.Now().UnixMilli(), Cat: "audit", Level: lvl, Action: "관리형 " + label, Target: name, Msg: msg, Actor: actor, IP: ip})
		}
	}()
	return m.snapshot(j), nil
}

var stackActionText = map[string]string{"install": "설치", "start": "시작", "stop": "정지", "restart": "재시작", "remove": "제거", "token": "토큰 반영", "compose": "compose 적용"}

// ---------------------------------------------------------------- paths, network, compose

// stackPaths: the stack folder inside Gilmok and the same folder as the Docker daemon resolves it.
// Gilmok's data folder is a bind mount or a named volume; either way the mount's Source is a path
// the daemon knows (Docker Desktop: converted with daemonPath), so stacks bind from below it.
func (a *App) stackPaths(name string) (local, host string, err error) {
	local = filepath.Join(a.dataDir, "stacks", name)
	if a.store.Snapshot().SelfName == "" { // Gilmok runs on the host itself
		abs, _ := filepath.Abs(local)
		return abs, filepath.ToSlash(abs), nil
	}
	ms, err := selfMounts()
	if err != nil {
		return "", "", err
	}
	data := filepath.ToSlash(filepath.Clean(a.dataDir))
	var best *mountInfo
	for i := range ms {
		dst := strings.TrimRight(filepath.ToSlash(ms[i].Destination), "/")
		if (dst == data || strings.HasPrefix(data, dst+"/")) && (best == nil || len(dst) > len(best.Destination)) {
			best = &ms[i]
		}
	}
	if best == nil || best.Source == "" {
		return "", "", fmt.Errorf("길목 데이터 폴더(%s)가 호스트 폴더나 볼륨으로 마운트되어 있지 않아, 다른 컨테이너가 그 아래 파일을 쓸 수 없습니다 — 길목 compose의 volumes에 데이터 폴더를 넣으세요", a.dataDir)
	}
	rel := strings.TrimPrefix(data, strings.TrimRight(filepath.ToSlash(best.Destination), "/"))
	host = strings.TrimRight(daemonPath(best.Source), "/") + rel + "/stacks/" + name
	return local, host, nil
}

// stackNetwork: a user-defined network Gilmok is on (container-name DNS works there, not on the
// default bridge); otherwise gilmok-net, created and joined by Gilmok first.
func (a *App) stackNetwork(ctx context.Context, log func(string, ...any), want string) (string, error) {
	self := a.store.Snapshot().SelfName
	if want != "" { // chosen by the user: make it if needed and put Gilmok on it too
		if _, err := docker(ctx, nil, nil, "network", "inspect", want); err != nil {
			log("$ docker network create %s", want)
			if out, err := docker(ctx, nil, nil, "network", "create", want); err != nil {
				return "", fmt.Errorf("네트워크 %s 를 만들지 못했습니다: %s", want, oneLine(out))
			}
		}
		if self != "" {
			if out, err := docker(ctx, nil, nil, "network", "connect", want, self); err != nil && !strings.Contains(out, "already exists") {
				return "", fmt.Errorf("길목을 %s 에 연결하지 못했습니다: %s", want, oneLine(out))
			}
		}
		return want, nil
	}
	if self != "" {
		if out, err := docker(ctx, nil, nil, "inspect", "-f", "{{json .NetworkSettings.Networks}}", self); err == nil {
			var nets map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(out)), &nets) == nil {
				names := []string{}
				for n := range nets {
					if n != "bridge" && n != "host" && n != "none" {
						names = append(names, n)
					}
				}
				sort.Strings(names)
				if len(names) > 0 {
					return names[0], nil
				}
			}
		}
	}
	const def = "gilmok-net"
	if _, err := docker(ctx, nil, nil, "network", "inspect", def); err != nil {
		log("$ docker network create %s", def)
		if out, err := docker(ctx, nil, nil, "network", "create", def); err != nil {
			return "", fmt.Errorf("네트워크 %s 를 만들지 못했습니다: %s", def, oneLine(out))
		}
	}
	if self != "" {
		log("$ docker network connect %s %s", def, self)
		if out, err := docker(ctx, nil, nil, "network", "connect", def, self); err != nil && !strings.Contains(out, "already exists") {
			return "", fmt.Errorf("길목을 %s 에 연결하지 못했습니다: %s", def, oneLine(out))
		}
	}
	return def, nil
}

// caddyNetwork: a user-defined network the Caddy container (Gilmok's managed one, else the configured
// one) is on — preferring one Gilmok shares. "" when there is no Caddy container yet.
func (a *App) caddyNetwork(ctx context.Context) string {
	d := a.store.Snapshot()
	ctr := d.Settings.CaddyContainer
	if rec := d.Stacks["caddy"]; rec != nil {
		ctr = rec.Container
	}
	if ctr == "" || caddyMode(d.Settings) != "docker" {
		return ""
	}
	caddy := ctrNetworks(ctx, ctr)
	if len(caddy) == 0 {
		return ""
	}
	if d.SelfName != "" {
		mine := map[string]bool{}
		for _, n := range ctrNetworks(ctx, d.SelfName) {
			mine[n] = true
		}
		for _, n := range caddy {
			if mine[n] {
				return n
			}
		}
	}
	return caddy[0]
}

// stackCompose runs compose on a stack folder. The project name comes from the file's top-level
// `name:` (stackProject of the container) — never one fixed name per kind: two Gilmoks on one Docker,
// or a reinstall under another container name, would otherwise replace each other's containers.
func stackCompose(ctx context.Context, k *stackKind, dir string, env []string, args ...string) (string, error) {
	base := []string{"compose", "--project-directory", dir, "-f", filepath.Join(dir, "compose.yml")}
	return docker(ctx, nil, env, append(base, args...)...)
}

// ctrStateOf: "" when the container does not exist.
func ctrStateOf(ctx context.Context, ctr string) (state, managed string) {
	out, err := docker(ctx, nil, nil, "inspect", "-f", `{{.State.Status}}|{{index .Config.Labels "gilmok.managed"}}`, ctr)
	if err != nil {
		return "", ""
	}
	p := strings.SplitN(strings.TrimSpace(out), "|", 2)
	if len(p) < 2 {
		return p[0], ""
	}
	return p[0], p[1]
}

// ---------------------------------------------------------------- preflight

// publishedPorts: host ports other containers already publish (name → "ip:port").
func publishedPorts(ctx context.Context) map[string][]string {
	res := map[string][]string{}
	out, err := docker(ctx, nil, nil, "ps", "--format", "{{.Names}}|{{.Ports}}")
	if err != nil {
		return res
	}
	re := regexp.MustCompile(`(\[?[0-9a-fA-F:.]*\]?):(\d+)->`)
	for _, l := range strings.Split(out, "\n") {
		p := strings.SplitN(strings.TrimSpace(l), "|", 2)
		if len(p) < 2 {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(p[1], -1) {
			ip := strings.Trim(m[1], "[]")
			res[p[0]] = append(res[p[0]], ip+":"+m[2])
		}
	}
	return res
}

func portClash(want string, used []string) bool {
	wi, wp, _ := strings.Cut(want, ":")
	any := func(ip string) bool { return ip == "" || ip == "0.0.0.0" || ip == "::" }
	for _, u := range used {
		i := strings.LastIndex(u, ":")
		ui, up := u[:i], u[i+1:]
		if up == wp && (any(wi) || any(ui) || wi == ui) {
			return true
		}
	}
	return false
}

func (a *App) stackPreflight(ctx context.Context, name string, o map[string]string) []Check {
	k := stackKinds[name]
	r := &CheckResult{}
	if out, err := docker(ctx, nil, nil, "version", "--format", "{{.Server.Version}}"); err != nil {
		r.add("docker", "Docker 연결", "fail", "Docker에 연결하지 못했습니다 (docker.sock 마운트 확인): "+oneLine(out))
		return r.Checks
	} else {
		r.add("docker", "Docker 연결", "ok", "Docker "+strings.TrimSpace(out))
	}
	ctr := o["container"]
	if !reStackCtr.MatchString(ctr) {
		r.add("name", "컨테이너 이름", "fail", "영문·숫자·_.- 로 1~63자")
	} else if st, mg := ctrStateOf(ctx, ctr); st == "" {
		r.add("name", "컨테이너 이름", "ok", ctr+" (새로 만듦)")
	} else if mg == name {
		r.add("name", "컨테이너 이름", "warn", ctr+" 는 이미 길목이 설치한 것입니다 — 다시 설치하면 설정 파일을 새로 만들고 컨테이너를 다시 만듭니다")
	} else {
		r.add("name", "컨테이너 이름", "fail", ctr+" 이름의 컨테이너가 이미 있습니다 (길목이 만든 것이 아님) — 다른 이름을 쓰거나 「이미 있는 컨테이너에 연결」을 고르세요")
	}
	used := publishedPorts(ctx)
	for _, want := range k.ports(a, o) {
		clash := ""
		for c, ps := range used {
			if c != ctr && portClash(want, ps) {
				clash = c
			}
		}
		if clash != "" {
			r.add("port", "포트 "+want, "fail", clash+" 컨테이너가 이미 쓰고 있습니다")
		} else {
			r.add("port", "포트 "+want, "ok", "비어 있음 (Docker 밖의 프로그램이 쓰는지는 설치할 때 확인됩니다)")
		}
	}
	if _, host, err := a.stackPaths(name); err != nil {
		r.add("path", "설치 폴더", "fail", err.Error())
	} else {
		r.add("path", "설치 폴더", "ok", host)
	}
	if total, free, err := diskUsageFn(a.dataDir); err == nil && total > 0 {
		if free < 2<<30 {
			r.add("disk", "디스크 여유", "warn", fmt.Sprintf("%s 남음 — 이미지 빌드에 1~2 GB가 필요합니다", fmtBytesGo(free)))
		} else {
			r.add("disk", "디스크 여유", "ok", fmtBytesGo(free))
		}
	}
	return r.Checks
}

// ---------------------------------------------------------------- actions

func (a *App) stackOptions(name string, in map[string]string) map[string]string {
	k := stackKinds[name]
	o := map[string]string{}
	if rec := a.store.Snapshot().Stacks[name]; rec != nil {
		for kk, v := range rec.Options {
			o[kk] = v
		}
		o["container"] = rec.Container
	}
	for kk, v := range in {
		o[kk] = strings.TrimSpace(v)
	}
	if o["container"] == "" {
		o["container"] = k.DefaultName
	}
	return o
}

func (a *App) stackInstall(name string, o map[string]string, log func(string, ...any)) error {
	k := stackKinds[name]
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	log("• 사전 점검")
	for _, c := range a.stackPreflight(ctx, name, o) {
		log("  %s %s — %s", map[string]string{"ok": "✓", "warn": "!", "fail": "✗"}[c.Status], c.Label, c.Detail)
		if c.Status == "fail" {
			return fmt.Errorf("사전 점검 실패: %s — %s", c.Label, c.Detail)
		}
	}
	dir, host, err := a.stackPaths(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	want := o["network"]
	if want == "" && name != "caddy" {
		// Caddy must reach it by name: join a network the Caddy container is on (Gilmok's own
		// networks are sorted alphabetically and may not include Caddy's — e.g. gilmok_default)
		want = a.caddyNetwork(ctx)
		if want != "" {
			log("• 네트워크: Caddy와 같은 %s (Caddy가 이름으로 찾아갈 수 있게)", want)
		}
	}
	network, err := a.stackNetwork(ctx, log, want)
	if err != nil {
		return err
	}
	ctr := o["container"]
	existed, _ := ctrStateOf(ctx, ctr)
	// a compose.yml the user edited survives a reinstall
	var custom []byte
	if o["customCompose"] == "1" {
		custom, _ = os.ReadFile(filepath.Join(dir, "compose.yml"))
	}
	log("• 파일 만들기 (%s)", host)
	if err := k.render(a, o, dir, host, network, ctr, log); err != nil {
		return err
	}
	if len(custom) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "compose.yml"), custom, 0o644); err != nil {
			return err
		}
		log("  직접 고친 compose.yml 을 그대로 둡니다 (기본값으로 되돌리려면 「compose 편집 › 기본값으로」)")
	}
	env := stackEnv(name)
	if out, err := stackCompose(ctx, k, dir, env, "config", "-q"); err != nil {
		return fmt.Errorf("만든 compose 파일이 올바르지 않습니다: %s", oneLine(lastLines(out, 3)))
	}
	if k.build {
		log("$ docker compose build --pull  (처음엔 몇 분 걸립니다 — 진행 내용이 아래에 이어집니다)")
		bctx := withLineSink(ctx, func(l string) { log("  %s", truncate(l, 200)) })
		out, err := stackCompose(bctx, k, dir, append(env, "BUILDKIT_PROGRESS=plain"), "build", "--pull")
		if err != nil {
			return fmt.Errorf("이미지 빌드 실패: %s", oneLine(lastLines(out, 2)))
		}
	} else {
		log("$ docker compose pull  (이미지 크기에 따라 몇 분 걸릴 수 있습니다)")
		pctx := withLineSink(ctx, func(l string) { log("  %s", truncate(l, 200)) })
		if out, err := stackCompose(pctx, k, dir, env, "pull"); err != nil {
			return fmt.Errorf("이미지를 받지 못했습니다: %s", oneLine(lastLines(out, 2)))
		}
	}
	log("$ docker compose up -d")
	out, err := stackCompose(ctx, k, dir, env, "up", "-d", "--remove-orphans")
	log("%s", lastLines(out, 6))
	cleanup := func() {
		if existed == "" { // only what this install created
			log("$ docker compose down  (이번에 만든 컨테이너 정리 — 파일은 남김)")
			_, _ = stackCompose(context.Background(), k, dir, env, "down")
		}
	}
	if err != nil {
		cleanup()
		return fmt.Errorf("컨테이너를 시작하지 못했습니다: %s", oneLine(lastLines(out, 2)))
	}
	// wait until it stays up
	state := ""
	for i := 0; i < 20; i++ {
		time.Sleep(time.Second)
		if state, _ = ctrStateOf(ctx, ctr); state == "running" && i >= 2 {
			break
		}
	}
	if state != "running" {
		logs, _ := docker(ctx, nil, nil, "logs", "--tail", "15", ctr)
		log("%s", logs)
		cleanup()
		return fmt.Errorf("컨테이너가 실행 상태가 아닙니다 (%s) — 위 로그를 확인하세요", state)
	}
	if k.verify != nil {
		if err := k.verify(a, ctr); err != nil {
			cleanup()
			return err
		}
	}
	rec := &ManagedStack{Name: name, Container: ctr, Network: network, Dir: dir, HostDir: host, Options: map[string]string{}, Installed: time.Now()}
	for kk, v := range o {
		if kk != "container" && !strings.HasPrefix(kk, "secret") && !strings.HasPrefix(kk, "file") { // one-time secrets / file contents are not kept
			rec.Options[kk] = v
		}
	}
	if err := a.store.Update(func(d *Data) error {
		if d.Stacks == nil {
			d.Stacks = map[string]*ManagedStack{}
		}
		d.Stacks[name] = rec
		k.adopt(d, rec)
		return nil
	}); err != nil {
		return err
	}
	if name == "caddy" {
		a.syncCrowdSecAcquis() // a managed CrowdSec follows the new Caddy
	}
	log("✓ %s 설치 완료 — 컨테이너 %s · 네트워크 %s", k.Label, ctr, network)
	return nil
}

func (a *App) stackSimple(name, action string, keepData bool, log func(string, ...any)) error {
	k := stackKinds[name]
	rec := a.store.Snapshot().Stacks[name]
	if rec == nil {
		return fmt.Errorf("길목이 설치한 %s 가 없습니다", k.Label)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	env := stackEnv(name)
	var args []string
	switch action {
	case "start":
		args = []string{"up", "-d"}
	case "stop":
		args = []string{"stop"}
	case "restart":
		args = []string{"restart"}
	case "token":
		args = []string{"up", "-d"} // recreate with the new .env
	case "remove":
		args = []string{"down"}
	}
	log("$ docker compose %s", strings.Join(args, " "))
	out, err := stackCompose(ctx, k, rec.Dir, env, args...)
	log("%s", lastLines(out, 8))
	if err != nil {
		return fmt.Errorf("%s 실패: %s", stackActionText[action], oneLine(lastLines(out, 2)))
	}
	// (re)started: "done" only once it really serves (CrowdSec's LAPI needs ~30s after a restart)
	if (action == "start" || action == "restart" || action == "token") && k.verify != nil {
		log("• 준비될 때까지 기다리는 중…")
		if err := k.verify(a, rec.Container); err != nil {
			return err
		}
		log("✓ 준비됨")
	}
	if action == "remove" {
		if !keepData {
			log("• 폴더 삭제 %s", rec.Dir)
			if err := os.RemoveAll(rec.Dir); err != nil {
				return err
			}
		}
		_ = a.store.Update(func(d *Data) error { delete(d.Stacks, name); return nil })
		log("✓ 제거했습니다 — 길목 설정의 %s 연결 정보는 그대로입니다 (설정 탭 › 구성요소에서 끄거나 다른 컨테이너로 바꾸세요)", k.Label)
	}
	return nil
}

// stackEnv: values compose needs besides the stack's .env (none for now — secrets live in .env /
// files so a plain `docker compose up` on the host gives the same result).
func stackEnv(name string) []string { return nil }

// ---------------------------------------------------------------- API

type stackView struct {
	Kind      string        `json:"kind"`
	Label     string        `json:"label"`
	Record    *ManagedStack `json:"record,omitempty"`
	State     string        `json:"state,omitempty"` // container state
	Job       *StackJob     `json:"job,omitempty"`   // last job of this stack
	DefaultCt string        `json:"defaultContainer"`
}

func (a *App) getStacks(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out := map[string]stackView{}
	for name, k := range stackKinds {
		v := stackView{Kind: name, Label: k.Label, Record: d.Stacks[name], DefaultCt: k.DefaultName}
		if v.Record != nil {
			v.State, _ = ctrStateOf(ctx, v.Record.Container)
		}
		a.stk.mu.Lock()
		j := a.stk.last[name]
		a.stk.mu.Unlock()
		v.Job = a.stk.snapshot(j)
		out[name] = v
	}
	a.stk.mu.Lock()
	cur := a.stk.cur
	a.stk.mu.Unlock()
	writeJSON(w, 200, map[string]any{"stacks": out, "running": cur != nil && cur.State == "running", "now": time.Now()})
}

func (a *App) postStackPreflight(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if stackKinds[name] == nil {
		fail(w, 404, errors.New("알 수 없는 구성요소"))
		return
	}
	var in map[string]string
	_ = readJSON(r, &in)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	o := a.stackOptions(name, in)
	if err := stackKinds[name].validate(a, o); err != nil { // also fills the defaults
		writeJSON(w, 200, map[string]any{"checks": []Check{{ID: "opts", Label: "설치 옵션", Status: "fail", Detail: err.Error()}}})
		return
	}
	writeJSON(w, 200, map[string]any{"checks": a.stackPreflight(ctx, name, o)})
}

func (a *App) postStackAction(w http.ResponseWriter, r *http.Request) {
	name, action := r.PathValue("name"), r.PathValue("action")
	k := stackKinds[name]
	if k == nil || stackActionText[action] == "" || action == "token" || action == "compose" {
		fail(w, 404, errors.New("알 수 없는 구성요소 또는 동작"))
		return
	}
	var in map[string]string
	_ = readJSON(r, &in)
	o := a.stackOptions(name, in)
	if action == "install" {
		if !reStackCtr.MatchString(o["container"]) {
			fail(w, 400, errors.New("컨테이너 이름은 영문·숫자·_.- 로 1~63자입니다"))
			return
		}
		if o["network"] != "" && (!reStackCtr.MatchString(o["network"]) || o["network"] == "bridge" || o["network"] == "host" || o["network"] == "none") {
			fail(w, 400, errors.New("네트워크는 사용자 정의 네트워크 이름이어야 합니다 (bridge·host·none은 컨테이너 이름으로 찾아갈 수 없어 안 됨)"))
			return
		}
		if err := k.validate(a, o); err != nil {
			fail(w, 400, err)
			return
		}
	}
	keep := in["keepData"] != "0"
	j, err := a.startStackJob(r, name, action, func(log func(string, ...any)) error {
		if action == "install" {
			return a.stackInstall(name, o, log)
		}
		return a.stackSimple(name, action, keep, log)
	})
	if err != nil {
		fail(w, 409, err)
		return
	}
	writeJSON(w, 202, map[string]any{"job": j})
}

// validate: option checks before a job starts (per kind; nil = none)
func (k *stackKind) validate(a *App, o map[string]string) error {
	if k.check == nil {
		return nil
	}
	return k.check(a, o)
}
