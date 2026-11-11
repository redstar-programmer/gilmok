package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Updating Caddy/Authelia means running `docker compose` for *their* stack from inside
// this container. Two path worlds are involved:
//
//   - the compose CLI (here) must read the compose file, .env and the build context;
//   - the Docker daemon receives absolute bind-mount sources and must resolve them
//     on the host. On Docker Desktop (Windows) host drives are /run/desktop/mnt/host/<d>/….
//
// So: read the target container's compose labels (project, working_dir, config_files,
// service), find where working_dir is mounted inside this container, and expose it at
// the daemon-visible path via a symlink. Then run compose with that path as the project
// directory: relative binds (./Caddyfile) resolve to paths the daemon understands, and
// the CLI can still read every file locally.

type ComposeTarget struct {
	Container   string   `json:"container"`
	Project     string   `json:"project"`
	Service     string   `json:"service"`
	HostDir     string   `json:"hostDir"`   // as the host sees it (label), e.g. D:\Docker\caddy
	DaemonDir   string   `json:"daemonDir"` // passed as --project-directory
	LocalDir    string   `json:"localDir"`  // where the files really are inside this container
	DaemonFiles []string `json:"files"`
	Manual      bool     `json:"manual"` // folder given in settings instead of auto-detected
}

type mountInfo struct {
	Source      string
	Destination string
}

func ctrLabels(ctr string) (map[string]string, error) {
	ctx, cancel := withTimeout(15 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{json .Config.Labels}}", ctr)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// selfMounts returns this container's bind mounts (needs docker.sock). The container is
// found by hostname (= short container id) unless GM_SELF_CONTAINER overrides it.
func selfMounts() ([]mountInfo, error) {
	self := env("GM_SELF_CONTAINER", "")
	if self == "" {
		self, _ = os.Hostname()
	}
	ctx, cancel := withTimeout(15 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{json .Mounts}}", self)
	if err != nil {
		return nil, fmt.Errorf("길목 컨테이너 자신을 찾지 못했습니다 (GM_SELF_CONTAINER 지정 필요): %s", oneLine(out))
	}
	var ms []mountInfo
	if err := json.Unmarshal([]byte(out), &ms); err != nil {
		return nil, err
	}
	return ms, nil
}

func isWinPath(p string) bool {
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// normHost makes host paths comparable: forward slashes, no trailing slash, lower-case drive.
func normHost(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimRight(p, "/")
	if isWinPath(p + "/") {
		p = strings.ToLower(p[:1]) + p[1:]
	}
	return p
}

// daemonPath converts a host path to what the Docker daemon resolves.
// D:\Docker\caddy → /run/desktop/mnt/host/d/Docker/caddy (Docker Desktop); POSIX paths unchanged.
func daemonPath(host string) string {
	n := normHost(host)
	if isWinPath(n + "/") {
		return "/run/desktop/mnt/host/" + n[:1] + n[2:]
	}
	return n
}

// hostFromDaemon reverses daemonPath: /run/desktop/mnt/host/d/Docker/x → d:/Docker/x.
// A stack recreated by compose *from this container* carries the daemon form in its
// working_dir label, while our own mounts still report the Windows form.
func hostFromDaemon(p string) string {
	const pre = "/run/desktop/mnt/host/"
	if rest, ok := strings.CutPrefix(p, pre); ok && len(rest) >= 1 && (len(rest) == 1 || rest[1] == '/') {
		return rest[:1] + ":" + rest[1:]
	}
	return p
}

// localFor finds where a host directory is visible inside this container (longest mount prefix).
func localFor(hostDir string, mounts []mountInfo) (string, bool) {
	want := normHost(hostFromDaemon(normHost(hostDir)))
	// Windows paths are case-insensitive: compare lower-cased, keep the original for the remainder
	key := func(p string) string {
		if isWinPath(p + "/") {
			return strings.ToLower(p)
		}
		return p
	}
	best, bestLen := "", -1
	for _, m := range mounts {
		src := normHost(m.Source)
		if src == "" || (key(want) != key(src) && !strings.HasPrefix(key(want), key(src)+"/")) {
			continue
		}
		if strings.EqualFold(src, "/var/run/docker.sock") {
			continue
		}
		if len(src) > bestLen {
			best, bestLen = path.Join(m.Destination, want[len(src):]), len(src)
		}
	}
	return best, bestLen >= 0
}

// resolveCompose finds how to run compose for the service behind container ctr.
// manualDir (settings) wins when set: it must already be a daemon-resolvable path that is
// also readable here (the old, manual way).
func resolveCompose(ctr, manualDir, manualService string) (ComposeTarget, error) {
	t := ComposeTarget{Container: ctr}
	labels, err := ctrLabels(ctr)
	if err != nil {
		return t, fmt.Errorf("%s 컨테이너를 찾지 못했습니다", ctr)
	}
	t.Project = labels["com.docker.compose.project"]
	t.Service = labels["com.docker.compose.service"]
	t.HostDir = labels["com.docker.compose.project.working_dir"]
	// a stack Gilmok installed (stacks.go): compose ran here, from <data>/stacks/<name>, so the
	// labels already carry paths that exist in this container
	if labels["gilmok.managed"] != "" && t.HostDir != "" {
		t.LocalDir, t.DaemonDir = t.HostDir, t.HostDir
		for _, f := range strings.Split(labels["com.docker.compose.project.config_files"], ",") {
			if f = strings.TrimSpace(f); f != "" {
				t.DaemonFiles = append(t.DaemonFiles, f)
			}
		}
		if len(t.DaemonFiles) == 0 {
			t.DaemonFiles = []string{t.HostDir + "/compose.yml"}
		}
		for _, f := range t.DaemonFiles {
			if _, err := os.Stat(f); err != nil {
				return t, fmt.Errorf("길목이 설치한 스택의 compose 파일을 읽지 못했습니다: %v", err)
			}
		}
		return t, nil
	}
	if manualDir != "" {
		t.Manual = true
		t.DaemonDir = strings.TrimRight(manualDir, "/")
		t.LocalDir = t.DaemonDir
		if t.Service == "" {
			t.Service = manualService
		}
		t.DaemonFiles = []string{t.DaemonDir + "/docker-compose.yml"}
		if _, err := os.Stat(t.DaemonFiles[0]); err != nil {
			return t, fmt.Errorf("지정한 compose 파일을 읽지 못했습니다: %v", err)
		}
		return t, nil
	}
	if t.Project == "" || t.HostDir == "" || t.Service == "" {
		return t, fmt.Errorf("%s 는 docker compose로 만든 컨테이너가 아닙니다 (compose 라벨 없음)", ctr)
	}
	mounts, err := selfMounts()
	if err != nil {
		return t, err
	}
	local, ok := localFor(t.HostDir, mounts)
	if !ok {
		return t, fmt.Errorf("compose 폴더 %s 가 길목 컨테이너에 마운트되어 있지 않습니다", t.HostDir)
	}
	t.LocalDir = local
	t.DaemonDir = daemonPath(t.HostDir)
	for _, f := range strings.Split(labels["com.docker.compose.project.config_files"], ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		nf, nd := normHost(hostFromDaemon(normHost(f))), normHost(hostFromDaemon(normHost(t.HostDir)))
		if !strings.HasPrefix(strings.ToLower(nf), strings.ToLower(nd)+"/") { // compose file outside the project dir
			return t, fmt.Errorf("compose 파일 %s 가 작업 폴더 밖에 있어 지원하지 않습니다", f)
		}
		rel := nf[len(nd):]
		t.DaemonFiles = append(t.DaemonFiles, t.DaemonDir+rel)
	}
	if len(t.DaemonFiles) == 0 {
		t.DaemonFiles = []string{t.DaemonDir + "/docker-compose.yml"}
	}
	if err := ensureLink(t.DaemonDir, t.LocalDir); err != nil {
		return t, err
	}
	for _, f := range t.DaemonFiles {
		if _, err := os.Stat(f); err != nil {
			return t, fmt.Errorf("compose 파일을 읽지 못했습니다: %v", err)
		}
	}
	return t, nil
}

// ensureLink makes daemonDir (e.g. /run/desktop/mnt/host/d/Docker/caddy) point at localDir.
var linkMu sync.Mutex

func ensureLink(daemonDir, localDir string) error {
	linkMu.Lock() // check-then-create of the symlink
	defer linkMu.Unlock()
	if daemonDir == localDir {
		return nil
	}
	if fi, err := os.Lstat(daemonDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			if cur, _ := os.Readlink(daemonDir); cur == localDir {
				return nil
			}
			_ = os.Remove(daemonDir)
		} else {
			return nil // a real directory (mounted there explicitly) — use it as is
		}
	}
	if err := os.MkdirAll(filepath.Dir(daemonDir), 0o755); err != nil {
		return err
	}
	return os.Symlink(localDir, daemonDir)
}

func (t ComposeTarget) args(extra ...string) []string {
	a := []string{"compose", "-p", t.Project, "--project-directory", t.DaemonDir}
	if t.Project == "" {
		a = []string{"compose", "--project-directory", t.DaemonDir}
	}
	for _, f := range t.DaemonFiles {
		a = append(a, "-f", f)
	}
	return append(a, extra...)
}

// composeCheck parses the stack without changing anything (`docker compose config -q`).
func composeCheck(t ComposeTarget, env []string) error {
	ctx, cancel := withTimeout(30 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, env, t.args("config", "-q")...)
	if err != nil {
		return fmt.Errorf("compose 설정 해석 실패: %s", oneLine(lastLines(out, 3)))
	}
	return nil
}

// composeUpdate pulls/builds the latest image of one compose service and recreates it.
func composeUpdate(t ComposeTarget, env []string, log func(string, ...any)) error {
	run := func(timeout time.Duration, args ...string) (string, error) {
		ctx, cancel := withTimeout(timeout)
		defer cancel()
		return docker(ctx, nil, env, t.args(args...)...)
	}
	log("• 프로젝트 %s · 서비스 %s · %s", t.Project, t.Service, t.DaemonDir)
	log("$ docker compose pull %s", t.Service)
	if out, err := run(10*time.Minute, "pull", "--ignore-buildable", t.Service); err != nil {
		log("%s", lastLines(out, 6))
		return err
	}
	log("$ docker compose build --pull %s", t.Service)
	if out, err := run(15*time.Minute, "build", "--pull", t.Service); err != nil {
		log("%s", lastLines(out, 10))
		return err
	}
	log("$ docker compose up -d %s", t.Service)
	out, err := run(5*time.Minute, "up", "-d", "--no-deps", t.Service)
	log("%s", lastLines(out, 6))
	return err
}

// caddyComposeEnv: the Caddy stack reads ${CLOUDFLARE_API_TOKEN}; its .env value is wrong
// in production, so pass the real token (process env beats .env in compose).
func caddyComposeEnv() []string {
	if t := cfToken(); t != "" {
		return []string{"CLOUDFLARE_API_TOKEN=" + t}
	}
	return nil
}
