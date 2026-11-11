package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Image update check: compares local image digests with the registry (HEAD on the manifest —
// does not count against Docker Hub pull limits). Images built from a Dockerfile (e.g. Caddy
// with plugins) are judged by their FROM base images.

type UpdItem struct {
	Target    string `json:"target"` // caddy | authelia | crowdsec
	Container string `json:"container"`
	Image     string `json:"image"` // image ref checked (base image for built ones)
	Built     bool   `json:"built"` // container image is built locally; Image is a FROM base
	Available bool   `json:"available"`
	Local     string `json:"local,omitempty"`
	Remote    string `json:"remote,omitempty"`
	Err       string `json:"err,omitempty"`
}

type UpdateInfo struct {
	Checked time.Time `json:"checked"`
	Items   []UpdItem `json:"items"`
}

func (u UpdateInfo) count() int {
	n := 0
	seen := map[string]bool{}
	for _, it := range u.Items {
		if it.Available && !seen[it.Target] {
			seen[it.Target] = true
			n++
		}
	}
	return n
}

var updMu sync.Mutex

func (a *App) updatesLoop() {
	time.Sleep(30 * time.Second)
	for {
		d := a.store.Snapshot()
		if d.Settings.UpdateCheck && time.Since(d.Updates.Checked) > 12*time.Hour {
			a.checkUpdates()
		}
		time.Sleep(30 * time.Minute)
	}
}

func (a *App) getUpdates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.store.Snapshot().Updates)
}

func (a *App) postUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.checkUpdates())
}

func (a *App) checkUpdates() UpdateInfo {
	updMu.Lock()
	defer updMu.Unlock()
	d := a.store.Snapshot()
	st := d.Settings
	var targets [][2]string
	if st.UseCaddy && caddyMode(st) == "docker" {
		targets = append(targets, [2]string{"caddy", st.CaddyContainer})
	}
	if st.UseAuthelia {
		targets = append(targets, [2]string{"authelia", st.AutheliaCtr})
	}
	if st.UseCrowdSec {
		targets = append(targets, [2]string{"crowdsec", st.CrowdSecContainer})
	}
	var items []UpdItem
	for _, t := range targets {
		if t[1] == "" || !ctrStatus(t[1]).Exists {
			continue
		}
		items = append(items, a.checkContainer(t[0], t[1], st)...)
	}
	info := UpdateInfo{Checked: time.Now(), Items: items}
	prev := d.Updates
	_ = a.store.Update(func(x *Data) error { x.Updates = info; return nil })
	// notify once per newly available target
	was := map[string]bool{}
	for _, it := range prev.Items {
		if it.Available {
			was[it.Target+it.Image] = true
		}
	}
	for _, it := range items {
		if it.Available && !was[it.Target+it.Image] {
			what := it.Image
			if it.Built {
				what = "베이스 이미지 " + it.Image
			}
			a.logEvent("system", "warn", "update.available", it.Container, fmt.Sprintf("%s: 새 이미지가 있습니다 (%s)", it.Container, what), it)
		}
	}
	return info
}

func (a *App) checkContainer(target, ctr string, st Settings) []UpdItem {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{.Config.Image}}|{{.Image}}", ctr)
	if err != nil {
		return []UpdItem{{Target: target, Container: ctr, Err: oneLine(out)}}
	}
	ref, imgID, _ := strings.Cut(strings.TrimSpace(out), "|")
	digests := localDigests(ctx, imgID)
	var regErr error
	if len(digests) > 0 {
		it := UpdItem{Target: target, Container: ctr, Image: ref}
		remote, err := registryDigest(ctx, ref)
		if err == nil {
			it.Remote, it.Local = short(remote), short(digests[0])
			it.Available = !hasDigest(digests, remote)
			return []UpdItem{it}
		}
		// not in a registry (Docker Desktop's image store also gives local builds a digest)
		// → treat it as a locally built image and check its Dockerfile base images
		regErr = err
	}
	// built locally → check the Dockerfile's base images
	var items []UpdItem
	dir, svc := manualStack(target, st)
	t, err := resolveCompose(ctr, dir, svc)
	if err != nil || t.LocalDir == "" {
		msg := "직접 빌드한 이미지 — compose 폴더를 찾지 못해 베이스 이미지를 확인할 수 없습니다"
		if regErr != nil {
			msg = regErr.Error()
		}
		return []UpdItem{{Target: target, Container: ctr, Image: ref, Built: true, Err: msg}}
	}
	bases := dockerfileBases(filepath.Join(t.LocalDir, "Dockerfile"))
	if svcDir := filepath.Join(t.LocalDir, t.Service); len(bases) == 0 {
		bases = dockerfileBases(filepath.Join(svcDir, "Dockerfile")) // build: ./<service>
	}
	if len(bases) == 0 {
		msg := "Dockerfile을 찾지 못했습니다"
		if regErr != nil {
			msg = regErr.Error()
		}
		return []UpdItem{{Target: target, Container: ctr, Image: ref, Built: true, Err: msg}}
	}
	for _, base := range bases {
		it := UpdItem{Target: target, Container: ctr, Image: base, Built: true}
		ld := localDigests(ctx, base)
		remote, err := registryDigest(ctx, base)
		switch {
		case err != nil:
			it.Err = err.Error()
		case len(ld) == 0:
			// base image not kept locally (BuildKit): compare with the digest recorded when it
			// was last built / first seen
			it.Remote = short(remote)
			base := base
			var baseline string
			_ = a.store.Update(func(d *Data) error {
				if d.UpdBaseline == nil {
					d.UpdBaseline = map[string]string{}
				}
				if d.UpdBaseline[base] == "" {
					d.UpdBaseline[base] = remote
				}
				baseline = d.UpdBaseline[base]
				return nil
			})
			it.Local = short(baseline)
			it.Available = baseline != remote
		default:
			it.Remote, it.Local = short(remote), short(ld[0])
			it.Available = !hasDigest(ld, remote)
		}
		items = append(items, it)
	}
	return items
}

// resetBaselines: after an in-app update (build --pull) the bases are current; then re-check.
func (a *App) resetBaselines(target string) UpdateInfo {
	func() {
		st := a.store.Snapshot().Settings
		ctr := map[string]string{"caddy": st.CaddyContainer, "authelia": st.AutheliaCtr}[target]
		if ctr == "" {
			return
		}
		dir, svc := manualStack(target, st)
		t, err := resolveCompose(ctr, dir, svc)
		if err != nil || t.LocalDir == "" {
			return
		}
		bases := dockerfileBases(filepath.Join(t.LocalDir, "Dockerfile"))
		if len(bases) == 0 {
			bases = dockerfileBases(filepath.Join(t.LocalDir, t.Service, "Dockerfile"))
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, b := range bases {
			if dg, err := registryDigest(ctx, b); err == nil {
				_ = a.store.Update(func(d *Data) error {
					if d.UpdBaseline == nil {
						d.UpdBaseline = map[string]string{}
					}
					d.UpdBaseline[b] = dg
					return nil
				})
			}
		}
	}()
	return a.checkUpdates()
}

func short(d string) string {
	if i := strings.Index(d, "sha256:"); i >= 0 && len(d) >= i+19 {
		return d[i : i+19]
	}
	return d
}

func hasDigest(list []string, digest string) bool {
	for _, x := range list {
		if strings.HasSuffix(x, digest) {
			return true
		}
	}
	return false
}

func localDigests(ctx context.Context, img string) []string {
	out, err := docker(ctx, nil, nil, "image", "inspect", "-f", "{{json .RepoDigests}}", img)
	if err != nil {
		return nil
	}
	var ds []string
	_ = json.Unmarshal([]byte(strings.TrimSpace(out)), &ds)
	for i, d := range ds {
		if _, after, ok := strings.Cut(d, "@"); ok {
			ds[i] = after
		}
	}
	return ds
}

var reFrom = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)

func dockerfileBases(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	stages := map[string]bool{}
	var out []string
	seen := map[string]bool{}
	for _, m := range reFrom.FindAllStringSubmatch(string(b), -1) {
		img := m[1]
		if !stages[strings.ToLower(img)] && !strings.Contains(img, "$") && !seen[img] {
			seen[img] = true
			out = append(out, img)
		}
		if m[2] != "" {
			stages[strings.ToLower(m[2])] = true
		}
	}
	return out
}

// ---------------------------------------------------------------- registry (anonymous)

func parseRef(ref string) (registry, repo, tag string) {
	ref = strings.SplitN(ref, "@", 2)[0]
	name := ref
	tag = "latest"
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		name, tag = ref[:i], ref[i+1:]
	}
	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		registry, repo = parts[0], parts[1]
	} else {
		registry, repo = "registry-1.docker.io", name
		if !strings.Contains(repo, "/") {
			repo = "library/" + repo
		}
	}
	if registry == "docker.io" {
		registry = "registry-1.docker.io"
	}
	return
}

var regHTTP = &http.Client{Timeout: 20 * time.Second}

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"

var reBearer = regexp.MustCompile(`(\w+)="([^"]*)"`)

func registryDigest(ctx context.Context, ref string) (string, error) {
	reg, repo, tag := parseRef(ref)
	u := fmt.Sprintf("https://%s/v2/%s/manifests/%s", reg, repo, tag)
	do := func(tok string) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, "HEAD", u, nil)
		req.Header.Set("Accept", manifestAccept)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return regHTTP.Do(req)
	}
	res, err := do("")
	if err != nil {
		return "", fmt.Errorf("레지스트리 연결 실패: %v", err)
	}
	res.Body.Close()
	if res.StatusCode == 401 {
		ch := res.Header.Get("Www-Authenticate")
		params := map[string]string{}
		for _, m := range reBearer.FindAllStringSubmatch(ch, -1) {
			params[m[1]] = m[2]
		}
		if params["realm"] == "" {
			return "", errors.New("레지스트리 인증 방식을 알 수 없습니다")
		}
		// the token endpoint comes from the registry's answer: https only, never a private address
		if ru, err := url.Parse(params["realm"]); err != nil || ru.Scheme != "https" || ru.Hostname() == "" || privateHost(ru.Hostname()) {
			return "", fmt.Errorf("레지스트리 인증 주소를 믿을 수 없습니다: %s", truncate(params["realm"], 120))
		}
		q := url.Values{}
		if params["service"] != "" {
			q.Set("service", params["service"])
		}
		q.Set("scope", "repository:"+repo+":pull")
		treq, _ := http.NewRequestWithContext(ctx, "GET", params["realm"]+"?"+q.Encode(), nil)
		tres, err := regHTTP.Do(treq)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(io.LimitReader(tres.Body, 1<<20))
		tres.Body.Close()
		var t struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
		}
		_ = json.Unmarshal(body, &t)
		tok := t.Token
		if tok == "" {
			tok = t.AccessToken
		}
		if res, err = do(tok); err != nil {
			return "", err
		}
		res.Body.Close()
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("레지스트리 응답 HTTP %d (%s)", res.StatusCode, ref)
	}
	dg := res.Header.Get("Docker-Content-Digest")
	if dg == "" {
		return "", errors.New("레지스트리가 digest를 알려주지 않았습니다")
	}
	return dg, nil
}

// manualStack: the compose folder / service set by hand in 설정 (used when auto-detect fails) —
// update checks must look where the update itself will run.
func manualStack(target string, st Settings) (dir, svc string) {
	switch target {
	case "caddy":
		return st.CaddyStackDir, st.CaddyService
	case "authelia":
		return st.AutheliaStackDir, st.AutheliaService
	}
	return "", ""
}

// privateHost: an IP literal that is loopback, private, link-local or unspecified.
func privateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}
