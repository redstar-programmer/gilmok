package main

// Editing the compose.yml of a managed stack (사용자 요구: 네트워크·포트·볼륨을 환경에 맞게).
//
//   GET  /api/stacks/{name}/compose            current file + whether it was edited
//   PUT  /api/stacks/{name}/compose {content}  validate → back up → write → up -d → ready? (job)
//                                              a failure restores the previous file and brings it back up
//   POST /api/stacks/{name}/compose-reset      back to what Gilmok generates (job)
//   GET  /api/docker/networks                  user-defined networks (for the install form)
//
// An edited file is kept on reinstall (Options["customCompose"]="1"). Two things must stay so Gilmok
// can still find and manage it: the service's container_name and the label gilmok.managed=<name>.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type composeDoc struct {
	Services map[string]struct {
		ContainerName string         `yaml:"container_name"`
		Labels        any            `yaml:"labels"`
		Networks      any            `yaml:"networks"`
		Extra         map[string]any `yaml:",inline"`
	} `yaml:"services"`
	Networks map[string]struct {
		Name     string `yaml:"name"`
		External any    `yaml:"external"`
	} `yaml:"networks"`
}

func labelValue(labels any, key string) string {
	switch l := labels.(type) {
	case map[string]any:
		if v, ok := l[key]; ok {
			return fmt.Sprint(v)
		}
	case []any:
		for _, x := range l {
			if k, v, ok := strings.Cut(fmt.Sprint(x), "="); ok && strings.TrimSpace(k) == key {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// checkManagedCompose: the file still describes the managed container. Returns the external
// networks it joins (Gilmok joins them too, so it can reach the stack).
func checkManagedCompose(name, content string, rec *ManagedStack) ([]string, error) {
	if len(content) > 64<<10 {
		return nil, errors.New("compose 파일이 너무 큽니다 (64 KB까지)")
	}
	var doc composeDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("YAML 형식이 아닙니다: %v", err)
	}
	var top struct {
		Name string `yaml:"name"`
	}
	_ = yaml.Unmarshal([]byte(content), &top)
	if strings.TrimSpace(top.Name) == "" {
		return nil, fmt.Errorf("맨 위의 name: 을 지우면 다른 설치와 compose 프로젝트가 겹칠 수 있습니다 — name: %s 를 두세요", stackProject(rec.Container))
	}
	found := false
	for _, s := range doc.Services {
		if s.ContainerName == rec.Container {
			found = true
			if labelValue(s.Labels, "gilmok.managed") != name {
				return nil, fmt.Errorf("라벨 gilmok.managed: %s 를 지우면 길목이 이 컨테이너를 관리할 수 없습니다", name)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("container_name: %s 인 서비스가 없습니다 — 컨테이너 이름은 바꿀 수 없습니다 (바꾸려면 제거 후 다시 설치)", rec.Container)
	}
	var ext []string
	for key, n := range doc.Networks {
		if e, _ := n.External.(bool); e {
			if n.Name != "" {
				ext = append(ext, n.Name)
			} else {
				ext = append(ext, key)
			}
		}
	}
	sort.Strings(ext)
	return ext, nil
}

func (a *App) getStackCompose(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rec := a.store.Snapshot().Stacks[name]
	if stackKinds[name] == nil || rec == nil {
		fail(w, 404, errors.New("길목이 설치한 구성요소가 아닙니다"))
		return
	}
	b, err := os.ReadFile(filepath.Join(rec.Dir, "compose.yml"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"content": string(b), "custom": rec.Options["customCompose"] == "1", "container": rec.Container, "network": rec.Network})
}

func (a *App) putStackCompose(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	k := stackKinds[name]
	rec := a.store.Snapshot().Stacks[name]
	if k == nil || rec == nil {
		fail(w, 404, errors.New("길목이 설치한 구성요소가 아닙니다"))
		return
	}
	var in struct {
		Content string `json:"content"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	content := strings.ReplaceAll(in.Content, "\r\n", "\n")
	nets, err := validateStackCompose(r.Context(), name, rec, content)
	if err != nil {
		fail(w, 400, err)
		return
	}
	j, err := a.startStackJob(r, name, "compose", func(log func(string, ...any)) error {
		return a.applyStackCompose(name, rec, content, nets, true, log)
	})
	if err != nil {
		fail(w, 409, err)
		return
	}
	writeJSON(w, 202, map[string]any{"job": j})
}

// applyStackCompose writes the file, recreates the stack and waits until it serves; on failure the
// previous file comes back and is brought up again.
func (a *App) applyStackCompose(name string, rec *ManagedStack, content string, nets []string, custom bool, log func(string, ...any)) error {
	k := stackKinds[name]
	path := filepath.Join(rec.Dir, "compose.yml")
	prev, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	bak := path + ".bak-" + time.Now().Format("20060102-150405")
	if err := os.WriteFile(bak, prev, 0o644); err != nil {
		return err
	}
	log("• 이전 파일 백업: %s", filepath.Base(bak))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	self := a.store.Snapshot().SelfName
	for _, n := range nets {
		if _, err := docker(ctx, nil, nil, "network", "inspect", n); err != nil {
			log("$ docker network create %s", n)
			if out, err := docker(ctx, nil, nil, "network", "create", n); err != nil {
				return fmt.Errorf("네트워크 %s 를 만들지 못했습니다: %s", n, oneLine(out))
			}
		}
		if self != "" { // Gilmok must still reach the stack (LAPI, health checks)
			if out, err := docker(ctx, nil, nil, "network", "connect", n, self); err == nil {
				log("  길목을 %s 네트워크에도 연결", n)
			} else if !strings.Contains(out, "already exists") {
				log("  ! 길목을 %s 에 연결하지 못했습니다: %s", n, oneLine(out))
			}
		}
	}
	if err := writeInPlace(path, []byte(content)); err != nil {
		return err
	}
	restore := func(why error) error {
		log("✗ %v — 이전 파일로 되돌립니다", why)
		_ = writeInPlace(path, prev)
		out, err := stackCompose(context.Background(), k, rec.Dir, nil, "up", "-d", "--remove-orphans")
		log("%s", lastLines(out, 4))
		if err != nil {
			return fmt.Errorf("%v (되돌린 파일로도 시작하지 못했습니다: %s)", why, oneLine(lastLines(out, 2)))
		}
		return why
	}
	log("$ docker compose up -d")
	out, err := stackCompose(ctx, k, rec.Dir, nil, "up", "-d", "--remove-orphans")
	log("%s", lastLines(out, 6))
	if err != nil {
		return restore(fmt.Errorf("새 파일로 시작하지 못했습니다: %s", oneLine(lastLines(out, 2))))
	}
	if k.verify != nil {
		log("• 준비될 때까지 기다리는 중…")
		if err := k.verify(a, rec.Container); err != nil {
			return restore(err)
		}
	}
	net := rec.Network
	if len(nets) > 0 {
		net = nets[0]
	}
	_ = a.store.Update(func(d *Data) error {
		if x := d.Stacks[name]; x != nil {
			if x.Options == nil {
				x.Options = map[string]string{}
			}
			if custom {
				x.Options["customCompose"] = "1"
			} else {
				delete(x.Options, "customCompose")
			}
			x.Network = net
		}
		return nil
	})
	log("✓ 적용했습니다")
	return nil
}

func (a *App) postStackComposeReset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	k := stackKinds[name]
	rec := a.store.Snapshot().Stacks[name]
	if k == nil || rec == nil {
		fail(w, 404, errors.New("길목이 설치한 구성요소가 아닙니다"))
		return
	}
	j, err := a.startStackJob(r, name, "compose", func(log func(string, ...any)) error {
		o := map[string]string{}
		for kk, v := range rec.Options {
			o[kk] = v
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		network, err := a.stackNetwork(ctx, log, firstNonEmpty(o["network"], rec.Network))
		cancel()
		if err != nil {
			return err
		}
		// render into a scratch copy of the compose file only: other files stay as they are
		path := filepath.Join(rec.Dir, "compose.yml")
		cur, _ := os.ReadFile(path)
		if err := k.render(a, o, rec.Dir, rec.HostDir, network, rec.Container, log); err != nil {
			return err
		}
		gen, _ := os.ReadFile(path)
		_ = writeInPlace(path, cur) // applyStackCompose backs up and writes the generated one
		return a.applyStackCompose(name, rec, string(gen), []string{network}, false, log)
	})
	if err != nil {
		fail(w, 409, err)
		return
	}
	writeJSON(w, 202, map[string]any{"job": j})
}

// getDockerNetworks: user-defined networks (container-name DNS works there; bridge/host/none do not).
func (a *App) getDockerNetworks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "network", "ls", "--format", "{{.Name}}|{{.Driver}}")
	if err != nil {
		fail(w, 502, fmt.Errorf("docker 네트워크 목록을 읽지 못했습니다: %s", oneLine(out)))
		return
	}
	list := []string{}
	for _, l := range strings.Split(out, "\n") {
		n, drv, _ := strings.Cut(strings.TrimSpace(l), "|")
		if n == "" || n == "bridge" || n == "host" || n == "none" || drv == "null" || drv == "host" {
			continue
		}
		list = append(list, n)
	}
	sort.Strings(list)
	writeJSON(w, 200, map[string]any{"networks": list})
}

func firstNonEmpty(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

// validateStackCompose: our rules (container name, label, project name) and then compose itself
// (`config -q` with the stack's .env), on a scratch copy — nothing is written to compose.yml.
func validateStackCompose(parent context.Context, name string, rec *ManagedStack, content string) ([]string, error) {
	nets, err := checkManagedCompose(name, content, rec)
	if err != nil {
		return nil, err
	}
	cand := filepath.Join(rec.Dir, "compose.candidate-"+newID()+".yml") // random: checks may overlap while typing
	if err := os.WriteFile(cand, []byte(content), 0o644); err != nil {
		return nil, err
	}
	defer os.Remove(cand)
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if out, err := docker(ctx, nil, nil, "compose", "--project-directory", rec.Dir, "-f", cand, "config", "-q"); err != nil {
		return nil, fmt.Errorf("compose가 이 파일을 받아들이지 않습니다: %s", oneLine(lastLines(out, 3)))
	}
	return nets, nil
}

// postStackComposeCheck: validate only (the editor checks as you type). No step-up: it changes nothing.
func (a *App) postStackComposeCheck(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rec := a.store.Snapshot().Stacks[name]
	if stackKinds[name] == nil || rec == nil {
		fail(w, 404, errors.New("길목이 설치한 구성요소가 아닙니다"))
		return
	}
	var in struct {
		Content string `json:"content"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	nets, err := validateStackCompose(r.Context(), name, rec, strings.ReplaceAll(in.Content, "\r\n", "\n"))
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "networks": nets})
}
