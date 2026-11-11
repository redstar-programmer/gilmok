package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// All Docker operations go through the docker CLI talking to the mounted socket.

// dockerRun is the single place the docker CLI runs — tests swap it for a fake (docs/TEST_SCENARIOS.md 0.2).
var dockerRun = runDocker

func docker(ctx context.Context, stdin []byte, extraEnv []string, args ...string) (string, error) {
	return dockerRun(ctx, stdin, extraEnv, args...)
}

func runDocker(ctx context.Context, stdin []byte, extraEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Env = append(os.Environ(), extraEnv...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if sink, ok := ctx.Value(lineSinkKey{}).(func(string)); ok && sink != nil {
		w := &lineWriter{buf: &out, fn: sink}
		cmd.Stdout, cmd.Stderr = w, w
		defer w.flush()
	}
	err := cmd.Run()
	s := strings.TrimSpace(out.String())
	if err != nil {
		if s == "" {
			s = err.Error()
		}
		return s, fmt.Errorf("%s", s)
	}
	return s, nil
}

// withLineSink: docker output is also handed to fn line by line while the command runs
// (long builds show progress instead of nothing for minutes).
type lineSinkKey struct{}

func withLineSink(ctx context.Context, fn func(string)) context.Context {
	return context.WithValue(ctx, lineSinkKey{}, fn)
}

type lineWriter struct {
	mu   sync.Mutex
	buf  *bytes.Buffer
	part []byte
	fn   func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	w.part = append(w.part, p...)
	for {
		i := bytes.IndexAny(w.part, "\r\n")
		if i < 0 {
			break
		}
		if l := strings.TrimSpace(string(w.part[:i])); l != "" {
			w.fn(l)
		}
		w.part = w.part[i+1:]
	}
	return len(p), nil
}

func (w *lineWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if l := strings.TrimSpace(string(w.part)); l != "" {
		w.fn(l)
	}
	w.part = nil
}

func withTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func ctrExec(ctr string, stdin []byte, args ...string) (string, error) {
	ctx, cancel := withTimeout(60 * time.Second)
	defer cancel()
	a := []string{"exec"}
	if stdin != nil {
		a = append(a, "-i")
	}
	a = append(a, ctr)
	return docker(ctx, stdin, nil, append(a, args...)...)
}

func ctrRestart(ctr string) error {
	ctx, cancel := withTimeout(90 * time.Second)
	defer cancel()
	_, err := docker(ctx, nil, nil, "restart", ctr)
	return err
}

type CtrStatus struct {
	Name    string `json:"name"`
	Exists  bool   `json:"exists"`
	State   string `json:"state"`
	Image   string `json:"image"`
	Created string `json:"created"`
	Version string `json:"version"`
}

func ctrStatus(ctr string) CtrStatus {
	ctx, cancel := withTimeout(15 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{.State.Status}}|{{.Config.Image}}|{{.Created}}", ctr)
	st := CtrStatus{Name: ctr}
	if err != nil {
		return st
	}
	p := strings.SplitN(out, "|", 3)
	st.Exists = true
	if len(p) == 3 {
		st.State, st.Image, st.Created = p[0], p[1], p[2]
	}
	return st
}

// ctrStartedAt returns when the container's current run started (State.StartedAt).
func ctrStartedAt(ctr string) (time.Time, bool) {
	ctx, cancel := withTimeout(10 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{.State.StartedAt}}", ctr)
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(out))
	if err != nil || t.Year() < 2000 {
		return time.Time{}, false
	}
	return t, true
}

// waitHealthy watches logs since `since` for Authelia/Caddy startup result.
func waitHealthy(ctr string, since time.Time, okMarker string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(1500 * time.Millisecond)
		ctx, cancel := withTimeout(10 * time.Second)
		// RFC3339Nano: whole-second precision would pull in the previous run's lines from the same second
		out, _ := docker(ctx, nil, nil, "logs", "--since", since.UTC().Format(time.RFC3339Nano), ctr)
		cancel()
		ok := strings.LastIndex(out, okMarker)
		bad := max(strings.LastIndex(out, "level=fatal"), strings.LastIndex(out, "level=error msg=\"Configuration"))
		if ok >= 0 && ok > bad {
			return nil
		}
		if bad >= 0 {
			return fmt.Errorf("시작 실패:\n%s", lastLines(out, 8))
		}
	}
	return fmt.Errorf("%s 이(가) %s 안에 정상 시작 로그를 남기지 않았습니다", ctr, timeout)
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// ctrID returns the full container id ("" if missing) — used to tell whether compose recreated it.
func ctrID(ctr string) string {
	ctx, cancel := withTimeout(10 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{.Id}}", ctr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
