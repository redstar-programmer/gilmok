package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// LOGF-01: Caddy outside Docker writes the access log to a file — the generated log block, its
// round trip through import, and the path checks.
func TestCaddyLogFileGenerate(t *testing.T) {
	d := Data{Settings: defaultSettings()}
	d.Settings.Domain = "example.com"
	d.Settings.UseCaddy, d.Settings.DashLogs = true, true
	d.Settings.CaddyMode, d.Settings.CaddyAdmin = "api", "http://host.docker.internal:2019"
	d.Services = []*Service{{ID: "s1", Subdomain: "app", Upstream: "localhost:8080", Exposure: ExposurePublic, Enabled: true, Extra: "encode gzip"}}

	if g := GenerateCaddyfile(d); !strings.Contains(g, "\tlog # gilmok\n") || strings.Contains(g, "output file") {
		t.Fatalf("LOGF-01: no file set → the plain marker\n%s", g)
	}
	d.Settings.CaddyLogFile = `C:\Caddy\logs\access.log`
	g := GenerateCaddyfile(d)
	for _, want := range []string{"\tlog { # gilmok\n", `output file "C:/Caddy/logs/access.log" {`, "roll_size 50MiB", "roll_keep 3"} {
		if !strings.Contains(g, want) {
			t.Errorf("LOGF-01 missing %q\n%s", want, g)
		}
	}
	_, got, _, err := ImportCaddyfile(g, d.Settings)
	if err != nil || len(got) != 1 {
		t.Fatalf("LOGF-01 import: %v %d", err, len(got))
	}
	if got[0].Extra != "encode gzip" {
		t.Errorf("LOGF-01: generated log block leaked into Extra: %q", got[0].Extra)
	}
	// Docker mode ignores the file setting (the container output is read)
	d.Settings.CaddyMode = "docker"
	if strings.Contains(GenerateCaddyfile(d), "output file") {
		t.Error("LOGF-01: docker mode wrote to a file")
	}

	for p, ok := range map[string]bool{
		"/var/log/caddy/access.log": true, `C:\Caddy\logs\a.log`: true, "D:/logs/a.log": true,
		"logs/a.log": false, `C:\a"b.log`: false, "/x/{y}.log": false, "/x/a.log\n}": false, "/x/#a.log": false,
	} {
		if caddyLogPathOK(p) != ok {
			t.Errorf("LOGF-01 path %q: want %v", p, ok)
		}
	}

	f := newFullApp(t)
	boss := f.admin(t)
	st := f.app.store.Snapshot().Settings
	st.CaddyMode, st.CaddyAdmin, st.UseCaddy = "api", "http://host.docker.internal:2019", true
	for _, c := range []struct {
		file, read string
		code       int
	}{
		{"C:/Caddy/logs/access.log", "/stacks/caddy-logs/access.log", 200},
		{`C:\Caddy\a".log`, "", 400},
		{"C:/Caddy/logs/access.log", "relative/a.log", 400},
		{"C:/Caddy/logs/access.log", filepath.ToSlash(filepath.Join(f.app.dataDir, "gilmok.json")), 400},
		{"/proc/self/environ", "", 400},
	} {
		s := st
		s.CaddyLogFile, s.CaddyLogRead = c.file, c.read
		if code, body := boss.do("PUT", "/api/settings", mustJSON(s)); code != c.code {
			t.Errorf("LOGF-01 settings %q / %q: %d %s", c.file, c.read, code, body)
		}
	}
}

// LOGF-02: following the file — new lines are counted, a rolled file is read from its start, a
// partial line waits for its end, and the follower stops when the setting changes.
func TestFollowCaddyLogFile(t *testing.T) {
	f := newFullApp(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	// already in the file when the follower starts: 2 h old (skipped) and just now (counted — written since the apply)
	if err := os.WriteFile(path, []byte(accessJSON("old.example.com", time.Now().Add(-2*time.Hour))+"\n"+accessJSON("pre.example.com", time.Now())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = f.app.store.Update(func(d *Data) error {
		d.Settings.UseCaddy, d.Settings.CaddyMode, d.Settings.CaddyLogFile, d.Settings.CaddyLogRead = true, "api", "C:/x/access.log", path
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- f.app.followLogFile(path) }()
	count := func(host string) int {
		n := 0
		for _, r := range f.app.mon.recent(0) {
			if r.Host == host {
				n++
			}
		}
		return n
	}
	wait := func(host string, want int) {
		t.Helper()
		for i := 0; i < 60 && count(host) < want; i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if got := count(host); got != want {
			t.Fatalf("LOGF-02 %s: %d requests, want %d", host, got, want)
		}
	}
	appendTo := func(s string) {
		fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fh.WriteString(s)
		fh.Close()
	}
	time.Sleep(300 * time.Millisecond)
	appendTo(accessJSON("a.example.com", time.Now()) + "\n" + accessJSON("a.example.com", time.Now()) + "\n")
	wait("a.example.com", 2)
	wait("pre.example.com", 1)
	if count("old.example.com") != 0 {
		t.Error("LOGF-02: a line older than an hour was replayed")
	}
	// a line written in two parts
	line := accessJSON("b.example.com", time.Now())
	appendTo(line[:20])
	time.Sleep(1500 * time.Millisecond)
	appendTo(line[20:] + "\n")
	wait("b.example.com", 1)
	// Caddy rolled the file: a new, smaller file
	if err := os.WriteFile(path, []byte(accessJSON("c.example.com", time.Now().Add(time.Second))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wait("c.example.com", 1)
	// the setting changes → the follower ends
	_ = f.app.store.Update(func(d *Data) error { d.Settings.CaddyLogFile = ""; return nil })
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("LOGF-02 stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LOGF-02: follower did not stop after the setting changed")
	}
}

func accessJSON(host string, at time.Time) string {
	return fmt.Sprintf(`{"level":"info","ts":%.3f,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"203.0.113.9","client_ip":"203.0.113.9","method":"GET","host":"%s","uri":"/"},"status":200,"duration":0.004,"size":12}`,
		float64(at.UnixNano())/1e9, host)
}
