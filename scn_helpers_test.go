package main

// Shared helpers for the scenario tests (docs/TEST_SCENARIOS.md). They drive the real router
// (app.handler) with fakes for Docker, the public IP and the disk.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPW = "correct horse battery"

// ---------------------------------------------------------------- fake docker

type dockerCall struct {
	Args  []string
	Stdin string
}

type fakeDocker struct {
	mu    sync.Mutex
	calls []dockerCall
	// handle answers one call; nil → ("", error "no fake")
	handle func(args []string, stdin []byte) (string, error)
}

func installFakeDocker(t *testing.T, handle func(args []string, stdin []byte) (string, error)) *fakeDocker {
	t.Helper()
	f := &fakeDocker{handle: handle}
	prev := dockerRun
	dockerRun = func(ctx context.Context, stdin []byte, env []string, args ...string) (string, error) {
		f.mu.Lock()
		f.calls = append(f.calls, dockerCall{Args: append([]string{}, args...), Stdin: string(stdin)})
		h := f.handle
		f.mu.Unlock()
		if h == nil {
			return "", errors.New("no fake docker")
		}
		return h(args, stdin)
	}
	t.Cleanup(func() { dockerRun = prev })
	return f
}

func (f *fakeDocker) count(sub string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c.Args, " "), sub) {
			n++
		}
	}
	return n
}

func (f *fakeDocker) joined() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, strings.Join(c.Args, " "))
	}
	return out
}

// ---------------------------------------------------------------- full app

type fullApp struct {
	app *App
	h   http.Handler
	dir string
}

func newFullApp(t *testing.T) *fullApp {
	t.Helper()
	installFakeDocker(t, nil) // nothing may reach the real docker
	prevIP := publicIPFn
	publicIPFn = func(ctx context.Context, v6 bool) (string, error) { return "", errors.New("no network in tests") }
	t.Cleanup(func() { publicIPFn = prevIP })
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "gilmok.json"))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{store: store, cf: NewCF(), dataDir: dir}
	ldb, err := openLogDB(filepath.Join(dir, "gilmok-logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ldb.w.Close(); ldb.r.Close() })
	app.ldb = ldb
	app.mon = newMonitor()
	app.cs.kick = make(chan struct{}, 1)
	ensureProxySecret(store)
	h := app.handler()
	return &fullApp{app: app, h: h, dir: dir}
}

// client keeps the session cookie; requests come from the loopback (direct access) unless set.
type client struct {
	t       *testing.T
	h       http.Handler
	cookie  string
	remote  string
	headers map[string]string
	noGM    bool
	last    *httptest.ResponseRecorder
}

func (f *fullApp) client(t *testing.T) *client {
	return &client{t: t, h: f.h, remote: "127.0.0.1:40000", headers: map[string]string{}}
}

func (c *client) raw(method, path, body string) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = c.remote
	if !c.noGM {
		req.Header.Set("X-GM", "1")
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck.Value
		}
	}
	c.last = rec
	return rec
}

func (c *client) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	rec := c.raw(method, path, body)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func (c *client) must(code int, method, path, body string) map[string]any {
	c.t.Helper()
	got, m := c.do(method, path, body)
	if got != code {
		c.t.Fatalf("%s %s: want %d, got %d %v %s", method, path, code, got, m, truncate(c.last.Body.String(), 300))
	}
	return m
}

// admin: first run → admin/admin → bootstrap "boss" (fresh session = recently verified).
func (f *fullApp) admin(t *testing.T) *client {
	t.Helper()
	c := f.client(t)
	c.must(200, "POST", "/api/auth/login", `{"name":"admin","password":"admin"}`)
	c.must(200, "POST", "/api/auth/bootstrap", `{"name":"boss","display":"대표","password":"`+testPW+`"}`)
	return c
}

// user creates an account with a role and returns a logged-in client (password changed).
func (f *fullApp) user(t *testing.T, admin *client, name, role string) *client {
	t.Helper()
	m := admin.must(200, "POST", "/api/accounts", `{"name":"`+name+`","display":"`+name+`","role":"`+role+`"}`)
	temp := m["tempPassword"].(string)
	c := f.client(t)
	f.app.auth.noteOK("127.0.0.1|" + name)
	c.must(200, "POST", "/api/auth/login", `{"name":"`+name+`","password":"`+temp+`"}`)
	c.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","new":"another strong passphrase 42"}`)
	return c
}

// expire the recent-password window of a client's session.
func (f *fullApp) staleReauth(c *client) {
	f.app.auth.mu.Lock()
	if s := f.app.auth.sessions[c.cookie]; s != nil {
		s.Reauth = time.Time{}
	}
	f.app.auth.mu.Unlock()
}

func (f *fullApp) session(c *client) *Session {
	f.app.auth.mu.Lock()
	defer f.app.auth.mu.Unlock()
	return f.app.auth.sessions[c.cookie]
}

func (f *fullApp) set(fn func(d *Data)) {
	_ = f.app.store.Update(func(d *Data) error { fn(d); return nil })
}

// events reads the log DB after a flush.
func (f *fullApp) events(t *testing.T, cat string) []Event {
	t.Helper()
	time.Sleep(1300 * time.Millisecond) // writer flushes every second
	evs, err := f.app.ldb.QueryEvents(context.Background(), EventQuery{Cat: cat, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// settingsJSON: the current settings with one change, as the settings form would send them.
func settingsJSON(t *testing.T, f *fullApp, mod func(s *Settings)) string {
	t.Helper()
	st := f.app.store.Snapshot().Settings
	mod(&st)
	b, _ := json.Marshal(st)
	return string(b)
}

func fmtAny(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func osWrite(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }
