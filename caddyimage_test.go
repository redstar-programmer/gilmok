package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// MSTK-23: an installed managed Caddy whose compose.yml still builds locally switches to the
// published image — only when the image is on the registry, only for the untouched generated file.
func TestMigrateManagedCaddyImage(t *testing.T) {
	f := newFullApp(t)
	var up atomic.Bool
	reg := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:published")
	}))
	reg.TLS = &tls.Config{}
	reg.StartTLS()
	defer reg.Close()
	prev := regHTTP
	regHTTP = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, reg.Listener.Addr().String())
		},
	}}
	defer func() { regHTTP = prev }()

	dir := t.TempDir()
	old := "name: gilmok-caddy\nservices:\n  caddy:\n" + caddyBuildLines + "    container_name: gilmok-caddy\n"
	p := filepath.Join(dir, "compose.yml")
	_ = os.WriteFile(p, []byte(old), 0o644)
	f.set(func(d *Data) {
		d.Stacks = map[string]*ManagedStack{"caddy": {Container: "gilmok-caddy", Dir: dir, Options: map[string]string{}}}
	})
	// not published (yet): untouched
	f.app.migrateManagedCaddyImage(context.Background())
	if b, _ := os.ReadFile(p); string(b) != old {
		t.Fatal("MSTK-23: switched before the image was published")
	}
	up.Store(true)
	// the user edited the compose file: untouched
	f.set(func(d *Data) { d.Stacks["caddy"].Options = map[string]string{"customCompose": "1"} })
	f.app.migrateManagedCaddyImage(context.Background())
	if b, _ := os.ReadFile(p); string(b) != old {
		t.Fatal("MSTK-23: an edited compose.yml was changed")
	}
	f.set(func(d *Data) { d.Stacks["caddy"].Options = map[string]string{} })
	f.app.migrateManagedCaddyImage(context.Background())
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "build:") || !strings.Contains(string(b), "    image: "+managedCaddyImage()+"\n    container_name: gilmok-caddy") {
		t.Fatalf("MSTK-23: not switched to the published image:\n%s", b)
	}
	// install option build=1 keeps building locally
	o := map[string]string{"build": "1"}
	if !strings.Contains(caddyComposeImageLines(o), "build: .") || strings.Contains(caddyComposeImageLines(map[string]string{}), "build:") {
		t.Error("MSTK-23: image lines for build / pull")
	}
}
