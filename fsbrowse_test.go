package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Import from a Caddyfile chosen on the user's PC, and the friendly error when the configured one is missing.
func TestImportUploadedCaddyfile(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	f.app.store.Update(func(d *Data) error {
		d.Settings.UseCaddy = true
		d.Settings.Domain = "example.com"
		d.Settings.CaddyfilePath = filepath.Join(f.dir, "missing", "Caddyfile")
		return nil
	})
	_, m := c.do("POST", "/api/import", "")
	if msg, _ := m["error"].(string); !strings.Contains(msg, "Caddyfile을 찾지 못했습니다") {
		t.Fatalf("missing file: want a friendly error, got %v", m)
	}
	body, _ := json.Marshal(map[string]string{"name": "Caddyfile", "content": "photo.example.com {\n\treverse_proxy photo:8080\n}\n"})
	m = c.must(200, "POST", "/api/import", string(body))
	if n, _ := m["imported"].(float64); n != 1 {
		t.Fatalf("want 1 imported service, got %v", m)
	}
	if svcs := f.app.store.Snapshot().Services; len(svcs) != 1 || svcs[0].Subdomain != "photo" {
		t.Fatalf("services after upload import: %+v", svcs)
	}
	// nothing was written to the configured path
	if _, err := os.Stat(f.app.store.Snapshot().Settings.CaddyfilePath); !os.IsNotExist(err) {
		t.Fatalf("the upload import must not create the Caddyfile: %v", err)
	}
	bad, _ := json.Marshal(map[string]string{"content": strings.Repeat("a", 1<<20+1)})
	if code, _ := c.do("POST", "/api/import", string(bad)); code != 400 {
		t.Fatalf("oversized upload: want 400, got %d", code)
	}
}

// The path browser lists folders, hides Gilmok's own data, and needs the 「연결·시스템」 permission.
func TestFSBrowse(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "caddy"), 0o755)
	os.WriteFile(filepath.Join(root, "caddy", "Caddyfile"), []byte("x"), 0o644)
	prev := stacksRoot
	stacksRoot = root
	t.Cleanup(func() { stacksRoot = prev })

	m := c.must(200, "GET", "/api/fs/browse", "")
	if m["path"] != filepath.Clean(root) {
		t.Fatalf("default start should be the stacks root, got %v", m["path"])
	}
	// a file path opens its folder
	m = c.must(200, "GET", "/api/fs/browse?path="+filepath.Join(root, "caddy", "Caddyfile"), "")
	ents, _ := m["entries"].([]any)
	if len(ents) != 1 || ents[0].(map[string]any)["name"] != "Caddyfile" {
		t.Fatalf("entries: %v", m)
	}
	// Gilmok's data folder is never listed
	m = c.must(200, "GET", "/api/fs/browse?path="+f.dir, "")
	if m["denied"] != true || len(m["entries"].([]any)) != 0 {
		t.Fatalf("data dir must be denied: %v", m)
	}
	// view-only accounts cannot browse
	v := f.user(t, c, "viewer", "viewer")
	if code, _ := v.do("GET", "/api/fs/browse", ""); code != 403 {
		t.Fatalf("viewer: want 403, got %d", code)
	}
}
