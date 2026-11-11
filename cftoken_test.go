package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCFTokenVerifyAndSource(t *testing.T) {
	const good = "goodtoken_abcdefghijklmnopqrstuvwxyz0123"
	const noZone = "nozonetok_abcdefghijklmnopqrstuvwxyz0123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case tok != good && tok != noZone:
			w.WriteHeader(401)
			w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"result":null}`))
		case r.URL.Path == "/user/tokens/verify":
			w.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
		case r.URL.Path == "/zones" && tok == good && r.URL.Query().Get("name") == "example.com":
			w.Write([]byte(`{"success":true,"result":[{"id":"z1"}]}`))
		case r.URL.Path == "/zones":
			w.Write([]byte(`{"success":true,"result":[]}`))
		case r.URL.Path == "/zones/z1/dns_records":
			w.Write([]byte(`{"success":true,"result":[]}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"success":false,"result":null}`))
		}
	}))
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()

	ctx := context.Background()
	if id, err := verifyCFToken(ctx, good, "example.com"); err != nil || id != "z1" {
		t.Fatalf("good token: %v %q", err, id)
	}
	if _, err := verifyCFToken(ctx, "badtoken_abcdefghijklmnopqrstuvwxyz0123", "example.com"); err == nil || !strings.Contains(err.Error(), "거부") {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := verifyCFToken(ctx, noZone, "example.com"); err == nil || !strings.Contains(err.Error(), "존을 볼 수 없습니다") {
		t.Fatalf("no zone: %v", err)
	}

	// source priority: container file > env > UI file
	dir := t.TempDir()
	oldUI := cfTokenUIPath
	cfTokenUIPath = filepath.Join(dir, "secrets", "cf_token")
	defer func() { cfTokenUIPath = oldUI }()
	t.Setenv("GM_CF_TOKEN_FILE", filepath.Join(dir, "missing"))
	t.Setenv("GM_CF_TOKEN", "")
	if _, src := cfTokenSource(); src != "" {
		t.Fatalf("expected none, got %q", src)
	}
	os.MkdirAll(filepath.Dir(cfTokenUIPath), 0o700)
	os.WriteFile(cfTokenUIPath, []byte("ui\n"), 0o600)
	if tok, src := cfTokenSource(); src != "ui" || tok != "ui" {
		t.Fatalf("ui: %q %q", tok, src)
	}
	t.Setenv("GM_CF_TOKEN", "env")
	if _, src := cfTokenSource(); src != "container-env" {
		t.Fatalf("env: %q", src)
	}
	f := filepath.Join(dir, "ctr")
	os.WriteFile(f, []byte("file"), 0o600)
	t.Setenv("GM_CF_TOKEN_FILE", f)
	if tok, src := cfTokenSource(); src != "container-file" || tok != "file" {
		t.Fatalf("file: %q %q", tok, src)
	}
}
