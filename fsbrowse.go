package main

// Folder browser for the config-file path fields (Caddyfile, configuration.yml, users_database.yml).
// It lists what Gilmok itself can see — inside a container that is only what is mounted (/stacks/…),
// which is exactly the path the setting needs. Same deny rules as checkSystemSettings, so the
// browser never shows Gilmok's data, secrets or system folders.

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fsEntry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size,omitempty"`
}

// pathDenied: the folder (or a file in it) Gilmok must not point a config path at.
func (a *App) pathDenied(p string) bool {
	p = filepath.Clean(p)
	sep := string(filepath.Separator)
	for _, sub := range []string{filepath.Join(a.dataDir, "stacks", "caddy", "conf"), filepath.Join(a.dataDir, "stacks", "authelia", "config")} {
		sub = filepath.Clean(sub)
		if p == sub || strings.HasPrefix(p, sub+sep) {
			return false
		}
	}
	for _, d := range []string{a.dataDir, "/run/secrets", "/proc", "/sys", "/dev", "/etc", "/root", "/var/run", "/run/desktop"} {
		if d == "" {
			continue
		}
		d = filepath.Clean(d)
		if p == d || strings.HasPrefix(p, d+sep) {
			return true
		}
	}
	return false
}

// GET /api/fs/browse?path=<dir or file>  — 「연결·시스템」 permission (the fields it fills need it too)
func (a *App) getFSBrowse(w http.ResponseWriter, r *http.Request) {
	if !a.auth.can(r, "system") {
		fail(w, 403, errors.New("「연결·시스템」 권한이 필요합니다"))
		return
	}
	p := strings.TrimSpace(r.URL.Query().Get("path"))
	if p != "" && !filepath.IsAbs(filepath.Clean(p)) {
		p = "" // e.g. "/stacks/…" on a Windows host: start from the default instead of failing
	}
	if p == "" {
		// start where it is most likely: the mounted stacks, else the filesystem root
		p = string(filepath.Separator)
		if wd, err := os.Getwd(); err == nil {
			p = filepath.VolumeName(wd) + string(filepath.Separator) // Windows: "C:\" (a bare "\" is not absolute)
		}
		if fi, err := os.Stat(stacksRoot); err == nil && fi.IsDir() {
			p = stacksRoot
		}
	}
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		fail(w, 400, errors.New("절대 경로여야 합니다"))
		return
	}
	// a file (or a path that no longer exists) → show its folder, walking up to one that exists
	for i := 0; i < 64; i++ {
		fi, err := os.Stat(p)
		if err == nil && fi.IsDir() {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	out := map[string]any{"path": p, "parent": "", "entries": []fsEntry{}}
	if parent := filepath.Dir(p); parent != p {
		out["parent"] = parent
	}
	if a.pathDenied(p) {
		out["denied"] = true
		writeJSON(w, 200, out)
		return
	}
	list, err := os.ReadDir(p)
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}
	entries := make([]fsEntry, 0, len(list))
	for _, e := range list {
		full := filepath.Join(p, e.Name())
		if a.pathDenied(full) {
			continue
		}
		fe := fsEntry{Name: e.Name(), Dir: e.IsDir()}
		if e.Type()&os.ModeSymlink != 0 {
			if fi, err := os.Stat(full); err == nil {
				fe.Dir = fi.IsDir()
			}
		}
		if !fe.Dir {
			if fi, err := e.Info(); err == nil {
				fe.Size = fi.Size()
			}
		}
		entries = append(entries, fe)
		if len(entries) >= 1000 {
			break
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	out["entries"] = entries
	writeJSON(w, 200, out)
}
