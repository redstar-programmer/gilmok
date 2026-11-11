package main

import (
	"strings"
	"testing"
)

// First visit picks the install's UI language (no login yet); afterwards it is a setting.
func TestUILanguageChoice(t *testing.T) {
	f := newFullApp(t)
	f.set(func(d *Data) { d.Settings.Lang = "" })
	anon := f.client(t)

	_, st := anon.do("GET", "/api/auth/state", "")
	if st["lang"] != "" {
		t.Fatalf("fresh install should not have a language yet: %v", st["lang"])
	}
	if code, _ := anon.do("POST", "/api/auth/lang", `{"lang":"xx"}`); code != 400 {
		t.Fatalf("unknown language: %d", code)
	}
	anon.must(200, "POST", "/api/auth/lang", `{"lang":"en"}`)
	if _, st = anon.do("GET", "/api/auth/state", ""); st["lang"] != "en" {
		t.Fatalf("state lang = %v", st["lang"])
	}
	// once chosen, the anonymous endpoint cannot change it any more
	if code, _ := anon.do("POST", "/api/auth/lang", `{"lang":"ko"}`); code != 409 {
		t.Fatalf("second choice should be refused: %d", code)
	}
	if f.app.store.Snapshot().Settings.Lang != "en" {
		t.Fatal("language changed by a second anonymous call")
	}

	// settings: an administrator changes it; unknown values are refused
	boss := f.admin(t)
	boss.must(200, "PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.Lang = "ko" }))
	if f.app.store.Snapshot().Settings.Lang != "ko" {
		t.Fatal("settings did not change the language")
	}
	code, m := boss.do("PUT", "/api/settings", settingsJSON(t, f, func(s *Settings) { s.Lang = "fr" }))
	if code != 400 || !strings.Contains(fmtAny(m["error"]), "ko") {
		t.Fatalf("unsupported language accepted: %d %v", code, m)
	}
}
