package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The UI catalog (web/i18n): ko.json is generated from the sources by `go run ./tools/i18n`,
// other languages translate its ids. A broken file would leave the UI half-translated.
func TestI18nCatalog(t *testing.T) {
	read := func(name string) map[string]string {
		b, err := webFS.ReadFile("web/i18n/" + name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s is not valid JSON: %v", name, err)
		}
		return m
	}
	ko := read("ko.json")
	if len(ko) < 1000 {
		t.Fatalf("ko.json has only %d messages — regenerate it with go run ./tools/i18n", len(ko))
	}
	ph := regexp.MustCompile(`\{\d+\}`)
	set := func(s string) string {
		x := ph.FindAllString(s, -1)
		sort.Strings(x)
		return strings.Join(x, ",")
	}
	entries, err := webFS.ReadDir("web/i18n")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "ko.json" || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		tr := read(e.Name())
		for k, v := range tr {
			if _, ok := ko[k]; !ok {
				t.Errorf("%s: %q is not a message of the sources (run go run ./tools/i18n -sync)", e.Name(), k)
			}
			if set(k) != set(v) {
				t.Errorf("%s: placeholders differ for %q: %q", e.Name(), k, v)
			}
		}
	}
}
