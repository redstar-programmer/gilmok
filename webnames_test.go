package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The UI scripts share one global scope (plain <script> tags). A top-level name declared in two files
// is a SyntaxError that stops the second file — the whole dashboard went blank once because
// stacks.js and dashboard.js both declared `ago`.
func TestWebScriptsNoDuplicateGlobals(t *testing.T) {
	re := regexp.MustCompile(`(?m)^(?:async\s+)?function\s+([A-Za-z0-9_$]+)|^(?:const|let|class)\s+([A-Za-z0-9_$]+)`)
	files, _ := filepath.Glob("web/*.js")
	if len(files) == 0 {
		t.Fatal("no web/*.js found")
	}
	seen := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			name := m[1] + m[2]
			if prev, ok := seen[name]; ok && prev != f {
				t.Errorf("global %q is declared in both %s and %s", name, prev, f)
			}
			seen[name] = f
		}
	}
}
