// Command i18n builds the message catalog for the web UI.
//
// Korean is the source language: every Korean string literal in web/*.js, web/index.html and the
// server's *.go files is a message id (gettext style). Interpolations become numbered placeholders:
//
//	JS  `적용 대기 변경 ${n}건`       → "적용 대기 변경 {0}건"
//	Go  fmt.Errorf("%s 를 찾지 못했습니다", x) → "{0} 를 찾지 못했습니다"
//
// Output:
//
//	web/i18n/ko.json   every message id → itself (the base catalog; copy it to start a new language)
//	web/i18n/<lang>.json is kept as is; with -sync, ids no longer in the sources are removed
//
// Usage (from the repository root):
//
//	go run ./tools/i18n                 # rewrite ko.json, report coverage of the other languages
//	go run ./tools/i18n -missing en     # also print the ids that en.json does not translate yet (JSON lines)
//	go run ./tools/i18n -sync           # drop translations whose id is gone from the sources
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func main() {
	missing := flag.String("missing", "", "print the ids this language does not translate yet")
	sync := flag.Bool("sync", false, "remove translations whose id no longer exists")
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	msgs := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if hasHangul(s) {
			msgs[s] = true
		}
	}
	js, _ := filepath.Glob(filepath.Join(*root, "web", "*.js"))
	for _, f := range js {
		b, err := os.ReadFile(f)
		if err != nil {
			fail(err)
		}
		for _, m := range scanJS(string(b)) {
			add(m)
		}
	}
	if b, err := os.ReadFile(filepath.Join(*root, "web", "index.html")); err == nil {
		for _, m := range scanHTML(string(b)) {
			add(m)
		}
	}
	gofiles, _ := filepath.Glob(filepath.Join(*root, "*.go"))
	for _, f := range gofiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			fail(err)
		}
		for _, m := range scanGo(string(b)) {
			add(m)
		}
	}

	dir := filepath.Join(*root, "web", "i18n")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail(err)
	}
	base := map[string]string{}
	for k := range msgs {
		base[k] = k
	}
	writeJSON(filepath.Join(dir, "ko.json"), base)
	fmt.Printf("ko.json: %d messages\n", len(base))

	others, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range others {
		lang := strings.TrimSuffix(filepath.Base(f), ".json")
		if lang == "ko" {
			continue
		}
		var tr map[string]string
		b, err := os.ReadFile(f)
		if err != nil {
			fail(err)
		}
		if err := json.Unmarshal(b, &tr); err != nil {
			fail(fmt.Errorf("%s: %w", f, err))
		}
		done, stale := 0, 0
		for k := range tr {
			if msgs[k] {
				done++
			} else {
				stale++
				if *sync {
					delete(tr, k)
				}
			}
		}
		if *sync {
			writeJSON(f, tr)
		}
		fmt.Printf("%s.json: %d/%d translated, %d not in the sources%s\n", lang, done, len(msgs), stale,
			map[bool]string{true: " (removed)", false: ""}[*sync && stale > 0])
		if *missing == lang {
			keys := sortedKeys(msgs)
			for _, k := range keys {
				if _, ok := tr[k]; !ok {
					q, _ := json.Marshal(k)
					fmt.Println(string(q))
				}
			}
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "i18n:", err)
	os.Exit(1)
}

func hasHangul(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Hangul, r) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writeJSON writes a sorted, readable JSON object without HTML escaping.
func writeJSON(path string, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range keys {
		b.WriteString("  ")
		b.Write(jsonStr(k))
		b.WriteString(": ")
		b.Write(jsonStr(m[k]))
		if i < len(keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		fail(err)
	}
}

func jsonStr(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// ---------------------------------------------------------------- JavaScript

// scanJS returns every string literal (template literals with ${…} → {n}); expressions inside
// templates are scanned too. Comments and regex literals are skipped.
func scanJS(src string) []string {
	var out []string
	p := &jsScanner{s: src}
	p.scan(&out, false)
	return out
}

type jsScanner struct {
	s string
	i int
}

// scan reads until EOF, or (inExpr) until the `}` that closes a template ${ … }.
func (p *jsScanner) scan(out *[]string, inExpr bool) {
	depth := 0
	prev := byte('(') // last significant char, decides "/" = regex or division
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '/' && p.i+1 < len(p.s) && p.s[p.i+1] == '/':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
			continue
		case c == '/' && p.i+1 < len(p.s) && p.s[p.i+1] == '*':
			end := strings.Index(p.s[p.i+2:], "*/")
			if end < 0 {
				p.i = len(p.s)
			} else {
				p.i += end + 4
			}
			continue
		case c == '/' && regexAllowed(prev, p.s[:p.i]):
			p.skipRegex()
			prev = 'a'
			continue
		case c == '\'' || c == '"':
			*out = append(*out, p.quoted(c))
			prev = 'a'
			continue
		case c == '`':
			*out = append(*out, p.template(out))
			prev = 'a'
			continue
		case c == '{':
			depth++
		case c == '}':
			if inExpr && depth == 0 {
				p.i++
				return
			}
			depth--
		}
		if !isSpace(c) {
			prev = c
		}
		p.i++
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

var kwBefore = regexp.MustCompile(`(?:return|typeof|case|in|of|delete|void|throw|new|do|else)\s*$`)

func regexAllowed(prev byte, before string) bool {
	if strings.ContainsRune("(,=:[!&|?{};+-*%<>~^", rune(prev)) {
		return true
	}
	if prev >= 'a' && prev <= 'z' {
		return kwBefore.MatchString(before)
	}
	return false
}

func (p *jsScanner) skipRegex() {
	p.i++ // opening /
	inClass := false
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '\\':
			p.i += 2
			continue
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			p.i++
			for p.i < len(p.s) && (p.s[p.i] >= 'a' && p.s[p.i] <= 'z') {
				p.i++
			}
			return
		case c == '\n':
			return
		}
		p.i++
	}
}

func (p *jsScanner) quoted(q byte) string {
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == q {
			p.i++
			break
		}
		if c == '\n' {
			break
		}
		if c == '\\' {
			p.i++
			p.escape(&b)
			continue
		}
		b.WriteByte(c)
		p.i++
	}
	return b.String()
}

func (p *jsScanner) escape(b *strings.Builder) {
	if p.i >= len(p.s) {
		return
	}
	c := p.s[p.i]
	p.i++
	switch c {
	case 'n':
		b.WriteByte('\n')
	case 't':
		b.WriteByte('\t')
	case 'r':
	case 'u':
		if p.i < len(p.s) && p.s[p.i] == '{' {
			end := strings.IndexByte(p.s[p.i:], '}')
			if end > 0 {
				if v, err := strconv.ParseUint(p.s[p.i+1:p.i+end], 16, 32); err == nil {
					b.WriteRune(rune(v))
				}
				p.i += end + 1
			}
			return
		}
		if p.i+4 <= len(p.s) {
			if v, err := strconv.ParseUint(p.s[p.i:p.i+4], 16, 32); err == nil {
				b.WriteRune(rune(v))
			}
			p.i += 4
		}
	case '\n':
	default:
		b.WriteByte(c)
	}
}

func (p *jsScanner) template(out *[]string) string {
	p.i++
	var b strings.Builder
	n := 0
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '`':
			p.i++
			return b.String()
		case c == '\\':
			p.i++
			p.escape(&b)
		case c == '$' && p.i+1 < len(p.s) && p.s[p.i+1] == '{':
			p.i += 2
			p.scan(out, true)
			fmt.Fprintf(&b, "{%d}", n)
			n++
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return b.String()
}

// ---------------------------------------------------------------- HTML

var htmlText = regexp.MustCompile(`>([^<]+)<`)
var htmlAttr = regexp.MustCompile(`(?:title|placeholder|aria-label|alt)="([^"]*)"`)

func scanHTML(src string) []string {
	src = regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(src, "")
	var out []string
	for _, m := range htmlText.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	for _, m := range htmlAttr.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	return out
}

// ---------------------------------------------------------------- Go

var goVerb = regexp.MustCompile(`%[-+# 0]*(?:\d+|\*)?(?:\.\d+)?[sdvqwfxXtTcegbo]`)

// scanGo returns Go string literals (interpreted and raw) with fmt verbs as {n}; comments and
// rune literals are skipped.
func scanGo(src string) []string {
	var out []string
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out
			}
			i += end + 4
		case c == '\'':
			i++
			for i < len(src) && src[i] != '\'' {
				if src[i] == '\\' {
					i++
				}
				i++
			}
			i++
		case c == '`':
			end := strings.IndexByte(src[i+1:], '`')
			if end < 0 {
				return out
			}
			out = append(out, goFormat(src[i+1:i+1+end]))
			i += end + 2
		case c == '"':
			j := i + 1
			for j < len(src) && src[j] != '"' && src[j] != '\n' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if s, err := strconv.Unquote(src[i : j+1]); err == nil {
				out = append(out, goFormat(s))
			}
			i = j + 1
		default:
			_, size := utf8.DecodeRuneInString(src[i:])
			i += size
		}
	}
	return out
}

func goFormat(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	n := 0
	s = strings.ReplaceAll(s, "%%", "\x00")
	s = goVerb.ReplaceAllStringFunc(s, func(string) string {
		r := fmt.Sprintf("{%d}", n)
		n++
		return r
	})
	return strings.ReplaceAll(s, "\x00", "%")
}
