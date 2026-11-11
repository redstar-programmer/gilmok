package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------- access_control

// topLevelBlock finds a top-level YAML key block (e.g. "access_control:") by text,
// so the rest of configuration.yml (comments, {{ secret }} templates) is untouched.
// Returns start/end line indexes; end is exclusive. Trailing comment/blank lines that
// belong to the next section are not included.
func topLevelBlock(lines []string, key string) (int, int, bool) {
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, key+":") {
			start = i
			break
		}
	}
	if start < 0 {
		return 0, 0, false
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if l == "" || strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") || strings.HasPrefix(l, "#") {
			continue
		}
		end = i
		break
	}
	// give back trailing blank/comment lines to the next section
	for end > start+1 {
		t := strings.TrimSpace(lines[end-1])
		if t == "" || strings.HasPrefix(lines[end-1], "#") {
			end--
			continue
		}
		break
	}
	return start, end, true
}

func ReplaceAccessControl(config, block string) string {
	lines := strings.Split(config, "\n")
	blk := strings.Split(strings.TrimRight(block, "\n"), "\n")
	start, end, ok := topLevelBlock(lines, "access_control")
	if !ok {
		return strings.TrimRight(config, "\n") + "\n\n" + strings.Join(blk, "\n") + "\n"
	}
	out := append([]string{}, lines[:start]...)
	out = append(out, blk...)
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n")
}

func ExtractAccessControl(config string) string {
	lines := strings.Split(config, "\n")
	start, end, ok := topLevelBlock(lines, "access_control")
	if !ok {
		return ""
	}
	return strings.Join(lines[start:end], "\n")
}

type acRule struct {
	Domain  any    `yaml:"domain"`
	Subject any    `yaml:"subject"`
	Policy  string `yaml:"policy"`
}

type acBlock struct {
	AccessControl struct {
		DefaultPolicy string   `yaml:"default_policy"`
		Rules         []acRule `yaml:"rules"`
	} `yaml:"access_control"`
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, toStrings(x)...)
		}
		return out
	}
	return nil
}

// ApplyAccessControlToImport fills Authelia policy/groups on imported services
// from the existing access_control rules (first matching rule wins, as in Authelia).
func ApplyAccessControlToImport(config string, svcs []*Service, st Settings) (defaultPolicy string, err error) {
	txt := ExtractAccessControl(config)
	if txt == "" {
		return "", nil
	}
	var ac acBlock
	if err := yaml.Unmarshal([]byte(txt), &ac); err != nil {
		return "", fmt.Errorf("access_control 해석 실패: %w", err)
	}
	for _, s := range svcs {
		if !s.Authelia.Enabled {
			continue
		}
		host := st.FQDN(s.Subdomain)
		matched := false
		for _, r := range ac.AccessControl.Rules {
			if !contains(toStrings(r.Domain), host) {
				continue
			}
			if r.Policy != "one_factor" && r.Policy != "two_factor" {
				continue
			}
			var groups []string
			for _, sub := range toStrings(r.Subject) {
				if g, ok := strings.CutPrefix(sub, "group:"); ok {
					groups = append(groups, g)
				}
			}
			s.Authelia.Policy = r.Policy
			s.Authelia.Groups = groups
			matched = true
			break
		}
		if !matched {
			p := ac.AccessControl.DefaultPolicy
			if p == "one_factor" || p == "two_factor" {
				s.Authelia.Policy = p
			}
		}
	}
	return ac.AccessControl.DefaultPolicy, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func q(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func GenerateAccessControl(d Data) string {
	st := d.Settings
	svcs := append([]*Service(nil), d.Services...)
	sortServices(svcs)
	var rules []string
	for _, s := range svcs {
		if !s.Enabled || s.DNSOnly || !s.Authelia.Enabled {
			continue
		}
		host := q(st.FQDN(s.Subdomain))
		r := "    - domain: " + host + "\n"
		if len(s.Authelia.Groups) > 0 {
			r += "      subject:\n"
			for _, g := range s.Authelia.Groups {
				r += "        - " + q("group:"+g) + "\n"
			}
		}
		r += "      policy: " + q(s.Authelia.Policy) + "\n"
		if len(s.Authelia.Groups) > 0 {
			r += "    - domain: " + host + "\n      policy: 'deny'\n"
		}
		rules = append(rules, r)
	}
	def := st.DefaultPolicy
	if def == "" {
		def = "deny"
	}
	var sb strings.Builder
	sb.WriteString("access_control:\n")
	sb.WriteString("  # 길목(Gilmok)이 관리하는 블록입니다. 서비스 화면에서 수정하세요.\n")
	if len(rules) == 0 {
		// Authelia refuses default 'deny' with no rules
		if def == "deny" {
			def = "two_factor"
		}
		sb.WriteString("  default_policy: " + q(def) + "\n")
		return sb.String()
	}
	sb.WriteString("  default_policy: " + q(def) + "\n  rules:\n")
	for _, r := range rules {
		sb.WriteString(r)
	}
	return sb.String()
}

// ---------------------------------------------------------------- users_database.yml

type AUser struct {
	Disabled    bool           `yaml:"disabled" json:"disabled"`
	DisplayName string         `yaml:"displayname" json:"displayname"`
	Password    string         `yaml:"password" json:"-"`
	Email       string         `yaml:"email" json:"email"`
	Groups      []string       `yaml:"groups" json:"groups"`
	Extra       map[string]any `yaml:",inline" json:"-"`
}

type usersFile struct {
	Users map[string]*AUser `yaml:"users"`
}

func LoadUsers(path string) (map[string]*AUser, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f usersFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("users_database.yml 해석 실패: %w", err)
	}
	if f.Users == nil {
		f.Users = map[string]*AUser{}
	}
	for _, u := range f.Users {
		if u.Groups == nil {
			u.Groups = []string{}
		}
	}
	return f.Users, nil
}

func MarshalUsers(users map[string]*AUser) ([]byte, error) {
	names := make([]string, 0, len(users))
	for n := range users {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	sb.WriteString("# 길목(Gilmok)이 관리하는 파일입니다.\n")
	sb.WriteString("users:\n")
	for _, n := range names {
		u := users[n]
		if u.Groups == nil {
			u.Groups = []string{}
		}
		b, err := yaml.Marshal(map[string]*AUser{n: u})
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			sb.WriteString("  " + l + "\n")
		}
	}
	return []byte(sb.String()), nil
}

// HashPassword returns an Authelia-compatible argon2id PHC string
// (Authelia defaults: m=65536 KiB, t=3, p=4, 32-byte key, 16-byte salt).
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const m, t, p = 65536, 3, 4
	key := argon2.IDKey([]byte(pw), salt, t, m, p, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, m, t, p, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func validUsername(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func VerifyPassword(phc, pw string) bool {
	// $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
