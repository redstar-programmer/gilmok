package main

import (
	"os"
	"strings"
	"testing"
)

func testSettings() Settings {
	st := defaultSettings()
	st.Domain = "example.com"
	st.TailscaleIP = "100.64.0.10"
	st.UseInit, st.UseCaddy, st.UseAuthelia, st.UseCloudflare, st.UseCrowdSec = true, true, true, true, true
	return st
}

func TestImportRealCaddyfile(t *testing.T) {
	src, err := os.ReadFile("testdata/Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	st := testSettings()
	base, svcs, warns, err := ImportCaddyfile(string(src), st)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warns {
		t.Log("warn:", w)
	}
	if !strings.Contains(base, "(cf_only)") || !strings.Contains(base, "(authelia)") || !strings.Contains(base, "acme_dns") {
		t.Fatalf("base skeleton missing parts:\n%s", base)
	}
	by := map[string]*Service{}
	for _, s := range svcs {
		by[s.Subdomain] = s
	}
	if len(svcs) != 19 {
		t.Fatalf("want 19 services, got %d", len(svcs))
	}
	if s := by["auth"]; s == nil || !s.MTLS || s.Exposure != ExposurePublic || s.Upstream != "authelia:9091" {
		t.Fatalf("auth parsed wrong: %+v", s)
	}
	if s := by["list"]; s == nil || s.Exposure != ExposureTailscale || !s.Authelia.Enabled || s.Upstream != "servicelist:80" {
		t.Fatalf("list parsed wrong: %+v", s)
	}
	if s := by["caddy"]; s == nil || !strings.Contains(s.Extra, "file_server") || s.Upstream != "" {
		t.Fatalf("caddy parsed wrong: %+v", s)
	}

	// round trip: generate -> import -> same services
	d := Data{Settings: st, Services: svcs}
	d.Settings.CaddyBase = base
	gen := GenerateCaddyfile(d)
	_, svcs2, _, err := ImportCaddyfile(gen, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs2) != len(svcs) {
		t.Fatalf("round trip count %d != %d", len(svcs2), len(svcs))
	}
	by2 := map[string]*Service{}
	for _, s := range svcs2 {
		by2[s.Subdomain] = s
	}
	for k, a := range by {
		b := by2[k]
		if b == nil || a.Upstream != b.Upstream || a.Exposure != b.Exposure || a.MTLS != b.MTLS || a.Authelia.Enabled != b.Authelia.Enabled || a.Extra != b.Extra {
			t.Fatalf("round trip mismatch for %s:\n%+v\n%+v", k, a, b)
		}
	}
}

func TestAccessControlReplace(t *testing.T) {
	cfg := "server:\n  address: 'tcp://0.0.0.0:9091'\n\naccess_control:\n  default_policy: one_factor\n  rules:\n    - domain: list.example.com\n      policy: one_factor\n\n# comment for session\nsession:\n  cookies: []\n"
	st := testSettings()
	svcs := []*Service{{Subdomain: "list", Enabled: true, Exposure: ExposureTailscale, Upstream: "servicelist:80",
		Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor", Groups: []string{"admins"}}}}
	out := ReplaceAccessControl(cfg, GenerateAccessControl(Data{Settings: st, Services: svcs}))
	if !strings.Contains(out, "# comment for session\nsession:") || !strings.Contains(out, "'group:admins'") || strings.Contains(out, "policy: one_factor") {
		t.Fatalf("bad replace:\n%s", out)
	}
	if _, err := ApplyAccessControlToImport(cfg, []*Service{{Subdomain: "list", Authelia: AutheliaOpts{Enabled: true}}}, st); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash %q %v", h, err)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "wrong") {
		t.Fatal("verify failed")
	}
}

func TestUsersRoundTrip(t *testing.T) {
	users := map[string]*AUser{"alice": {DisplayName: "홍", Email: "a@b.c", Password: "$argon2id$x", Groups: nil}}
	b, err := MarshalUsers(users)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "groups: []") {
		t.Fatalf("groups must be a list:\n%s", b)
	}
	p := t.TempDir() + "/u.yml"
	_ = os.WriteFile(p, b, 0o600)
	u2, err := LoadUsers(p)
	if err != nil || u2["alice"].Email != "a@b.c" {
		t.Fatalf("%v %+v", err, u2)
	}
}

func TestComposePaths(t *testing.T) {
	cases := map[string]string{
		`D:\Docker\caddy`:    "/run/desktop/mnt/host/d/Docker/caddy",
		`E:\05. 개발\gilmok\dev\`: "/run/desktop/mnt/host/e/05. 개발/gilmok/dev",
		"/opt/stacks/caddy":     "/opt/stacks/caddy",
	}
	for in, want := range cases {
		if got := daemonPath(in); got != want {
			t.Errorf("daemonPath(%q) = %q, want %q", in, got, want)
		}
	}
	mounts := []mountInfo{
		{`/var/run/docker.sock`, "/var/run/docker.sock"},
		{`D:\Docker\caddy`, "/stacks/caddy"},
		{`D:\Docker\authelia\authelia\config`, "/stacks/authelia-config"},
		{`d:\docker\authelia`, "/stacks/authelia"},
	}
	for in, want := range map[string]string{
		`D:\Docker\caddy`:                    "/stacks/caddy",
		`D:\Docker\authelia`:                 "/stacks/authelia",
		`D:\Docker\authelia\authelia\config`: "/stacks/authelia-config", // longest prefix wins
	} {
		if got, ok := localFor(in, mounts); !ok || got != want {
			t.Errorf("localFor(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	// a stack recreated from inside the container has the daemon form in its label
	if got, ok := localFor("/run/desktop/mnt/host/d/Docker/caddy", mounts); !ok || got != "/stacks/caddy" {
		t.Errorf("daemon-form label: got %q,%v", got, ok)
	}
	if _, ok := localFor(`D:\Docker\02_other`, mounts); ok {
		t.Error("unmounted dir must not resolve")
	}
}

func TestTopologyDetect(t *testing.T) {
	p := parsePorts(`{"443/tcp":[{"HostIp":"0.0.0.0","HostPort":"443"},{"HostIp":"::","HostPort":"443"}],"443/udp":[{"HostIp":"0.0.0.0","HostPort":"443"}],"80/tcp":null,"8443/tcp":[{"HostIp":"127.0.0.1","HostPort":"8443"}]}`)
	if len(p) != 4 || p[0].CtrPort != 443 || p[0].Proto != "tcp" || p[3].CtrPort != 8443 || p[3].HostIP != "127.0.0.1" || p[3].HostPort != 8443 {
		t.Fatalf("%+v", p)
	}
	if caddyHTTPSPort("{\n\thttps_port 4443\n}") != 4443 || caddyHTTPSPort("{\n}") != 443 {
		t.Fatal("https_port")
	}
}

func TestInferDomain(t *testing.T) {
	cf := "{\n\temail a@b.c\n}\n\n(cf_only) {\n\ttls x\n}\n\nauth.example.com {\n\treverse_proxy a:1\n}\nimmich.example.com {\n}\nlist.example.com:8443 {\n}\nother.site.org, www.other.site.org {\n}\n"
	if d := inferDomain(cf); d != "example.com" {
		t.Fatalf("got %q", d)
	}
	if d := inferDomain("a.shop.co.kr {\n}\nb.shop.co.kr {\n}\n"); d != "shop.co.kr" {
		t.Fatalf("co.kr: %q", d)
	}
	if d := inferDomain(":80 {\n}\n"); d != "" {
		t.Fatalf("none: %q", d)
	}
}

func TestCheckBraces(t *testing.T) {
	for _, ok := range []string{"", "header_up X-Real-IP {remote_host}", "handle /a {\n\trespond 200\n}", "# } comment only"} {
		if err := checkBraces(ok); err != nil {
			t.Fatalf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"}\nevil.example.com {\n\trespond 200", "{", "}{", "a }\n{ b"} {
		if err := checkBraces(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
