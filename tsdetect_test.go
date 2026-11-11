package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestTailscaleDetect(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	old := tsLocalStatus
	tsLocalStatus = func(context.Context) ([]byte, error) { return nil, errors.New("no tailscale here") }
	defer func() { tsLocalStatus = old }()
	noMagicDNS(t)
	f.set(func(d *Data) { d.Settings.TopoHostName, d.Settings.CaddyfilePath = "Home-NAS", "" })

	status := `{"Self":{"HostName":"ts-router","DNSName":"ts-router.tail1.ts.net.","OS":"linux","Online":true,"TailscaleIPs":["100.80.1.2","fd7a::1"]},
	 "Peer":{"a":{"HostName":"home-nas","DNSName":"home-nas.tail1.ts.net.","OS":"windows","Online":true,"TailscaleIPs":["100.100.5.6"]},
	         "b":{"HostName":"phone","OS":"android","Online":false,"TailscaleIPs":["100.70.0.9"]}}}`
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(j, "ps"):
			return `{"Names":"ts-router","Image":"tailscale/tailscale:latest","State":"running"}` + "\n" + `{"Names":"web","Image":"nginx","State":"running"}`, nil
		case strings.HasPrefix(j, "info"):
			return "docker-desktop\n", nil
		case strings.Contains(j, "tailscale status --json"):
			return status, nil
		}
		return "", nil
	})
	_, m := boss.do("GET", "/api/tailscale/detect", "")
	if m["ip"] != "100.100.5.6" || !strings.Contains(m["source"].(string), "home-nas") {
		t.Fatalf("detect: %v", m)
	}
	devs := m["devices"].([]any)
	if len(devs) != 3 || devs[0].(map[string]any)["name"] != "home-nas" {
		t.Fatalf("devices: %v", devs)
	}
	// no host name match → nothing suggested, but the devices are offered to pick
	f.set(func(d *Data) { d.Settings.TopoHostName = "" })
	_, m = boss.do("GET", "/api/tailscale/detect", "")
	if m["ip"] != "" || len(m["devices"].([]any)) != 3 {
		t.Fatalf("no match: %v", m)
	}
}

// no Tailscale DNS in tests unless a test fakes one
func noMagicDNS(t *testing.T) {
	old := tsMagicLookup
	tsMagicLookup = func(context.Context, string) ([]string, bool) { return nil, false }
	t.Cleanup(func() { tsMagicLookup = old })
}

// Tailscale installed directly on a Windows/macOS host: only MagicDNS (by device name) and the
// installer's GM_TAILSCALE_IP can see it from the container.
func TestTailscaleDetectMagicDNS(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	old := tsLocalStatus
	tsLocalStatus = func(context.Context) ([]byte, error) { return nil, errors.New("no tailscale here") }
	defer func() { tsLocalStatus = old }()
	f.set(func(d *Data) { d.Settings.CaddyfilePath = "" })
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		if strings.HasPrefix(strings.Join(args, " "), "info") {
			return "docker-desktop\n", nil
		}
		return "", nil
	})
	asked := []string{}
	oldM := tsMagicLookup
	tsMagicLookup = func(_ context.Context, name string) ([]string, bool) {
		asked = append(asked, name)
		if name == "my-nas" {
			return []string{"fd7a:115c::1", "100.90.1.2"}, true
		}
		return nil, true // NXDOMAIN: reachable, not found
	}
	defer func() { tsMagicLookup = oldM }()

	_, m := boss.do("GET", "/api/tailscale/detect", "")
	if m["ip"] != "" || m["magicDns"] != true {
		t.Fatalf("nothing to guess, but MagicDNS answers: %v", m)
	}
	for _, n := range asked {
		if n == "docker-desktop" {
			t.Fatalf("docker-desktop must not be looked up: %v", asked)
		}
	}
	_, m = boss.do("GET", "/api/tailscale/detect?name=My-NAS", "")
	if m["ip"] != "100.90.1.2" || !strings.Contains(m["source"].(string), "my-nas") {
		t.Fatalf("by name: %v", m)
	}
	_, m = boss.do("GET", "/api/tailscale/detect?name=other", "")
	if m["nameMiss"] != "other" || m["ip"] != "" {
		t.Fatalf("unknown name: %v", m)
	}
	if _, m = boss.do("GET", "/api/tailscale/detect?name=bad%20name;", ""); m["nameMiss"] != nil {
		t.Fatalf("invalid names are ignored, not looked up: %v", m)
	}
	t.Setenv("GM_TAILSCALE_IP", "100.64.0.10")
	_, m = boss.do("GET", "/api/tailscale/detect", "")
	if m["ip"] != "100.64.0.10" || !strings.Contains(m["source"].(string), "GM_TAILSCALE_IP") {
		t.Fatalf("installer value: %v", m)
	}
}
