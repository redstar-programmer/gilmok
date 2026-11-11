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
