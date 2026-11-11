package main

import (
	"encoding/json"
	"testing"
)

func TestBuildUpstreams(t *testing.T) {
	js := `[
 {"Name":"/caddy","Config":{"Image":"caddy","Labels":{}},"State":{"Status":"running"},"NetworkSettings":{"Networks":{"proxy":{}},"Ports":{"443/tcp":[{"HostIp":"0.0.0.0","HostPort":"443"}]}}},
 {"Name":"/immich_server","Config":{"Image":"immich","Labels":{"com.docker.compose.service":"immich-server","com.docker.compose.project":"immich"},"ExposedPorts":{"2283/tcp":{},"9000/udp":{}}},"State":{"Status":"running"},"NetworkSettings":{"Networks":{"proxy":{},"immich_default":{}},"Ports":{}}},
 {"Name":"/plex","Config":{"Image":"plex","Labels":{},"ExposedPorts":{"32400/tcp":{}}},"State":{"Status":"running"},"NetworkSettings":{"Networks":{"bridge":{}},"Ports":{"32400/tcp":[{"HostIp":"0.0.0.0","HostPort":"32400"}]}}},
 {"Name":"/db","Config":{"Image":"postgres","Labels":{},"ExposedPorts":{"5432/tcp":{}}},"State":{"Status":"exited"},"NetworkSettings":{"Networks":{"other":{}},"Ports":{}}}
]`
	var raw []inspectCtr
	if err := json.Unmarshal([]byte(js), &raw); err != nil {
		t.Fatal(err)
	}
	st := Settings{CaddyContainer: "caddy"}
	svcs := []*Service{{Subdomain: "photos", Upstream: "immich_server:2283"}}
	got := map[string]UpCtr{}
	for _, c := range buildUpstreams(raw, st, svcs, "") {
		got[c.Name] = c
	}
	im := got["immich_server"]
	if im.Reach != "network" || len(im.Ports) != 1 || im.Ports[0].Upstream != "immich_server:2283" || len(im.UsedBy) != 1 || im.Suggested != "immich-server" {
		t.Fatalf("immich = %+v", im)
	}
	if p := got["plex"]; p.Reach != "published" || p.Ports[0].Upstream != "host.docker.internal:32400" {
		t.Fatalf("plex = %+v", p)
	}
	if db := got["db"]; db.Reach != "none" || db.Ports[0].Upstream != "" {
		t.Fatalf("db = %+v", db)
	}
	if !got["caddy"].IsCaddy {
		t.Fatal("caddy not marked")
	}
	st.CaddyMode = "native"
	for _, c := range buildUpstreams(raw, st, svcs, "") {
		if c.Name == "plex" && c.Ports[0].Upstream != "localhost:32400" {
			t.Fatalf("native plex = %+v", c)
		}
		if c.Name == "immich_server" && c.Reach != "none" {
			t.Fatalf("native immich (not published) = %+v", c)
		}
	}
	if upstreamHost("http://app:80/x") != "app" || upstreamHost("app:80") != "app" {
		t.Fatal("upstreamHost")
	}
}
