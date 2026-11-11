package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func siteBySub(t *testing.T, sites []any, sub string) map[string]any {
	t.Helper()
	for _, s := range sites {
		m := s.(map[string]any)
		if m["sub"] == sub {
			return m
		}
	}
	t.Fatalf("no site %q in %v", sub, sites)
	return nil
}

func importBody(t *testing.T, format string, files map[string]string, pick, overwrite []string) string {
	t.Helper()
	var fl []importFile
	for n, c := range files {
		fl = append(fl, importFile{Name: n, Content: c})
	}
	b, _ := json.Marshal(map[string]any{"format": format, "files": fl, "pick": pick, "overwrite": overwrite})
	return string(b)
}

func TestImportSitesNginx(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	f.set(func(d *Data) {
		d.Settings.Domain = "example.com"
		d.Services = []*Service{{ID: "x1", Subdomain: "photo", Upstream: "old:1", Exposure: ExposurePublic, Enabled: true, Authelia: AutheliaOpts{Policy: "two_factor"}}}
	})
	conf := `
upstream wiki_up { server wiki:3000 max_fails=3; }
server { listen 80; server_name _; return 301 https://$host$request_uri; }
server {
    listen 443 ssl;
    server_name photo.example.com;   # comment
    location / { proxy_pass http://immich:2283/; }
    location /api { proxy_pass http://other:1; }
}
server { server_name wiki.example.com; location / { proxy_pass http://wiki_up; auth_request /auth; } }
server { server_name notes.other.net; location / { proxy_pass https://joplin:22300; } }
`
	// Nginx Proxy Manager host file: target in variables, proxy_pass in an include
	npm := `server {
  set $forward_scheme http;
  set $server         "jellyfin";
  set $port           8096;
  listen 443 ssl;
  server_name media.example.com;
  location / { include conf.d/include/proxy.conf; }
}`
	m := c.must(200, "POST", "/api/import/sites", importBody(t, "auto", map[string]string{"site.conf": conf, "proxy_host/3.conf": npm}, nil, nil))
	sites := m["sites"].([]any)
	if p := siteBySub(t, sites, "photo"); p["upstream"] != "immich:2283" || p["status"] != "exists" || p["current"] != "old:1" {
		t.Fatalf("photo: %v", p)
	}
	if w := siteBySub(t, sites, "wiki"); w["upstream"] != "wiki:3000" || !strings.Contains(strings.Join(anyStrings(w["notes"]), " "), "auth_request") {
		t.Fatalf("wiki (upstream block + auth note): %v", w)
	}
	if n := siteBySub(t, sites, "notes"); n["upstream"] != "https://joplin:22300" || !strings.Contains(strings.Join(anyStrings(n["notes"]), " "), "other.net") {
		t.Fatalf("notes (other domain, https): %v", n)
	}
	if j := siteBySub(t, sites, "media"); j["upstream"] != "jellyfin:8096" {
		t.Fatalf("NPM variables: %v", j)
	}
	for _, s := range sites {
		if s.(map[string]any)["host"] == "_" {
			t.Fatal("the catch-all server_name _ must be skipped")
		}
	}

	// apply: wiki + media added, photo only when overwrite is asked
	r := c.must(200, "POST", "/api/import/sites/apply", importBody(t, "auto", map[string]string{"site.conf": conf, "proxy_host/3.conf": npm}, []string{"wiki", "media", "photo"}, nil))
	if len(r["added"].([]any)) != 2 || len(r["updated"].([]any)) != 0 {
		t.Fatalf("apply: %v", r)
	}
	d := f.app.store.Snapshot()
	if len(d.Services) != 3 || d.Services[0].Upstream != "old:1" || !d.Dirty {
		t.Fatalf("services after merge: %+v dirty=%v", d.Services, d.Dirty)
	}
	r = c.must(200, "POST", "/api/import/sites/apply", importBody(t, "nginx", map[string]string{"site.conf": conf}, []string{"photo"}, []string{"photo"}))
	if len(r["updated"].([]any)) != 1 || f.app.store.Snapshot().Services[0].Upstream != "immich:2283" {
		t.Fatalf("overwrite: %v", r)
	}
}

func anyStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			out = append(out, x.(string))
		}
	}
	return out
}

func TestImportSitesTraefikAndCaddy(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	f.set(func(d *Data) { d.Settings.Domain = "example.com" })

	dyn := `http:
  routers:
    grafana:
      rule: "Host(` + "`grafana.example.com`" + `) || Host(` + "`g.example.com`" + `)"
      service: grafana-svc
      middlewares: [authelia]
  services:
    grafana-svc:
      loadBalancer:
        servers:
          - url: "http://grafana:3000"
`
	toml := `[http.routers.code]
  rule = "Host(` + "`code.example.com`" + `)"
  service = "code"
[[http.services.code.loadBalancer.servers]]
  url = "http://vscode:8443"
`
	compose := `services:
  whoami:
    image: traefik/whoami
    expose: ["80"]
    labels:
      - traefik.enable=true
      - traefik.http.routers.who.rule=Host(` + "`who.example.com`" + `)
  app:
    container_name: my-app
    labels:
      traefik.http.routers.app.rule: Host(` + "`app.example.com`" + `)
      traefik.http.services.app.loadbalancer.server.port: "9000"
`
	m := c.must(200, "POST", "/api/import/sites", importBody(t, "traefik", map[string]string{"dynamic.yml": dyn, "dyn.toml": toml, "docker-compose.yml": compose}, nil, nil))
	sites := m["sites"].([]any)
	for sub, up := range map[string]string{"grafana": "grafana:3000", "g": "grafana:3000", "code": "vscode:8443", "who": "whoami:80", "app": "my-app:9000"} {
		if s := siteBySub(t, sites, sub); s["upstream"] != up || s["status"] != "new" {
			t.Fatalf("%s: %v", sub, s)
		}
	}

	caddy := `{
	email a@b.c
}
(mysnip) { header X-A 1 }
photo.other.org {
	import mysnip
	reverse_proxy immich:2283
}
:80 { respond "hi" }
`
	m = c.must(200, "POST", "/api/import/sites", importBody(t, "caddy", map[string]string{"Caddyfile": caddy}, nil, nil))
	p := siteBySub(t, m["sites"].([]any), "photo")
	if p["upstream"] != "immich:2283" || !strings.Contains(strings.Join(anyStrings(p["notes"]), " "), "mysnip") {
		t.Fatalf("caddy: %v", p)
	}
	if len(m["sites"].([]any)) != 1 {
		t.Fatalf("only the named site: %v", m["sites"])
	}
}

// Traefik labels of the running containers.
func TestImportSitesTraefikDocker(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	f.set(func(d *Data) { d.Settings.Domain = "example.com" })
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		switch args[0] {
		case "ps":
			return "abc\ndef", nil
		case "inspect":
			return `[{"Name":"/nextcloud","Config":{"Labels":{"traefik.http.routers.nc.rule":"Host(` + "`cloud.example.com`" + `)"},"ExposedPorts":{"80/tcp":{}}}},
			         {"Name":"/plain","Config":{"Labels":{},"ExposedPorts":{"80/tcp":{}}}}]`, nil
		}
		return "", nil
	})
	m := c.must(200, "POST", "/api/import/sites", `{"format":"traefik-docker"}`)
	sites := m["sites"].([]any)
	if len(sites) != 1 || siteBySub(t, sites, "cloud")["upstream"] != "nextcloud:80" {
		t.Fatalf("docker labels: %v", sites)
	}
}

// Topology grouping by Docker network + the host port for 「로컬에서 열기」.
func TestServiceNetworksAndLocal(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.CaddyContainer = "example.com", "edge"
		d.Services = []*Service{
			{ID: "a", Subdomain: "photo", Upstream: "immich:2283", Exposure: ExposurePublic, Enabled: true},
			{ID: "b", Subdomain: "wiki", Upstream: "wiki-svc:3000", Exposure: ExposurePublic, Enabled: true},
			{ID: "c", Subdomain: "nas", Upstream: "host.docker.internal:5000", Exposure: ExposureTailscale, Enabled: true},
			{ID: "d", Subdomain: "ext", Upstream: "192.0.2.10:80", Exposure: ExposurePublic, Enabled: true},
		}
	})
	installFakeDocker(t, func(args []string, _ []byte) (string, error) {
		switch args[0] {
		case "ps":
			return "1\n2\n3", nil
		case "inspect":
			return `[{"Name":"/edge","NetworkSettings":{"Networks":{"proxy":{}}}},
			 {"Name":"/immich","Config":{"Labels":{}},"NetworkSettings":{"Networks":{"proxy":{},"immich_default":{}},"Ports":{"2283/tcp":[{"HostIp":"0.0.0.0","HostPort":"12283"}]}}},
			 {"Name":"/wiki-1","Config":{"Labels":{"com.docker.compose.service":"wiki-svc"}},"NetworkSettings":{"Networks":{"wiki_net":{}}}}]`, nil
		}
		return "", nil
	})
	m := c.must(200, "GET", "/api/services/local", "")
	a := m["a"].(map[string]any)
	if a["network"] != "proxy" || a["shared"] != true || a["localPort"] != float64(12283) {
		t.Fatalf("immich: %v", a)
	}
	if b := m["b"].(map[string]any); b["network"] != "wiki_net" || b["shared"] != nil || b["container"] != "wiki-1" {
		t.Fatalf("wiki (compose service name, not shared with Caddy): %v", b)
	}
	if h := m["c"].(map[string]any); h["kind"] != "host" || h["localPort"] != float64(5000) {
		t.Fatalf("host upstream: %v", h)
	}
	if o := m["d"].(map[string]any); o["kind"] != "other" {
		t.Fatalf("outside: %v", o)
	}
}
