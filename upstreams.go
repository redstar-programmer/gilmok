package main

// GET /api/docker/upstreams — containers Caddy can proxy to, for the service editor's picker.
// For each container: its ports and the upstream value to use. With Caddy in Docker that is
// <container>:<container port> when they share a network (Docker DNS), otherwise only a
// published port works (host.docker.internal:<host port>). With Caddy on the host (api/native
// mode) it is localhost:<host port>.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type UpPort struct {
	Port      int    `json:"port"`               // container port
	HostPort  int    `json:"hostPort,omitempty"` // published on the host
	Upstream  string `json:"upstream"`           // value for the 대상 field ("" = not reachable from Caddy)
	Published bool   `json:"published"`
}

type UpCtr struct {
	Name      string   `json:"name"`
	Service   string   `json:"service,omitempty"` // compose service
	Project   string   `json:"project,omitempty"`
	Image     string   `json:"image"`
	State     string   `json:"state"`
	Networks  []string `json:"networks"`
	Shared    []string `json:"shared,omitempty"` // networks shared with Caddy
	Reach     string   `json:"reach"`            // network | published | none
	Ports     []UpPort `json:"ports"`
	UsedBy    []string `json:"usedBy,omitempty"` // subdomains already pointing here
	Self      bool     `json:"self,omitempty"`   // Gilmok itself
	IsCaddy   bool     `json:"isCaddy,omitempty"`
	Suggested string   `json:"suggested,omitempty"` // subdomain suggestion
}

type inspectCtr struct {
	Name   string
	Config struct {
		Image        string
		Labels       map[string]string
		ExposedPorts map[string]struct{}
	}
	State struct {
		Status string
	}
	NetworkSettings struct {
		Networks map[string]struct{} `json:"Networks"`
		Ports    map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	}
}

func (a *App) getUpstreams(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	d := a.store.Snapshot()
	st := d.Settings
	ids, err := docker(ctx, nil, nil, "ps", "-aq")
	if err != nil {
		fail(w, 502, fmt.Errorf("docker 목록을 읽지 못했습니다: %s", oneLine(ids)))
		return
	}
	idList := strings.Fields(ids)
	if len(idList) == 0 {
		writeJSON(w, 200, map[string]any{"containers": []UpCtr{}, "mode": caddyMode(st)})
		return
	}
	out, err := docker(ctx, nil, nil, append([]string{"inspect"}, idList...)...)
	if err != nil {
		fail(w, 502, fmt.Errorf("docker inspect 실패: %s", oneLine(out)))
		return
	}
	var raw []inspectCtr
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		fail(w, 502, fmt.Errorf("docker inspect 결과를 읽지 못했습니다: %v", err))
		return
	}
	self, _ := hostnameSelf()
	list := buildUpstreams(raw, st, d.Services, self)
	writeJSON(w, 200, map[string]any{"containers": list, "mode": caddyMode(st), "caddy": st.CaddyContainer})
}

func buildUpstreams(raw []inspectCtr, st Settings, svcs []*Service, self string) []UpCtr {
	mode := caddyMode(st)
	caddyNets := map[string]bool{}
	for _, c := range raw {
		if strings.TrimPrefix(c.Name, "/") == st.CaddyContainer {
			for n := range c.NetworkSettings.Networks {
				caddyNets[n] = true
			}
		}
	}
	used := map[string][]string{}
	for _, s := range svcs {
		host := strings.ToLower(upstreamHost(s.Upstream))
		if host != "" {
			used[host] = append(used[host], s.Subdomain)
		}
	}
	var list []UpCtr
	for _, c := range raw {
		name := strings.TrimPrefix(c.Name, "/")
		it := UpCtr{Name: name, Image: c.Config.Image, State: c.State.Status, Ports: []UpPort{}, Networks: []string{},
			Service: c.Config.Labels["com.docker.compose.service"], Project: c.Config.Labels["com.docker.compose.project"]}
		it.IsCaddy = name == st.CaddyContainer
		it.Self = self != "" && name == self
		for n := range c.NetworkSettings.Networks {
			it.Networks = append(it.Networks, n)
			if caddyNets[n] && n != "host" && n != "none" {
				it.Shared = append(it.Shared, n)
			}
		}
		sort.Strings(it.Networks)
		sort.Strings(it.Shared)
		// ports: exposed + published (tcp only)
		ports := map[int]*UpPort{}
		add := func(key string) *UpPort {
			p, proto, _ := strings.Cut(key, "/")
			if proto != "" && proto != "tcp" {
				return nil
			}
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 {
				return nil
			}
			if ports[n] == nil {
				ports[n] = &UpPort{Port: n}
			}
			return ports[n]
		}
		for k := range c.Config.ExposedPorts {
			add(k)
		}
		for k, binds := range c.NetworkSettings.Ports {
			p := add(k)
			if p == nil {
				continue
			}
			for _, b := range binds {
				if hp, err := strconv.Atoi(b.HostPort); err == nil && hp > 0 {
					p.HostPort, p.Published = hp, true
					break
				}
			}
		}
		nets := len(it.Shared) > 0
		anyPub := false
		for _, p := range ports {
			switch {
			case mode != "docker":
				if p.Published {
					p.Upstream = "localhost:" + strconv.Itoa(p.HostPort)
				}
			case nets:
				p.Upstream = name + ":" + strconv.Itoa(p.Port)
			case p.Published:
				p.Upstream = "host.docker.internal:" + strconv.Itoa(p.HostPort)
			}
			anyPub = anyPub || p.Published
			it.Ports = append(it.Ports, *p)
		}
		sort.Slice(it.Ports, func(i, j int) bool { return it.Ports[i].Port < it.Ports[j].Port })
		switch {
		case mode == "docker" && nets:
			it.Reach = "network"
		case anyPub:
			it.Reach = "published"
		default:
			it.Reach = "none"
		}
		for _, k := range []string{strings.ToLower(name), strings.ToLower(it.Service)} {
			if k != "" {
				it.UsedBy = append(it.UsedBy, used[k]...)
			}
		}
		it.UsedBy = uniqStrings(it.UsedBy)
		it.Suggested = suggestSub(it.Service, name)
		list = append(list, it)
	}
	rank := map[string]int{"network": 0, "published": 1, "none": 2}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if (a.State == "running") != (b.State == "running") {
			return a.State == "running"
		}
		if rank[a.Reach] != rank[b.Reach] {
			return rank[a.Reach] < rank[b.Reach]
		}
		return a.Name < b.Name
	})
	return list
}

// upstreamHost: "immich_server:2283" / "http://x:80" → host part.
func upstreamHost(u string) string {
	u = strings.TrimSpace(u)
	for _, p := range []string{"http://", "https://", "h2c://"} {
		u = strings.TrimPrefix(u, p)
	}
	if i := strings.IndexAny(u, "/ "); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndexByte(u, ':'); i >= 0 {
		u = u[:i]
	}
	return u
}

// suggestSub: a subdomain from the compose service (or container) name — "immich_server" → "immich-server".
func suggestSub(service, name string) string {
	src := service
	if src == "" {
		src = name
	}
	src = strings.ToLower(src)
	var b strings.Builder
	for _, r := range src {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ' ':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// TopoSvcNet: where a service's upstream lives, for grouping the topology by Docker network.
type TopoSvcNet struct {
	Kind      string `json:"kind"`                // network | host | other
	Network   string `json:"network,omitempty"`   // Docker network (kind network)
	Container string `json:"container,omitempty"` // the upstream container
	Shared    bool   `json:"shared,omitempty"`    // Caddy is on that network too
	// LocalPort: the upstream port as published on the host — the service's own page can be opened
	// directly from this machine (http(s)://localhost:<port>) without going through Caddy
	LocalPort int  `json:"localPort,omitempty"`
	LocalTLS  bool `json:"localTls,omitempty"`
}

// upstreamPort: "app:8080" → 8080, "https://app" → 443, "app" → 80.
func upstreamPort(u string) (int, bool) {
	u = strings.TrimSpace(u)
	tls := strings.HasPrefix(u, "https://")
	for _, p := range []string{"http://", "https://", "h2c://"} {
		u = strings.TrimPrefix(u, p)
	}
	if i := strings.IndexAny(u, "/ "); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndexByte(u, ':'); i >= 0 {
		if n, err := strconv.Atoi(u[i+1:]); err == nil {
			return n, tls
		}
	}
	if tls {
		return 443, true
	}
	return 80, false
}

// serviceNetworks maps each service id to the Docker network its upstream container is on
// (preferring a network Caddy shares). One `docker ps` + `docker inspect` for all.
func serviceNetworks(ctx context.Context, st Settings, svcs []*Service) map[string]TopoSvcNet {
	out := map[string]TopoSvcNet{}
	ids, err := docker(ctx, nil, nil, "ps", "-aq")
	if err != nil || strings.TrimSpace(ids) == "" {
		return out
	}
	raw, err := docker(ctx, nil, nil, append([]string{"inspect"}, strings.Fields(ids)...)...)
	if err != nil {
		return out
	}
	var list []inspectCtr
	if json.Unmarshal([]byte(raw), &list) != nil {
		return out
	}
	byName := map[string]*inspectCtr{}
	var caddyNets map[string]bool
	for i := range list {
		c := &list[i]
		name := strings.TrimPrefix(c.Name, "/")
		byName[strings.ToLower(name)] = c
		if svc := c.Config.Labels["com.docker.compose.service"]; svc != "" {
			if _, dup := byName[strings.ToLower(svc)]; !dup {
				byName[strings.ToLower(svc)] = c
			}
		}
		if name == st.CaddyContainer {
			caddyNets = map[string]bool{}
			for n := range c.NetworkSettings.Networks {
				caddyNets[n] = true
			}
		}
	}
	for _, s := range svcs {
		if s.DNSOnly || s.Upstream == "" {
			continue
		}
		host := strings.ToLower(upstreamHost(s.Upstream))
		switch {
		case host == "host.docker.internal" || host == "localhost" || strings.HasPrefix(host, "127.") || host == "[::1]":
			port, tls := upstreamPort(s.Upstream)
			out[s.ID] = TopoSvcNet{Kind: "host", LocalPort: port, LocalTLS: tls}
			continue
		}
		c := byName[host]
		if c == nil {
			out[s.ID] = TopoSvcNet{Kind: "other"}
			continue
		}
		var nets, shared []string
		for n := range c.NetworkSettings.Networks {
			nets = append(nets, n)
			if caddyNets[n] {
				shared = append(shared, n)
			}
		}
		sort.Strings(nets)
		sort.Strings(shared)
		v := TopoSvcNet{Kind: "network", Container: strings.TrimPrefix(c.Name, "/")}
		if port, tls := upstreamPort(s.Upstream); port > 0 {
			for _, b := range c.NetworkSettings.Ports[strconv.Itoa(port)+"/tcp"] {
				if hp, err := strconv.Atoi(b.HostPort); err == nil && hp > 0 {
					v.LocalPort, v.LocalTLS = hp, tls
					break
				}
			}
		}
		switch {
		case len(shared) > 0:
			v.Network, v.Shared = shared[0], true
		case len(nets) > 0:
			v.Network = nets[0]
		default:
			v.Kind = "other"
		}
		out[s.ID] = v
	}
	return out
}

// GET /api/services/local — per service: the Docker network of its upstream and the host port it is
// published on (for 「로컬에서 열기」). Read-only.
func (a *App) getServicesLocal(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	out := map[string]TopoSvcNet{}
	if caddyMode(d.Settings) == "docker" {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		out = serviceNetworks(ctx, d.Settings, d.Services)
	} else {
		// Caddy on the host: localhost:<port> upstreams are the local address already
		for _, s := range d.Services {
			if h := strings.ToLower(upstreamHost(s.Upstream)); !s.DNSOnly && (h == "localhost" || strings.HasPrefix(h, "127.")) {
				port, tls := upstreamPort(s.Upstream)
				out[s.ID] = TopoSvcNet{Kind: "host", LocalPort: port, LocalTLS: tls}
			}
		}
	}
	writeJSON(w, 200, out)
}
