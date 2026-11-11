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
