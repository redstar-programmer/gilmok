package main

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Topology map: what Gilmok can detect about the path in front of Caddy. Everything else
// (router, tunnel, VPN, host name) is entered by the user (Settings.Topo*) and only drawn.

type TopoPort struct {
	CtrPort  int    `json:"ctrPort"`
	Proto    string `json:"proto"`
	HostIP   string `json:"hostIp"`
	HostPort int    `json:"hostPort"`
}

type TopoInfo struct {
	CaddyRunning  bool       `json:"caddyRunning"`
	Ports         []TopoPort `json:"ports"`      // Caddy's published ports (docker inspect)
	PublicPort    int        `json:"publicPort"` // Caddy HTTPS port inside the container (https_port or 443)
	DockerOS      string     `json:"dockerOs"`   // "Docker Desktop", "Ubuntu 24.04", …
	DockerDesktop bool       `json:"dockerDesktop"`
	PublicIP      string     `json:"publicIp"`
	SelfName      string     `json:"selfName"`  // Gilmok's own container
	SelfPorts     []TopoPort `json:"selfPorts"` // its published ports (direct admin access)
}

type topoCache struct {
	mu     sync.Mutex
	ip     string
	ipAt   time.Time
	osName string
}

var reHTTPSPort = regexp.MustCompile(`(?m)^\s*https_port\s+(\d+)`)

func caddyHTTPSPort(base string) int {
	if m := reHTTPSPort.FindStringSubmatch(base); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	return 443
}

func parsePorts(raw string) []TopoPort {
	var m map[string][]struct{ HostIp, HostPort string }
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil
	}
	var out []TopoPort
	for k, binds := range m {
		p, proto, _ := strings.Cut(k, "/")
		cp, _ := strconv.Atoi(p)
		for _, b := range binds {
			hp, _ := strconv.Atoi(b.HostPort)
			out = append(out, TopoPort{CtrPort: cp, Proto: proto, HostIP: b.HostIp, HostPort: hp})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CtrPort != out[j].CtrPort {
			return out[i].CtrPort < out[j].CtrPort
		}
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].HostIP < out[j].HostIP
	})
	return out
}

func (a *App) getTopology(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	st := d.Settings
	info := TopoInfo{PublicPort: caddyHTTPSPort(st.CaddyBase), Ports: []TopoPort{}}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if out, err := docker(ctx, nil, nil, "inspect", "-f", "{{.State.Running}}|{{json .NetworkSettings.Ports}}", st.CaddyContainer); err == nil {
		run, ports, _ := strings.Cut(out, "|")
		info.CaddyRunning = run == "true"
		if p := parsePorts(ports); p != nil {
			info.Ports = p
		}
	}
	info.SelfName, info.SelfPorts = d.SelfName, []TopoPort{}
	if d.SelfName != "" {
		if out, err := docker(ctx, nil, nil, "inspect", "-f", "{{json .NetworkSettings.Ports}}", d.SelfName); err == nil {
			if p := parsePorts(strings.TrimSpace(out)); p != nil {
				info.SelfPorts = p
			}
		}
	}
	a.topo.mu.Lock()
	osName := a.topo.osName
	ip, ipAt := a.topo.ip, a.topo.ipAt
	a.topo.mu.Unlock()
	if osName == "" {
		if out, err := docker(ctx, nil, nil, "info", "-f", "{{.OperatingSystem}}"); err == nil {
			osName = strings.TrimSpace(out)
			a.topo.mu.Lock()
			a.topo.osName = osName
			a.topo.mu.Unlock()
		}
	}
	info.DockerOS = osName
	info.DockerDesktop = strings.Contains(osName, "Docker Desktop")
	switch {
	case d.LastPublicIP != "":
		info.PublicIP = d.LastPublicIP
	case ip != "" && time.Since(ipAt) < 10*time.Minute:
		info.PublicIP = ip
	default:
		pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
		if v, err := PublicIP(pctx); err == nil {
			info.PublicIP = v
			a.topo.mu.Lock()
			a.topo.ip, a.topo.ipAt = v, time.Now()
			a.topo.mu.Unlock()
		}
		pcancel()
	}
	writeJSON(w, 200, info)
}
