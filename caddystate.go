package main

import (
	"context"
	"net"
	"net/url"
	"sync"
	"time"
)

// Service health is probed from Gilmok straight to each upstream, so it says nothing about Caddy:
// with Caddy stopped every site is unreachable while the upstreams still answer. caddyRunState
// tells whether the Caddy serving the sites is up, for the service list, the map and the dashboard.

type CaddyRun struct {
	Known bool   `json:"known"`           // false: not told (Caddy not used, native mode)
	Down  bool   `json:"down"`            // known and not running
	State string `json:"state,omitempty"` // docker: running | exited | restarting | … | "" = no container; api: up | unreachable
	Name  string `json:"name,omitempty"`  // container name or admin address
}

var (
	caddyRunMu  sync.Mutex
	caddyRunAt  time.Time
	caddyRunKey string
	caddyRunVal CaddyRun
)

// caddyRunState: cached for 10 s (the list, the map and the dashboard ask at the same time).
func (a *App) caddyRunState(ctx context.Context) CaddyRun {
	st := a.store.Snapshot().Settings
	if !st.UseCaddy {
		return CaddyRun{}
	}
	mode := caddyMode(st)
	key := mode + "|" + st.CaddyContainer + "|" + st.CaddyAdmin
	caddyRunMu.Lock()
	if key == caddyRunKey && time.Since(caddyRunAt) < 10*time.Second {
		v := caddyRunVal
		caddyRunMu.Unlock()
		return v
	}
	caddyRunMu.Unlock()
	var v CaddyRun
	switch mode {
	case "docker":
		if st.CaddyContainer == "" {
			return CaddyRun{}
		}
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if _, err := docker(c, nil, nil, "version", "--format", "{{.Server.Version}}"); err != nil {
			return CaddyRun{} // Docker itself is not reachable: cannot tell, do not claim Caddy is down
		}
		s, _ := ctrStateOf(c, st.CaddyContainer)
		v = CaddyRun{Known: true, Down: s != "running", State: s, Name: st.CaddyContainer}
	case "api":
		u, err := url.Parse(st.CaddyAdmin)
		if err != nil || u.Host == "" {
			return CaddyRun{}
		}
		host := u.Host
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), map[bool]string{true: "443", false: "80"}[u.Scheme == "https"])
		}
		c, err := net.DialTimeout("tcp", host, 2*time.Second)
		if c != nil {
			c.Close()
		}
		v = CaddyRun{Known: true, Down: err != nil, State: map[bool]string{true: "unreachable", false: "up"}[err != nil], Name: st.CaddyAdmin}
	default:
		return CaddyRun{}
	}
	caddyRunMu.Lock()
	caddyRunAt, caddyRunKey, caddyRunVal = time.Now(), key, v
	caddyRunMu.Unlock()
	return v
}
