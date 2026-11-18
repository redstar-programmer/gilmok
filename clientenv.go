package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Whether Caddy can see the real client address depends on how Docker forwards the published
// port. clientIPEnv works out which case this server is in, so the UI explains the "unknown
// client" rows (and the country block's limits) for this server instead of listing every case:
//
//	desktop  Docker Desktop (Windows/macOS/Linux): a VM forwards connections → every client is
//	         the gateway; nothing to fix inside the server
//	rootless rootless Docker: the default port driver (RootlessKit builtin) hides the source
//	ingress  a Swarm service published through the routing mesh
//	bridge   Docker Engine, port published on a bridge network: IPv4 keeps the source (iptables
//	         DNAT); IPv6 does not when the network has no IPv6 (docker-proxy relays it) — IPv6 says
//	hostnet  Caddy on the host network: Docker does not touch the address
//	outside  Caddy is not a container (admin API / local binary)
//	none     Caddy not used;  unknown  could not tell (Docker not reachable, no container)
type ClientIPEnv struct {
	Kind      string   `json:"kind"`
	IPv6      bool     `json:"ipv6,omitempty"`     // bridge: a network Caddy is on has IPv6
	Networks  []string `json:"networks,omitempty"` // bridge: the networks Caddy is on
	Container string   `json:"container,omitempty"`
	DockerOS  string   `json:"dockerOS,omitempty"`
}

var (
	clientEnvMu  sync.Mutex
	clientEnvAt  time.Time
	clientEnvKey string
	clientEnvVal ClientIPEnv
)

func (a *App) clientIPEnv(ctx context.Context) ClientIPEnv {
	st := a.store.Snapshot().Settings
	if !st.UseCaddy {
		return ClientIPEnv{Kind: "none"}
	}
	mode := caddyMode(st)
	if mode != "docker" {
		return ClientIPEnv{Kind: "outside"}
	}
	key := mode + "|" + st.CaddyContainer
	clientEnvMu.Lock()
	if key == clientEnvKey && time.Since(clientEnvAt) < 2*time.Minute {
		v := clientEnvVal
		clientEnvMu.Unlock()
		return v
	}
	clientEnvMu.Unlock()

	v := detectClientIPEnv(ctx, st.CaddyContainer)
	clientEnvMu.Lock()
	clientEnvKey, clientEnvAt, clientEnvVal = key, time.Now(), v
	clientEnvMu.Unlock()
	return v
}

func detectClientIPEnv(ctx context.Context, ctr string) ClientIPEnv {
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	v := ClientIPEnv{Kind: "unknown", Container: ctr}
	out, err := docker(c, nil, nil, "info", "-f", "{{json .OperatingSystem}}|{{json .SecurityOptions}}")
	if err != nil {
		return v
	}
	osName, secOpts, _ := strings.Cut(strings.TrimSpace(out), "|")
	_ = json.Unmarshal([]byte(osName), &v.DockerOS)
	var opts []string
	_ = json.Unmarshal([]byte(secOpts), &opts)
	if strings.Contains(v.DockerOS, "Docker Desktop") {
		v.Kind = "desktop"
		return v
	}
	for _, o := range opts {
		if strings.Contains(o, "rootless") {
			v.Kind = "rootless"
			return v
		}
	}
	if ctr == "" {
		return v
	}
	out, err = docker(c, nil, nil, "inspect", "-f", `{{.HostConfig.NetworkMode}}|{{index .Config.Labels "com.docker.swarm.service.id"}}|{{json .NetworkSettings.Networks}}`, ctr)
	if err != nil {
		return v
	}
	parts := strings.SplitN(strings.TrimSpace(out), "|", 3)
	if len(parts) < 3 {
		return v
	}
	switch {
	case parts[0] == "host":
		v.Kind = "hostnet"
		return v
	case parts[1] != "":
		v.Kind = "ingress"
		return v
	}
	var nets map[string]any
	_ = json.Unmarshal([]byte(parts[2]), &nets)
	for n := range nets {
		v.Networks = append(v.Networks, n)
	}
	sort.Strings(v.Networks)
	v.Kind = "bridge"
	for _, n := range v.Networks {
		if o, err := docker(c, nil, nil, "network", "inspect", "-f", "{{.EnableIPv6}}", n); err == nil && strings.TrimSpace(o) == "true" {
			v.IPv6 = true
			break
		}
	}
	return v
}

// GET /api/client-env
func (a *App) getClientEnv(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.clientIPEnv(r.Context()))
}
