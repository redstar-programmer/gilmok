package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Installing a managed stack joins Gilmok to that stack's network with `docker network connect` at
// run time. That join is not in Gilmok's own compose file, so an update (`docker compose up -d`
// recreates the container) drops it: Gilmok can no longer reach the services (every service shows
// as not responding), CrowdSec's LAPI, … while the sites themselves keep working through Caddy.
// On start Gilmok joins again the user-defined networks of the stacks it manages.

// rejoinStackNetworks: joins Gilmok to the networks of its managed stacks it is missing; returns
// the networks joined. ok=false when Docker could not be asked (try again later).
func (a *App) rejoinStackNetworks(ctx context.Context) (joined []string, ok bool) {
	d := a.store.Snapshot()
	self := d.SelfName
	if self == "" || len(d.Stacks) == 0 {
		return nil, true // Gilmok on the host itself, or nothing installed
	}
	if _, err := docker(ctx, nil, nil, "version", "--format", "{{.Server.Version}}"); err != nil {
		return nil, false
	}
	have := map[string]bool{}
	for _, n := range ctrNetworks(ctx, self) {
		have[n] = true
	}
	want := map[string]bool{}
	for _, rec := range d.Stacks {
		if rec == nil {
			continue
		}
		nets := ctrNetworks(ctx, rec.Container)
		if len(nets) == 0 && rec.Network != "" {
			nets = []string{rec.Network} // container missing right now: the network it was installed on
		}
		for _, n := range nets {
			if n != "bridge" && n != "host" && n != "none" {
				want[n] = true
			}
		}
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if have[n] {
			continue
		}
		out, err := docker(ctx, nil, nil, "network", "connect", n, self)
		if err != nil && !strings.Contains(out, "already exists") {
			a.logEvent("system", "warn", "gilmok.network", n, fmt.Sprintf("길목을 네트워크 %s에 다시 연결하지 못했습니다: %s", n, oneLine(out)), nil)
			continue
		}
		joined = append(joined, n)
	}
	if len(joined) > 0 {
		a.logEvent("system", "info", "gilmok.network", strings.Join(joined, ", "), fmt.Sprintf("길목을 관리형 구성요소의 네트워크에 다시 연결했습니다: %s", strings.Join(joined, ", ")), nil)
		go a.probeHealthBg() // the services were "not responding" until now
	}
	return joined, true
}

// rejoinLoop: right after start (Docker may still be coming up), retried a few times.
func (a *App) rejoinLoop() {
	for i := 0; i < 6; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, ok := a.rejoinStackNetworks(ctx)
		cancel()
		if ok {
			return
		}
		time.Sleep(10 * time.Second)
	}
}
