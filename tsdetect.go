package main

// Finding this server's Tailscale address (GET /api/tailscale/detect).
//
// Gilmok usually runs in a container, where the host's `tailscale` CLI is out of reach. So it
// tries, in order, what it can see — and lets the user pick when it cannot be sure:
//   0. GM_TAILSCALE_IP (install.ps1 reads `tailscale ip -4` on a Windows host and saves it)
//   1. a local tailscale CLI (Gilmok running on the host itself)            → this machine's IP
//   2. Tailscale containers on this Docker (`tailscale status --json`)       → the tailnet's devices;
//      a device whose host name matches this server is suggested, the rest are offered to pick
//   2b. Tailscale DNS (MagicDNS, 100.100.100.100): Docker Desktop routes the container's traffic
//      through the host, so a host with Tailscale installed directly (Windows, macOS) still answers
//      a lookup of this server's device name (?name=…, or the names we can guess)
//   3. Cloudflare DNS: 100.64/10 values already used by records in the zone (most common)
//   4. the Caddyfile: 100.64/10 addresses written in it (e.g. `bind`)
// Read-only; nothing is saved.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type TSDevice struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	OS     string `json:"os,omitempty"`
	Online bool   `json:"online"`
	Match  bool   `json:"match,omitempty"` // host name matches this server
	Via    string `json:"via"`             // container that listed it
}

type TSDetect struct {
	IP      string     `json:"ip"`      // best suggestion ("" = none)
	Source  string     `json:"source"`  // how it was found
	Devices []TSDevice `json:"devices"` // tailnet devices to pick from
	Tried   []string   `json:"tried"`   // what was tried (shown when nothing was found)
	// MagicDNS: the Tailscale DNS (100.100.100.100) answers from here, so a device name can be looked up
	MagicDNS bool   `json:"magicDns"`
	NameMiss string `json:"nameMiss,omitempty"` // the name asked for was not found
}

type tsStatus struct {
	Self *tsNode           `json:"Self"`
	Peer map[string]tsNode `json:"Peer"`
}
type tsNode struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	Online       bool     `json:"Online"`
	TailscaleIPs []string `json:"TailscaleIPs"`
}

func (n tsNode) ip4() string {
	for _, ip := range n.TailscaleIPs {
		if reTailnetIP.MatchString(ip) {
			return ip
		}
	}
	return ""
}

// tsLocalStatus: overridable for tests (runs the local tailscale CLI).
var tsLocalStatus = func(ctx context.Context) ([]byte, error) {
	bin := "tailscale"
	if _, err := exec.LookPath(bin); err != nil && runtime.GOOS == "windows" {
		bin = `C:\Program Files\Tailscale\tailscale.exe` // the installer does not always add it to PATH
	}
	return exec.CommandContext(ctx, bin, "status", "--json").Output()
}

// tsMagicLookup asks the Tailscale DNS (MagicDNS) for a device name. reachable=false when it does not answer.
var tsMagicLookup = func(ctx context.Context, name string) (ips []string, reachable bool) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "udp", "100.100.100.100:53")
	}}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, name)
	if err != nil {
		var de *net.DNSError
		return nil, errors.As(err, &de) && de.IsNotFound // NXDOMAIN = it answered
	}
	return addrs, true
}

// reTSName: a tailnet device name (or its MagicDNS FQDN)
var reTSName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9-]{1,63}){0,4}$`)

func (a *App) getTailscaleDetect(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.detectTailscaleNamed(r.Context(), r.URL.Query().Get("name")))
}

func (a *App) detectTailscale(parent context.Context) TSDetect {
	return a.detectTailscaleNamed(parent, "")
}

func (a *App) detectTailscaleNamed(parent context.Context, askName string) TSDetect {
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	d := a.store.Snapshot()
	st := d.Settings
	out := TSDetect{Devices: []TSDevice{}}
	suggest := func(ip, src string) {
		if out.IP == "" && ip != "" {
			out.IP, out.Source = ip, src
		}
	}

	// names this server may have in the tailnet
	names := map[string]bool{}
	addName := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			names[s] = true
			names[strings.SplitN(s, ".", 2)[0]] = true
		}
	}
	addName(st.TopoHostName)
	if h, err := os.Hostname(); err == nil && d.SelfName == "" {
		addName(h) // only meaningful when Gilmok runs on the host itself
	}
	if info, err := docker(ctx, nil, nil, "info", "-f", "{{.Name}}"); err == nil {
		addName(info)
	}

	askName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(askName), "."))
	if askName != "" && !reTSName.MatchString(askName) {
		askName = ""
	}

	// 0. what the installer found on the host (install.ps1 → GM_TAILSCALE_IP)
	if v := strings.TrimSpace(os.Getenv("GM_TAILSCALE_IP")); v != "" && reTailnetIP.FindString(v) == v && askName == "" {
		out.Tried = append(out.Tried, "배포 설정 GM_TAILSCALE_IP")
		suggest(v, "배포 설정 (GM_TAILSCALE_IP)")
	}

	// a name the user typed: ask MagicDNS first, it is the most direct answer
	if askName != "" {
		out.Tried = append(out.Tried, "Tailscale DNS: "+askName)
		ips, ok := tsMagicLookup(ctx, askName)
		out.MagicDNS = out.MagicDNS || ok
		found := ""
		for _, ip := range ips {
			if reTailnetIP.FindString(ip) == ip {
				found = ip
				break
			}
		}
		if found != "" {
			suggest(found, "Tailscale DNS ("+askName+")")
		} else {
			out.NameMiss = askName
		}
	}

	// 1. local CLI
	out.Tried = append(out.Tried, "이 컴퓨터의 tailscale 명령")
	if b, err := tsLocalStatus(ctx); err == nil {
		var s tsStatus
		if json.Unmarshal(b, &s) == nil && s.Self != nil {
			suggest(s.Self.ip4(), "이 컴퓨터의 Tailscale")
		}
	}

	// 2. Tailscale containers
	if raw, err := docker(ctx, nil, nil, "ps", "--format", "{{json .}}"); err == nil {
		for _, l := range strings.Split(raw, "\n") {
			var c struct{ Names, Image, State string }
			if json.Unmarshal([]byte(strings.TrimSpace(l)), &c) != nil || !strings.Contains(strings.ToLower(c.Image), "tailscale") {
				continue
			}
			out.Tried = append(out.Tried, "Tailscale 컨테이너 "+c.Names)
			b, err := ctrExec(c.Names, nil, "tailscale", "status", "--json")
			if err != nil {
				continue
			}
			var s tsStatus
			if json.Unmarshal([]byte(b), &s) != nil {
				continue
			}
			nodes := []tsNode{}
			if s.Self != nil {
				nodes = append(nodes, *s.Self)
			}
			for _, p := range s.Peer {
				nodes = append(nodes, p)
			}
			for _, n := range nodes {
				ip := n.ip4()
				if ip == "" {
					continue
				}
				dev := TSDevice{Name: n.HostName, IP: ip, OS: n.OS, Online: n.Online || (s.Self != nil && n.HostName == s.Self.HostName), Via: c.Names}
				dns := strings.ToLower(strings.TrimSuffix(n.DNSName, "."))
				dev.Match = names[strings.ToLower(n.HostName)] || (dns != "" && names[strings.SplitN(dns, ".", 2)[0]])
				out.Devices = append(out.Devices, dev)
			}
		}
	}
	sort.SliceStable(out.Devices, func(i, j int) bool {
		x, y := out.Devices[i], out.Devices[j]
		if x.Match != y.Match {
			return x.Match
		}
		if x.Online != y.Online {
			return x.Online
		}
		return strings.ToLower(x.Name) < strings.ToLower(y.Name)
	})
	for _, dv := range out.Devices {
		if dv.Match {
			suggest(dv.IP, "Tailscale 기기 목록 ("+dv.Name+")")
			break
		}
	}

	// 2b. MagicDNS with the names we can guess (a host with Tailscale installed directly)
	if askName == "" || out.IP == "" {
		guessed := []string{}
		for n := range names {
			if n != "docker-desktop" && !strings.Contains(n, ".") && reTSName.MatchString(n) {
				guessed = append(guessed, n)
			}
		}
		sort.Strings(guessed)
		if len(guessed) > 6 {
			guessed = guessed[:6]
		}
		probe := len(guessed) == 0
		out.Tried = append(out.Tried, "Tailscale DNS (100.100.100.100)")
		for _, n := range guessed {
			ips, ok := tsMagicLookup(ctx, n)
			out.MagicDNS = out.MagicDNS || ok
			if !ok {
				break // not reachable: do not wait on every name
			}
			for _, ip := range ips {
				if reTailnetIP.FindString(ip) == ip {
					suggest(ip, "Tailscale DNS ("+n+")")
					break
				}
			}
		}
		if probe && !out.MagicDNS {
			_, out.MagicDNS = tsMagicLookup(ctx, "gilmok-probe.invalid")
		}
	}

	// 3. Cloudflare DNS: the 100.x value records already use
	if st.Domain != "" && a.cf.Configured() {
		out.Tried = append(out.Tried, "Cloudflare DNS 레코드")
		if recs, err := a.cf.Records(ctx, st.Domain); err == nil {
			count := map[string]int{}
			for _, rc := range recs {
				if rc.Type == "A" && reTailnetIP.MatchString(rc.Content) && reTailnetIP.FindString(rc.Content) == rc.Content {
					count[rc.Content]++
				}
			}
			best, bn := "", 0
			for ip, n := range count {
				if n > bn || n == bn && ip < best {
					best, bn = ip, n
				}
			}
			if best != "" {
				suggest(best, "Cloudflare DNS (레코드 "+itoa(bn)+"개가 이 주소)")
			}
		}
	}

	// 4. the Caddyfile
	out.Tried = append(out.Tried, "Caddyfile")
	if b, err := os.ReadFile(st.CaddyfilePath); err == nil {
		suggest(reTailnetIP.FindString(string(b)), "Caddyfile")
	}
	return out
}
