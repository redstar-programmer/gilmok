package main

// First-run setup (빠른 설정 / 설정 마법사). Shown after a fresh install or a factory reset until the
// user finishes it or says not to ask again (Data.SetupDone).
//
//   GET  /api/setup/detect      what Gilmok can find by itself — suggestions only, nothing is saved
//   POST /api/setup/done {done} finish (true) / ask again next time (false)
//
// Detection is generic: containers are matched by image name, files are searched in the folders
// mounted under /stacks (the deploy layout), the domain comes from the Caddyfile's site addresses.
// Nothing here assumes a particular installation.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type SetupDetect struct {
	Docker     bool                `json:"docker"` // docker CLI reachable
	DockerErr  string              `json:"dockerErr,omitempty"`
	Containers map[string][]string `json:"containers"` // caddy / authelia / crowdsec → names (running first)
	Files      map[string][]string `json:"files"`      // caddyfile / autheliaConfig / autheliaUsers → found paths
	Suggest    map[string]any      `json:"suggest"`    // Settings keys (json names) → suggested value
	Sites      int                 `json:"sites"`      // site blocks in the suggested Caddyfile
	CFToken    string              `json:"cfToken"`    // token source ("" = none)
	CSKey      bool                `json:"csKey"`      // a CrowdSec bouncer key is available
	CaddyToken bool                `json:"caddyToken"` // the suggested Caddy container has a Cloudflare token (value never sent)
	SelfName   string              `json:"selfName"`
}

// stacksRoot: where the deploy compose mounts the other stacks (overridable for tests).
var stacksRoot = "/stacks"

func (a *App) getSetupDetect(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.setupDetect(r.Context()))
}

func (a *App) setupDetect(parent context.Context) SetupDetect {
	d := a.store.Snapshot()
	st := d.Settings
	out := SetupDetect{Containers: map[string][]string{}, Files: map[string][]string{}, Suggest: map[string]any{}, SelfName: d.SelfName}
	_, out.CFToken = cfTokenSource()
	out.CSKey = csKey() != ""

	// ---- containers, by image
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	if raw, err := docker(ctx, nil, nil, "ps", "-a", "--format", "{{json .}}"); err == nil {
		out.Docker = true
		type ctr struct{ name, state string }
		found := map[string][]ctr{}
		for _, l := range strings.Split(raw, "\n") {
			var c struct{ Names, Image, State string }
			if json.Unmarshal([]byte(strings.TrimSpace(l)), &c) != nil || c.Names == "" || c.Names == d.SelfName {
				continue
			}
			img := strings.ToLower(c.Image)
			kind := ""
			switch {
			case strings.Contains(img, "authelia"):
				kind = "authelia"
			case strings.Contains(img, "crowdsec"):
				kind = "crowdsec"
			case strings.Contains(img, "caddy"):
				kind = "caddy"
			}
			if kind != "" {
				found[kind] = append(found[kind], ctr{c.Names, c.State})
			}
		}
		for k, list := range found {
			sort.SliceStable(list, func(i, j int) bool { return list[i].state == "running" && list[j].state != "running" })
			for _, c := range list {
				out.Containers[k] = append(out.Containers[k], c.name)
			}
		}
	} else {
		out.DockerErr = oneLine(raw)
	}

	// ---- files: the current setting first, then whatever is mounted under /stacks
	find := func(cur string, patterns ...string) []string {
		var res []string
		seen := map[string]bool{}
		add := func(p string) {
			if p == "" || seen[p] {
				return
			}
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				seen[p] = true
				res = append(res, p)
			}
		}
		add(cur)
		for _, pat := range patterns {
			m, _ := filepath.Glob(filepath.Join(stacksRoot, pat))
			sort.Strings(m)
			for _, p := range m {
				add(filepath.ToSlash(p))
			}
		}
		return res
	}
	out.Files["caddyfile"] = find(st.CaddyfilePath, "Caddyfile", "*/Caddyfile", "*/*/Caddyfile")
	out.Files["autheliaConfig"] = find(st.AutheliaConfig, "configuration.yml", "*/configuration.yml", "*/*/configuration.yml")
	out.Files["autheliaUsers"] = find(st.AutheliaUsers, "users_database.yml", "*/users_database.yml", "*/*/users_database.yml")

	// ---- suggestions
	sg := out.Suggest
	pick := func(key string, list []string) string {
		if len(list) > 0 {
			sg[key] = list[0]
			return list[0]
		}
		return ""
	}
	caddyCtr := pick("caddyContainer", out.Containers["caddy"])
	authCtr := pick("autheliaContainer", out.Containers["authelia"])
	csCtr := pick("crowdsecContainer", out.Containers["crowdsec"])
	if csCtr != "" {
		sg["crowdsecLapi"] = "http://" + csCtr + ":8080"
	}
	cf := pick("caddyfilePath", out.Files["caddyfile"])
	ac := pick("autheliaConfig", out.Files["autheliaConfig"])
	// the users file that sits next to the chosen configuration.yml
	if ac != "" {
		for _, u := range out.Files["autheliaUsers"] {
			if filepath.Dir(u) == filepath.Dir(ac) {
				sg["autheliaUsers"] = u
			}
		}
	}
	if _, ok := sg["autheliaUsers"]; !ok {
		pick("autheliaUsers", out.Files["autheliaUsers"])
	}

	caddyText := ""
	if cf != "" {
		if b, err := os.ReadFile(cf); err == nil {
			caddyText = string(b)
		}
	}
	if dom := inferDomain(caddyText); dom != "" {
		sg["domain"] = dom
	} else if st.Domain != "" {
		sg["domain"] = st.Domain
	}
	out.Sites = len(reSiteHost.FindAllString(strings.ToLower(caddyText), -1))
	lc := strings.ToLower(caddyText)
	sg["useCaddy"] = caddyCtr != "" || cf != ""
	sg["useAuthelia"] = authCtr != "" || ac != "" || strings.Contains(lc, "forward_auth")
	sg["useCrowdSec"] = csCtr != ""
	sg["useCloudflare"] = out.CFToken != "" || strings.Contains(lc, "dns cloudflare") || strings.Contains(lc, "cf_only") || strings.Contains(lc, "trusted_proxies cloudflare")
	sg["useTailscale"] = st.TailscaleIP != "" || strings.Contains(lc, ":"+itoa(st.TailscalePort))
	if st.TailscaleIP != "" {
		sg["tailscaleIp"] = st.TailscaleIP
	} else if m := reTailnetIP.FindString(caddyText); m != "" {
		sg["tailscaleIp"] = m // e.g. "bind 100.x.y.z" on the private listener
		sg["tailscaleSrc"] = "Caddyfile"
	} else if ts := a.detectTailscale(parent); ts.IP != "" {
		sg["tailscaleIp"], sg["tailscaleSrc"] = ts.IP, ts.Source
	}
	if out.CFToken == "" && caddyCtr != "" {
		out.CaddyToken = reCFToken.MatchString(caddyEnvToken(caddyCtr)) // a placeholder value is not offered
	}
	return out
}

// Tailscale addresses live in 100.64.0.0/10.
var reTailnetIP = regexp.MustCompile(`\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b`)

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (a *App) postSetupDone(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Done bool `json:"done"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := a.store.Update(func(d *Data) error { d.SetupDone = in.Done; return nil }); err != nil {
		fail(w, 500, err)
		return
	}
	if in.Done {
		a.auth.audit(r, "audit", "info", "초기 설정", "", "초기 설정 마침", nil)
	}
	writeJSON(w, 200, map[string]bool{"ok": true, "setupDone": in.Done})
}
