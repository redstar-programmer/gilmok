package main

import "os"

// Components: which parts of the edge this installation actually uses. Inferred once for data
// files written before the flags existed (and on a fresh install), then owned by the user
// (설정 탭 › 구성요소).
func (a *App) inferComponents() {
	d := a.store.Snapshot()
	if d.Settings.UseInit {
		if !d.Settings.UseTSInit { // added later: infer Tailscale once for existing installs
			useTS := d.Settings.TailscaleIP != ""
			for _, s := range d.Services {
				if s.Exposure == ExposureTailscale {
					useTS = true
				}
			}
			_ = a.store.Update(func(x *Data) error { x.Settings.UseTailscale, x.Settings.UseTSInit = useTS, true; return nil })
		}
		return
	}
	st := d.Settings
	exists := func(p string) bool { _, err := os.Stat(p); return p != "" && err == nil }
	useCaddy := exists(st.CaddyfilePath) || ctrStatus(st.CaddyContainer).Exists || len(d.Services) > 0
	useAuth := exists(st.AutheliaConfig) || ctrStatus(st.AutheliaCtr).Exists
	// Cloudflare is "in use" when Gilmok manages its DNS (token) or when sites rely on it
	// (orange cloud / mTLS cf_only) — even if DNS is managed by hand.
	useCF := cfToken() != ""
	for _, s := range d.Services {
		if s.Enabled && s.Exposure == ExposurePublic && (s.Proxied || s.MTLS) {
			useCF = true
		}
	}
	if !useAuth {
		for _, s := range d.Services {
			if s.Enabled && s.Authelia.Enabled {
				useAuth = true // never silently drop a login gate
			}
		}
	}
	useCS := csKey() != "" || st.CrowdSecEnabled
	useTS := st.TailscaleIP != ""
	for _, s := range d.Services {
		if s.Exposure == ExposureTailscale {
			useTS = true
		}
	}
	_ = a.store.Update(func(x *Data) error {
		x.Settings.UseInit, x.Settings.UseTSInit = true, true
		x.Settings.UseCaddy, x.Settings.UseAuthelia, x.Settings.UseCloudflare, x.Settings.UseCrowdSec, x.Settings.UseTailscale = useCaddy, useAuth, useCF, useCS, useTS
		return nil
	})
	a.logEvent("system", "info", "components.infer", "", "사용 중인 구성요소를 자동으로 판단했습니다 (설정 탭 › 구성요소에서 바꿀 수 있음)",
		map[string]bool{"caddy": useCaddy, "authelia": useAuth, "cloudflare": useCF, "crowdsec": useCS, "tailscale": useTS})
}
