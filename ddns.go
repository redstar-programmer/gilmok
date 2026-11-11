package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DDNS: keeps the A (and, when turned on, AAAA) records of public services pointing at this
// network's current WAN address.
//
//   - Only the *content* of existing records is changed. Creating/deleting records and the
//     proxied flag belong to 「적용」 (so unapplied service edits are never pushed by DDNS).
//   - The last known address is recorded only when every record is in sync; after a failure
//     the next run retries even if the address did not change again.
//   - Once an hour the records are compared even without an address change (manual edits, drift).
//   - Address changes, failures and recovery go to the system event log.

type DDNSStatus struct {
	Checked time.Time `json:"checked"`          // last run
	Synced  time.Time `json:"synced"`           // last time records were compared with Cloudflare
	Changed time.Time `json:"changed"`          // last time a record was updated
	IP4     string    `json:"ip4"`              //
	IP6     string    `json:"ip6"`              //
	IP4Err  string    `json:"ip4Err,omitempty"` //
	IP6Err  string    `json:"ip6Err,omitempty"` //
	Result  string    `json:"result"`           // ok | updated | fail | off
	Msg     string    `json:"msg"`              //
	Updated []string  `json:"updated,omitempty"`
	Failed  []string  `json:"failed,omitempty"`
}

const ddnsDriftCheck = time.Hour

var ddnsMu sync.Mutex // one run at a time (loop + 「지금 확인」)

func (a *App) ddnsLoop() {
	time.Sleep(20 * time.Second) // let the app settle
	for {
		d := a.store.Snapshot()
		iv := time.Duration(d.Settings.DDNSIntervalMin) * time.Minute
		if iv < time.Minute {
			iv = 5 * time.Minute
		}
		if ddnsActive(d.Settings) && a.cf.Configured() {
			a.ddnsOnce(false)
		}
		time.Sleep(iv)
	}
}

func ddnsActive(st Settings) bool { return st.UseCloudflare && st.DDNSEnabled }

// ddnsTargets: records DDNS may touch = public, enabled, DNS-managed services.
func ddnsTargets(d Data) map[string]bool {
	t := map[string]bool{}
	for _, s := range d.Services {
		if s.Enabled && s.ManageDNS && s.Exposure == ExposurePublic { // DNS-only services too (desiredDNS gives them the WAN address)
			t[d.Settings.FQDN(s.Subdomain)] = true
		}
	}
	return t
}

type ddnsCF interface {
	Records(ctx context.Context, domain string) ([]DNSRecord, error)
	Patch(ctx context.Context, domain, id string, fields map[string]any) error
}

type ddnsAddrs struct {
	ip4, ip6   string
	err4, err6 error
}

// ddnsReconcile patches the records whose address differs; pure enough to test with a fake CF.
func ddnsReconcile(ctx context.Context, cf ddnsCF, d Data, ad ddnsAddrs) (updated, failed []string, err error) {
	recs, err := cf.Records(ctx, d.Settings.Domain)
	if err != nil {
		return nil, nil, err
	}
	targets := ddnsTargets(d)
	for _, r := range recs {
		if !targets[r.Name] {
			continue
		}
		var want string
		switch {
		case r.Type == "A" && ad.ip4 != "":
			want = ad.ip4
		case r.Type == "AAAA" && d.Settings.DDNSIPv6 && ad.ip6 != "":
			want = ad.ip6
		default:
			continue
		}
		if r.Content == want {
			continue
		}
		label := fmt.Sprintf("%s %s", r.Type, r.Name)
		if e := cf.Patch(ctx, d.Settings.Domain, r.ID, map[string]any{"content": want}); e != nil {
			failed = append(failed, label+": "+e.Error())
			continue
		}
		updated = append(updated, label+" → "+want)
	}
	return updated, failed, nil
}

func (a *App) ddnsOnce(force bool) DDNSStatus {
	ddnsMu.Lock()
	defer ddnsMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	d := a.store.Snapshot()
	st := d.Settings
	prev := d.DDNS
	now := time.Now()
	s := DDNSStatus{Checked: now, Synced: prev.Synced, Changed: prev.Changed}

	var ad ddnsAddrs
	ad.ip4, ad.err4 = PublicIP(ctx)
	if st.DDNSIPv6 {
		ad.ip6, ad.err6 = PublicIP6(ctx)
	}
	s.IP4, s.IP6 = ad.ip4, ad.ip6
	if ad.err4 != nil {
		s.IP4Err = ad.err4.Error()
	}
	if ad.err6 != nil {
		s.IP6Err = ad.err6.Error()
	}

	changed4 := ad.ip4 != "" && ad.ip4 != d.LastPublicIP
	changed6 := ad.ip6 != "" && ad.ip6 != d.LastPublicIP6
	retry := prev.Result == "fail"
	drift := now.Sub(prev.Synced) >= ddnsDriftCheck

	switch {
	case ad.ip4 == "" && ad.ip6 == "":
		s.Result, s.Msg = "fail", "공인 IP를 확인하지 못해 이번에는 건너뜁니다"
	case !force && !changed4 && !changed6 && !retry && !drift:
		s.Result, s.Msg = "ok", "주소 변화 없음"
	default:
		updated, failed, err := ddnsReconcile(ctx, a.cf, d, ad)
		s.Updated, s.Failed = updated, failed
		switch {
		case err != nil:
			s.Result, s.Msg = "fail", "Cloudflare 레코드를 읽지 못했습니다: "+err.Error()
		case len(failed) > 0:
			s.Result, s.Msg = "fail", fmt.Sprintf("%d개 수정 실패 — 다음 확인 때 다시 시도합니다", len(failed))
		case len(updated) > 0:
			s.Result, s.Msg, s.Changed, s.Synced = "updated", fmt.Sprintf("%d개 레코드를 새 주소로 바꿨습니다", len(updated)), now, now
		default:
			s.Result, s.Msg, s.Synced = "ok", "모든 레코드가 현재 주소와 같습니다", now
		}
		if len(updated) > 0 && len(failed) > 0 {
			s.Changed = now
		}
		if ad.err4 != nil && s.Result != "fail" {
			s.Msg += " (IPv4 확인 실패 — A 레코드는 건너뜀)"
		}
		if st.DDNSIPv6 && ad.err6 != nil {
			s.Msg += " (IPv6 확인 실패 — AAAA 레코드는 건너뜀)"
		}
	}

	ok := s.Result == "ok" || s.Result == "updated"
	_ = a.store.Update(func(x *Data) error {
		x.DDNS = s
		if ok { // remember the address only when Cloudflare matches it (otherwise retry next time)
			if ad.ip4 != "" {
				x.LastPublicIP = ad.ip4
			}
			if ad.ip6 != "" {
				x.LastPublicIP6 = ad.ip6
			}
		}
		return nil
	})
	a.ddnsEvents(prev, s, d, changed4, changed6)
	return s
}

func (a *App) ddnsEvents(prev, s DDNSStatus, d Data, changed4, changed6 bool) {
	if a.ldb == nil {
		return
	}
	var addr []string
	if changed4 && d.LastPublicIP != "" {
		addr = append(addr, fmt.Sprintf("IPv4 %s → %s", d.LastPublicIP, s.IP4))
	}
	if changed6 && d.LastPublicIP6 != "" {
		addr = append(addr, fmt.Sprintf("IPv6 %s → %s", d.LastPublicIP6, s.IP6))
	}
	detail := func() string { return mustJSON(map[string]any{"updated": s.Updated, "failed": s.Failed}) }
	switch {
	case s.Result == "updated":
		msg := "DDNS Updater: " + s.Msg
		if len(addr) > 0 {
			msg = "DDNS Updater: 공인 IP 변경 (" + strings.Join(addr, ", ") + ") — " + s.Msg
		}
		a.ldb.Event(Event{Cat: "system", Level: "warn", Action: "ddns.update", Target: d.Settings.Domain, Msg: msg, Detail: detail()})
	case s.Result == "fail" && (prev.Result != "fail" || prev.Msg != s.Msg):
		a.ldb.Event(Event{Cat: "system", Level: "error", Action: "ddns.fail", Target: d.Settings.Domain, Msg: "DDNS Updater: " + s.Msg, Detail: detail()})
	case s.Result == "ok" && prev.Result == "fail":
		a.ldb.Event(Event{Cat: "system", Level: "info", Action: "ddns.recover", Target: d.Settings.Domain, Msg: "DDNS Updater 정상화 — " + s.Msg})
	}
	if d.Settings.DDNSIPv6 && s.IP6Err != "" && prev.IP6Err == "" {
		a.ldb.Event(Event{Cat: "system", Level: "warn", Action: "ddns.ipv6", Target: d.Settings.Domain, Msg: s.IP6Err})
	}
}

func (a *App) postDDNSRun(w http.ResponseWriter, r *http.Request) {
	st := a.store.Snapshot().Settings
	switch {
	case !st.UseCloudflare:
		fail(w, 400, errors.New("Cloudflare를 쓰지 않습니다"))
		return
	case !st.DDNSEnabled:
		fail(w, 400, errors.New("DDNS Updater가 꺼져 있습니다 — 먼저 「DDNS Updater 사용」을 켜고 저장하세요"))
		return
	case !a.cf.Configured():
		fail(w, 400, errors.New("Cloudflare API 토큰이 없습니다"))
		return
	}
	writeJSON(w, 200, a.ddnsOnce(true))
}
