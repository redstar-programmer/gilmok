package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DNS records view + direct editing.
//
//   - GET /api/dns: every record of the zone, each with its relation to Gilmok's services
//     (same / differs → what 「적용」 will do / will be deleted / missing). Uses the last known
//     public IP (no live lookup), so it is fast and never guesses a wrong address.
//   - POST/PUT/DELETE /api/dns/records: records that no service owns (CNAME, TXT, MX, an A record
//     of another machine…). Records a service manages can only be changed through the service.

type dnsRow struct {
	DNSRecord
	Service   string `json:"service"`             // subdomain of the service with this name
	ServiceID string `json:"serviceId,omitempty"` //
	SvcManage bool   `json:"svcManage"`           // that service has 「DNS 자동 관리」 on
	Managed   bool   `json:"managed"`             // Gilmok created/owns it (deleted with the service)
	Status    string `json:"status"`              // ok | diff | missing | orphan | unknown | "" (not related)
	Desired   string `json:"desired,omitempty"`   // what 「적용」 will make of it
	Reason    string `json:"reason,omitempty"`
	Editable  bool   `json:"editable"`           // may be edited here
	IPChange  bool   `json:"ipChange,omitempty"` // only the WAN address differs (held back unless confirmed)
	Missing   bool   `json:"missing,omitempty"`
}

var dnsEditTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "TXT": true, "MX": true}

func (a *App) dnsRows(ctx context.Context, d Data) ([]dnsRow, error) {
	recs, err := a.cf.Records(ctx, d.Settings.Domain)
	if err != nil {
		return nil, err
	}
	svcBy := map[string]*Service{}
	for _, s := range d.Services {
		svcBy[d.Settings.FQDN(s.Subdomain)] = s
	}
	managed := map[string]bool{}
	for _, n := range d.ManagedDNS {
		managed["A "+n] = true
	}
	for _, n := range d.ManagedDNS6 {
		managed["AAAA "+n] = true
	}
	acts := map[string]DNSAction{}
	if d.Settings.UseCloudflare {
		for _, x := range PlanDNS(d, recs, d.LastPublicIP, d.LastPublicIP6, d.ManagedDNS, d.ManagedDNS6) {
			acts[x.Type+" "+x.Name] = x
		}
	}
	var out []dnsRow
	seen := map[string]bool{}
	for _, rec := range recs {
		key := rec.Type + " " + rec.Name
		seen[key] = true
		row := dnsRow{DNSRecord: rec, Managed: managed[key]}
		if s := svcBy[rec.Name]; s != nil {
			row.Service, row.ServiceID, row.SvcManage = s.Subdomain, s.ID, s.ManageDNS && s.Enabled
		}
		if x, ok := acts[key]; ok {
			switch x.Action {
			case "ok":
				row.Status = "ok"
			case "update":
				row.Status, row.Desired, row.Reason, row.IPChange = "diff", x.Desired, x.Reason, x.IPChange
				if x.IPChange {
					row.Reason = "레코드 주소와 길목이 본 공인 IP가 다름 — 적용할 때 「공인 IP 변경 반영」을 체크해야만 바뀝니다"
				}
			case "delete":
				row.Status, row.Desired, row.Reason = "orphan", "-", "적용하면 삭제 ("+x.Reason+")"
			case "skip":
				row.Status, row.Reason = "unknown", x.Reason
			}
		}
		row.Editable = dnsEditTypes[rec.Type] && editableRecord(d, rec)
		out = append(out, row)
	}
	for key, x := range acts {
		if x.Action == "create" && !seen[key] {
			row := dnsRow{DNSRecord: DNSRecord{Type: x.Type, Name: x.Name}, Status: "missing", Desired: x.Desired, Reason: "적용하면 만듭니다", Missing: true}
			if s := svcBy[x.Name]; s != nil {
				row.Service, row.ServiceID, row.SvcManage = s.Subdomain, s.ID, true
			}
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

// editableRecord: not owned by Gilmok and not the A/AAAA record of a DNS-managed service.
func editableRecord(d Data, rec DNSRecord) bool {
	if rec.Type == "A" || rec.Type == "AAAA" {
		for _, n := range append(append([]string{}, d.ManagedDNS...), d.ManagedDNS6...) {
			if n == rec.Name {
				return false
			}
		}
		for _, s := range d.Services {
			if s.Enabled && s.ManageDNS && d.Settings.FQDN(s.Subdomain) == rec.Name {
				return false
			}
		}
	}
	return true
}

func (a *App) getDNS(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rows, err := a.dnsRows(ctx, d)
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, rows)
}

// ---------------------------------------------------------------- direct editing

type dnsEdit struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Proxied  bool   `json:"proxied"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
	Comment  string `json:"comment"`
}

var reHostname = regexp.MustCompile(`^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.?$`)

func normalizeDNSEdit(d Data, in *dnsEdit) error {
	dom := strings.ToLower(d.Settings.Domain)
	in.Type = strings.ToUpper(strings.TrimSpace(in.Type))
	if !dnsEditTypes[in.Type] {
		return errors.New("유형은 A, AAAA, CNAME, TXT, MX 중 하나여야 합니다")
	}
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Name)), ".")
	switch {
	case n == "" || n == "@":
		n = dom
	case n == dom || strings.HasSuffix(n, "."+dom):
	default:
		n += "." + dom
	}
	if !reHostname.MatchString(n) {
		return fmt.Errorf("이름 %q 이 올바르지 않습니다 (영문 소문자·숫자·- 만, 예: www 또는 mail)", n)
	}
	in.Name = n
	in.Content = strings.TrimSpace(in.Content)
	switch in.Type {
	case "A":
		if ip := net.ParseIP(in.Content); ip == nil || ip.To4() == nil {
			return errors.New("A 레코드 내용은 IPv4 주소여야 합니다 (예: 203.0.113.10)")
		}
	case "AAAA":
		if ip := net.ParseIP(in.Content); ip == nil || ip.To4() != nil {
			return errors.New("AAAA 레코드 내용은 IPv6 주소여야 합니다")
		}
	case "CNAME", "MX":
		in.Content = strings.TrimSuffix(strings.ToLower(in.Content), ".")
		if !reHostname.MatchString(in.Content) || !strings.Contains(in.Content, ".") {
			return fmt.Errorf("%s 내용은 도메인 이름이어야 합니다 (예: target.example.com)", in.Type)
		}
		if in.Type == "CNAME" && in.Content == in.Name {
			return errors.New("CNAME이 자기 자신을 가리킬 수 없습니다")
		}
	case "TXT":
		if in.Content == "" || len(in.Content) > 2048 || strings.ContainsAny(in.Content, "\r\n") {
			return errors.New("TXT 내용은 한 줄, 2048자 이하여야 합니다")
		}
	}
	if in.Type == "MX" {
		if in.Priority < 0 || in.Priority > 65535 {
			return errors.New("MX 우선순위는 0~65535 입니다")
		}
	} else {
		in.Priority = 0
	}
	if in.Type != "A" && in.Type != "AAAA" && in.Type != "CNAME" {
		in.Proxied = false
	}
	if in.TTL != 1 && (in.TTL < 60 || in.TTL > 86400) {
		in.TTL = 1
	}
	if in.Proxied {
		in.TTL = 1 // Cloudflare: proxied records are always automatic
	}
	in.Comment = strings.TrimSpace(in.Comment)
	if len(in.Comment) > 100 {
		return errors.New("메모는 100자 이하여야 합니다")
	}
	// never collide with what a service manages
	if in.Type == "A" || in.Type == "AAAA" || in.Type == "CNAME" {
		for _, s := range d.Services {
			if s.Enabled && s.ManageDNS && d.Settings.FQDN(s.Subdomain) == in.Name {
				return fmt.Errorf("%s 은 서비스 「%s」가 관리하는 이름입니다 — 서비스 탭에서 바꾸세요", in.Name, s.Subdomain)
			}
		}
	}
	return nil
}

func dnsBody(in dnsEdit) map[string]any {
	b := map[string]any{"type": in.Type, "name": in.Name, "content": in.Content, "ttl": in.TTL, "comment": in.Comment}
	if in.Type == "A" || in.Type == "AAAA" || in.Type == "CNAME" {
		b["proxied"] = in.Proxied
	}
	if in.Type == "MX" {
		b["priority"] = in.Priority
	}
	return b
}

func (a *App) findRecord(ctx context.Context, d Data, id string) (*DNSRecord, error) {
	recs, err := a.cf.Records(ctx, d.Settings.Domain)
	if err != nil {
		return nil, err
	}
	for i := range recs {
		if recs[i].ID == id {
			if !dnsEditTypes[recs[i].Type] || !editableRecord(d, recs[i]) {
				return nil, errors.New("서비스가 관리하는 레코드라 여기서 바꿀 수 없습니다 — 서비스 탭에서 바꾸고 「적용」하세요")
			}
			return &recs[i], nil
		}
	}
	return nil, errors.New("레코드를 찾을 수 없습니다 (이미 지워졌을 수 있습니다)")
}

func (a *App) postDNSRecord(w http.ResponseWriter, r *http.Request) {
	var in dnsEdit
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	d := a.store.Snapshot()
	if err := normalizeDNSEdit(d, &in); err != nil {
		fail(w, 400, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	zid, err := a.cf.ZoneID(ctx, d.Settings.Domain)
	if err != nil {
		fail(w, 502, err)
		return
	}
	if _, err := a.cf.do(ctx, "POST", "/zones/"+zid+"/dns_records", dnsBody(in)); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "name": in.Name})
}

func (a *App) putDNSRecord(w http.ResponseWriter, r *http.Request) {
	var in dnsEdit
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	d := a.store.Snapshot()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cur, err := a.findRecord(ctx, d, r.PathValue("id"))
	if err != nil {
		fail(w, 400, err)
		return
	}
	if err := normalizeDNSEdit(d, &in); err != nil {
		fail(w, 400, err)
		return
	}
	zid, err := a.cf.ZoneID(ctx, d.Settings.Domain)
	if err != nil {
		fail(w, 502, err)
		return
	}
	if _, err := a.cf.do(ctx, "PUT", "/zones/"+zid+"/dns_records/"+cur.ID, dnsBody(in)); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "name": in.Name})
}

func (a *App) deleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cur, err := a.findRecord(ctx, d, r.PathValue("id"))
	if err != nil {
		fail(w, 400, err)
		return
	}
	if err := a.cf.Delete(ctx, d.Settings.Domain, cur.ID); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "name": cur.Name, "type": cur.Type})
}
