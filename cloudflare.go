package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var cfAPI = "https://api.cloudflare.com/client/v4" // var: tests point it at httptest

type CF struct {
	mu     sync.Mutex
	zoneID string
	zone   string
	http   *http.Client
}

func NewCF() *CF { return &CF{http: &http.Client{Timeout: 20 * time.Second}} }

func (c *CF) Configured() bool { return cfToken() != "" }

type cfResp struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int
		Message string
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
	status int
}

func (c *CF) do(ctx context.Context, method, path string, body any) (*cfResp, error) {
	tok := cfToken()
	if tok == "" {
		return nil, errors.New("Cloudflare API 토큰이 없습니다 — Cloudflare 탭 › API 토큰에서 입력하세요")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfAPI+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	var r cfResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("Cloudflare 응답 해석 실패 (HTTP %d)", res.StatusCode)
	}
	r.status = res.StatusCode
	if !r.Success {
		var msgs []string
		for _, e := range r.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return &r, fmt.Errorf("Cloudflare 오류: %s", strings.Join(msgs, "; "))
	}
	return &r, nil
}

func (c *CF) ZoneID(ctx context.Context, domain string) (string, error) {
	c.mu.Lock()
	if c.zone == domain && c.zoneID != "" {
		id := c.zoneID
		c.mu.Unlock()
		return id, nil
	}
	c.mu.Unlock()
	r, err := c.do(ctx, "GET", "/zones?name="+domain, nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(r.Result, &zones)
	if len(zones) == 0 {
		return "", fmt.Errorf("Cloudflare에서 %s 존을 찾지 못했습니다", domain)
	}
	c.mu.Lock()
	c.zone, c.zoneID = domain, zones[0].ID
	c.mu.Unlock()
	return zones[0].ID, nil
}

type DNSRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Proxied  bool   `json:"proxied"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority,omitempty"`
	Comment  string `json:"comment"`
}

func (c *CF) Records(ctx context.Context, domain string) ([]DNSRecord, error) {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return nil, err
	}
	var all []DNSRecord
	for page := 1; page < 50; page++ {
		r, err := c.do(ctx, "GET", fmt.Sprintf("/zones/%s/dns_records?per_page=100&page=%d", zid, page), nil)
		if err != nil {
			return nil, err
		}
		var recs []DNSRecord
		_ = json.Unmarshal(r.Result, &recs)
		all = append(all, recs...)
		if r.ResultInfo.TotalPages <= page {
			break
		}
	}
	return all, nil
}

func (c *CF) Create(ctx context.Context, domain string, rec DNSRecord) error {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, "POST", "/zones/"+zid+"/dns_records", map[string]any{
		"type": rec.Type, "name": rec.Name, "content": rec.Content, "proxied": rec.Proxied, "ttl": 1,
		"comment": "managed by gilmok",
	})
	return err
}

func (c *CF) Patch(ctx context.Context, domain, id string, fields map[string]any) error {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, "PATCH", "/zones/"+zid+"/dns_records/"+id, fields)
	return err
}

func (c *CF) Delete(ctx context.Context, domain, id string) error {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, "DELETE", "/zones/"+zid+"/dns_records/"+id, nil)
	return err
}

// PublicIP returns this network's IPv4 WAN address.
// publicIPFn: swapped in tests (no outside calls).
var publicIPFn = publicIP

func PublicIP(ctx context.Context) (string, error) { return publicIPFn(ctx, false) }

// PublicIP6 returns a global IPv6 address this host is seen with (over an IPv6-only connection).
func PublicIP6(ctx context.Context) (string, error) { return publicIPFn(ctx, true) }

func publicIP(ctx context.Context, v6 bool) (string, error) {
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 6 * time.Second,
	}}
	valid := func(ip string) bool {
		p := net.ParseIP(ip)
		if p == nil {
			return false
		}
		if !v6 {
			return p.To4() != nil
		}
		// global unicast IPv6 only: not v4, not ULA (fc00::/7), not link-local
		return p.To4() == nil && p.IsGlobalUnicast() && !p.IsPrivate()
	}
	try := func(url string, parse func(string) string) string {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		res, err := cl.Do(req)
		if err != nil {
			return ""
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		if ip := parse(string(b)); valid(ip) {
			return ip
		}
		return ""
	}
	trace := func(s string) string {
		for _, l := range strings.Split(s, "\n") {
			if v, ok := strings.CutPrefix(l, "ip="); ok {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	urls := []string{"https://1.1.1.1/cdn-cgi/trace", "https://api.ipify.org"}
	if v6 {
		urls = []string{"https://[2606:4700:4700::1111]/cdn-cgi/trace", "https://api6.ipify.org"}
	}
	if ip := try(urls[0], trace); ip != "" {
		return ip, nil
	}
	if ip := try(urls[1], strings.TrimSpace); ip != "" {
		return ip, nil
	}
	if v6 {
		return "", errors.New("공인 IPv6 주소를 확인하지 못했습니다 — 이 컨테이너(또는 PC)에 IPv6 인터넷 연결이 없습니다")
	}
	return "", errors.New("공인 IP를 확인하지 못했습니다")
}

// ---------------------------------------------------------------- plan / reconcile

type DNSAction struct {
	Name       string `json:"name"`
	Type       string `json:"type"`   // A | AAAA
	Action     string `json:"action"` // create | update | delete | ok | skip
	Current    string `json:"current"`
	Desired    string `json:"desired"`
	Reason     string `json:"reason"`
	IPChange   bool   `json:"ipChange,omitempty"` // the address of an existing public record would change
	recordID   string
	curContent string
	content    string
	proxied    bool
}

type dnsWant struct {
	Type, Name, Content string
	Proxied             bool
	Public              bool   // content is this network's WAN address
	Reason              string // why Content is empty
}

// desiredDNS lists the records the services want. AAAA records exist only for public
// services and only when IPv6 is turned on; ip6 == "" means "could not detect" (skip, keep).
func desiredDNS(d Data, ip4, ip6 string) []dnsWant {
	var want []dnsWant
	for _, s := range d.Services {
		if !s.Enabled || !s.ManageDNS {
			continue
		}
		name := d.Settings.FQDN(s.Subdomain)
		if s.Exposure == ExposureTailscale {
			want = append(want, dnsWant{Type: "A", Name: name, Content: d.Settings.TailscaleIP, Reason: "IP를 알 수 없음 (설정에서 Tailscale IP 확인)"})
			continue
		}
		want = append(want, dnsWant{Type: "A", Name: name, Content: ip4, Proxied: s.Proxied, Public: true, Reason: "공인 IP를 확인하지 못함"})
		if d.Settings.DDNSIPv6 {
			want = append(want, dnsWant{Type: "AAAA", Name: name, Content: ip6, Proxied: s.Proxied, Public: true, Reason: "공인 IPv6 주소를 확인하지 못함 — 기존 AAAA는 그대로 둡니다"})
		}
	}
	return want
}

func managedNames(want []dnsWant, typ string) []string {
	var out []string
	for _, w := range want {
		if w.Type == typ {
			out = append(out, w.Name)
		}
	}
	return out
}

func describe(content string, proxied bool) string {
	if content == "" {
		return "-"
	}
	if proxied {
		return content + " (Proxied)"
	}
	return content + " (DNS only)"
}

// PlanDNS compares Cloudflare with the services. prev4/prev6 list names whose A/AAAA records
// this app created earlier, so records of removed services (or of IPv6 turned off) can be deleted safely.
func PlanDNS(d Data, recs []DNSRecord, ip4, ip6 string, prev4, prev6 []string) []DNSAction {
	want := desiredDNS(d, ip4, ip6)
	cur := map[string]DNSRecord{}
	for _, r := range recs {
		if r.Type == "A" || r.Type == "AAAA" {
			cur[r.Type+" "+r.Name] = r
		}
	}
	wanted := map[string]bool{}
	var acts []DNSAction
	for _, w := range want {
		key := w.Type + " " + w.Name
		wanted[key] = true
		a := DNSAction{Name: w.Name, Type: w.Type, Desired: describe(w.Content, w.Proxied), content: w.Content, proxied: w.Proxied}
		if w.Content == "" {
			a.Action, a.Reason = "skip", w.Reason
			if c, ok := cur[key]; ok {
				a.Current = describe(c.Content, c.Proxied)
			}
			acts = append(acts, a)
			continue
		}
		c, ok := cur[key]
		switch {
		case !ok:
			a.Action = "create"
		case c.Content != w.Content || c.Proxied != w.Proxied:
			a.Action, a.recordID, a.Current, a.curContent = "update", c.ID, describe(c.Content, c.Proxied), c.Content
			if w.Public && c.Content != w.Content && c.Content != "" {
				a.IPChange = true
				a.Reason = fmt.Sprintf("주소 변경 %s → %s", c.Content, w.Content)
			}
		default:
			a.Action, a.Current = "ok", describe(c.Content, c.Proxied)
		}
		acts = append(acts, a)
	}
	del := func(typ string, prev []string, reason string) {
		for _, name := range prev {
			key := typ + " " + name
			if wanted[key] {
				continue
			}
			if c, ok := cur[key]; ok {
				acts = append(acts, DNSAction{Name: name, Type: typ, Action: "delete", Current: describe(c.Content, c.Proxied), Desired: "-", recordID: c.ID, Reason: reason})
			}
		}
	}
	del("A", prev4, "서비스 삭제/비활성")
	r6 := "서비스 삭제/비활성"
	if !d.Settings.DDNSIPv6 {
		r6 = "IPv6(AAAA) 관리를 껐음"
	}
	del("AAAA", prev6, r6)
	sortDNS(acts)
	return acts
}

// holdIPChanges keeps the current address of public records (proxied changes still apply).
// Used when the caller did not confirm an address change: Gilmok may be running on another
// network than the web server (e.g. a test machine), and its WAN address would be wrong.
func holdIPChanges(acts []DNSAction) (out []DNSAction, held []string) {
	for _, a := range acts {
		if a.Action == "update" && a.IPChange {
			held = append(held, fmt.Sprintf("%s %s (%s)", a.Type, a.Name, a.Reason))
			a.content, a.IPChange = a.curContent, false
			if strings.HasSuffix(a.Current, "(Proxied)") == a.proxied {
				a.Action = "ok" // only the address differed
			}
		}
		out = append(out, a)
	}
	return out, held
}

func sortDNS(a []DNSAction) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && (a[j].Name < a[j-1].Name || a[j].Name == a[j-1].Name && a[j].Type < a[j-1].Type); j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (c *CF) Execute(ctx context.Context, domain string, acts []DNSAction, log func(string, ...any)) []string {
	var done []string
	for _, a := range acts {
		var err error
		switch a.Action {
		case "create":
			err = c.Create(ctx, domain, DNSRecord{Type: a.Type, Name: a.Name, Content: a.content, Proxied: a.proxied})
		case "update":
			err = c.Patch(ctx, domain, a.recordID, map[string]any{"content": a.content, "proxied": a.proxied})
		case "delete":
			err = c.Delete(ctx, domain, a.recordID)
		default:
			continue
		}
		if err != nil {
			log("  ✗ DNS %s %s %s: %v", a.Action, a.Type, a.Name, err)
			continue
		}
		log("  ✓ DNS %s %s %s → %s", a.Action, a.Type, a.Name, a.Desired)
		done = append(done, a.Type+" "+a.Name)
	}
	return done
}
