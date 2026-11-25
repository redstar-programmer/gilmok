package main

// Network map (서비스 탭 › 네트워크): a free-form diagram of the whole network — the parts Gilmok
// knows (internet, Cloudflare, front devices, this host, Caddy, services …, drawn by the UI with ids
// "auto:…") plus devices the user adds (switches, access points, NAS, PCs, VMs …), links between any
// of them, zones (LAN / DMZ / VLAN / subnet) and saved positions. Display only: nothing here changes
// Caddy, DNS or Authelia, so saving never marks "pending apply".
//
// Devices may carry a status check (ping / TCP / HTTP) that Gilmok runs while someone looks at the
// map (netmapLoop) — the result is up / down / latency, never response content.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type MapNode struct {
	ID     string `json:"id"`   // n_<random>
	Kind   string `json:"kind"` // see mapNodeKinds
	Name   string `json:"name"`
	IP     string `json:"ip,omitempty"`
	Note   string `json:"note,omitempty"`
	Check  string `json:"check,omitempty"`  // "" | ping | tcp | http
	Target string `json:"target,omitempty"` // ping: host · tcp: host:port · http: URL
}

type MapLink struct {
	ID    string `json:"id"`
	From  string `json:"from"` // a device id or an "auto:…" id
	To    string `json:"to"`
	Kind  string `json:"kind"` // eth | fiber | wifi | vpn | virtual
	Label string `json:"label,omitempty"`
}

type MapZone struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"` // lan | dmz | vlan | subnet | wifi | cloud | other
	CIDR  string `json:"cidr,omitempty"`
	Color string `json:"color,omitempty"` // #rrggbb ("" = by kind)
	Note  string `json:"note,omitempty"`
}

type NetMap struct {
	Nodes  []MapNode             `json:"nodes"`
	Links  []MapLink             `json:"links"`
	Zones  []MapZone             `json:"zones"`
	Member map[string]string     `json:"member,omitempty"` // node id (device or auto) → zone id
	Pos    map[string][2]float64 `json:"pos,omitempty"`    // node id → saved x, y (no entry = automatic layout)
	Hidden []string              `json:"hidden,omitempty"` // auto nodes the user took off the map
}

var mapNodeKinds = map[string]bool{
	"router": true, "firewall": true, "switch": true, "ap": true, "modem": true, "server": true, "nas": true,
	"pc": true, "laptop": true, "phone": true, "tablet": true, "tv": true, "vm": true, "container": true,
	"iot": true, "camera": true, "printer": true, "ups": true, "cloud": true, "internet": true, "other": true,
}
var mapLinkKinds = map[string]bool{"eth": true, "fiber": true, "wifi": true, "vpn": true, "virtual": true}
var mapZoneKinds = map[string]bool{"lan": true, "dmz": true, "vlan": true, "subnet": true, "wifi": true, "cloud": true, "other": true}

var (
	reMapID   = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,40}$`)
	reAutoID  = regexp.MustCompile(`^auto:[a-zA-Z0-9:_.@-]{1,120}$`)
	reMapHost = regexp.MustCompile(`^[a-zA-Z0-9.:_\[\]-]{1,253}$`)
)

const (
	mapMaxNodes = 300
	mapMaxLinks = 800
	mapMaxZones = 40
)

// normalizeNetMap checks and cleans a map from the UI (or a restored settings file).
func normalizeNetMap(m *NetMap) error {
	if m == nil {
		return nil
	}
	if len(m.Nodes) > mapMaxNodes || len(m.Links) > mapMaxLinks || len(m.Zones) > mapMaxZones {
		return fmt.Errorf("네트워크 맵은 장비 %d · 연결 %d · 영역 %d개까지입니다", mapMaxNodes, mapMaxLinks, mapMaxZones)
	}
	text := func(s string, n int) string {
		s = strings.TrimSpace(strings.Map(func(r rune) rune {
			if r < 0x20 && r != '\n' {
				return -1
			}
			return r
		}, s))
		if utf8.RuneCountInString(s) > n {
			s = string([]rune(s)[:n])
		}
		return s
	}
	ids := map[string]bool{}
	for i := range m.Nodes {
		n := &m.Nodes[i]
		if !reMapID.MatchString(n.ID) || ids[n.ID] {
			return fmt.Errorf("장비 id가 잘못됐거나 겹칩니다: %q", n.ID)
		}
		ids[n.ID] = true
		if !mapNodeKinds[n.Kind] {
			n.Kind = "other"
		}
		n.Name, n.IP, n.Note = text(n.Name, 60), text(n.IP, 64), text(n.Note, 300)
		if n.Name == "" {
			return errors.New("장비 이름을 적으세요")
		}
		if err := checkMapTarget(n); err != nil {
			return fmt.Errorf("%s: %w", n.Name, err)
		}
	}
	known := func(id string) bool { return ids[id] || reAutoID.MatchString(id) }
	lids := map[string]bool{}
	for i := range m.Links {
		l := &m.Links[i]
		if !reMapID.MatchString(l.ID) || lids[l.ID] {
			return fmt.Errorf("연결 id가 잘못됐거나 겹칩니다: %q", l.ID)
		}
		lids[l.ID] = true
		if !known(l.From) || !known(l.To) || l.From == l.To {
			return errors.New("연결의 양 끝이 잘못됐습니다")
		}
		if !mapLinkKinds[l.Kind] {
			l.Kind = "eth"
		}
		l.Label = text(l.Label, 40)
	}
	zids := map[string]bool{}
	for i := range m.Zones {
		z := &m.Zones[i]
		if !reMapID.MatchString(z.ID) || zids[z.ID] {
			return fmt.Errorf("영역 id가 잘못됐거나 겹칩니다: %q", z.ID)
		}
		zids[z.ID] = true
		if !mapZoneKinds[z.Kind] {
			z.Kind = "other"
		}
		z.Name, z.CIDR, z.Note = text(z.Name, 40), text(z.CIDR, 64), text(z.Note, 200)
		if z.Name == "" {
			return errors.New("영역 이름을 적으세요")
		}
		if z.Color != "" && !reHexColor.MatchString(z.Color) {
			z.Color = ""
		}
		z.Color = strings.ToLower(z.Color)
	}
	for id, z := range m.Member {
		if !known(id) || !zids[z] {
			delete(m.Member, id)
		}
	}
	if len(m.Pos) > mapMaxNodes+200 {
		return errors.New("위치 정보가 너무 많습니다")
	}
	for id, p := range m.Pos {
		if !known(id) || p[0] < -20000 || p[0] > 20000 || p[1] < -20000 || p[1] > 20000 {
			delete(m.Pos, id)
		}
	}
	hid := m.Hidden[:0]
	seen := map[string]bool{}
	for _, id := range m.Hidden {
		if reAutoID.MatchString(id) && !seen[id] && len(hid) < 300 {
			seen[id] = true
			hid = append(hid, id)
		}
	}
	m.Hidden = hid
	return nil
}

// checkMapTarget: the status check of a device — what may be probed, and how.
func checkMapTarget(n *MapNode) error {
	n.Target = strings.TrimSpace(n.Target)
	switch n.Check {
	case "":
		n.Target = ""
		return nil
	case "ping":
		if n.Target == "" {
			n.Target = n.IP
		}
		if !reMapHost.MatchString(n.Target) || strings.Contains(n.Target, "://") {
			return errors.New("ping 대상은 IP 주소나 호스트 이름입니다")
		}
		if blockedHost(strings.Trim(n.Target, "[]")) {
			return errors.New("링크 로컬·메타데이터 주소는 점검할 수 없습니다")
		}
	case "tcp":
		if n.Target == "" && n.IP != "" {
			return errors.New("TCP 점검은 주소:포트로 적으세요 (예: 192.168.1.2:22)")
		}
		host, port, err := net.SplitHostPort(n.Target)
		p, perr := strconv.Atoi(port)
		if err != nil || perr != nil || p < 1 || p > 65535 || !reMapHost.MatchString(host) {
			return errors.New("TCP 점검은 주소:포트로 적으세요 (예: 192.168.1.2:22)")
		}
		if blockedHost(host) {
			return errors.New("링크 로컬·메타데이터 주소는 점검할 수 없습니다")
		}
	case "http":
		if err := checkServiceURL("HTTP 점검 주소", n.Target); err != nil || n.Target == "" {
			return errors.New("HTTP 점검은 http(s):// 주소로 적으세요")
		}
	default:
		return errors.New("점검 방식은 ping · TCP · HTTP 중 하나입니다")
	}
	return nil
}

// ---------------------------------------------------------------- status checks

type MapStatus struct {
	OK      bool    `json:"ok"`
	Ms      float64 `json:"ms"`
	Err     string  `json:"err,omitempty"`
	Checked int64   `json:"checked"`
}

type mapChecker struct {
	mu     sync.Mutex
	status map[string]MapStatus
	viewed time.Time
	run    sync.Mutex // one round of checks at a time; a caller waits for the round in progress
}

func (a *App) mapTouch() {
	a.mapc.mu.Lock()
	a.mapc.viewed = time.Now()
	a.mapc.mu.Unlock()
}

func (a *App) mapStatus() map[string]MapStatus {
	a.mapc.mu.Lock()
	defer a.mapc.mu.Unlock()
	out := make(map[string]MapStatus, len(a.mapc.status))
	for k, v := range a.mapc.status {
		out[k] = v
	}
	return out
}

// netmapLoop: every 30 s, while someone looked at the map in the last 10 minutes, check the devices.
func (a *App) netmapLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		a.mapc.mu.Lock()
		on := time.Since(a.mapc.viewed) < 10*time.Minute
		a.mapc.mu.Unlock()
		if on {
			a.checkMapDevices(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) checkMapDevices(ctx context.Context) {
	// "check now" right after a save must not skip because the save's own round is still running
	a.mapc.run.Lock()
	defer a.mapc.run.Unlock()

	var nodes []MapNode
	a.store.Read(func(d *Data) {
		if d.NetMap != nil {
			for _, n := range d.NetMap.Nodes {
				if n.Check != "" {
					nodes = append(nodes, n)
				}
			}
		}
	})
	res := map[string]MapStatus{}
	var mu sync.Mutex
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(n MapNode) {
			defer wg.Done()
			defer func() { <-sem }()
			st := probeMapNode(ctx, n)
			mu.Lock()
			res[n.ID] = st
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	a.mapc.mu.Lock()
	a.mapc.status = res
	a.mapc.mu.Unlock()
}

var mapHTTP = &http.Client{
	Timeout: 4 * time.Second,
	// self-signed device pages (routers, NAS) are normal on a LAN; only reachability is checked
	Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}, //nolint:gosec
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// probeMapFn: swappable in tests
var probeMapFn = probeMapNodeReal

func probeMapNode(ctx context.Context, n MapNode) MapStatus { return probeMapFn(ctx, n) }

func probeMapNodeReal(ctx context.Context, n MapNode) MapStatus {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	start := time.Now()
	var err error
	switch n.Check {
	case "ping":
		err = pingHost(ctx, strings.Trim(n.Target, "[]"))
	case "tcp":
		var c net.Conn
		c, err = (&net.Dialer{}).DialContext(ctx, "tcp", n.Target)
		if err == nil {
			c.Close()
		}
	case "http":
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, n.Target, nil)
		if err == nil {
			var resp *http.Response
			if resp, err = mapHTTP.Do(req); err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 500 {
					err = fmt.Errorf("HTTP %d", resp.StatusCode)
				}
			}
		}
	}
	st := MapStatus{OK: err == nil, Ms: float64(time.Since(start).Microseconds()) / 1000, Checked: time.Now().UnixMilli()}
	if err != nil {
		st.Err = truncate(shortNetErr(err), 120)
	}
	return st
}

func shortNetErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "deadline exceeded"), strings.Contains(s, "i/o timeout"):
		return "시간 초과"
	case strings.Contains(s, "connection refused"):
		return "연결 거부"
	case strings.Contains(s, "no such host"):
		return "이름을 찾을 수 없음"
	case strings.Contains(s, "network is unreachable"), strings.Contains(s, "no route"):
		return "경로 없음"
	}
	return s
}

// ---------------------------------------------------------------- API

func (a *App) getNetMap(w http.ResponseWriter, r *http.Request) {
	a.mapTouch()
	var m NetMap
	a.store.Read(func(d *Data) {
		if d.NetMap != nil {
			m = *d.NetMap
		}
	})
	if m.Nodes == nil {
		m.Nodes = []MapNode{}
	}
	if m.Links == nil {
		m.Links = []MapLink{}
	}
	if m.Zones == nil {
		m.Zones = []MapZone{}
	}
	writeJSON(w, 200, map[string]any{"map": m, "status": a.mapStatus(), "ping": pingSupported()})
}

func (a *App) getNetMapStatus(w http.ResponseWriter, r *http.Request) {
	a.mapTouch()
	writeJSON(w, 200, map[string]any{"status": a.mapStatus()})
}

func (a *App) putNetMap(w http.ResponseWriter, r *http.Request) {
	var m NetMap
	if err := readJSON(r, &m); err != nil {
		fail(w, 400, err)
		return
	}
	if err := normalizeNetMap(&m); err != nil {
		fail(w, 400, err)
		return
	}
	if err := a.store.Update(func(d *Data) error { d.NetMap = &m; return nil }); err != nil {
		fail(w, 500, err)
		return
	}
	go a.checkMapDevices(context.Background())
	writeJSON(w, 200, map[string]any{"map": m})
}

// POST /api/netmap/check: check now (after adding a device)
func (a *App) postNetMapCheck(w http.ResponseWriter, r *http.Request) {
	a.mapTouch()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	a.checkMapDevices(ctx)
	writeJSON(w, 200, map[string]any{"status": a.mapStatus()})
}
