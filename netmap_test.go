package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// MAP-01: what a saved map may contain — ids, kinds, link ends, zones, checks.
func TestNetMapNormalize(t *testing.T) {
	ok := func() NetMap {
		return NetMap{
			Nodes:  []MapNode{{ID: "n_sw", Kind: "switch", Name: "  코어 스위치 ", IP: "192.168.1.2"}, {ID: "n_nas", Kind: "spaceship", Name: "NAS", Check: "tcp", Target: "192.168.1.5:5000"}},
			Links:  []MapLink{{ID: "l_1", From: "n_sw", To: "auto:host", Kind: "eth"}, {ID: "l_2", From: "n_nas", To: "n_sw", Kind: "laser"}},
			Zones:  []MapZone{{ID: "z_lan", Name: "LAN", Kind: "lan", CIDR: "192.168.1.0/24", Color: "#ABCDEF"}},
			Member: map[string]string{"n_sw": "z_lan", "auto:svc:x": "z_lan", "n_gone": "z_lan", "n_nas": "z_none"},
			Pos:    map[string][2]float64{"n_sw": {10, 20}, "auto:caddy": {1, 2}, "n_gone": {1, 1}, "n_nas": {99999, 0}},
			Hidden: []string{"auto:crowdsec", "auto:crowdsec", "not-auto"},
		}
	}
	m := ok()
	if err := normalizeNetMap(&m); err != nil {
		t.Fatal(err)
	}
	if m.Nodes[0].Name != "코어 스위치" || m.Nodes[1].Kind != "other" || m.Links[1].Kind != "eth" || m.Zones[0].Color != "#abcdef" {
		t.Errorf("MAP-01 cleanup: %+v %+v %+v", m.Nodes, m.Links, m.Zones)
	}
	if len(m.Member) != 2 || m.Member["auto:svc:x"] != "z_lan" || len(m.Pos) != 2 || len(m.Hidden) != 1 {
		t.Errorf("MAP-01 member/pos/hidden: %v %v %v", m.Member, m.Pos, m.Hidden)
	}
	bad := map[string]func(m *NetMap){
		"dup id":        func(m *NetMap) { m.Nodes[1].ID = "n_sw" },
		"bad id":        func(m *NetMap) { m.Nodes[0].ID = "<x>" },
		"no name":       func(m *NetMap) { m.Nodes[0].Name = " " },
		"link to ghost": func(m *NetMap) { m.Links[0].To = "n_ghost" },
		"self link":     func(m *NetMap) { m.Links[0].To = "n_sw" },
		"ping metadata": func(m *NetMap) { m.Nodes[0].Check, m.Nodes[0].Target = "ping", "169.254.169.254" },
		"tcp no port":   func(m *NetMap) { m.Nodes[1].Target = "192.168.1.5" },
		"http scheme":   func(m *NetMap) { m.Nodes[1].Check, m.Nodes[1].Target = "http", "file:///etc/passwd" },
		"http metadata": func(m *NetMap) { m.Nodes[1].Check, m.Nodes[1].Target = "http", "http://169.254.169.254/latest" },
		"bad check":     func(m *NetMap) { m.Nodes[1].Check = "exec" },
		"ping url":      func(m *NetMap) { m.Nodes[0].Check, m.Nodes[0].Target = "ping", "http://x" },
	}
	for name, mod := range bad {
		m := ok()
		mod(&m)
		if err := normalizeNetMap(&m); err == nil {
			t.Errorf("MAP-01 %s accepted", name)
		}
	}
	many := ok()
	for i := 0; i < mapMaxNodes; i++ {
		many.Nodes = append(many.Nodes, MapNode{ID: "n_x" + strings.Repeat("a", i%30) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)), Kind: "pc", Name: "pc"})
	}
	if err := normalizeNetMap(&many); err == nil {
		t.Error("MAP-01 more than the node cap accepted")
	}
	// ping defaults to the device's IP
	p := NetMap{Nodes: []MapNode{{ID: "n_r", Kind: "router", Name: "R", IP: "10.0.0.1", Check: "ping"}}}
	if err := normalizeNetMap(&p); err != nil || p.Nodes[0].Target != "10.0.0.1" {
		t.Errorf("MAP-01 ping target default: %v %q", err, p.Nodes[0].Target)
	}
}

// MAP-02: the API — viewers read, config writers save (display only: no pending apply), audit,
// status checks run on save and on demand.
func TestNetMapAPI(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	viewer := f.user(t, boss, "viewer3", "viewer")
	prev := probeMapFn
	probeMapFn = func(ctx context.Context, n MapNode) MapStatus { return MapStatus{OK: n.ID == "n_up", Ms: 1.5} }
	t.Cleanup(func() { probeMapFn = prev })

	r := viewer.must(200, "GET", "/api/netmap", "")
	if len(r["map"].(map[string]any)["nodes"].([]any)) != 0 {
		t.Errorf("MAP-02 empty map: %v", r)
	}
	body := `{"nodes":[{"id":"n_up","kind":"nas","name":"NAS","check":"tcp","target":"10.0.0.5:445"},{"id":"n_dn","kind":"pc","name":"PC","check":"http","target":"http://10.0.0.9/"}],
	  "links":[{"id":"l_a","from":"n_up","to":"auto:host","kind":"eth"}],"zones":[{"id":"z_a","name":"LAN","kind":"lan"}],"member":{"n_up":"z_a"},"pos":{"n_up":[100,200]}}`
	if code, _ := viewer.do("PUT", "/api/netmap", body); code != 403 {
		t.Errorf("MAP-02 viewer saved the map: %d", code)
	}
	pend := len(f.app.store.Snapshot().Pending)
	slow := make(chan struct{})
	probeMapFn = func(ctx context.Context, n MapNode) MapStatus { <-slow; return MapStatus{OK: n.ID == "n_up", Ms: 1.5} }
	boss.must(200, "PUT", "/api/netmap", body) // starts a round in the background (held by slow)
	go func() { time.Sleep(150 * time.Millisecond); close(slow) }()
	if len(f.app.store.Snapshot().Pending) != pend {
		t.Error("MAP-02 saving the map marked pending apply")
	}
	st := boss.must(200, "POST", "/api/netmap/check", "")["status"].(map[string]any)
	if st["n_up"].(map[string]any)["ok"] != true || st["n_dn"].(map[string]any)["ok"] != false {
		t.Errorf("MAP-02 status: %v", st)
	}
	got := viewer.must(200, "GET", "/api/netmap", "")["map"].(map[string]any)
	if len(got["nodes"].([]any)) != 2 || got["pos"].(map[string]any)["n_up"] == nil {
		t.Errorf("MAP-02 saved map: %v", got)
	}
	found := false
	for _, e := range f.events(t, "audit") {
		if strings.Contains(e.Action+e.Msg, "네트워크 맵") {
			found = true
		}
	}
	if !found {
		t.Error("MAP-02 no audit entry")
	}
	if code, _ := boss.do("PUT", "/api/netmap", `{"nodes":[{"id":"n_x","kind":"pc","name":"x","check":"http","target":"http://169.254.169.254/"}]}`); code != 400 {
		t.Errorf("MAP-02 metadata probe accepted: %d", code)
	}
	// backup / restore carries the map
	exp := boss.raw("GET", "/api/config/export", "")
	var cfg ConfigFile
	if err := json.Unmarshal(exp.Body.Bytes(), &cfg); err != nil || cfg.NetMap == nil || len(cfg.NetMap.Nodes) != 2 {
		t.Errorf("MAP-02 export: %v %+v", err, cfg.NetMap)
	}
}

// MAP-03: the real probes — TCP to a listener, HTTP (5xx = down), a closed port.
func TestNetMapProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()
	ctx := context.Background()
	for _, c := range []struct {
		n    MapNode
		want bool
	}{
		{MapNode{Check: "tcp", Target: ln.Addr().String()}, true},
		{MapNode{Check: "tcp", Target: closedAddr}, false},
		{MapNode{Check: "http", Target: ok.URL}, true}, // a login page (401) still answers
		{MapNode{Check: "http", Target: bad.URL}, false},
	} {
		if st := probeMapNodeReal(ctx, c.n); st.OK != c.want {
			t.Errorf("MAP-03 %s %s: %+v", c.n.Check, c.n.Target, st)
		}
	}
	if !pingSupported() {
		if st := probeMapNodeReal(ctx, MapNode{Check: "ping", Target: "127.0.0.1"}); st.OK || st.Err == "" {
			t.Errorf("MAP-03 ping without support: %+v", st)
		}
	}
}
