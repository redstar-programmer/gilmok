package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// DASH-12: dashboard variables — sites / status classes / countries / client paths filter every
// request-based panel, from memory (live) and from the log database (a past window); the request
// drill-down and the variable choices follow.
func TestDashFilters(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	now := time.Now().UnixMilli()
	recs := []ReqRec{}
	for i := 0; i < 40; i++ {
		r := ReqRec{T: now - int64(i*2000), Host: "a.example.com", Status: 200, Ms: 10, IP: "203.0.113.1", CC: "KR", Via: "cf", Method: "GET", URI: "/"}
		switch i % 4 {
		case 1:
			r.Host, r.CC, r.Via = "b.example.com", "US", "direct"
		case 2:
			r.Status, r.Ms = 503, 900
		case 3:
			r.Host, r.Status, r.CC = "b.example.com", 404, "JP"
		}
		recs = append(recs, r)
	}
	for _, r := range recs {
		f.app.mon.addReq(r)
		f.app.ldb.Req(r)
	}
	waitFlush(t, f.app.ldb, int64(len(recs)))
	ws := []Widget{
		{ID: "n", Type: "stat", Metric: "requests"}, {ID: "p", Type: "stat", Metric: "p95Ms"},
		{ID: "s", Type: "series", Metric: "status"}, {ID: "c", Type: "scatter"},
		{ID: "t", Type: "top", Dim: "host", Limit: 5}, {ID: "m", Type: "map"}, {ID: "h", Type: "health"},
	}
	ask := func(tag string, extra map[string]any) map[string]any {
		t.Helper()
		body := map[string]any{"widgets": ws}
		for k, v := range extra {
			body[k] = v
		}
		b, _ := json.Marshal(body)
		return boss.must(200, "POST", "/api/dash/data", string(b))["data"].(map[string]any)
	}
	num := func(d map[string]any, id string) float64 { return d[id].(map[string]any)["value"].(float64) }

	// no filter: everything (memory, per-site buckets)
	d := ask("all", map[string]any{"range": "5m"})
	if num(d, "n") != 40 {
		t.Fatalf("DASH-12 all: %v", d["n"])
	}
	// one site only → the cheap path, same numbers as a filter would give
	d = ask("host", map[string]any{"range": "5m", "filters": map[string]any{"hosts": []string{"b.example.com"}}})
	if num(d, "n") != 20 {
		t.Errorf("DASH-12 one site: %v", d["n"])
	}
	// classes + country: computed from the requests themselves
	d = ask("5xx", map[string]any{"range": "5m", "filters": map[string]any{"classes": []int{5}}})
	if num(d, "n") != 10 || num(d, "p") < 800 || d["n"].(map[string]any)["filtered"] != true {
		t.Errorf("DASH-12 5xx: n=%v p95=%v", d["n"], d["p"])
	}
	if pts := d["c"].(map[string]any)["points"].([]any); len(pts) != 10 {
		t.Errorf("DASH-12 scatter filtered: %d points", len(pts))
	}
	if _, ok := d["h"].(map[string]any)["filtered"]; ok {
		t.Error("DASH-12: service health is not request-based — no filter")
	}
	d = ask("cc", map[string]any{"range": "5m", "filters": map[string]any{"countries": []string{"us", "JP"}, "vias": []string{"direct"}}})
	if num(d, "n") != 10 { // US+direct = the 10 b.example.com 200s; JP rows are cf
		t.Errorf("DASH-12 country+via: %v", d["n"])
	}
	rows := d["t"].(map[string]any)["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["key"] != "b.example.com" {
		t.Errorf("DASH-12 top filtered: %v", rows)
	}
	if cs := d["m"].(map[string]any)["countries"].([]any); len(cs) != 1 || cs[0].(map[string]any)["cc"] != "US" {
		t.Errorf("DASH-12 map filtered: %v", cs)
	}
	// a past window → the log database, same filter
	d = ask("db", map[string]any{"from": now - 10*60_000, "to": now + 1000, "filters": map[string]any{"classes": []int{4, 5}}})
	if num(d, "n") != 20 || d["n"].(map[string]any)["history"] != true {
		t.Errorf("DASH-12 db 4xx+5xx: %v", d["n"])
	}
	// the request drill-down honours the variables
	q := fmt.Sprintf("/api/dash/requests?from=%d&to=%d&hosts=b.example.com&cc=JP", now-10*60_000, now+1000)
	if r := boss.must(200, "GET", q, ""); r["total"].(float64) != 10 {
		t.Errorf("DASH-12 drill-down: %v", r["total"])
	}
	// choices
	v := boss.must(200, "GET", "/api/dash/vars", "")
	if len(v["hosts"].([]any)) < 2 || len(v["countries"].([]any)) != 3 {
		t.Errorf("DASH-12 vars: %v", v)
	}
}

// DASH-13: the 24-column layout — placement kept and clamped; an older 4-column widget stays in
// its own shape (the UI converts it); the default layout is on the grid.
func TestDashGridLayout(t *testing.T) {
	w := Widget{Type: "series", Metric: "status", G: 24, X: 30, Y: -3, W: 40, H: 1}
	if err := normalizeWidget(&w); err != nil {
		t.Fatal(err)
	}
	if w.W != 24 || w.X != 0 || w.Y != 0 || w.H != 2 {
		t.Errorf("DASH-13 clamp: %+v", w)
	}
	w = Widget{Type: "series", Metric: "status", G: 24, X: 18, Y: 5, W: 8, H: 9}
	_ = normalizeWidget(&w)
	if w.X != 16 || w.W != 8 || w.Y != 5 {
		t.Errorf("DASH-13 keeps inside 24 columns: %+v", w)
	}
	old := Widget{Type: "stat", Metric: "rpm", W: 2, H: 1, X: 5}
	_ = normalizeWidget(&old)
	if old.G != 0 || old.X != 0 || old.W != 2 {
		t.Errorf("DASH-13 old layout: %+v", old)
	}
	// display styles: kept when the type offers them, cleared otherwise
	for _, c := range []struct{ typ, view, want string }{
		{"health", "donut", "donut"}, {"health", "bar", "bar"}, {"health", "gauge", ""},
		{"containers", "gauge", "gauge"}, {"containers", "bar", "bar"}, {"containers", "pie", ""},
		{"events", "bar", ""},
	} {
		v := Widget{Type: c.typ, View: c.view, G: 24, W: 6, H: 6}
		_ = normalizeWidget(&v)
		if v.View != c.want {
			t.Errorf("DASH-13 view %s/%s: got %q", c.typ, c.view, v.View)
		}
	}
	// display options: only known keys / values survive
	o := Widget{Type: "health", G: 24, W: 8, H: 8, Opts: map[string]string{
		"size": "s", "group": "each", "c.up": "#00AA00", "c.down": "red", "c.cpu": "#123456", "x": "1",
	}}
	_ = normalizeWidget(&o)
	if len(o.Opts) != 3 || o.Opts["size"] != "s" || o.Opts["group"] != "each" || o.Opts["c.up"] != "#00aa00" {
		t.Errorf("DASH-13 opts health: %v", o.Opts)
	}
	o = Widget{Type: "containers", G: 24, W: 8, H: 8, Opts: map[string]string{"group": "each", "c.cpu": "#123456", "size": "xl"}}
	_ = normalizeWidget(&o)
	if len(o.Opts) != 1 || o.Opts["c.cpu"] != "#123456" {
		t.Errorf("DASH-13 opts containers: %v", o.Opts)
	}
	o = Widget{Type: "events", G: 24, W: 8, H: 8, Opts: map[string]string{"size": "s"}}
	_ = normalizeWidget(&o)
	if o.Opts != nil {
		t.Errorf("DASH-13 opts events: %v", o.Opts)
	}
	for _, d := range defaultDashboard() {
		if d.G != 24 || d.X+d.W > 24 {
			t.Errorf("DASH-13 default not on the grid: %+v", d)
		}
	}
}
