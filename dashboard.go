package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dashboard: user-defined widgets (add / edit / delete / reorder), stored in Data.Dashboard.

type Widget struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`  // stat | series | scatter | top | health | containers | certs | events
	Title      string   `json:"title"` //
	W          int      `json:"w"`     // grid columns 1..4
	H          int      `json:"h"`     // grid rows 1..3
	Metric     string   `json:"metric,omitempty"`
	Range      string   `json:"range,omitempty"` // 5m 15m 1h 6h 24h
	Host       string   `json:"host,omitempty"`  // "" = all sites
	Dim        string   `json:"dim,omitempty"`   // top: host | path | status | client | slow
	Limit      int      `json:"limit,omitempty"`
	Containers []string `json:"containers,omitempty"`
	Warn       float64  `json:"warn,omitempty"` // stat: threshold for the warning state (0 = none)
}

var (
	widgetTypes   = map[string]bool{"stat": true, "series": true, "scatter": true, "top": true, "health": true, "containers": true, "certs": true, "events": true}
	statMetrics   = map[string]bool{"rpm": true, "requests": true, "err5xx": true, "err4xx": true, "avgMs": true, "p95Ms": true, "bytes": true, "waf": true, "csBans": true, "healthUp": true, "certDays": true}
	seriesMetrics = map[string]bool{"requests": true, "status": true, "latency": true, "bytes": true, "waf": true}
	topDims       = map[string]bool{"host": true, "path": true, "status": true, "client": true, "slow": true}
	ranges        = map[string]time.Duration{"5m": 5 * time.Minute, "15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}
)

func defaultDashboard() []Widget {
	return []Widget{
		{Type: "stat", Title: "분당 요청", Metric: "rpm", Range: "15m", W: 1, H: 1},
		{Type: "stat", Title: "5xx 오류율", Metric: "err5xx", Range: "1h", W: 1, H: 1, Warn: 1},
		{Type: "stat", Title: "응답시간 p95", Metric: "p95Ms", Range: "15m", W: 1, H: 1, Warn: 1000},
		{Type: "stat", Title: "WAF 차단", Metric: "waf", Range: "24h", W: 1, H: 1},
		{Type: "scatter", Title: "응답시간 분포", Range: "15m", W: 2, H: 2},
		{Type: "series", Title: "요청 추이 (상태코드별)", Metric: "status", Range: "1h", W: 2, H: 2},
		{Type: "health", Title: "서비스 상태", W: 2, H: 2},
		{Type: "top", Title: "많이 쓰는 사이트", Dim: "host", Range: "1h", Limit: 8, W: 1, H: 2},
		{Type: "containers", Title: "컨테이너 리소스", W: 1, H: 2},
		{Type: "series", Title: "응답시간 추이", Metric: "latency", Range: "1h", W: 2, H: 2},
		{Type: "certs", Title: "인증서 만료", W: 1, H: 2},
		{Type: "events", Title: "최근 이벤트", W: 1, H: 2},
	}
}

func normalizeWidget(w *Widget) error {
	if !widgetTypes[w.Type] {
		return fmt.Errorf("알 수 없는 위젯 종류: %s", w.Type)
	}
	if w.ID == "" {
		w.ID = newID()
	}
	w.Title = strings.TrimSpace(w.Title)
	if len([]rune(w.Title)) > 40 {
		w.Title = string([]rune(w.Title)[:40])
	}
	w.W = min(max(w.W, 1), 4)
	w.H = min(max(w.H, 1), 3)
	if _, ok := ranges[w.Range]; !ok {
		w.Range = "1h"
	}
	if w.Type == "scatter" && ranges[w.Range] > time.Hour {
		w.Range = "1h"
	}
	switch w.Type {
	case "stat":
		if !statMetrics[w.Metric] {
			return errors.New("숫자 카드의 지표를 고르세요")
		}
	case "series":
		if !seriesMetrics[w.Metric] {
			return errors.New("추이 차트의 지표를 고르세요")
		}
	case "top":
		if !topDims[w.Dim] {
			w.Dim = "host"
		}
	}
	if w.Limit <= 0 || w.Limit > 50 {
		w.Limit = 8
	}
	if len(w.Containers) > 30 {
		w.Containers = w.Containers[:30]
	}
	if w.Warn < 0 || math.IsNaN(w.Warn) {
		w.Warn = 0
	}
	w.Host = strings.ToLower(strings.TrimSpace(w.Host))
	return nil
}

func (a *App) getDashboard(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	ws := d.Dashboard
	if ws == nil {
		ws = defaultDashboard()
		for i := range ws {
			_ = normalizeWidget(&ws[i])
		}
		_ = a.store.Update(func(x *Data) error {
			if x.Dashboard == nil {
				x.Dashboard = ws
			}
			ws = x.Dashboard
			return nil
		})
	}
	writeJSON(w, 200, map[string]any{"widgets": ws})
}

func (a *App) putDashboard(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Widgets []Widget `json:"widgets"`
		Reset   bool     `json:"reset"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if in.Reset {
		// back to "no custom layout" (nil), so later changes to the default layout reach this install too
		_ = a.store.Update(func(x *Data) error { x.Dashboard = nil; return nil })
		writeJSON(w, 200, map[string]any{"widgets": defaultDashboard()})
		return
	}
	if len(in.Widgets) > 40 {
		fail(w, 400, errors.New("위젯은 40개까지 둘 수 있습니다"))
		return
	}
	seen := map[string]bool{}
	for i := range in.Widgets {
		if err := normalizeWidget(&in.Widgets[i]); err != nil {
			fail(w, 400, err)
			return
		}
		if seen[in.Widgets[i].ID] {
			in.Widgets[i].ID = newID()
		}
		seen[in.Widgets[i].ID] = true
	}
	if in.Widgets == nil {
		in.Widgets = []Widget{}
	}
	_ = a.store.Update(func(x *Data) error { x.Dashboard = in.Widgets; return nil })
	writeJSON(w, 200, map[string]any{"widgets": in.Widgets})
}

// ---------------------------------------------------------------- data

type seriesOut struct {
	Step   int64        `json:"step"` // seconds
	T      []int64      `json:"t"`
	Series []seriesLine `json:"series"`
	Unit   string       `json:"unit"`
}
type seriesLine struct {
	Key    string    `json:"key"`
	Name   string    `json:"name"`
	Values []float64 `json:"values"`
}

func (a *App) statData(wd Widget) map[string]any {
	rng := ranges[wd.Range]
	out := map[string]any{}
	_, ts, bs := a.mon.series(rng, wd.Host, 30)
	spark := make([]float64, len(bs))
	tot := a.mon.total(rng, wd.Host)
	val, unit := 0.0, ""
	switch wd.Metric {
	case "rpm":
		last := a.mon.total(time.Minute, wd.Host)
		val, unit = float64(last.N), "회/분"
		for i := range bs {
			spark[i] = float64(bs[i].N)
		}
	case "requests":
		val, unit = float64(tot.N), "회"
		for i := range bs {
			spark[i] = float64(bs[i].N)
		}
	case "err5xx", "err4xx":
		pick := func(b *Bucket) int {
			if wd.Metric == "err5xx" {
				return b.S5
			}
			return b.S4
		}
		if tot.N > 0 {
			val = math.Round(float64(pick(&tot))/float64(tot.N)*1000) / 10
		}
		unit = "%"
		for i := range bs {
			if bs[i].N > 0 {
				spark[i] = float64(pick(&bs[i])) / float64(bs[i].N) * 100
			}
		}
		out["count"] = pick(&tot)
	case "avgMs":
		val, unit = math.Round(tot.avg()), "ms"
		for i := range bs {
			spark[i] = bs[i].avg()
		}
	case "p95Ms":
		val, unit = tot.pct(0.95), "ms"
		for i := range bs {
			spark[i] = bs[i].pct(0.95)
		}
	case "bytes":
		val, unit = float64(tot.Bytes), "bytes"
		for i := range bs {
			spark[i] = float64(bs[i].Bytes)
		}
	case "waf":
		val, unit = float64(tot.Waf), "건"
		for i := range bs {
			spark[i] = float64(bs[i].Waf)
		}
	case "csBans":
		a.mon.mu.Lock()
		val, unit = float64(a.mon.csBans), "IP"
		if a.mon.csErr != "" {
			out["error"] = a.mon.csErr
		} else if csKey() == "" {
			out["error"] = "CrowdSec이 연결되지 않았습니다"
		}
		a.mon.mu.Unlock()
		spark = nil
	case "healthUp":
		a.mon.mu.Lock()
		up, n := 0, 0
		for _, h := range a.mon.health {
			n++
			if h.OK {
				up++
			}
		}
		a.mon.mu.Unlock()
		val, unit = float64(up), fmt.Sprintf("/ %d", n)
		out["down"] = n - up
		spark = nil
	case "certDays":
		a.mon.mu.Lock()
		val, unit = -1, "일"
		for _, c := range a.mon.certs {
			if c.Err == "" && !c.Internal && (val < 0 || float64(c.Days) < val) {
				val = float64(c.Days)
				out["fqdn"] = c.FQDN
			}
		}
		a.mon.mu.Unlock()
		spark = nil
	}
	out["value"], out["unit"] = val, unit
	if spark != nil {
		out["spark"], out["t"] = spark, ts
	}
	return out
}

func (a *App) seriesData(wd Widget) seriesOut {
	step, ts, bs := a.mon.series(ranges[wd.Range], wd.Host, 60)
	return buildSeries(wd.Metric, step, ts, bs)
}

func (a *App) scatterData(wd Widget) map[string]any {
	since := time.Now().Add(-ranges[wd.Range]).UnixMilli()
	rs := a.mon.recent(since)
	pts := make([][4]float64, 0, len(rs))
	for _, r := range rs {
		if wd.Host != "" && r.Host != wd.Host {
			continue
		}
		pts = append(pts, [4]float64{float64(r.T), r.Ms, float64(r.Status), 0})
	}
	if len(pts) > 6000 { // keep the newest
		pts = pts[len(pts)-6000:]
	}
	return map[string]any{"from": since, "to": time.Now().UnixMilli(), "points": pts}
}

type topRow struct {
	Key   string  `json:"key"`
	N     int     `json:"n"`
	AvgMs float64 `json:"avgMs"`
	Err   float64 `json:"errPct"`
}

func (a *App) topData(wd Widget) map[string]any {
	since := time.Now().Add(-ranges[wd.Range]).UnixMilli()
	rs := a.mon.recent(since)
	if wd.Dim == "slow" {
		var list []ReqRec
		for _, r := range rs {
			if wd.Host == "" || r.Host == wd.Host {
				list = append(list, r)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Ms > list[j].Ms })
		if len(list) > wd.Limit {
			list = list[:wd.Limit]
		}
		return map[string]any{"slow": list}
	}
	type acc struct {
		n, e int
		ms   float64
	}
	m := map[string]*acc{}
	for _, r := range rs {
		if wd.Host != "" && r.Host != wd.Host {
			continue
		}
		var k string
		switch wd.Dim {
		case "host":
			k = r.Host
		case "path":
			k = r.URI
			if i := strings.IndexByte(k, '?'); i >= 0 {
				k = k[:i]
			}
			if wd.Host == "" {
				k = r.Host + k
			}
		case "status":
			k = strconv.Itoa(r.Status)
		case "client":
			if r.IP == "" {
				continue // only mTLS sites carry a trustworthy client IP
			}
			k = r.IP
		}
		x := m[k]
		if x == nil {
			x = &acc{}
			m[k] = x
		}
		x.n++
		x.ms += r.Ms
		if r.Status >= 500 {
			x.e++
		}
	}
	rows := make([]topRow, 0, len(m))
	for k, x := range m {
		rows = append(rows, topRow{Key: k, N: x.n, AvgMs: math.Round(x.ms / float64(x.n)), Err: math.Round(float64(x.e)/float64(x.n)*1000) / 10})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].N > rows[j].N || rows[i].N == rows[j].N && rows[i].Key < rows[j].Key
	})
	if len(rows) > wd.Limit {
		rows = rows[:wd.Limit]
	}
	out := map[string]any{"rows": rows}
	if a.mon.ringSpan() < ranges[wd.Range] {
		out["partial"] = true
	}
	return out
}

func (m *Monitor) ringSpan() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.reqs) < reqRingCap {
		return 365 * 24 * time.Hour // not full yet → complete since start
	}
	return time.Since(time.UnixMilli(m.reqs[m.pos].T))
}

func (a *App) healthData() map[string]any {
	a.mon.mu.Lock()
	defer a.mon.mu.Unlock()
	list := make([]HealthState, 0, len(a.mon.health))
	for _, h := range a.mon.health {
		c := *h
		c.History = append([]HealthPoint(nil), h.History...)
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].OK != list[j].OK {
			return !list[i].OK
		}
		return list[i].Sub < list[j].Sub
	})
	return map[string]any{"services": list}
}

func (a *App) containersData(wd Widget) map[string]any {
	st := a.store.Snapshot().Settings
	want := wd.Containers
	if len(want) == 0 {
		want = []string{st.CaddyContainer, st.AutheliaCtr, st.CrowdSecContainer}
		if host, err := hostnameSelf(); err == nil {
			want = append(want, host)
		}
	}
	a.mon.mu.Lock()
	defer a.mon.mu.Unlock()
	type row struct {
		Name    string     `json:"name"`
		Running bool       `json:"running"`
		Last    *CtrPoint  `json:"last,omitempty"`
		History []CtrPoint `json:"history"`
	}
	var rows []row
	for _, n := range want {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		h, ok := a.mon.ctr[n]
		if !ok {
			// self is listed by container name, hostname is the short id
			for k, v := range a.mon.ctr {
				if strings.HasPrefix(n, k) || strings.HasPrefix(k, n) && len(n) >= 12 {
					h, ok, n = v, true, k
					break
				}
			}
		}
		r := row{Name: n, Running: ok && len(h) > 0 && time.Since(time.UnixMilli(h[len(h)-1].T)) < 2*time.Minute}
		if len(h) > 0 {
			l := h[len(h)-1]
			r.Last = &l
			r.History = append([]CtrPoint(nil), h[max(0, len(h)-60):]...)
		}
		rows = append(rows, r)
	}
	all := make([]string, 0, len(a.mon.ctr))
	for k := range a.mon.ctr {
		all = append(all, k)
	}
	sort.Strings(all)
	return map[string]any{"containers": rows, "known": all, "collected": !a.mon.ctrAt.IsZero()}
}

var (
	selfNameOnce sync.Once
	selfName     string
	selfNameErr  error
)

// hostnameSelf: this container's name (cached; one docker inspect per process).
func hostnameSelf() (string, error) {
	selfNameOnce.Do(func() {
		if v := env("GM_SELF_CONTAINER", ""); v != "" {
			selfName = v
			return
		}
		h, err := os.Hostname()
		if err != nil {
			selfNameErr = err
			return
		}
		ctx, cancel := withTimeout(5 * time.Second)
		defer cancel()
		out, err := docker(ctx, nil, nil, "inspect", "-f", "{{.Name}}", h)
		selfName, selfNameErr = strings.TrimPrefix(strings.TrimSpace(out), "/"), err
	})
	return selfName, selfNameErr
}

func (a *App) certsData() map[string]any {
	a.mon.mu.Lock()
	defer a.mon.mu.Unlock()
	return map[string]any{"certs": a.mon.certs, "checked": a.mon.certsAt}
}

type dashEvent struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"` // waf | 5xx
	Text string `json:"text"`
	Sub  string `json:"sub,omitempty"`
}

func (a *App) eventsData(wd Widget) map[string]any {
	since := time.Now().Add(-24 * time.Hour).UnixMilli()
	var evs []dashEvent
	for _, r := range a.mon.recent(since) {
		if r.Status >= 500 {
			evs = append(evs, dashEvent{T: r.T, Kind: "5xx", Text: fmt.Sprintf("%d %s", r.Status, r.Host), Sub: r.Method + " " + r.URI})
		}
	}
	a.mon.mu.Lock()
	for _, w := range a.mon.waf {
		if w.Time.UnixMilli() >= since {
			evs = append(evs, dashEvent{T: w.Time.UnixMilli(), Kind: "waf", Text: "WAF 차단 · 규칙 " + w.RuleID, Sub: w.URI})
		}
	}
	a.mon.mu.Unlock()
	sort.Slice(evs, func(i, j int) bool { return evs[i].T > evs[j].T })
	if len(evs) > 30 {
		evs = evs[:30]
	}
	return map[string]any{"events": evs}
}

func (a *App) postDashData(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Widgets []Widget `json:"widgets"`
		At      int64    `json:"at"` // unix ms; 0 = live
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	a.touchDashboard()
	data := map[string]any{}
	end := time.Now()
	if in.At > 0 && in.At < end.UnixMilli() {
		end = time.UnixMilli(in.At)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	for _, wd := range in.Widgets {
		if normalizeWidget(&wd) != nil {
			continue
		}
		if in.At > 0 || ranges[wd.Range] > 24*time.Hour {
			switch wd.Type {
			case "stat":
				data[wd.ID] = a.dbStat(ctx, wd, end)
			case "series":
				data[wd.ID] = a.dbSeriesData(ctx, wd, end)
			case "scatter":
				data[wd.ID] = a.dbScatter(ctx, wd, end)
			case "top":
				data[wd.ID] = a.dbTop(ctx, wd, end)
			case "events":
				data[wd.ID] = a.dbEvents(ctx, end)
			default:
				if in.At > 0 {
					data[wd.ID] = map[string]any{"liveOnly": true}
					continue
				}
			}
			if _, done := data[wd.ID]; done {
				continue
			}
		}
		switch wd.Type {
		case "stat":
			data[wd.ID] = a.statData(wd)
		case "series":
			data[wd.ID] = a.seriesData(wd)
		case "scatter":
			data[wd.ID] = a.scatterData(wd)
		case "top":
			data[wd.ID] = a.topData(wd)
		case "health":
			data[wd.ID] = a.healthData()
		case "containers":
			data[wd.ID] = a.containersData(wd)
		case "certs":
			data[wd.ID] = a.certsData()
		case "events":
			data[wd.ID] = a.eventsData(wd)
		}
	}
	a.mon.mu.Lock()
	stream := map[string]any{"ok": a.mon.streamOK, "error": a.mon.streamErr, "lines": a.mon.lines}
	if a.mon.lastTs > 0 {
		stream["lastTs"] = a.mon.lastTs
	}
	a.mon.mu.Unlock()
	writeJSON(w, 200, map[string]any{"now": time.Now().UnixMilli(), "stream": stream, "data": data})
}

// getDashRequests: drill-down for a scatter selection (time × response-time box).
func (a *App) getDashRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := func(k string, def float64) float64 {
		v, err := strconv.ParseFloat(q.Get(k), 64)
		if err != nil {
			return def
		}
		return v
	}
	// times are integers (unix ms): parse them as such — float64(MaxInt64) converts back to MinInt64
	ms := func(k string, def int64) int64 {
		v, err := strconv.ParseInt(q.Get(k), 10, 64)
		if err != nil {
			return def
		}
		return v
	}
	from, to := ms("from", 0), ms("to", time.Now().UnixMilli()+60_000)
	lo, hi := f("min", 0), f("max", math.MaxFloat64)
	host := strings.ToLower(q.Get("host"))
	if a.mon.ringSpan() < time.Since(time.UnixMilli(from)) || q.Get("db") == "1" {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		rows, err := a.ldb.QueryRequests(ctx, ReqQuery{From: from, To: to, Host: host, MinMs: lo, MaxMs: func() float64 {
			if hi > 1e11 {
				return 0
			}
			return hi
		}(), Limit: 300, SlowFirst: true})
		if err != nil {
			fail(w, 500, err)
			return
		}
		list := make([]ReqRec, 0, len(rows))
		for _, x := range rows {
			list = append(list, x.ReqRec)
		}
		writeJSON(w, 200, map[string]any{"total": len(list), "requests": list, "db": true})
		return
	}
	var out []ReqRec
	for _, x := range a.mon.recent(from) {
		if x.T <= to && x.Ms >= lo && x.Ms <= hi && (host == "" || x.Host == host) {
			out = append(out, x)
		}
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool { return out[i].Ms > out[j].Ms })
	if len(out) > 300 {
		out = out[:300]
	}
	if out == nil {
		out = []ReqRec{}
	}
	writeJSON(w, 200, map[string]any{"total": total, "requests": out})
}

// getHealth: latest upstream probe per service (probed every 60 s, 30 s while the dashboard is open).
func (a *App) getHealth(w http.ResponseWriter, r *http.Request) {
	type hs struct {
		OK      bool    `json:"ok"`
		Ms      float64 `json:"ms"`
		Err     string  `json:"err,omitempty"`
		Checked int64   `json:"checked"`
		Recent  []bool  `json:"recent"`
	}
	out := map[string]hs{}
	a.mon.mu.Lock()
	empty := len(a.mon.health) == 0
	a.mon.mu.Unlock()
	if empty {
		a.probeHealth() // first call after a restart: answer with real results (dial timeout 3 s)
	}
	a.mon.mu.Lock()
	for id, h := range a.mon.health {
		x := hs{OK: h.OK, Ms: h.Ms, Err: h.Err}
		if n := len(h.History); n > 0 {
			x.Checked = h.History[n-1].T
			for _, p := range h.History[max(0, n-10):] {
				x.Recent = append(x.Recent, p.OK)
			}
		}
		out[id] = x
	}
	a.mon.mu.Unlock()
	writeJSON(w, 200, map[string]any{"services": out})
}
