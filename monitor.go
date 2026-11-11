package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Monitoring for the dashboard.
//
//   - Caddy access logs are streamed with `docker logs -f` (Gilmok adds `log # gilmok` to every
//     generated site when Settings.DashLogs is on) and aggregated in memory: raw ring of recent
//     requests (scatter, top lists, drill-down), 10 s buckets for 1 h, 1 min buckets for 24 h
//     (persisted to /data/metrics.json).
//   - While the dashboard is being looked at (lastSeen < 10 min): container resources
//     (docker stats), upstream TCP health, TLS certificates served by Caddy.

const (
	reqRingCap   = 20000
	fineRes      = 10 // seconds
	fineKeep     = 3600
	coarseRes    = 60
	coarseKeep   = 24 * 3600
	activeWindow = 10 * time.Minute
)

var histEdges = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000} // ms

type ReqRec struct {
	T      int64   `json:"t"` // unix ms
	Host   string  `json:"host"`
	Method string  `json:"method"`
	URI    string  `json:"uri"`
	Status int     `json:"status"`
	Ms     float64 `json:"ms"`
	Size   int64   `json:"size"`
	IP     string  `json:"ip,omitempty"` // real client IP (mTLS sites only)
}

type Bucket struct {
	N      int     `json:"n"`
	S2     int     `json:"s2"`
	S3     int     `json:"s3"`
	S4     int     `json:"s4"`
	S5     int     `json:"s5"`
	DurSum float64 `json:"ds"`
	DurMax float64 `json:"dm"`
	Bytes  int64   `json:"b"`
	Waf    int     `json:"w"`
	Hist   []int   `json:"h"`
}

func (b *Bucket) add(r ReqRec) {
	if b.Hist == nil {
		b.Hist = make([]int, len(histEdges)+1)
	}
	b.N++
	switch {
	case r.Status >= 500:
		b.S5++
	case r.Status >= 400:
		b.S4++
	case r.Status >= 300:
		b.S3++
	default:
		b.S2++
	}
	b.DurSum += r.Ms
	b.DurMax = math.Max(b.DurMax, r.Ms)
	b.Bytes += r.Size
	i := sort.SearchFloat64s(histEdges, r.Ms)
	b.Hist[i]++
}

func (b *Bucket) merge(o *Bucket) {
	if o == nil {
		return
	}
	if b.Hist == nil {
		b.Hist = make([]int, len(histEdges)+1)
	}
	b.N += o.N
	b.S2 += o.S2
	b.S3 += o.S3
	b.S4 += o.S4
	b.S5 += o.S5
	b.DurSum += o.DurSum
	b.DurMax = math.Max(b.DurMax, o.DurMax)
	b.Bytes += o.Bytes
	b.Waf += o.Waf
	for i := range o.Hist {
		if i < len(b.Hist) {
			b.Hist[i] += o.Hist[i]
		}
	}
}

func (b *Bucket) avg() float64 {
	if b.N == 0 {
		return 0
	}
	return b.DurSum / float64(b.N)
}

// pct returns an approximate percentile (upper edge of the histogram bucket).
func (b *Bucket) pct(p float64) float64 {
	if b.N == 0 {
		return 0
	}
	want := float64(b.N) * p
	acc := 0
	for i, c := range b.Hist {
		if c == 0 {
			continue
		}
		if float64(acc+c) >= want {
			lo := 0.0
			if i > 0 {
				lo = histEdges[i-1]
			}
			hi := b.DurMax
			if i < len(histEdges) && histEdges[i] < hi {
				hi = histEdges[i]
			}
			if hi < lo {
				hi = lo
			}
			// linear interpolation inside the bucket
			return math.Round(lo + (hi-lo)*(want-float64(acc))/float64(c))
		}
		acc += c
	}
	return b.DurMax
}

type Slot struct {
	All   Bucket             `json:"all"`
	Hosts map[string]*Bucket `json:"hosts"`
}

type CtrPoint struct {
	T      int64   `json:"t"`
	CPU    float64 `json:"cpu"`
	Mem    float64 `json:"mem"` // bytes
	MemPct float64 `json:"memPct"`
}

type HealthPoint struct {
	T  int64   `json:"t"`
	OK bool    `json:"ok"`
	Ms float64 `json:"ms"`
}

type HealthState struct {
	ID       string        `json:"id"`
	FQDN     string        `json:"fqdn"`
	Sub      string        `json:"sub"`
	Upstream string        `json:"upstream"`
	OK       bool          `json:"ok"`
	Ms       float64       `json:"ms"`
	Err      string        `json:"err,omitempty"`
	History  []HealthPoint `json:"history"`
}

type CertInfo struct {
	FQDN     string    `json:"fqdn"`
	NotAfter time.Time `json:"notAfter"`
	Days     int       `json:"days"`
	Hours    int       `json:"hours"`
	Issuer   string    `json:"issuer"`
	Internal bool      `json:"internal"` // Caddy's local CA: short-lived, renewed automatically
	Err      string    `json:"err,omitempty"`
}

type Monitor struct {
	mu        sync.Mutex
	reqs      []ReqRec
	pos       int
	fine      map[int64]*Slot
	coarse    map[int64]*Slot
	waf       []WAFEvent
	lastTs    int64 // unix ms of the newest processed line
	lines     int64
	streamOK  bool
	streamErr string
	streamAt  time.Time
	lastSeen  time.Time

	ctr     map[string][]CtrPoint
	ctrAt   time.Time
	health  map[string]*HealthState
	certs   []CertInfo
	certsAt time.Time
	csBans  int
	csErr   string
	csAt    time.Time
	dirty   bool

	streamLogAt time.Time
	csKnown     map[int64]Decision
}

func newMonitor() *Monitor {
	return &Monitor{fine: map[int64]*Slot{}, coarse: map[int64]*Slot{}, ctr: map[string][]CtrPoint{}, health: map[string]*HealthState{}}
}

func addSlot(m map[int64]*Slot, key int64, r ReqRec) {
	s := m[key]
	if s == nil {
		s = &Slot{Hosts: map[string]*Bucket{}}
		m[key] = s
	}
	s.All.add(r)
	b := s.Hosts[r.Host]
	if b == nil {
		b = &Bucket{}
		s.Hosts[r.Host] = b
	}
	b.add(r)
}

func (m *Monitor) addReq(r ReqRec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.T <= m.lastTs-5*60*1000 { // replayed old line after a reconnect
		return
	}
	if len(m.reqs) < reqRingCap {
		m.reqs = append(m.reqs, r)
	} else {
		m.reqs[m.pos] = r
		m.pos = (m.pos + 1) % reqRingCap
	}
	sec := r.T / 1000
	addSlot(m.fine, sec/fineRes, r)
	addSlot(m.coarse, sec/coarseRes, r)
	if r.T > m.lastTs {
		m.lastTs = r.T
	}
	m.lines++
	m.dirty = true
}

func (m *Monitor) addWaf(ev WAFEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.waf) >= 500 {
		m.waf = m.waf[1:]
	}
	m.waf = append(m.waf, ev)
	sec := ev.Time.Unix()
	for _, x := range []struct {
		m   map[int64]*Slot
		res int64
	}{{m.fine, fineRes}, {m.coarse, coarseRes}} {
		s := x.m[sec/x.res]
		if s == nil {
			s = &Slot{Hosts: map[string]*Bucket{}}
			x.m[sec/x.res] = s
		}
		s.All.Waf++
		if ev.Host != "" {
			b := s.Hosts[ev.Host]
			if b == nil {
				b = &Bucket{}
				s.Hosts[ev.Host] = b
			}
			b.Waf++
		}
	}
	if t := ev.Time.UnixMilli(); t > m.lastTs {
		m.lastTs = t
	}
	m.dirty = true
}

func (m *Monitor) prune() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().Unix()
	for k := range m.fine {
		if k*fineRes < now-fineKeep {
			delete(m.fine, k)
		}
	}
	for k := range m.coarse {
		if k*coarseRes < now-coarseKeep {
			delete(m.coarse, k)
		}
	}
}

// recent returns raw requests newer than since (oldest first).
func (m *Monitor) recent(since int64) []ReqRec {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ReqRec, 0, 256)
	n := len(m.reqs)
	for i := 0; i < n; i++ {
		r := m.reqs[(m.pos+i)%n]
		if r.T >= since {
			out = append(out, r)
		}
	}
	return out
}

// series returns buckets covering [now-rng, now] merged to ~points steps.
func (m *Monitor) series(rng time.Duration, host string, points int) (step int64, ts []int64, bs []Bucket) {
	res, src := int64(fineRes), m.fine
	if rng > time.Hour {
		res, src = coarseRes, m.coarse
	}
	step = int64(rng.Seconds()) / int64(points)
	if step < res {
		step = res
	}
	step = (step + res - 1) / res * res
	now := time.Now().Unix()
	end := now / step * step
	start := end - int64(rng.Seconds()) + step
	m.mu.Lock()
	defer m.mu.Unlock()
	for t := start; t <= end; t += step {
		var b Bucket
		for k := t / res; k < (t+step)/res; k++ {
			s := src[k]
			if s == nil {
				continue
			}
			if host == "" {
				b.merge(&s.All)
			} else {
				b.merge(s.Hosts[host])
			}
		}
		ts = append(ts, t*1000)
		bs = append(bs, b)
	}
	return
}

// total sums the last rng (at bucket resolution).
func (m *Monitor) total(rng time.Duration, host string) Bucket {
	res, src := int64(fineRes), m.fine
	if rng > time.Hour {
		res, src = coarseRes, m.coarse
	}
	from := (time.Now().Unix() - int64(rng.Seconds())) / res
	m.mu.Lock()
	defer m.mu.Unlock()
	var t Bucket
	for k, s := range src {
		if k <= from {
			continue
		}
		if host == "" {
			t.merge(&s.All)
		} else {
			t.merge(s.Hosts[host])
		}
	}
	return t
}

// ---------------------------------------------------------------- persistence

type metricsFile struct {
	LastTs int64           `json:"lastTs"`
	Coarse map[int64]*Slot `json:"coarse"`
	Fine   map[int64]*Slot `json:"fine"`
}

func (a *App) metricsPath() string { return filepath.Join(a.dataDir, "metrics.json") }

func (a *App) loadMetrics() {
	b, err := os.ReadFile(a.metricsPath())
	if err != nil {
		return
	}
	var f metricsFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	a.mon.mu.Lock()
	if f.Coarse != nil {
		a.mon.coarse = f.Coarse
	}
	if f.Fine != nil {
		a.mon.fine = f.Fine
	}
	a.mon.lastTs = f.LastTs
	a.mon.mu.Unlock()
	a.mon.prune()
}

func (a *App) saveMetrics() {
	a.mon.mu.Lock()
	if !a.mon.dirty {
		a.mon.mu.Unlock()
		return
	}
	b, err := json.Marshal(metricsFile{LastTs: a.mon.lastTs, Coarse: a.mon.coarse, Fine: a.mon.fine})
	a.mon.dirty = false
	a.mon.mu.Unlock()
	if err != nil {
		return
	}
	tmp := a.metricsPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, a.metricsPath())
	}
}

// ---------------------------------------------------------------- log stream

type accessLine struct {
	Logger  string  `json:"logger"`
	Ts      float64 `json:"ts"`
	Request struct {
		Host     string `json:"host"`
		Method   string `json:"method"`
		URI      string `json:"uri"`
		ClientIP string `json:"client_ip"`
	} `json:"request"`
	Status   int     `json:"status"`
	Duration float64 `json:"duration"`
	Size     int64   `json:"size"`
	RealIP   string  `json:"gm_real_ip"`
}

func parseAccessLine(line string) (ReqRec, bool) {
	if !strings.Contains(line, `"logger":"http.log.access`) {
		return ReqRec{}, false
	}
	var e accessLine
	if json.Unmarshal([]byte(line), &e) != nil || e.Request.Host == "" {
		return ReqRec{}, false
	}
	host := e.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	uri := e.Request.URI
	if len(uri) > 300 {
		uri = uri[:300] + "…"
	}
	return ReqRec{
		T: int64(e.Ts * 1000), Host: strings.ToLower(host), Method: e.Request.Method, URI: uri,
		Status: e.Status, Ms: math.Round(e.Duration*1e5) / 100, Size: e.Size, IP: e.RealIP,
	}, true
}

func (a *App) logStreamLoop() {
	for {
		st := a.store.Snapshot().Settings
		if !st.UseCaddy || caddyMode(st) != "docker" {
			a.mon.mu.Lock()
			a.mon.streamOK, a.mon.streamErr = false, "Docker의 Caddy를 쓰지 않아 요청 통계를 모으지 않습니다"
			a.mon.mu.Unlock()
			time.Sleep(30 * time.Second)
			continue
		}
		ctr := st.CaddyContainer
		a.mon.mu.Lock()
		last := a.mon.lastTs
		a.mon.mu.Unlock()
		args := []string{"logs", "-f"}
		if last > 0 && time.Since(time.UnixMilli(last)) < 30*time.Minute {
			args = append(args, "--since", time.UnixMilli(last).UTC().Format(time.RFC3339Nano))
		} else {
			args = append(args, "--tail", "0")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, "docker", append(args, ctr)...)
		pr, pw := io.Pipe()
		cmd.Stdout, cmd.Stderr = pw, pw
		err := cmd.Start()
		if err == nil {
			a.mon.mu.Lock()
			a.mon.streamOK, a.mon.streamErr, a.mon.streamAt = true, "", time.Now()
			a.mon.mu.Unlock()
			go func() { _ = cmd.Wait(); pw.Close() }()
			// stop when the container setting changes
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-time.After(15 * time.Second):
					}
					if a.store.Snapshot().Settings.CaddyContainer != ctr {
						cancel()
					}
				}
			}()
			sc := bufio.NewScanner(pr)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			var lastErrLine string
			for sc.Scan() {
				line := sc.Text()
				if r, ok := parseAccessLine(line); ok {
					if r.T > last {
						a.mon.addReq(r)
						a.ldb.Req(r)
					}
					continue
				}
				if ev, ok := parseWAFLine(line); ok && ev.Action == "denied" && ev.Time.UnixMilli() > last {
					a.mon.addWaf(ev)
					a.ldb.Event(Event{Ts: ev.Time.UnixMilli(), Cat: "security", Level: "warn", Action: "waf.block", Target: "규칙 " + ev.RuleID, Msg: "WAF 차단: " + truncate(ev.Msg, 200), Actor: "caddy-waf",
						Detail: mustJSON(map[string]string{"rule": ev.RuleID, "uri": ev.URI, "data": ev.Data, "tx": ev.TxID})})
					continue
				}
				if !strings.HasPrefix(line, "{") {
					lastErrLine = line
				}
			}
			cancel()
			if lastErrLine != "" {
				err = &streamErr{lastErrLine}
			}
		}
		cancel()
		a.mon.mu.Lock()
		a.mon.streamOK = false
		if err != nil {
			a.mon.streamErr = oneLine(err.Error())
		} else {
			a.mon.streamErr = "Caddy 로그 스트림이 끊겼습니다 (컨테이너 재시작?)"
		}
		msg := a.mon.streamErr
		noisy := time.Since(a.mon.streamLogAt) < 10*time.Minute
		if !noisy {
			a.mon.streamLogAt = time.Now()
		}
		a.mon.mu.Unlock()
		if !noisy {
			a.logEvent("system", "warn", "caddy.logstream", ctr, "Caddy 로그 수집이 끊겼습니다 — 다시 연결합니다: "+msg, nil)
		}
		time.Sleep(5 * time.Second)
	}
}

type streamErr struct{ s string }

func (e *streamErr) Error() string { return e.s }

// ---------------------------------------------------------------- background collectors

func (a *App) monitorLoop() {
	a.loadMetrics()
	go a.logStreamLoop()
	tick := time.NewTicker(15 * time.Second)
	n := 0
	for range tick.C {
		n++
		if n%20 == 0 { // 5 min
			a.mon.prune()
			a.saveMetrics()
		}
		a.mon.mu.Lock()
		active := time.Since(a.mon.lastSeen) < activeWindow
		certsDue := time.Since(a.mon.certsAt) > 6*time.Hour
		csDue := time.Since(a.mon.csAt) > 30*time.Second
		a.mon.mu.Unlock()
		// always (for the logs): service health every 60 s, CrowdSec decisions every 60 s
		if n%4 == 0 || (active && n%2 == 0) {
			go a.probeHealthBg()
		}
		if csDue && (active || n%4 == 0) {
			go a.collectCrowdSec()
		}
		if certsDue {
			a.mon.mu.Lock()
			a.mon.certsAt = time.Now()
			a.mon.mu.Unlock()
			go a.checkCerts()
		}
		if active {
			go a.collectContainers()
		}
	}
}

// touchDashboard marks the dashboard as watched and kicks the collectors on first view.
func (a *App) touchDashboard() {
	a.mon.mu.Lock()
	first := time.Since(a.mon.lastSeen) >= activeWindow
	a.mon.lastSeen = time.Now()
	certsDue := time.Since(a.mon.certsAt) > 6*time.Hour
	a.mon.mu.Unlock()
	if first {
		go a.collectContainers()
		go a.probeHealthBg()
		go a.collectCrowdSec()
	}
	if certsDue {
		a.mon.mu.Lock()
		a.mon.certsAt = time.Now() // avoid parallel runs
		a.mon.mu.Unlock()
		go a.checkCerts()
	}
}

var memUnits = map[string]float64{"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}

func parseSize(s string) float64 {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i <= 0 {
		v, _ := strconv.ParseFloat(s, 64)
		return v
	}
	v, _ := strconv.ParseFloat(s[:i], 64)
	return v * memUnits[strings.TrimSpace(s[i:])]
}

func parsePct(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(s), "%"), 64)
	return v
}

func (a *App) collectContainers() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "stats", "--no-stream", "--format", "{{json .}}")
	if err != nil {
		return
	}
	now := time.Now().UnixMilli()
	a.mon.mu.Lock()
	defer a.mon.mu.Unlock()
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		var s struct{ Name, CPUPerc, MemUsage, MemPerc string }
		if json.Unmarshal([]byte(strings.TrimSpace(l)), &s) != nil || s.Name == "" {
			continue
		}
		used, _, _ := strings.Cut(s.MemUsage, "/")
		p := CtrPoint{T: now, CPU: parsePct(s.CPUPerc), Mem: parseSize(used), MemPct: parsePct(s.MemPerc)}
		h := append(a.mon.ctr[s.Name], p)
		if len(h) > 240 {
			h = h[len(h)-240:]
		}
		a.mon.ctr[s.Name] = h
		seen[s.Name] = true
	}
	for k := range a.mon.ctr {
		if !seen[k] { // stopped: keep history, but mark with a zero point once
			h := a.mon.ctr[k]
			if len(h) > 0 && h[len(h)-1].T != 0 && now-h[len(h)-1].T > 5*60*1000 {
				delete(a.mon.ctr, k)
			}
		}
	}
	a.mon.ctrAt = time.Now()
}

func upstreamAddr(u string) string {
	u = strings.TrimSpace(u)
	for _, p := range []string{"http://", "https://", "h2c://"} {
		u = strings.TrimPrefix(u, p)
	}
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	if _, _, err := net.SplitHostPort(u); err != nil {
		u = net.JoinHostPort(u, "80")
	}
	return u
}

// probeMu / csMu: one probe at a time — a slow upstream (3 s dial timeout) must not let the
// 30 s ticker and the dashboard pile up overlapping runs that race on the results.
var probeMu, csMu sync.Mutex

func (a *App) probeHealth() {
	probeMu.Lock() // the dashboard's first call waits for a running probe and then reuses its results
	defer probeMu.Unlock()
	d := a.store.Snapshot()
	type job struct {
		s    *Service
		addr string
	}
	var jobs []job
	for _, s := range d.Services {
		if s.Enabled && !s.DNSOnly && strings.TrimSpace(s.Upstream) != "" {
			jobs = append(jobs, job{s, upstreamAddr(s.Upstream)})
		}
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var fdMu sync.Mutex
	var firstDown []string
	now := time.Now().UnixMilli()
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			t0 := time.Now()
			c, err := net.DialTimeout("tcp", j.addr, 3*time.Second)
			ms := math.Round(float64(time.Since(t0).Microseconds())/10) / 100
			if c != nil {
				c.Close()
			}
			a.mon.mu.Lock()
			hs := a.mon.health[j.s.ID]
			if hs == nil {
				hs = &HealthState{ID: j.s.ID}
				a.mon.health[j.s.ID] = hs
			}
			hs.FQDN, hs.Sub, hs.Upstream = d.Settings.FQDN(j.s.Subdomain), j.s.Subdomain, j.s.Upstream
			first := len(hs.History) == 0
			wasOK := hs.OK
			hs.OK, hs.Ms, hs.Err = err == nil, ms, ""
			if err != nil {
				hs.Err = oneLine(err.Error())
			}
			hs.History = append(hs.History, HealthPoint{T: now, OK: err == nil, Ms: ms})
			if len(hs.History) > 40 {
				hs.History = hs.History[len(hs.History)-40:]
			}
			hsc := *hs
			a.mon.mu.Unlock()
			switch {
			case first && !hsc.OK:
				fdMu.Lock()
				firstDown = append(firstDown, hsc.Sub)
				fdMu.Unlock()
			case wasOK && !hsc.OK:
				a.logEvent("system", "error", "service.down", hsc.FQDN, fmt.Sprintf("%s 응답 없음 (%s): %s", hsc.FQDN, hsc.Upstream, hsc.Err), nil)
			case !first && !wasOK && hsc.OK:
				a.logEvent("system", "info", "service.up", hsc.FQDN, fmt.Sprintf("%s 복구됨 (%s, %.0fms)", hsc.FQDN, hsc.Upstream, hsc.Ms), nil)
			}
		}(j)
	}
	wg.Wait()
	if len(firstDown) > 0 {
		sort.Strings(firstDown)
		a.logEvent("system", "warn", "service.down", fmt.Sprintf("%d개", len(firstDown)), fmt.Sprintf("시작 시 응답 없는 서비스 %d개: %s", len(firstDown), strings.Join(firstDown, ", ")), nil)
	}
	// forget removed services
	ids := map[string]bool{}
	for _, j := range jobs {
		ids[j.s.ID] = true
	}
	a.mon.mu.Lock()
	for k := range a.mon.health {
		if !ids[k] {
			delete(a.mon.health, k)
		}
	}
	a.mon.mu.Unlock()
}

func (a *App) checkCerts() {
	d := a.store.Snapshot()
	st := d.Settings
	if !st.UseCaddy || caddyMode(st) != "docker" {
		return
	}
	pub := caddyHTTPSPort(st.CaddyBase)
	var out []CertInfo
	for _, s := range d.Services {
		if !s.Enabled || s.DNSOnly {
			continue
		}
		port := pub
		if s.Exposure == ExposureTailscale {
			port = st.TailscalePort
		}
		fq := st.FQDN(s.Subdomain)
		ci := CertInfo{FQDN: fq}
		dl := &net.Dialer{Timeout: 5 * time.Second}
		c, err := tls.DialWithDialer(dl, "tcp", net.JoinHostPort(st.CaddyContainer, strconv.Itoa(port)), &tls.Config{ServerName: fq, InsecureSkipVerify: true}) // reading the cert only
		if err != nil {
			ci.Err = oneLine(err.Error())
			if strings.Contains(ci.Err, "certificate required") || strings.Contains(ci.Err, "bad certificate") {
				ci.Err = "mTLS 사이트 — 클라이언트 인증서 없이는 확인할 수 없음"
			}
		} else {
			if certs := c.ConnectionState().PeerCertificates; len(certs) > 0 {
				ci.NotAfter = certs[0].NotAfter
				ci.Days = int(time.Until(certs[0].NotAfter).Hours() / 24)
				ci.Hours = int(time.Until(certs[0].NotAfter).Hours())
				ci.Issuer = certs[0].Issuer.CommonName
				if ci.Issuer == "" && len(certs[0].Issuer.Organization) > 0 {
					ci.Issuer = certs[0].Issuer.Organization[0]
				}
			}
			ci.Internal = strings.Contains(ci.Issuer, "Caddy Local Authority")
			c.Close()
		}
		out = append(out, ci)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Err == "") != (out[j].Err == "") {
			return out[i].Err == ""
		}
		return out[i].Days < out[j].Days
	})
	a.mon.mu.Lock()
	a.mon.certs, a.mon.certsAt = out, time.Now()
	a.mon.mu.Unlock()
}

func (a *App) collectCrowdSec() {
	if !csMu.TryLock() { // already running
		return
	}
	defer csMu.Unlock()
	st := a.store.Snapshot().Settings
	if !st.UseCrowdSec || csKey() == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ds, err := csDecisions(ctx, st)
	a.mon.mu.Lock()
	defer a.mon.mu.Unlock()
	a.mon.csAt = time.Now()
	if err != nil {
		a.mon.csErr = err.Error()
		return
	}
	a.mon.csErr = ""
	a.mon.csBans = len(banItems(ds))
	cur := map[int64]Decision{}
	for _, x := range ds {
		cur[x.ID] = x
	}
	first := a.mon.csKnown == nil
	prev := a.mon.csKnown
	a.mon.csKnown = cur
	if first {
		return
	}
	go func() {
		for id, x := range cur {
			if _, ok := prev[id]; !ok {
				a.ldb.Event(Event{Cat: "security", Level: "error", Action: "crowdsec.ban", Target: x.Value, IP: x.Value, Actor: "crowdsec",
					Msg: fmt.Sprintf("CrowdSec 차단: %s (%s, %s)", x.Value, x.Scenario, x.Duration), Detail: mustJSON(x)})
			}
		}
		for id, x := range prev {
			if _, ok := cur[id]; !ok {
				a.ldb.Event(Event{Cat: "security", Level: "info", Action: "crowdsec.unban", Target: x.Value, IP: x.Value, Actor: "crowdsec", Msg: "CrowdSec 차단 해제/만료: " + x.Value})
			}
		}
	}()
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// probeHealthBg: background tick — skip when a probe is still running.
func (a *App) probeHealthBg() {
	if !probeMu.TryLock() {
		return
	}
	probeMu.Unlock()
	a.probeHealth()
}
