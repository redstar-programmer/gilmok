package main

import (
	"context"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Dashboard variables: filters the whole dashboard applies to every request-based panel (sites,
// status classes, client countries, client paths). With a filter the panels are computed from the
// requests themselves — the in-memory ring when it covers the range, else the log database — so
// percentiles stay exact. Without one the per-site buckets are used as before (cheap).

type dashFilter struct {
	Hosts     []string `json:"hosts"`
	Classes   []int    `json:"classes"`   // 2 = 2xx … 5 = 5xx
	Countries []string `json:"countries"` // ISO codes
	Vias      []string `json:"vias"`      // cf | direct | lan | tailnet | hidden

	hs, cs, vs map[string]bool
	cl         map[int]bool
}

func (f *dashFilter) prepare() *dashFilter {
	if f == nil {
		return nil
	}
	set := func(xs []string, lower bool) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			x = strings.TrimSpace(x)
			if lower {
				x = strings.ToLower(x)
			} else {
				x = strings.ToUpper(x)
			}
			if x != "" {
				m[x] = true
			}
		}
		return m
	}
	f.hs, f.cs = set(f.Hosts, true), set(f.Countries, false)
	f.vs = set(f.Vias, true)
	f.cl = map[int]bool{}
	for _, c := range f.Classes {
		if c >= 1 && c <= 5 {
			f.cl[c] = true
		}
	}
	if !f.active() {
		return nil
	}
	return f
}

func (f *dashFilter) active() bool {
	return f != nil && (len(f.hs) > 0 || len(f.cs) > 0 || len(f.vs) > 0 || len(f.cl) > 0)
}

// onlyOneHost: the filter is just one site — the cheap per-site buckets can answer it.
func (f *dashFilter) onlyOneHost() (string, bool) {
	if f == nil || len(f.hs) != 1 || len(f.cs) > 0 || len(f.vs) > 0 || len(f.cl) > 0 {
		return "", false
	}
	for h := range f.hs {
		return h, true
	}
	return "", false
}

func (f *dashFilter) match(r ReqRec) bool {
	if f == nil {
		return true
	}
	if len(f.hs) > 0 && !f.hs[strings.ToLower(r.Host)] {
		return false
	}
	if len(f.cl) > 0 && !f.cl[r.Status/100] {
		return false
	}
	if len(f.cs) > 0 && !f.cs[r.CC] {
		return false
	}
	if len(f.vs) > 0 && !f.vs[r.Via] {
		return false
	}
	return true
}

// sql: the filter as SQL conditions on the requests table.
func (f *dashFilter) sql() (conds []string, args []any) {
	if f == nil {
		return nil, nil
	}
	in := func(col string, vals []any) {
		if len(vals) == 0 {
			return
		}
		ph := make([]string, len(vals))
		for i := range vals {
			ph[i] = "?"
		}
		conds = append(conds, col+" IN ("+strings.Join(ph, ",")+")")
		args = append(args, vals...)
	}
	keys := func(m map[string]bool) []any {
		var out []any
		for k := range m {
			out = append(out, k)
		}
		return out
	}
	in("host", keys(f.hs))
	in("IFNULL(cc,'')", keys(f.cs))
	in("IFNULL(via,'')", keys(f.vs))
	var cl []any
	for c := range f.cl {
		cl = append(cl, c)
	}
	in("status/100", cl)
	return conds, args
}

// reqBased: panels computed from the request log (the ones a filter applies to).
func reqBased(wd Widget) bool {
	switch wd.Type {
	case "series", "scatter", "top", "map":
		return true
	case "stat":
		switch wd.Metric {
		case "rpm", "requests", "err5xx", "err4xx", "avgMs", "p95Ms", "bytes", "waf":
			return true
		}
	}
	return false
}

// RawRequests: the requests of [from, to] matching the filter (and host), oldest first; at most
// limit of the newest — partial = there were more.
func (l *LogDB) RawRequests(ctx context.Context, from, to int64, f *dashFilter, host string, limit int) ([]ReqRec, bool, error) {
	conds, args := []string{"ts>=?", "ts<=?"}, []any{from, to}
	if host != "" {
		conds, args = append(conds, "host=?"), append(args, strings.ToLower(host))
	}
	fc, fa := f.sql()
	conds, args = append(conds, fc...), append(args, fa...)
	rows, err := l.r.QueryContext(ctx, `SELECT ts,host,IFNULL(method,''),IFNULL(uri,''),status,ms,size,IFNULL(ip,''),IFNULL(cc,''),IFNULL(via,'') FROM requests WHERE `+strings.Join(conds, " AND ")+` ORDER BY ts DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []ReqRec
	for rows.Next() {
		var r ReqRec
		if err := rows.Scan(&r.T, &r.Host, &r.Method, &r.URI, &r.Status, &r.Ms, &r.Size, &r.IP, &r.CC, &r.Via); err != nil {
			return nil, false, err
		}
		out = append(out, r)
	}
	partial := len(out) > limit
	if partial {
		out = out[:limit]
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, partial, rows.Err()
}

// SampleRequests: up to max requests spread over [from, to] for the response-time scatter — every
// k-th row plus every error (errors are what one looks for), oldest first.
func (l *LogDB) SampleRequests(ctx context.Context, from, to int64, f *dashFilter, host string, max int) ([]ReqRec, bool, error) {
	conds, args := []string{"ts>=?", "ts<=?"}, []any{from, to}
	if host != "" {
		conds, args = append(conds, "host=?"), append(args, strings.ToLower(host))
	}
	fc, fa := f.sql()
	conds, args = append(conds, fc...), append(args, fa...)
	where := strings.Join(conds, " AND ")
	var n int
	if err := l.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM requests WHERE `+where, args...).Scan(&n); err != nil {
		return nil, false, err
	}
	k := (n + max - 1) / max
	q := `SELECT ts,host,IFNULL(method,''),IFNULL(uri,''),status,ms,size,IFNULL(ip,''),IFNULL(cc,''),IFNULL(via,'') FROM requests WHERE ` + where
	if k > 1 {
		q += ` AND (id % ? = 0 OR status >= 400)`
		args = append(args, k)
	}
	rows, err := l.r.QueryContext(ctx, q+` ORDER BY ts LIMIT ?`, append(args, max*2)...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []ReqRec
	for rows.Next() {
		var r ReqRec
		if err := rows.Scan(&r.T, &r.Host, &r.Method, &r.URI, &r.Status, &r.Ms, &r.Size, &r.IP, &r.CC, &r.Via); err != nil {
			return nil, false, err
		}
		out = append(out, r)
	}
	return out, k > 1, rows.Err()
}

// filteredRecs: the requests a filtered panel is computed from — memory when it holds the whole
// range (live), the log database otherwise.
func (a *App) filteredRecs(ctx context.Context, wd Widget, end time.Time, live bool) ([]ReqRec, bool) {
	from := end.Add(-wd.dur()).UnixMilli()
	if live && a.mon.ringSpan() >= wd.dur() {
		var out []ReqRec
		for _, r := range a.mon.recent(from) {
			if (wd.Host == "" || r.Host == wd.Host) && wd.flt.match(r) {
				out = append(out, r)
			}
		}
		return out, false
	}
	rows, partial, err := a.ldb.RawRequests(ctx, from, end.UnixMilli(), wd.flt, wd.Host, 300000)
	if err != nil {
		return nil, true
	}
	return rows, partial
}

// bucketsOf: requests into time buckets over the panel's range (the per-site buckets' shape).
func bucketsOf(recs []ReqRec, rng time.Duration, end time.Time, points int) (int64, []int64, []Bucket) {
	step := int64(rng.Seconds()) / int64(points)
	if step <= 60 {
		step = max((step+9)/10*10, 10)
	} else {
		step = (step + 59) / 60 * 60
	}
	endA := end.Unix() / step * step
	start := endA - int64(rng.Seconds()) + step
	n := int((endA-start)/step) + 1
	ts := make([]int64, n)
	bs := make([]Bucket, n)
	for i := range ts {
		ts[i] = (start + int64(i)*step) * 1000
	}
	for _, r := range recs {
		i := int((r.T/1000 - start) / step)
		if i >= 0 && i < n {
			bs[i].add(r)
		}
	}
	return step, ts, bs
}

// filteredData: a request-based panel computed from the filtered requests.
func (a *App) filteredData(ctx context.Context, wd Widget, end time.Time, live bool) map[string]any {
	recs, partial := a.filteredRecs(ctx, wd, end, live)
	var out map[string]any
	switch wd.Type {
	case "stat":
		step, ts, bs := bucketsOf(recs, wd.dur(), end, 30)
		_ = step
		var tot, last Bucket
		for i := range bs {
			tot.merge(&bs[i])
		}
		cut := end.Add(-time.Minute).UnixMilli()
		for _, r := range recs {
			if r.T >= cut {
				last.add(r)
			}
		}
		out = statFromBuckets(wd.Metric, tot, last, bs, ts)
	case "series":
		step, ts, bs := bucketsOf(recs, wd.dur(), end, 60)
		s := buildSeries(wd.Metric, step, ts, bs)
		out = map[string]any{"step": s.Step, "t": s.T, "series": s.Series, "unit": s.Unit}
	case "scatter":
		list := recs
		if len(list) > 6000 {
			// keep every error, thin out the rest evenly
			k := (len(list) + 5999) / 6000
			thin := make([]ReqRec, 0, 6000+64)
			for i, r := range list {
				if i%k == 0 || r.Status >= 400 {
					thin = append(thin, r)
				}
			}
			list, partial = thin, true
		}
		out = scatterPoints(list)
		out["from"], out["to"] = end.Add(-wd.dur()).UnixMilli(), end.UnixMilli()
	case "top":
		out = topFrom(wd, recs)
	case "map":
		out = mapFrom(wd, recs)
	}
	if out == nil {
		out = map[string]any{}
	}
	if partial {
		out["partial"] = true
	}
	out["filtered"] = true
	if !live {
		out["history"] = true
	}
	return out
}

// statFromBuckets: the request-based numbers of a stat panel.
func statFromBuckets(metric string, tot, last Bucket, bs []Bucket, ts []int64) map[string]any {
	out := map[string]any{}
	spark := make([]float64, len(bs))
	val, unit := 0.0, ""
	switch metric {
	case "rpm":
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
			if metric == "err5xx" {
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
	}
	out["value"], out["unit"], out["spark"], out["t"] = val, unit, spark, ts
	return out
}

// GET /api/dash/vars — choices for the dashboard variables: sites and countries seen in 7 days.
func (a *App) getDashVars(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	from := time.Now().Add(-7 * 24 * time.Hour).UnixMilli()
	type kv struct {
		Key string `json:"key"`
		N   int    `json:"n"`
	}
	read := func(col string) []kv {
		rows, err := a.ldb.r.QueryContext(ctx, `SELECT `+col+`, COUNT(*) FROM requests WHERE ts>=? AND IFNULL(`+col+`,'')<>'' GROUP BY 1 ORDER BY 2 DESC LIMIT 100`, from)
		if err != nil {
			return []kv{}
		}
		defer rows.Close()
		out := []kv{}
		for rows.Next() {
			var x kv
			if rows.Scan(&x.Key, &x.N) == nil {
				out = append(out, x)
			}
		}
		return out
	}
	hosts := read("host")
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h.Key] = true
	}
	// sites without traffic yet are choices too
	d := a.store.Snapshot()
	for _, s := range d.Services {
		if s.Enabled && !s.DNSOnly {
			fq := strings.ToLower(d.Settings.FQDN(s.Subdomain))
			if !seen[fq] {
				hosts = append(hosts, kv{Key: fq})
			}
		}
	}
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].N > hosts[j].N })
	writeJSON(w, 200, map[string]any{"hosts": hosts, "countries": read("cc"), "vias": []string{"cf", "direct", "lan", "tailnet", "hidden"}})
}
