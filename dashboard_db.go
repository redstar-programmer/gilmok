package main

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Dashboard over the log DB: used when the user looks at a past moment ("at") or at a range
// longer than the in-memory window (7d / 30d). Live views keep using memory (no DB load on
// the 5 s refresh).

func (a *App) dbSeries(ctx context.Context, rng time.Duration, end time.Time, host string, points int) (int64, []int64, []Bucket) {
	step := int64(rng.Seconds()) / int64(points)
	step = max((step+59)/60*60, 60)
	endA := end.Unix() / step * step
	start := endA - int64(rng.Seconds()) + step
	n := int((endA-start)/step) + 1
	ts := make([]int64, n)
	bs := make([]Bucket, n)
	for i := range ts {
		ts[i] = (start + int64(i)*step) * 1000
	}
	rows, err := a.ldb.MetricBuckets(ctx, host, start, endA+step)
	if err == nil {
		for t, b := range rows {
			i := int((t - start) / step)
			if i >= 0 && i < n {
				b := b
				bs[i].merge(&b)
			}
		}
	}
	return step, ts, bs
}

func (a *App) dbTotal(ctx context.Context, rng time.Duration, end time.Time, host string) Bucket {
	rows, _ := a.ldb.MetricBuckets(ctx, host, end.Unix()-int64(rng.Seconds()), end.Unix())
	var t Bucket
	for _, b := range rows {
		b := b
		t.merge(&b)
	}
	return t
}

func (a *App) dbStat(ctx context.Context, wd Widget, end time.Time) map[string]any {
	rng := ranges[wd.Range]
	_, ts, bs := a.dbSeries(ctx, rng, end, wd.Host, 30)
	tot := a.dbTotal(ctx, rng, end, wd.Host)
	out := map[string]any{"history": true}
	spark := make([]float64, len(bs))
	val, unit := 0.0, ""
	switch wd.Metric {
	case "rpm":
		last := a.dbTotal(ctx, time.Minute, end, wd.Host)
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
	default:
		return map[string]any{"liveOnly": true}
	}
	out["value"], out["unit"], out["spark"], out["t"] = val, unit, spark, ts
	return out
}

func (a *App) dbSeriesData(ctx context.Context, wd Widget, end time.Time) seriesOut {
	step, ts, bs := a.dbSeries(ctx, ranges[wd.Range], end, wd.Host, 60)
	return buildSeries(wd.Metric, step, ts, bs)
}

func buildSeries(metric string, step int64, ts []int64, bs []Bucket) seriesOut {
	o := seriesOut{Step: step, T: ts}
	col := func(key, name string, f func(b *Bucket) float64) {
		v := make([]float64, len(bs))
		for i := range bs {
			v[i] = f(&bs[i])
		}
		o.Series = append(o.Series, seriesLine{key, name, v})
	}
	switch metric {
	case "requests":
		o.Unit = "회"
		col("n", "요청", func(b *Bucket) float64 { return float64(b.N) })
	case "status":
		o.Unit = "회"
		col("s2", "2xx", func(b *Bucket) float64 { return float64(b.S2) })
		col("s3", "3xx", func(b *Bucket) float64 { return float64(b.S3) })
		col("s4", "4xx", func(b *Bucket) float64 { return float64(b.S4) })
		col("s5", "5xx", func(b *Bucket) float64 { return float64(b.S5) })
	case "latency":
		o.Unit = "ms"
		col("avg", "평균", func(b *Bucket) float64 { return math.Round(b.avg()*10) / 10 })
		col("p95", "p95", func(b *Bucket) float64 { return b.pct(0.95) })
	case "bytes":
		o.Unit = "bytes"
		col("b", "전송량", func(b *Bucket) float64 { return float64(b.Bytes) })
	case "waf":
		o.Unit = "건"
		col("w", "WAF 차단", func(b *Bucket) float64 { return float64(b.Waf) })
	}
	return o
}

func (a *App) dbScatter(ctx context.Context, wd Widget, end time.Time) map[string]any {
	from := end.Add(-ranges[wd.Range]).UnixMilli()
	rows, _ := a.ldb.QueryRequests(ctx, ReqQuery{From: from, To: end.UnixMilli(), Host: wd.Host, Limit: 6000})
	pts := make([][4]float64, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		pts = append(pts, [4]float64{float64(r.T), r.Ms, float64(r.Status), 0})
	}
	return map[string]any{"from": from, "to": end.UnixMilli(), "points": pts, "history": true}
}

// TopRequests aggregates the request log in SQL (bounded by the time index).
func (l *LogDB) TopRequests(ctx context.Context, dim string, from, to int64, host string, limit int) ([]topRow, error) {
	key := map[string]string{
		"host":   "host",
		"status": "CAST(status AS TEXT)",
		"client": "ip",
		"path":   "CASE WHEN instr(uri,'?')>0 THEN substr(uri,1,instr(uri,'?')-1) ELSE uri END",
	}[dim]
	if key == "" {
		return nil, fmt.Errorf("unknown dim")
	}
	if dim == "path" && host == "" {
		key = "host || " + key
	}
	conds, args := []string{"ts>=?", "ts<=?"}, []any{from, to}
	if host != "" {
		conds, args = append(conds, "host=?"), append(args, host)
	}
	if dim == "client" {
		conds = append(conds, "ip<>''")
	}
	rows, err := l.r.QueryContext(ctx, `SELECT `+key+` AS k, COUNT(*), AVG(ms), SUM(status>=500) FROM requests WHERE `+strings.Join(conds, " AND ")+` GROUP BY k ORDER BY 2 DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []topRow
	for rows.Next() {
		var k string
		var n, e int
		var avg float64
		if err := rows.Scan(&k, &n, &avg, &e); err != nil {
			return nil, err
		}
		out = append(out, topRow{Key: k, N: n, AvgMs: math.Round(avg), Err: math.Round(float64(e)/float64(max(n, 1))*1000) / 10})
	}
	return out, rows.Err()
}

func (a *App) dbTop(ctx context.Context, wd Widget, end time.Time) map[string]any {
	from := end.Add(-ranges[wd.Range]).UnixMilli()
	if wd.Dim == "slow" {
		rows, _ := a.ldb.QueryRequests(ctx, ReqQuery{From: from, To: end.UnixMilli(), Host: wd.Host, Limit: wd.Limit, SlowFirst: true})
		list := make([]ReqRec, 0, len(rows))
		for _, r := range rows {
			list = append(list, r.ReqRec)
		}
		return map[string]any{"slow": list, "history": true}
	}
	rows, err := a.ldb.TopRequests(ctx, wd.Dim, from, end.UnixMilli(), wd.Host, wd.Limit)
	if err != nil {
		return map[string]any{"rows": []topRow{}, "error": err.Error()}
	}
	if rows == nil {
		rows = []topRow{}
	}
	return map[string]any{"rows": rows, "history": true}
}

func (a *App) dbEvents(ctx context.Context, end time.Time) map[string]any {
	from := end.Add(-24 * time.Hour).UnixMilli()
	var evs []dashEvent
	sec, _ := a.ldb.QueryEvents(ctx, EventQuery{Cat: "security", From: from, To: end.UnixMilli(), Limit: 30})
	for _, e := range sec {
		kind := "waf"
		if !strings.HasPrefix(e.Action, "waf") {
			kind = "sec"
		}
		evs = append(evs, dashEvent{T: e.Ts, Kind: kind, Text: e.Msg, Sub: e.Target})
	}
	errs, _ := a.ldb.QueryRequests(ctx, ReqQuery{From: from, To: end.UnixMilli(), Status: "5xx", Limit: 30})
	for _, r := range errs {
		evs = append(evs, dashEvent{T: r.T, Kind: "5xx", Text: strconv.Itoa(r.Status) + " " + r.Host, Sub: r.Method + " " + r.URI})
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].T > evs[j].T })
	if len(evs) > 30 {
		evs = evs[:30]
	}
	return map[string]any{"events": evs, "history": true}
}
