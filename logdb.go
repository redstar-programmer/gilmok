package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Persistent logging (SQLite, /data/gilmok-logs.db).
//
// Concurrency / I/O design — nothing in the request path ever waits for the disk:
//   - one writer goroutine owns the write connection; producers enqueue into buffered channels
//     with a non-blocking send (full queue → the record is dropped and counted, never blocks)
//   - writes are batched (≤1 s or 1000 records) into a single transaction; WAL journal,
//     synchronous=NORMAL, busy_timeout so readers never block the writer
//   - reads use a separate pool with per-query timeouts
//   - deletes (retention, size cap, user deletes) run in 5000-row chunks with short pauses
//   - no application lock (store / monitor) is ever held while calling the DB
//
// Disk guard: free space of the /data filesystem is checked every 30 s.
//   level 1 warn (< DiskWarnPct) · 2 critical (< DiskCritPct) · 3 stop (< DiskStopPct):
//   at "stop" request logs and metrics are not written; audit/security/system events continue
//   (tiny) unless LogKeepEventsOnStop is off, and never below 1 % free.

const (
	LvlOK = iota
	LvlWarn
	LvlCrit
	LvlStop
)

var levelNames = []string{"ok", "warn", "critical", "stop"}

type Event struct {
	ID     int64  `json:"id"`
	Ts     int64  `json:"ts"` // unix ms
	Cat    string `json:"cat"`
	Level  string `json:"level"` // info | warn | error | critical
	Actor  string `json:"actor,omitempty"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Msg    string `json:"msg"`
	Detail string `json:"detail,omitempty"` // JSON
	IP     string `json:"ip,omitempty"`
}

type metricRow struct {
	Ts   int64 // unix seconds, minute aligned
	Host string
	B    Bucket
}

type LogStats struct {
	Queued    int       `json:"queued"`
	Written   int64     `json:"written"`
	Dropped   int64     `json:"dropped"` // queue full / write error
	Skipped   int64     `json:"skipped"` // disabled or disk guard
	LastFlush time.Time `json:"lastFlush"`
	LastErr   string    `json:"lastErr,omitempty"`
}

type DiskState struct {
	Path    string    `json:"path"`
	Total   uint64    `json:"total"`
	Free    uint64    `json:"free"`
	FreePct float64   `json:"freePct"`
	Level   string    `json:"level"`
	DBBytes int64     `json:"dbBytes"`
	Checked time.Time `json:"checked"`
	Err     string    `json:"err,omitempty"`
}

type LogDB struct {
	path string
	w    *sql.DB
	r    *sql.DB
	reqs chan ReqRec
	mets chan []metricRow
	evs  chan Event

	level      atomic.Int32
	floor      atomic.Bool // < 1 % free: write nothing
	reqOn      atomic.Bool
	metOn      atomic.Bool
	keepEvents atomic.Bool
	written    atomic.Int64
	dropped    atomic.Int64
	skipped    atomic.Int64

	mu       sync.Mutex
	lastErr  string
	lastFl   time.Time
	disk     DiskState
	busy     string // running maintenance job (delete / prune)
	busyDone int64
}

func openLogDB(path string) (*LogDB, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	fresh := false
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		fresh = true
	}
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	if fresh {
		if _, err := w.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			return nil, err
		}
	}
	schema := []string{
		`CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, host TEXT NOT NULL, method TEXT, uri TEXT, status INTEGER, ms REAL, size INTEGER, ip TEXT)`,
		`CREATE INDEX IF NOT EXISTS req_ts ON requests(ts)`,
		`CREATE INDEX IF NOT EXISTS req_host_ts ON requests(host, ts)`,
		`CREATE TABLE IF NOT EXISTS metrics(ts INTEGER NOT NULL, host TEXT NOT NULL, n INTEGER, s2 INTEGER, s3 INTEGER, s4 INTEGER, s5 INTEGER, dsum REAL, dmax REAL, bytes INTEGER, waf INTEGER, hist TEXT, PRIMARY KEY(host, ts)) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS met_ts ON metrics(ts)`,
		`CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, cat TEXT NOT NULL, level TEXT, actor TEXT, action TEXT, target TEXT, msg TEXT, detail TEXT, ip TEXT)`,
		`CREATE INDEX IF NOT EXISTS ev_cat_ts ON events(cat, ts)`,
		`CREATE INDEX IF NOT EXISTS ev_ts ON events(ts)`,
	}
	for _, q := range schema {
		if _, err := w.Exec(q); err != nil {
			return nil, fmt.Errorf("log db schema: %w", err)
		}
	}
	r, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	r.SetMaxOpenConns(4)
	l := &LogDB{path: path, w: w, r: r, reqs: make(chan ReqRec, 20000), mets: make(chan []metricRow, 64), evs: make(chan Event, 4000)}
	l.reqOn.Store(true)
	l.metOn.Store(true)
	l.keepEvents.Store(true)
	go l.writer()
	return l, nil
}

// ---------------------------------------------------------------- producers (never block)

func (l *LogDB) Req(r ReqRec) {
	if l == nil {
		return
	}
	if !l.reqOn.Load() || l.level.Load() >= LvlStop || l.floor.Load() {
		l.skipped.Add(1)
		return
	}
	select {
	case l.reqs <- r:
	default:
		l.dropped.Add(1)
	}
}

func (l *LogDB) Metrics(rows []metricRow) {
	if l == nil || len(rows) == 0 {
		return
	}
	if !l.metOn.Load() || l.level.Load() >= LvlStop || l.floor.Load() {
		l.skipped.Add(int64(len(rows)))
		return
	}
	select {
	case l.mets <- rows:
	default:
		l.dropped.Add(int64(len(rows)))
	}
}

func (l *LogDB) Event(e Event) {
	if e.Ts == 0 {
		e.Ts = time.Now().UnixMilli()
	}
	if e.Level == "" {
		e.Level = "info"
	}
	// mirror to the container log as well (docker logs gilmok)
	log.Printf("[%s/%s] %s %s %s%s", e.Cat, e.Level, e.Action, e.Target, e.Msg, func() string {
		if e.Actor != "" {
			return " (" + e.Actor + ")"
		}
		return ""
	}())
	if l == nil {
		return
	}
	if l.floor.Load() || (l.level.Load() >= LvlStop && !l.keepEvents.Load()) {
		l.skipped.Add(1)
		return
	}
	select {
	case l.evs <- e:
	default:
		l.dropped.Add(1)
	}
}

// ---------------------------------------------------------------- writer

func (l *LogDB) writer() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var reqs []ReqRec
	var mets []metricRow
	var evs []Event
	flush := func() {
		n := len(reqs) + len(mets) + len(evs)
		if n == 0 {
			return
		}
		err := l.writeBatch(reqs, mets, evs)
		l.mu.Lock()
		l.lastFl = time.Now()
		if err != nil {
			l.lastErr = oneLine(err.Error())
			l.dropped.Add(int64(n))
		} else {
			l.lastErr = ""
			l.written.Add(int64(n))
		}
		l.mu.Unlock()
		reqs, mets, evs = reqs[:0], mets[:0], evs[:0]
	}
	for {
		select {
		case r := <-l.reqs:
			reqs = append(reqs, r)
			if len(reqs) >= 1000 {
				flush()
			}
		case m := <-l.mets:
			mets = append(mets, m...)
		case e := <-l.evs:
			evs = append(evs, e)
			if len(evs) >= 500 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func histStr(h []int) string {
	parts := make([]string, len(h))
	for i, v := range h {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

func parseHist(s string) []int {
	out := make([]int, len(histEdges)+1)
	for i, p := range strings.Split(s, ",") {
		if i < len(out) {
			out[i], _ = strconv.Atoi(p)
		}
	}
	return out
}

func (l *LogDB) writeBatch(reqs []ReqRec, mets []metricRow, evs []Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := l.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(reqs) > 0 {
		st, err := tx.PrepareContext(ctx, `INSERT INTO requests(ts,host,method,uri,status,ms,size,ip) VALUES(?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close() // also on an early error return
		for _, r := range reqs {
			if _, err := st.ExecContext(ctx, r.T, r.Host, r.Method, r.URI, r.Status, r.Ms, r.Size, r.IP); err != nil {
				return err
			}
		}
	}
	if len(mets) > 0 {
		st, err := tx.PrepareContext(ctx, `INSERT INTO metrics(ts,host,n,s2,s3,s4,s5,dsum,dmax,bytes,waf,hist) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(host,ts) DO UPDATE SET n=excluded.n,s2=excluded.s2,s3=excluded.s3,s4=excluded.s4,s5=excluded.s5,dsum=excluded.dsum,dmax=excluded.dmax,bytes=excluded.bytes,waf=excluded.waf,hist=excluded.hist`)
		if err != nil {
			return err
		}
		defer st.Close() // also on an early error return
		for _, m := range mets {
			b := m.B
			if _, err := st.ExecContext(ctx, m.Ts, m.Host, b.N, b.S2, b.S3, b.S4, b.S5, b.DurSum, b.DurMax, b.Bytes, b.Waf, histStr(b.Hist)); err != nil {
				return err
			}
		}
	}
	if len(evs) > 0 {
		st, err := tx.PrepareContext(ctx, `INSERT INTO events(ts,cat,level,actor,action,target,msg,detail,ip) VALUES(?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close() // also on an early error return
		for _, e := range evs {
			if _, err := st.ExecContext(ctx, e.Ts, e.Cat, e.Level, e.Actor, e.Action, e.Target, e.Msg, e.Detail, e.IP); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (l *LogDB) Stats() LogStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return LogStats{Queued: len(l.reqs) + len(l.evs), Written: l.written.Load(), Dropped: l.dropped.Load(), Skipped: l.skipped.Load(), LastFlush: l.lastFl, LastErr: l.lastErr}
}

// usedBytes: pages that hold data (page_count − freelist_count). The file sizes (dbBytes) do not
// shrink right after a delete — the WAL keeps its size until a checkpoint succeeds and free pages
// stay in the file — so the size-cap loop must measure this, or it keeps deleting recent data.
func (l *LogDB) usedBytes() int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var pc, fc, ps int64
	if l.r.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pc) != nil ||
		l.r.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&fc) != nil ||
		l.r.QueryRowContext(ctx, "PRAGMA page_size").Scan(&ps) != nil {
		return l.dbBytes()
	}
	return (pc - fc) * ps
}

func (l *LogDB) dbBytes() int64 {
	var n int64
	for _, suf := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(l.path + suf); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// ---------------------------------------------------------------- maintenance (chunked deletes)

var logTables = map[string]struct{ table, where string }{
	"requests": {"requests", ""},
	"metrics":  {"metrics", ""},
	"audit":    {"events", "cat='audit'"},
	"security": {"events", "cat='security'"},
	"system":   {"events", "cat='system'"},
}

// deleteBefore removes rows of a category older than beforeMs (0 = everything), in chunks.
func (l *LogDB) deleteBefore(cat string, beforeMs int64) (int64, error) {
	t, ok := logTables[cat]
	if !ok {
		return 0, errors.New("알 수 없는 로그 종류")
	}
	conds := []string{}
	if t.where != "" {
		conds = append(conds, t.where)
	}
	tsCol := "ts"
	cut := beforeMs
	if t.table == "metrics" {
		cut = beforeMs / 1000 // seconds
	}
	if beforeMs > 0 {
		conds = append(conds, fmt.Sprintf("%s < %d", tsCol, cut))
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	key := "rowid"
	if t.table == "metrics" {
		key = "host||'/'||ts" // WITHOUT ROWID: delete by key range instead
	}
	var total int64
	for {
		var res sql.Result
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if t.table == "metrics" {
			res, err = l.w.ExecContext(ctx, `DELETE FROM metrics WHERE (host, ts) IN (SELECT host, ts FROM metrics`+where+` LIMIT 5000)`)
		} else {
			res, err = l.w.ExecContext(ctx, `DELETE FROM `+t.table+` WHERE `+key+` IN (SELECT `+key+` FROM `+t.table+where+` LIMIT 5000)`)
		}
		cancel()
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		l.mu.Lock()
		l.busyDone = total
		l.mu.Unlock()
		if n < 5000 {
			break
		}
		time.Sleep(50 * time.Millisecond) // let the writer in between chunks
	}
	return total, nil
}

func (l *LogDB) vacuum() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, _ = l.w.ExecContext(ctx, "PRAGMA incremental_vacuum(20000)")
	_, _ = l.w.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
}

func (l *LogDB) setBusy(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s != "" && l.busy != "" {
		return false
	}
	l.busy, l.busyDone = s, 0
	return true
}

// ---------------------------------------------------------------- queries (read pool, timeouts)

type EventQuery struct {
	Cat, Q, Level string
	From, To      int64
	Before        int64 // id cursor
	Limit         int
}

func (l *LogDB) QueryEvents(ctx context.Context, q EventQuery) ([]Event, error) {
	conds, args := []string{"1=1"}, []any{}
	if q.Cat != "" {
		conds, args = append(conds, "cat=?"), append(args, q.Cat)
	}
	if q.Level != "" {
		conds, args = append(conds, "level=?"), append(args, q.Level)
	}
	if q.From > 0 {
		conds, args = append(conds, "ts>=?"), append(args, q.From)
	}
	if q.To > 0 {
		conds, args = append(conds, "ts<=?"), append(args, q.To)
	}
	if q.Before > 0 {
		conds, args = append(conds, "id<?"), append(args, q.Before)
	}
	if s := strings.TrimSpace(q.Q); s != "" {
		like := "%" + strings.NewReplacer("%", `\%`, "_", `\_`).Replace(s) + "%"
		conds = append(conds, `(msg LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\' OR action LIKE ? ESCAPE '\' OR actor LIKE ? ESCAPE '\' OR ip LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like, like, like)
	}
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	rows, err := l.r.QueryContext(ctx, `SELECT id,ts,cat,level,IFNULL(actor,''),IFNULL(action,''),IFNULL(target,''),IFNULL(msg,''),IFNULL(detail,''),IFNULL(ip,'') FROM events WHERE `+strings.Join(conds, " AND ")+` ORDER BY id DESC LIMIT ?`, append(args, q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Ts, &e.Cat, &e.Level, &e.Actor, &e.Action, &e.Target, &e.Msg, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type ReqQuery struct {
	From, To  int64
	Host, Q   string
	Status    string // "", 2xx, 3xx, 4xx, 5xx or exact code
	MinMs     float64
	MaxMs     float64
	Before    int64
	Limit     int
	SlowFirst bool
}

type ReqRow struct {
	ID int64 `json:"id"`
	ReqRec
}

func (l *LogDB) QueryRequests(ctx context.Context, q ReqQuery) ([]ReqRow, error) {
	conds, args := []string{"1=1"}, []any{}
	if q.From > 0 {
		conds, args = append(conds, "ts>=?"), append(args, q.From)
	}
	if q.To > 0 {
		conds, args = append(conds, "ts<=?"), append(args, q.To)
	}
	if q.Host != "" {
		conds, args = append(conds, "host=?"), append(args, strings.ToLower(q.Host))
	}
	if s := q.Status; s != "" {
		if len(s) == 3 && s[1:] == "xx" && s[0] >= '1' && s[0] <= '5' {
			lo := int(s[0]-'0') * 100
			conds, args = append(conds, "status>=? AND status<?"), append(args, lo, lo+100)
		} else if n, err := strconv.Atoi(s); err == nil {
			conds, args = append(conds, "status=?"), append(args, n)
		}
	}
	if q.MinMs > 0 {
		conds, args = append(conds, "ms>=?"), append(args, q.MinMs)
	}
	if q.MaxMs > 0 {
		conds, args = append(conds, "ms<=?"), append(args, q.MaxMs)
	}
	if q.Before > 0 {
		conds, args = append(conds, "id<?"), append(args, q.Before)
	}
	if s := strings.TrimSpace(q.Q); s != "" {
		like := "%" + strings.NewReplacer("%", `\%`, "_", `\_`).Replace(s) + "%"
		conds, args = append(conds, `(uri LIKE ? ESCAPE '\' OR ip LIKE ? ESCAPE '\' OR host LIKE ? ESCAPE '\')`), append(args, like, like, like)
	}
	if q.Limit <= 0 || q.Limit > 6000 {
		q.Limit = 100
	}
	order := "id DESC"
	if q.SlowFirst {
		order = "ms DESC"
	}
	rows, err := l.r.QueryContext(ctx, `SELECT id,ts,host,IFNULL(method,''),IFNULL(uri,''),status,ms,size,IFNULL(ip,'') FROM requests WHERE `+strings.Join(conds, " AND ")+` ORDER BY `+order+` LIMIT ?`, append(args, q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReqRow{}
	for rows.Next() {
		var x ReqRow
		if err := rows.Scan(&x.ID, &x.T, &x.Host, &x.Method, &x.URI, &x.Status, &x.Ms, &x.Size, &x.IP); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// MetricBuckets returns per-minute rows for host ("" = all sites) in [from, to) seconds.
func (l *LogDB) MetricBuckets(ctx context.Context, host string, from, to int64) (map[int64]Bucket, error) {
	rows, err := l.r.QueryContext(ctx, `SELECT ts,n,s2,s3,s4,s5,dsum,dmax,bytes,waf,IFNULL(hist,'') FROM metrics WHERE host=? AND ts>=? AND ts<?`, host, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]Bucket{}
	for rows.Next() {
		var ts int64
		var b Bucket
		var h string
		if err := rows.Scan(&ts, &b.N, &b.S2, &b.S3, &b.S4, &b.S5, &b.DurSum, &b.DurMax, &b.Bytes, &b.Waf, &h); err != nil {
			return nil, err
		}
		b.Hist = parseHist(h)
		out[ts] = b
	}
	return out, rows.Err()
}

type catStat struct {
	Rows   int64 `json:"rows"`
	Oldest int64 `json:"oldest,omitempty"` // unix ms
}

func (l *LogDB) Counts(ctx context.Context) map[string]catStat {
	out := map[string]catStat{}
	q := func(key, sqlq string, scaleSec bool) {
		var n int64
		var oldest sql.NullInt64
		if err := l.r.QueryRowContext(ctx, sqlq).Scan(&n, &oldest); err == nil {
			o := oldest.Int64
			if scaleSec {
				o *= 1000
			}
			out[key] = catStat{n, o}
		}
	}
	q("requests", `SELECT COUNT(*), MIN(ts) FROM requests`, false)
	q("metrics", `SELECT COUNT(*), MIN(ts) FROM metrics`, true)
	for _, c := range []string{"audit", "security", "system"} {
		q(c, `SELECT COUNT(*), MIN(ts) FROM events WHERE cat='`+c+`'`, false)
	}
	return out
}

// ---------------------------------------------------------------- app glue

func (a *App) logEvent(cat, level, action, target, msg string, detail any) {
	e := Event{Cat: cat, Level: level, Action: action, Target: target, Msg: msg, Actor: "system"}
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil && string(b) != "null" {
			e.Detail = truncate(string(b), 20000)
		}
	}
	a.ldb.Event(e)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// applyLogPolicy pushes the settings into the writer's switches.
func (a *App) applyLogPolicy(st Settings) {
	if a.ldb == nil {
		return
	}
	a.ldb.reqOn.Store(st.LogRequests)
	a.ldb.metOn.Store(st.LogMetrics)
	a.ldb.keepEvents.Store(st.LogKeepEventsOnStop)
}

// diskGuardLoop: free space levels, DB size cap, retention, checkpoint.
func (a *App) diskGuardLoop() {
	n := 0
	for {
		a.checkDisk()
		if n%120 == 0 { // hourly (30 s × 120)
			a.retention()
		}
		if n%10 == 0 { // 5 min
			a.ldb.mu.Lock()
			idle := a.ldb.busy == ""
			a.ldb.mu.Unlock()
			if idle {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_, _ = a.ldb.w.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")
				cancel()
			}
		}
		n++
		time.Sleep(30 * time.Second)
	}
}

func (a *App) checkDisk() {
	st := a.store.Snapshot().Settings
	total, free, err := diskUsageFn(a.dataDir)
	ds := DiskState{Path: a.dataDir, Total: total, Free: free, Checked: time.Now(), DBBytes: a.ldb.dbBytes()}
	lvl := LvlOK
	if err != nil {
		ds.Err = err.Error()
	} else if total > 0 {
		ds.FreePct = float64(free) / float64(total) * 100
		switch {
		case ds.FreePct < float64(st.DiskStopPct):
			lvl = LvlStop
		case ds.FreePct < float64(st.DiskCritPct):
			lvl = LvlCrit
		case ds.FreePct < float64(st.DiskWarnPct):
			lvl = LvlWarn
		}
		a.ldb.floor.Store(ds.FreePct < 1)
	}
	ds.Level = levelNames[lvl]
	prev := a.ldb.level.Swap(int32(lvl))
	a.ldb.mu.Lock()
	a.ldb.disk = ds
	a.ldb.mu.Unlock()
	if int(prev) != lvl {
		msgs := []string{"디스크 여유 공간 정상", "디스크 여유 공간 부족 (경고)", "디스크 여유 공간 매우 부족 (강력 경고)", "디스크 여유 공간 위험 — 요청 로그·지표 기록을 중단했습니다"}
		levels := []string{"info", "warn", "error", "critical"}
		a.logEvent("system", levels[lvl], "disk.level", a.dataDir, fmt.Sprintf("%s · 여유 %.1f%% (%s / %s)", msgs[lvl], ds.FreePct, fmtBytesGo(free), fmtBytesGo(total)), map[string]any{"from": levelNames[prev], "to": levelNames[lvl]})
	}
	// DB size cap: trim the oldest request logs first, then metrics
	if max := int64(st.LogMaxDBMB) << 20; max > 0 && ds.DBBytes > max && a.ldb.setBusy("용량 제한 정리") {
		go func() {
			defer a.ldb.setBusy("")
			deleted := a.trimToCap(max)
			a.logEvent("system", "warn", "logs.sizecap", "", fmt.Sprintf("로그 DB가 최대 크기(%d MB)를 넘어 오래된 기록 %d건을 지웠습니다", st.LogMaxDBMB, deleted), nil)
		}()
	}
}

func (a *App) oldestTs(cat string) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var v sql.NullInt64
	switch cat {
	case "requests":
		_ = a.ldb.r.QueryRowContext(ctx, `SELECT MIN(ts) FROM requests`).Scan(&v)
	case "metrics":
		_ = a.ldb.r.QueryRowContext(ctx, `SELECT MIN(ts) FROM metrics`).Scan(&v)
		v.Int64 *= 1000
	}
	return v.Int64
}

func (a *App) retention() {
	st := a.store.Snapshot().Settings
	if !a.ldb.setBusy("보존 기간 정리") {
		return
	}
	defer a.ldb.setBusy("")
	day := int64(24 * 3600 * 1000)
	now := time.Now().UnixMilli()
	var report []string
	for cat, days := range map[string]int{"requests": st.LogRetReqDays, "metrics": st.LogRetMetricDays, "audit": st.LogRetAuditDays, "security": st.LogRetSecurityDays, "system": st.LogRetSystemDays} {
		if days <= 0 {
			continue
		}
		n, err := a.ldb.deleteBefore(cat, now-int64(days)*day)
		if err != nil {
			report = append(report, fmt.Sprintf("%s 오류: %v", cat, err))
		} else if n > 0 {
			report = append(report, fmt.Sprintf("%s %d건", cat, n))
		}
	}
	if len(report) > 0 {
		a.ldb.vacuum()
		a.logEvent("system", "info", "logs.retention", "", "보존 기간이 지난 기록을 지웠습니다: "+strings.Join(report, ", "), nil)
	}
}

func fmtBytesGo(v uint64) string {
	f := float64(v)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 || u == "TB" {
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}

// metricsFlushLoop writes finished minutes (and re-writes the last two for late WAF/lines).
func (a *App) metricsFlushLoop() {
	for {
		time.Sleep(60*time.Second - time.Duration(time.Now().Second())*time.Second + 2*time.Second)
		now := time.Now().Unix() / coarseRes
		var rows []metricRow
		a.mon.mu.Lock()
		for k := now - 3; k < now; k++ {
			s := a.mon.coarse[k]
			if s == nil {
				continue
			}
			rows = append(rows, metricRow{Ts: k * coarseRes, Host: "", B: cloneBucket(s.All)})
			for h, b := range s.Hosts {
				rows = append(rows, metricRow{Ts: k * coarseRes, Host: h, B: cloneBucket(*b)})
			}
		}
		a.mon.mu.Unlock()
		a.ldb.Metrics(rows)
	}
}

func cloneBucket(b Bucket) Bucket {
	b.Hist = append([]int(nil), b.Hist...)
	if b.Hist == nil {
		b.Hist = make([]int, len(histEdges)+1)
	}
	return b
}

func (a *App) diskSummary() map[string]any {
	a.ldb.mu.Lock()
	defer a.ldb.mu.Unlock()
	return map[string]any{"level": a.ldb.disk.Level, "freePct": a.ldb.disk.FreePct, "free": a.ldb.disk.Free, "total": a.ldb.disk.Total}
}

// diskUsageFn: swapped in tests to simulate a filling disk.
var diskUsageFn = diskUsage

// trimToCap deletes the oldest request logs, then metrics, in 6-hour slices until the used size
// is under 90 % of max — never touching the last 24 hours. Returns how many rows went.
func (a *App) trimToCap(max int64) int64 {
	var deleted int64
	for _, cat := range []string{"requests", "metrics"} {
		keep := time.Now().Add(-24 * time.Hour).UnixMilli() // never trim the last day here
		for i := 0; i < 20 && a.ldb.usedBytes() > max*9/10; i++ {
			oldest := a.oldestTs(cat)
			if oldest == 0 || oldest+6*3600*1000 > keep {
				break
			}
			n, err := a.ldb.deleteBefore(cat, oldest+6*3600*1000) // 6 h slices
			deleted += n
			if err != nil || n == 0 {
				break
			}
			a.ldb.vacuum()
		}
	}
	return deleted
}
