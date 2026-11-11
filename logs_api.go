package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- logs API

func (a *App) getLogStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	a.ldb.mu.Lock()
	disk, busy, done := a.ldb.disk, a.ldb.busy, a.ldb.busyDone
	a.ldb.mu.Unlock()
	st := a.store.Snapshot().Settings
	writeJSON(w, 200, map[string]any{
		"disk": disk, "dbBytes": a.ldb.dbBytes(), "counts": a.ldb.Counts(ctx), "writer": a.ldb.Stats(),
		"busy": busy, "busyDone": done, "level": levelNames[a.ldb.level.Load()],
		"thresholds": map[string]int{"warn": st.DiskWarnPct, "critical": st.DiskCritPct, "stop": st.DiskStopPct},
	})
}

func qInt(r *http.Request, k string) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get(k), 10, 64)
	return v
}

func (a *App) getLogEvents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	q := r.URL.Query()
	evs, err := a.ldb.QueryEvents(ctx, EventQuery{Cat: q.Get("cat"), Q: q.Get("q"), Level: q.Get("level"), From: qInt(r, "from"), To: qInt(r, "to"), Before: qInt(r, "before"), Limit: int(qInt(r, "limit"))})
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"events": evs})
}

func reqQueryFrom(r *http.Request) ReqQuery {
	q := r.URL.Query()
	f := func(k string) float64 { v, _ := strconv.ParseFloat(q.Get(k), 64); return v }
	return ReqQuery{From: qInt(r, "from"), To: qInt(r, "to"), Host: q.Get("host"), Q: q.Get("q"), Status: q.Get("status"),
		MinMs: f("min"), MaxMs: f("max"), Before: qInt(r, "before"), Limit: int(qInt(r, "limit"))}
}

func (a *App) getLogRequests(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rows, err := a.ldb.QueryRequests(ctx, reqQueryFrom(r))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"requests": rows})
}

// getLogExport streams CSV (max 100 000 rows), newest first.
func (a *App) getLogExport(w http.ResponseWriter, r *http.Request) {
	cat := r.URL.Query().Get("cat")
	switch cat {
	case "requests", "audit", "security", "system":
	default:
		fail(w, 400, errors.New("알 수 없는 로그 종류"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="gilmok-%s-%s.csv"`, cat, time.Now().Format("20060102-1504")))
	_, _ = w.Write([]byte("\xEF\xBB\xBF")) // BOM: Excel reads UTF-8 Korean
	cw := csv.NewWriter(w)
	total := 0
	if cat == "requests" {
		q := reqQueryFrom(r)
		q.Limit = 5000
		_ = cw.Write([]string{"time", "host", "method", "uri", "status", "ms", "size", "client_ip"})
		for total < 100000 {
			rows, err := a.ldb.QueryRequests(ctx, q)
			if err != nil || len(rows) == 0 {
				break
			}
			for _, x := range rows {
				_ = cw.Write(csvSafe(time.UnixMilli(x.T).Format(time.RFC3339), x.Host, x.Method, x.URI, strconv.Itoa(x.Status), strconv.FormatFloat(x.Ms, 'f', 2, 64), strconv.FormatInt(x.Size, 10), x.IP))
			}
			total += len(rows)
			q.Before = rows[len(rows)-1].ID
			cw.Flush()
		}
	} else {
		q := EventQuery{Cat: cat, Q: r.URL.Query().Get("q"), Level: r.URL.Query().Get("level"), From: qInt(r, "from"), To: qInt(r, "to"), Limit: 500}
		_ = cw.Write([]string{"time", "category", "level", "actor", "action", "target", "message", "ip", "detail"})
		for total < 100000 {
			evs, err := a.ldb.QueryEvents(ctx, q)
			if err != nil || len(evs) == 0 {
				break
			}
			for _, e := range evs {
				_ = cw.Write(csvSafe(time.UnixMilli(e.Ts).Format(time.RFC3339), e.Cat, e.Level, e.Actor, e.Action, e.Target, e.Msg, e.IP, e.Detail))
			}
			total += len(evs)
			q.Before = evs[len(evs)-1].ID
			cw.Flush()
		}
	}
	cw.Flush()
	a.ldb.Event(Event{Cat: "audit", Level: "info", Action: "로그 내보내기", Target: cat, Msg: fmt.Sprintf("로그 내보내기 (%s, %d건)", cat, total), Actor: a.auth.actor(r), IP: clientIP(r)})
}

func (a *App) postLogDelete(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cats   []string `json:"cats"`
		Before int64    `json:"before"` // unix ms; 0 = everything
	}
	if err := readJSON(r, &in); err != nil || len(in.Cats) == 0 {
		fail(w, 400, errors.New("지울 로그 종류를 고르세요"))
		return
	}
	for _, c := range in.Cats {
		if _, ok := logTables[c]; !ok {
			fail(w, 400, fmt.Errorf("알 수 없는 로그 종류: %s", c))
			return
		}
	}
	if !a.ldb.setBusy("로그 삭제") {
		fail(w, 409, errors.New("다른 정리 작업이 진행 중입니다. 잠시 후 다시 시도하세요"))
		return
	}
	actor, ip := a.auth.actor(r), clientIP(r)
	go func() {
		defer a.ldb.setBusy("")
		var parts []string
		for _, c := range in.Cats {
			n, err := a.ldb.deleteBefore(c, in.Before)
			if err != nil {
				parts = append(parts, fmt.Sprintf("%s 오류: %v", c, err))
				continue
			}
			parts = append(parts, fmt.Sprintf("%s %d건", c, n))
		}
		a.ldb.vacuum()
		when := "전체"
		if in.Before > 0 {
			when = time.UnixMilli(in.Before).Format("2006-01-02 15:04") + " 이전"
		}
		// this record is written after the deletion, so even "delete all audit logs" leaves a trace
		a.ldb.Event(Event{Cat: "audit", Level: "critical", Action: "로그 삭제 결과", Target: strings.Join(in.Cats, ","), Msg: fmt.Sprintf("로그 삭제 (%s): %s", when, strings.Join(parts, ", ")), Actor: actor, IP: ip})
	}()
	writeJSON(w, 200, map[string]any{"ok": true, "started": true})
}

// ---------------------------------------------------------------- docker containers (picker)

type CtrItem struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Project string `json:"project,omitempty"`
}

func (a *App) getContainers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "ps", "-a", "--format", "{{json .}}")
	if err != nil {
		fail(w, 502, fmt.Errorf("docker 목록을 읽지 못했습니다: %s", oneLine(out)))
		return
	}
	list := []CtrItem{}
	for _, l := range strings.Split(out, "\n") {
		var c struct{ Names, Image, State, Status, Labels string }
		if json.Unmarshal([]byte(strings.TrimSpace(l)), &c) != nil || c.Names == "" {
			continue
		}
		it := CtrItem{Name: c.Names, Image: c.Image, State: c.State, Status: c.Status}
		for _, kv := range strings.Split(c.Labels, ",") {
			if v, ok := strings.CutPrefix(kv, "com.docker.compose.project="); ok {
				it.Project = v
			}
		}
		list = append(list, it)
	}
	writeJSON(w, 200, map[string]any{"containers": list})
}

// ---------------------------------------------------------------- self detection

// detectSelf records this container's name and, if not chosen yet, which service is Gilmok's
// own site (its upstream points at this container) — that site gets the proxy secret header.
func (a *App) detectSelf() {
	name, _ := hostnameSelf()
	_ = a.store.Update(func(d *Data) error {
		d.SelfName = name
		if d.Settings.SecSelfService != "" {
			for _, s := range d.Services {
				if s.ID == d.Settings.SecSelfService {
					return nil
				}
			}
			d.Settings.SecSelfService = ""
		}
		if name == "" {
			return nil
		}
		for _, s := range d.Services {
			host := strings.SplitN(upstreamAddr(s.Upstream), ":", 2)[0]
			if strings.EqualFold(host, name) {
				d.Settings.SecSelfService = s.ID
				break
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------- Authelia log stream → security events

var (
	reAuthUser = regexp.MustCompile(`(?i)(?:by user|user)\s+'([^']+)'`)
	reAuthIP   = regexp.MustCompile(`remote_ip"?[=:]\s*"?([0-9a-fA-F:.]+)`)
	reAuthMsg  = regexp.MustCompile(`msg="((?:[^"\\]|\\.)*)"`)
)

func classifyAutheliaLine(line string) (level, action, msg string, ok bool) {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "unsuccessful") && (strings.Contains(l, "1fa") || strings.Contains(l, "authentication")):
		return "warn", "authelia.login.fail", "Authelia 1단계 로그인 실패", true
	case strings.Contains(l, "unsuccessful") && (strings.Contains(l, "totp") || strings.Contains(l, "2fa") || strings.Contains(l, "webauthn") || strings.Contains(l, "duo")):
		return "warn", "authelia.2fa.fail", "Authelia 2단계 인증 실패", true
	case strings.Contains(l, "regulation") || strings.Contains(l, "banned") || strings.Contains(l, "too many"):
		return "error", "authelia.ban", "Authelia 반복 실패로 사용자 일시 차단", true
	case strings.Contains(l, "successful") && strings.Contains(l, "authentication attempt"):
		return "info", "authelia.login", "Authelia 로그인 성공", true
	}
	return "", "", "", false
}

func (a *App) autheliaStreamLoop() {
	time.Sleep(5 * time.Second)
	for {
		st := a.store.Snapshot().Settings
		if !st.UseAuthelia {
			time.Sleep(30 * time.Second)
			continue
		}
		ctr := st.AutheliaCtr
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, "docker", "logs", "-f", "--tail", "0", ctr)
		pr, pw := io.Pipe()
		cmd.Stdout, cmd.Stderr = pw, pw
		if err := cmd.Start(); err == nil {
			go func() { _ = cmd.Wait(); pw.Close() }()
			go func() {
				for ctx.Err() == nil {
					time.Sleep(15 * time.Second)
					if a.store.Snapshot().Settings.AutheliaCtr != ctr {
						cancel()
					}
				}
			}()
			sc := bufio.NewScanner(pr)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				line := sc.Text()
				lvl, act, msg, ok := classifyAutheliaLine(line)
				if !ok {
					continue
				}
				e := Event{Cat: "security", Level: lvl, Action: act, Msg: msg, Actor: "authelia"}
				if m := reAuthUser.FindStringSubmatch(line); m != nil {
					e.Target = m[1]
				}
				if m := reAuthIP.FindStringSubmatch(line); m != nil {
					e.IP = m[1]
				}
				if m := reAuthMsg.FindStringSubmatch(line); m != nil {
					e.Detail = `{"msg":` + strconv.Quote(m[1]) + `}`
				}
				if act == "authelia.login" {
					e.Cat = "audit"
				}
				a.ldb.Event(e)
			}
		}
		cancel()
		time.Sleep(10 * time.Second)
	}
}

// csvSafe: cells that a spreadsheet would read as a formula (=, +, -, @, tab, CR) get a leading
// apostrophe. Log fields hold attacker-chosen text (request URIs, user agents, names).
func csvSafe(cells ...string) []string {
	for i, c := range cells {
		if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
			cells[i] = "'" + c
		}
	}
	return cells
}
