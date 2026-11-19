package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Automatic image updates: once a day at Settings.AutoUpdateHour (local time), each component
// that is switched on and has a newer image is updated the same way as the button (compose
// pull / build → recreate → check it runs). The image the container ran before is remembered;
// when the new one does not come up, it is put back under the same name and the container is
// recreated with it (rollback) — the same protection applies to updates by hand.

// AutoUpdateRun: the last automatic run, for the screen.
type AutoUpdateRun struct {
	At      time.Time `json:"at"`
	Results []string  `json:"results"`
	OK      bool      `json:"ok"`
}

// autoCheck: the fresh update check before an automatic run (tests swap it).
var autoCheck = func(a *App) UpdateInfo { return a.checkUpdates() }

func autoUpdateTargets(st Settings) []string {
	var t []string
	if st.AutoUpdateCaddy && st.UseCaddy && caddyMode(st) == "docker" {
		t = append(t, "caddy")
	}
	if st.AutoUpdateAuthelia && st.UseAuthelia && autheliaInDocker(st) {
		t = append(t, "authelia")
	}
	if st.AutoUpdateCrowdSec && st.UseCrowdSec && crowdsecInDocker(st) {
		t = append(t, "crowdsec")
	}
	return t
}

// autoUpdateTick: called every few minutes by updatesLoop; acts once a day in the chosen hour.
func (a *App) autoUpdateTick(now time.Time) {
	d := a.store.Snapshot()
	targets := autoUpdateTargets(d.Settings)
	if len(targets) == 0 || now.Hour() != d.Settings.AutoUpdateHour || d.AutoUpdateDay == now.Format("2006-01-02") {
		return
	}
	_ = a.store.Update(func(x *Data) error { x.AutoUpdateDay = now.Format("2006-01-02"); return nil })
	info := autoCheck(a)
	avail := map[string]bool{}
	for _, it := range info.Items {
		if it.Available {
			avail[it.Target] = true
		}
	}
	run := AutoUpdateRun{At: now, OK: true}
	for _, t := range targets {
		if !avail[t] {
			continue
		}
		L := &logger{}
		a.applyMu.Lock()
		err := a.update(t, a.store.Snapshot().Settings, L)
		a.applyMu.Unlock()
		if err != nil {
			run.OK = false
			run.Results = append(run.Results, fmt.Sprintf("%s: 실패 — %s", t, oneLine(err.Error())))
			a.logEvent("system", "error", "update.auto", t, fmt.Sprintf("자동 업데이트 실패 (%s): %s", t, oneLine(err.Error())), map[string]any{"log": L.lines})
			continue
		}
		a.resetBaselines(t)
		run.Results = append(run.Results, fmt.Sprintf("%s: 업데이트됨", t))
		a.logEvent("system", "info", "update.auto", t, fmt.Sprintf("자동 업데이트 완료 (%s)", t), map[string]any{"log": L.lines})
	}
	if len(run.Results) == 0 {
		run.Results = []string{"새 이미지 없음"}
	}
	_ = a.store.Update(func(x *Data) error { x.AutoUpdateLast = &run; return nil })
}

// ctrImage: the image a container runs (ID) and the name it was created from.
func ctrImage(ctr string) (id, ref string) {
	ctx, cancel := withTimeout(15 * time.Second)
	defer cancel()
	out, err := docker(ctx, nil, nil, "inspect", "-f", "{{.Image}}|{{.Config.Image}}", ctr)
	if err != nil {
		return "", ""
	}
	id, ref, _ = strings.Cut(strings.TrimSpace(out), "|")
	return id, ref
}

// backupRef: the name the image a container ran before an update is kept under — an untagged
// image can be deleted as soon as the new build or pull takes its name (Docker Desktop's
// containerd store does, seen in testing), so it gets a name of its own.
func backupRef(ref string) string {
	repo := ref
	if i := strings.Index(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	return repo + ":gilmok-prev"
}

// keepPrevious names the running image <repo>:gilmok-prev before an update (one per repository,
// replaced by the next update).
func keepPrevious(oldID, ref string, log func(string, ...any)) {
	if oldID == "" || ref == "" {
		return
	}
	ctx, cancel := withTimeout(30 * time.Second)
	defer cancel()
	if out, err := docker(ctx, nil, nil, "tag", oldID, backupRef(ref)); err != nil {
		log("! 지금 이미지를 백업 이름으로 남기지 못했습니다 (실패 시 되돌리기 불가): %s", oneLine(out))
	}
}

// rollbackImage puts the previous image (kept as <repo>:gilmok-prev) back under the name compose
// uses and recreates the container with it (compose up uses the local image; it does not pull).
func rollbackImage(t ComposeTarget, env []string, oldID, ref string, log func(string, ...any)) error {
	if oldID == "" || ref == "" {
		return fmt.Errorf("이전 이미지를 알 수 없어 되돌릴 수 없습니다")
	}
	ctx, cancel := withTimeout(5 * time.Minute)
	defer cancel()
	log("↺ 이전 이미지로 되돌리는 중 (%s → %s)", backupRef(ref), ref)
	if out, err := docker(ctx, nil, nil, "tag", backupRef(ref), ref); err != nil {
		return fmt.Errorf("이전 이미지 태그 실패: %s", oneLine(out))
	}
	out, err := docker(ctx, nil, env, t.args("up", "-d", "--no-deps", "--pull", "never", t.Service)...)
	log("%s", lastLines(out, 4))
	return err
}

// verifyPause: the wait between checks of a recreated container (tests shorten it).
var verifyPause = 3 * time.Second

// verifyUpdated: the recreated container runs the way it should.
func (a *App) verifyUpdated(target, ctr string, since time.Time, L *logger) error {
	switch target {
	case "caddy":
		var last string
		for i := 0; i < 10; i++ {
			time.Sleep(verifyPause)
			v, e := ctrExec(ctr, nil, "caddy", "version")
			if e == nil {
				L.f("✓ Caddy %s", strings.Fields(v + " ")[0])
				// and it accepts its own Caddyfile (modules present)
				cf := a.store.Snapshot().Settings.CaddyfileInCtr
				if cf == "" {
					cf = "/etc/caddy/Caddyfile"
				}
				if out, err := ctrExec(ctr, nil, "caddy", "validate", "--config", cf, "--adapter", "caddyfile"); err != nil {
					return fmt.Errorf("새 Caddy가 지금 Caddyfile을 받지 못합니다: %s", caddyErr(out))
				}
				return nil
			}
			last = v
		}
		return fmt.Errorf("새 Caddy 컨테이너 확인 실패: %s", oneLine(last))
	case "authelia":
		if err := waitHealthy(ctr, since, "Startup complete", 60*time.Second); err != nil {
			return err
		}
		L.f("✓ Authelia 정상 시작")
	case "crowdsec":
		st := a.store.Snapshot().Settings
		var err error
		for i := 0; i < 30; i++ {
			time.Sleep(verifyPause)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err = csDecisions(ctx, st)
			cancel()
			if err == nil {
				L.f("✓ CrowdSec LAPI 응답")
				return nil
			}
		}
		return fmt.Errorf("새 CrowdSec이 응답하지 않습니다: %v", err)
	}
	return nil
}
