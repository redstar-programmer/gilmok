package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// How Gilmok drives Caddy (Settings.CaddyMode):
//
//	docker — `docker exec <container> caddy …` (default; Caddy in Docker)
//	native — the caddy binary on the same machine as Gilmok (Gilmok itself runs natively,
//	         e.g. gilmok.exe next to a Windows Caddy service)
//	api    — Caddy's admin API (e.g. Gilmok in Docker Desktop → native Windows Caddy at
//	         http://host.docker.internal:2019). Validation = POST /adapt, apply = POST /load
//	         (Caddy keeps the old config when the new one fails to load).

func caddyMode(st Settings) string {
	if st.CaddyMode == "" {
		return "docker"
	}
	return st.CaddyMode
}

func caddyErr(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "Error:") {
			return strings.TrimSpace(l)
		}
	}
	return lastLines(out, 8)
}

func localCaddy(st Settings, args ...string) (string, error) {
	bin := st.CaddyBin
	if bin == "" {
		bin = "caddy"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

var adminHTTP = &http.Client{Timeout: 30 * time.Second}

func caddyAdmin(st Settings, method, path, ctype string, body []byte) (string, error) {
	req, err := http.NewRequest(method, strings.TrimRight(st.CaddyAdmin, "/")+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	res, err := adminHTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("Caddy 관리 API(%s)에 연결하지 못했습니다: %v", st.CaddyAdmin, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		// only a short excerpt: the body is whatever that address answered, not necessarily Caddy
		return "", fmt.Errorf("Caddy 관리 API HTTP %d: %s", res.StatusCode, truncate(oneLine(string(b)), 300))
	}
	return string(b), nil
}

// validateCaddy checks a candidate Caddyfile without applying it.
func validateCaddy(st Settings, content string) error {
	switch caddyMode(st) {
	case "native":
		f, err := os.CreateTemp("", "gilmok-candidate-*.caddyfile")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		_, _ = f.WriteString(content)
		f.Close()
		// relative paths in the Caddyfile resolve like the real file: run from its folder
		if out, err := localCaddy(st, "validate", "--config", f.Name(), "--adapter", "caddyfile"); err != nil {
			return fmt.Errorf("Caddy 검증 실패:\n%s", caddyErr(out))
		}
		return nil
	case "api":
		// /adapt parses the Caddyfile (unknown directives, syntax); provisioning errors surface at /load
		if out, err := caddyAdmin(st, "POST", "/adapt", "text/caddyfile", []byte(content)); err != nil {
			return fmt.Errorf("Caddy 검증 실패:\n%s", oneLine(out+" "+err.Error()))
		}
		return nil
	}
	out, err := ctrExec(st.CaddyContainer, []byte(content), "caddy", "validate", "--config", "/dev/stdin", "--adapter", "caddyfile")
	if err != nil {
		return fmt.Errorf("Caddy 검증 실패:\n%s", caddyErr(out))
	}
	return nil
}

// reloadCaddy applies the Caddyfile on disk (zero downtime).
func reloadCaddy(st Settings) error {
	switch caddyMode(st) {
	case "native":
		if out, err := localCaddy(st, "reload", "--config", st.CaddyfilePath, "--adapter", "caddyfile"); err != nil {
			return fmt.Errorf("Caddy reload 실패:\n%s", caddyErr(out))
		}
		return nil
	case "api":
		b, err := os.ReadFile(st.CaddyfilePath)
		if err != nil {
			return err
		}
		if out, err := caddyAdmin(st, "POST", "/load", "text/caddyfile", b); err != nil {
			return fmt.Errorf("Caddy 적용 실패 (Caddy는 이전 설정을 유지합니다):\n%s", oneLine(out+" "+err.Error()))
		}
		return nil
	}
	out, err := ctrExec(st.CaddyContainer, nil, "caddy", "reload", "--config", st.CaddyfileInCtr, "--adapter", "caddyfile")
	if err != nil {
		return fmt.Errorf("Caddy reload 실패:\n%s", lastLines(out, 8))
	}
	return nil
}

// caddyVersion returns the running Caddy's version ("" if unknown).
func caddyVersion(st Settings) (string, error) {
	switch caddyMode(st) {
	case "native":
		out, err := localCaddy(st, "version")
		return strings.Fields(out + " ")[0], err
	case "api":
		_, err := caddyAdmin(st, "GET", "/config/", "", nil)
		if err != nil {
			return "", err
		}
		return "(관리 API)", nil
	}
	out, err := ctrExec(st.CaddyContainer, nil, "caddy", "version")
	return strings.Fields(out + " ")[0], err
}

// caddyHasWAFMode: is the Coraza module compiled in?
func caddyHasWAFMode(st Settings) (bool, error) {
	switch caddyMode(st) {
	case "native":
		out, err := localCaddy(st, "list-modules")
		if err != nil {
			return false, errors.New(oneLine(out))
		}
		return strings.Contains(out, wafModule), nil
	case "api":
		_, err := caddyAdmin(st, "POST", "/adapt", "text/caddyfile", []byte(":1 {\n\troute {\n\t\tcoraza_waf {\n\t\t}\n\t}\n}\n"))
		if err == nil {
			return true, nil
		}
		if strings.Contains(err.Error(), "unrecognized directive") {
			return false, nil
		}
		return false, err
	}
	return caddyHasWAF(st.CaddyContainer)
}

// caddyConnChecks: the "connection" part of the Caddy check for non-docker modes.
func caddyConnChecks(r *CheckResult, st Settings) bool {
	switch caddyMode(st) {
	case "native":
		v, err := caddyVersion(st)
		if err != nil {
			r.add("ctr", "Caddy 실행 파일", "fail", fmt.Sprintf("%s 를 실행하지 못했습니다: %v (설정의 caddy 경로 확인)", st.CaddyBin, err))
			return false
		}
		r.add("ctr", "Caddy 실행 파일", "ok", fmt.Sprintf("%s · %s", st.CaddyBin, v))
		if _, err := localCaddy(st, "reload", "--help"); err != nil {
			r.add("admin", "로컬 관리 API", "warn", "caddy reload는 Caddy의 localhost:2019 관리 API를 씁니다 — Caddy가 실행 중인지 확인하세요")
		}
		r.Container = &CtrStatus{Name: filepath.Base(st.CaddyBin), Exists: true, State: "native", Version: v}
		return true
	case "api":
		if _, err := caddyAdmin(st, "GET", "/config/", "", nil); err != nil {
			r.add("ctr", "Caddy 관리 API", "fail", err.Error()+" — Caddyfile 전역 옵션에 admin 주소와 origins를 지정하고, 방화벽에서 Docker(WSL) 대역만 허용하세요")
			return false
		}
		r.add("ctr", "Caddy 관리 API", "ok", st.CaddyAdmin)
		r.Container = &CtrStatus{Name: st.CaddyAdmin, Exists: true, State: "admin API", Version: "(관리 API)"}
		return true
	}
	return false
}
