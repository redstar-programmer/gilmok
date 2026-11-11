package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Cloudflare API token: where it comes from, in priority order
//
//	1. GM_CF_TOKEN_FILE (container secret file)   — set by the deployment
//	2. GM_CF_TOKEN      (container env)
//	3. <data>/secrets/cf_token                     — entered in the UI (Cloudflare tab)
//
// The value is never returned by the API or written to logs; the UI only sees the source.

var cfTokenUIPath string // set in main(): <data>/secrets/cf_token

func cfTokenSource() (tok, src string) {
	if p := os.Getenv("GM_CF_TOKEN_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, "container-file"
			}
		}
	}
	if t := strings.TrimSpace(os.Getenv("GM_CF_TOKEN")); t != "" {
		return t, "container-env"
	}
	if cfTokenUIPath != "" {
		if b, err := os.ReadFile(cfTokenUIPath); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, "ui"
			}
		}
	}
	return "", ""
}

func cfTokenSourceName() string {
	_, src := cfTokenSource()
	return src
}

func cfToken() string {
	t, _ := cfTokenSource()
	return t
}

var reCFToken = regexp.MustCompile(`^[A-Za-z0-9_\-]{30,200}$`)

// cfCall makes one Cloudflare API call with an explicit token (used to verify before saving).
func cfCall(ctx context.Context, tok, path string) (*cfResp, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cfAPI+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare에 연결하지 못했습니다: %v", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var r cfResp
	if json.Unmarshal(b, &r) != nil {
		return nil, fmt.Errorf("Cloudflare 응답을 해석하지 못했습니다 (HTTP %d)", res.StatusCode)
	}
	r.status = res.StatusCode
	return &r, nil
}

// verifyCFToken checks that the token is active and can see the zone of this installation.
func verifyCFToken(ctx context.Context, tok, domain string) (zoneID string, err error) {
	r, err := cfCall(ctx, tok, "/user/tokens/verify")
	if err != nil {
		return "", err
	}
	if !r.Success {
		return "", errors.New("Cloudflare가 이 토큰을 거부했습니다 — 복사가 잘렸거나, 삭제·만료된 토큰입니다. 「API 토큰」 화면에서 새로 만드세요")
	}
	var v struct{ Status string }
	_ = json.Unmarshal(r.Result, &v)
	if v.Status != "" && v.Status != "active" {
		return "", fmt.Errorf("토큰 상태가 %q 입니다 — 활성(active) 토큰이 필요합니다", v.Status)
	}
	z, err := cfCall(ctx, tok, "/zones?name="+domain)
	if err != nil {
		return "", err
	}
	var zones []struct{ ID string }
	_ = json.Unmarshal(z.Result, &zones)
	if !z.Success || len(zones) == 0 {
		return "", fmt.Errorf("토큰은 유효하지만 %s 존을 볼 수 없습니다 — 토큰의 「영역 리소스」에 %s 를 포함하고, 권한에 「영역 · 영역 · 읽기」가 있는지 확인하세요 (또는 설정의 도메인이 틀렸습니다)", domain, domain)
	}
	d, err := cfCall(ctx, tok, "/zones/"+zones[0].ID+"/dns_records?per_page=1")
	if err != nil {
		return "", err
	}
	if !d.Success {
		return "", errors.New("존은 보이지만 DNS 레코드를 읽을 수 없습니다 — 권한에 「영역 · DNS · 편집」을 넣으세요")
	}
	return zones[0].ID, nil
}

var cfSourceText = map[string]string{
	"container-file": "컨테이너 설정 (GM_CF_TOKEN_FILE)",
	"container-env":  "컨테이너 환경변수 (GM_CF_TOKEN)",
	"ui":             "이 화면에서 입력",
}

func (a *App) getCFToken(w http.ResponseWriter, r *http.Request) {
	_, src := cfTokenSource()
	writeJSON(w, 200, map[string]any{"configured": src != "", "source": src, "sourceText": cfSourceText[src]})
}

func (a *App) postCFToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token     string
		FromCaddy bool `json:"fromCaddy"` // use the token the Caddy container already has (never shown)
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if _, src := cfTokenSource(); src == "container-file" || src == "container-env" {
		fail(w, 409, fmt.Errorf("토큰이 %s 에 이미 지정되어 있고 그쪽이 우선합니다 — 바꾸려면 그 값을 바꾸고 길목을 다시 시작하세요", cfSourceText[src]))
		return
	}
	tok := strings.TrimSpace(in.Token)
	if in.FromCaddy {
		tok = caddyEnvToken(a.store.Snapshot().Settings.CaddyContainer)
		if tok == "" {
			fail(w, 400, errors.New("Caddy 컨테이너에서 Cloudflare 토큰(CLOUDFLARE_API_TOKEN)을 찾지 못했습니다 — 토큰을 직접 붙여넣으세요"))
			return
		}
	}
	if !reCFToken.MatchString(tok) {
		fail(w, 400, errors.New("토큰 형식이 아닙니다 — Cloudflare 「API 토큰」 화면에서 만든 토큰 문자열 전체를 붙여넣으세요 (Global API Key가 아닙니다)"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	domain := a.store.Snapshot().Settings.Domain
	zid, err := verifyCFToken(ctx, tok, domain)
	if err != nil {
		fail(w, 400, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(cfTokenUIPath), 0o700); err != nil {
		fail(w, 500, err)
		return
	}
	tmp := cfTokenUIPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(tok), 0o600); err != nil {
		fail(w, 500, err)
		return
	}
	if err := os.Rename(tmp, cfTokenUIPath); err != nil {
		fail(w, 500, err)
		return
	}
	a.cf.mu.Lock()
	a.cf.zone, a.cf.zoneID = "", "" // re-resolve with the new token
	a.cf.mu.Unlock()
	a.caddyTokenChanged(r)
	writeJSON(w, 200, map[string]any{"ok": true, "zone": domain, "zoneId": zid})
}

func (a *App) deleteCFToken(w http.ResponseWriter, r *http.Request) {
	if err := os.Remove(cfTokenUIPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		fail(w, 500, err)
		return
	}
	a.cf.mu.Lock()
	a.cf.zone, a.cf.zoneID = "", ""
	a.cf.mu.Unlock()
	a.caddyTokenChanged(r)
	writeJSON(w, 200, map[string]any{"ok": true})
}
