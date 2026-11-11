package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Edge security events (what Cloudflare blocked / challenged) via the GraphQL Analytics API,
// dataset firewallEventsAdaptive. Needs the token permission Zone > Analytics: Read.

type CFEvent struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Source  string    `json:"source"`
	RuleID  string    `json:"ruleId"`
	Rule    string    `json:"rule"`    // rule description when known
	Managed string    `json:"managed"` // Gilmok rule key when it is one of ours
	IP      string    `json:"ip"`
	ASN     int       `json:"asn"`
	Country string    `json:"country"`
	Host    string    `json:"host"`
	Method  string    `json:"method"`
	Path    string    `json:"path"`
	Query   string    `json:"query"`
	UA      string    `json:"ua"`
	Guard   string    `json:"guard,omitempty"` // basic-blocking category guessed from UA / path
}

type cfCount struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	Count int    `json:"count"`
}

const cfEventsQuery = `query($zone: String!, $since: Time!, $until: Time!) {
  viewer { zones(filter: {zoneTag: $zone}) {
    firewallEventsAdaptive(filter: {datetime_geq: $since, datetime_leq: $until}, limit: 1000, orderBy: [datetime_DESC]) {
      action source ruleId datetime clientIP clientAsn clientCountryName
      clientRequestHTTPHost clientRequestHTTPMethodName clientRequestPath clientRequestQuery userAgent
    }
  } }
}`

func (c *CF) graphql(ctx context.Context, query string, vars map[string]any, out any) error {
	tok := cfToken()
	if tok == "" {
		return errors.New("Cloudflare API 토큰이 없습니다")
	}
	b, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	req, err := http.NewRequestWithContext(ctx, "POST", cfAPI+"/graphql", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	var r struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("Cloudflare GraphQL 응답 해석 실패 (HTTP %d)", res.StatusCode)
	}
	if len(r.Errors) > 0 {
		var msgs []string
		for _, e := range r.Errors {
			msgs = append(msgs, e.Message)
		}
		m := strings.Join(msgs, "; ")
		if isPermMsg(m) || res.StatusCode == 403 {
			return &PermError{Perm: permAnalytics, err: errors.New(m)}
		}
		return errors.New("Cloudflare GraphQL: " + m)
	}
	return json.Unmarshal(r.Data, out)
}

var cfSourceNames = map[string]string{
	"firewallCustom": "사용자 지정 규칙", "firewallManaged": "관리형 규칙", "ratelimit": "속도 제한", "firewallRules": "방화벽 규칙(구)",
	"securitylevel": "보안 수준", "bic": "브라우저 무결성 검사", "hot": "핫링크 보호", "uablock": "UA 차단", "zonelockdown": "영역 잠금",
	"waf": "WAF(구)", "botFight": "Bot Fight Mode", "botManagement": "봇 관리", "dlp": "DLP", "validation": "검증", "l7ddos": "DDoS 방어",
	"accessRules": "IP 액세스 규칙", "apiShield": "API Shield", "country": "국가", "asn": "ASN",
}

func (a *App) getCFEvents(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	st := d.Settings
	if !st.UseCloudflare || !a.cf.Configured() {
		fail(w, 400, errors.New("Cloudflare 토큰이 없습니다"))
		return
	}
	hours := map[string]int{"1h": 1, "6h": 6, "24h": 24}[r.URL.Query().Get("since")]
	if hours == 0 {
		hours = 24
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	zid, err := a.cf.ZoneID(ctx, st.Domain)
	if err != nil {
		fail(w, 400, err)
		return
	}
	until := time.Now().UTC()
	since := until.Add(-time.Duration(hours) * time.Hour)
	var out struct {
		Viewer struct {
			Zones []struct {
				Events []struct {
					Action, Source, RuleID, Datetime, ClientIP string
					ClientAsn                                  any
					ClientCountryName                          string
					ClientRequestHTTPHost                      string
					ClientRequestHTTPMethodName                string
					ClientRequestPath, ClientRequestQuery      string
					UserAgent                                  string
				} `json:"firewallEventsAdaptive"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	if err := a.cf.graphql(ctx, cfEventsQuery, map[string]any{"zone": zid, "since": since.Format(time.RFC3339), "until": until.Format(time.RFC3339)}, &out); err != nil {
		if p := permOf(err); p != "" {
			writeJSON(w, 400, map[string]any{"error": err.Error(), "perms": []string{p}})
			return
		}
		fail(w, 400, err)
		return
	}
	// rule id → description / Gilmok key
	names := map[string][2]string{}
	if rs, err := a.cf.CustomRules(ctx, st.Domain); err == nil {
		for _, x := range rs.Rules {
			names[x.ID] = [2]string{x.Description, managedKey(d.CFWAF, x.ID)}
		}
	}
	if rs, err := a.cf.PhaseRules(ctx, st.Domain, cfRatePhase); err == nil {
		for _, x := range rs.Rules {
			names[x.ID] = [2]string{x.Description, managedKey(d.CFWAF, x.ID)}
		}
	}
	events := []CFEvent{}
	by := map[string]map[string]int{"action": {}, "rule": {}, "country": {}, "ip": {}, "path": {}, "host": {}, "guard": {}}
	ruleLabel := map[string]string{}
	ipASN := map[string]int{}
	for _, z := range out.Viewer.Zones {
		for _, e := range z.Events {
			t, _ := time.Parse(time.RFC3339, e.Datetime)
			ev := CFEvent{Time: t, Action: e.Action, Source: e.Source, RuleID: e.RuleID, IP: e.ClientIP, Country: e.ClientCountryName,
				Host: e.ClientRequestHTTPHost, Method: e.ClientRequestHTTPMethodName, Path: e.ClientRequestPath, Query: e.ClientRequestQuery, UA: e.UserAgent}
			fmt.Sscan(fmt.Sprint(e.ClientAsn), &ev.ASN)
			if n, ok := names[e.RuleID]; ok {
				ev.Rule, ev.Managed = n[0], n[1]
			}
			if ev.Rule == "" {
				ev.Rule = cfSourceNames[e.Source]
				if ev.Rule == "" {
					ev.Rule = e.Source
				}
			}
			if ev.Managed == "threat" {
				ev.Guard = guardCategory(st, ev.UA, ev.Path)
			}
			events = append(events, ev)
			by["action"][ev.Action]++
			rk := ev.RuleID
			if rk == "" {
				rk = ev.Source
			}
			by["rule"][rk]++
			ruleLabel[rk] = ev.Rule
			by["country"][ev.Country]++
			by["ip"][ev.IP]++
			ipASN[ev.IP] = ev.ASN
			by["path"][ev.Path]++
			by["host"][ev.Host]++
			if ev.Guard != "" {
				by["guard"][ev.Guard]++
			}
		}
	}
	top := func(m map[string]int, n int, label func(string) string) []cfCount {
		out := []cfCount{}
		for k, v := range m {
			c := cfCount{Key: k, Count: v}
			if label != nil {
				c.Label = label(k)
			}
			out = append(out, c)
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].Count > out[j].Count || out[i].Count == out[j].Count && out[i].Key < out[j].Key
		})
		if len(out) > n {
			out = out[:n]
		}
		return out
	}
	shown := events
	if len(shown) > 300 {
		shown = shown[:300]
	}
	writeJSON(w, 200, map[string]any{
		"hours": hours, "total": len(events), "truncated": len(events) >= 1000, "events": shown,
		"byAction":  top(by["action"], 10, nil),
		"byRule":    top(by["rule"], 15, func(k string) string { return ruleLabel[k] }),
		"byCountry": top(by["country"], 15, nil),
		"byIP":      top(by["ip"], 15, func(k string) string { return fmt.Sprintf("AS%d", ipASN[k]) }),
		"byPath":    top(by["path"], 15, nil),
		"byHost":    top(by["host"], 15, nil),
		"byGuard":   top(by["guard"], 10, func(k string) string { return guardCategoryText[k] }),
	})
}

func managedKey(ids CFWAFState, id string) string {
	switch id {
	case "":
		return ""
	case ids.AllowRuleID:
		return "allow"
	case ids.CsRuleID:
		return "crowdsec"
	case ids.ThreatRuleID:
		return "threat"
	case ids.AsnRuleID:
		return "asn"
	case ids.CustomRuleID:
		return "custom"
	case ids.RateRuleID:
		return "rate"
	}
	return ""
}
