package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Cloudflare WAF at the edge: custom rules (phase http_request_firewall_custom), one rate
// limiting rule (phase http_ratelimit) and the IP list that carries CrowdSec bans.
// Gilmok only touches the rules it owns (ids in Data.CFWAF or ref gilmok_*); every other
// rule in the zone is left alone. Rules Gilmok created are deleted when turned off (the Free
// plan allows only 5 custom rules); an adopted hand-made rule is only disabled.

const (
	cfPhase      = "http_request_firewall_custom"
	cfRatePhase  = "http_ratelimit"
	refASN       = "gilmok_asn"
	refCrowdSec  = "gilmok_crowdsec"
	refAllow     = "gilmok_allow"
	refThreat    = "gilmok_threat"
	refCustom    = "gilmok_custom"
	refRate      = "gilmok_rate"
	csListName   = "gilmok_crowdsec"
	csListMax    = 10000 // Cloudflare list item limit
	descASN      = "국가·통신사 제한 (길목 관리)"
	descCrowdSec = "CrowdSec 차단 목록 (길목 관리)"
	descAllow    = "신뢰 IP 허용 (길목 관리)"
	descThreat   = "위협 차단 (길목 관리)"
	descRate     = "요청 속도 제한 (길목 관리)"
)

var cfAsnActions = map[string]string{"managed_challenge": "관리형 챌린지", "block": "차단", "js_challenge": "JS 챌린지", "challenge": "대화형 챌린지"}

// rule limits per plan (custom rules, rate limiting rules)
var cfPlanLimits = map[string][2]int{"free": {5, 1}, "pro": {20, 2}, "business": {100, 5}, "enterprise": {1000, 100}}

type CFRatelimit struct {
	Characteristics   []string `json:"characteristics"`
	Period            int      `json:"period"`
	RequestsPerPeriod int      `json:"requests_per_period"`
	MitigationTimeout int      `json:"mitigation_timeout"`
}

type CFRule struct {
	ID               string         `json:"id"`
	Ref              string         `json:"ref,omitempty"`
	Action           string         `json:"action"`
	Expression       string         `json:"expression"`
	Description      string         `json:"description"`
	Enabled          bool           `json:"enabled"`
	ActionParameters map[string]any `json:"action_parameters,omitempty"`
	Ratelimit        *CFRatelimit   `json:"ratelimit,omitempty"`
}

type cfRuleset struct {
	ID    string   `json:"id"`
	Rules []CFRule `json:"rules"`
}

func isNotFound(r *cfResp) bool { return r != nil && r.status == http.StatusNotFound }

// PhaseRules returns the zone's entrypoint ruleset of a phase ("" id when it does not exist yet).
func (c *CF) PhaseRules(ctx context.Context, domain, phase string) (cfRuleset, error) {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return cfRuleset{}, err
	}
	r, err := c.do(ctx, "GET", "/zones/"+zid+"/rulesets/phases/"+phase+"/entrypoint", nil)
	if err != nil {
		if isNotFound(r) {
			return cfRuleset{}, nil
		}
		return cfRuleset{}, permHint(err, permWAF)
	}
	var rs cfRuleset
	_ = json.Unmarshal(r.Result, &rs)
	return rs, nil
}

func (c *CF) CustomRules(ctx context.Context, domain string) (cfRuleset, error) {
	return c.PhaseRules(ctx, domain, cfPhase)
}

// Token permissions, named as in the (Korean) Cloudflare dashboard. The UI keys its how-to on these ids.
const (
	permWAF       = "waf"       // 영역 · 영역 WAF · 편집
	permLists     = "lists"     // 계정 · 계정 필터 목록 · 편집
	permAnalytics = "analytics" // 영역 · 분석 · 읽기
)

var permText = map[string]string{
	permWAF:       "영역 · 영역 WAF · 편집 (Zone · Zone WAF · Edit)",
	permLists:     "계정 · 계정 필터 목록 · 편집 (Account · Account Filter Lists · Edit)",
	permAnalytics: "영역 · 분석 · 읽기 (Zone · Analytics · Read)",
}

// PermError: the token works but lacks a permission.
type PermError struct {
	Perm string
	err  error
}

func (e *PermError) Error() string {
	return fmt.Sprintf("토큰에 「%s」 권한이 없습니다 (Cloudflare: %v)", permText[e.Perm], e.err)
}

func isPermMsg(m string) bool {
	m = strings.ToLower(m)
	return strings.Contains(m, "10000") || strings.Contains(m, "authentication") || strings.Contains(m, "permission") || strings.Contains(m, "not authorized") || strings.Contains(m, "unauthorized")
}

func permHint(err error, perm string) error {
	if err != nil && isPermMsg(err.Error()) {
		return &PermError{Perm: perm, err: err}
	}
	return err
}

// permOf returns the missing permission id of an error ("" when it is something else).
func permOf(err error) string {
	var pe *PermError
	if errors.As(err, &pe) {
		return pe.Perm
	}
	return ""
}

func ruleBody(r CFRule) map[string]any {
	b := map[string]any{"action": r.Action, "expression": r.Expression, "description": r.Description, "enabled": r.Enabled}
	if r.Ref != "" {
		b["ref"] = r.Ref
	}
	if len(r.ActionParameters) > 0 {
		b["action_parameters"] = r.ActionParameters
	}
	if r.Ratelimit != nil {
		b["ratelimit"] = r.Ratelimit
	}
	return b
}

// UpsertRule creates or updates a rule; pos (create only): nil = append, {"index":1}, {"after": id}.
func (c *CF) UpsertRule(ctx context.Context, domain, phase string, rs cfRuleset, id string, rule CFRule, pos map[string]any) (string, error) {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return "", err
	}
	var r *cfResp
	switch {
	case rs.ID == "":
		r, err = c.do(ctx, "PUT", "/zones/"+zid+"/rulesets/phases/"+phase+"/entrypoint", map[string]any{"rules": []any{ruleBody(rule)}})
	case id != "":
		r, err = c.do(ctx, "PATCH", "/zones/"+zid+"/rulesets/"+rs.ID+"/rules/"+id, ruleBody(rule))
	default:
		body := ruleBody(rule)
		if pos != nil && len(rs.Rules) > 0 {
			body["position"] = pos
		}
		r, err = c.do(ctx, "POST", "/zones/"+zid+"/rulesets/"+rs.ID+"/rules", body)
	}
	if err != nil {
		return "", permHint(err, permWAF)
	}
	var out cfRuleset
	_ = json.Unmarshal(r.Result, &out)
	for _, x := range out.Rules {
		if (id != "" && x.ID == id) || (rule.Ref != "" && x.Ref == rule.Ref) {
			return x.ID, nil
		}
	}
	if id != "" {
		return id, nil
	}
	return "", errors.New("만든 규칙을 응답에서 찾지 못했습니다")
}

func (c *CF) DeleteRule(ctx context.Context, domain, rsID, id string) error {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, "DELETE", "/zones/"+zid+"/rulesets/"+rsID+"/rules/"+id, nil)
	return permHint(err, permWAF)
}

// ZonePlan returns the plan id (free | pro | business | enterprise).
func (c *CF) ZonePlan(ctx context.Context, domain string) (string, error) {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return "", err
	}
	r, err := c.do(ctx, "GET", "/zones/"+zid, nil)
	if err != nil {
		return "", err
	}
	var z struct {
		Plan struct {
			LegacyID string `json:"legacy_id"`
		} `json:"plan"`
	}
	_ = json.Unmarshal(r.Result, &z)
	return z.Plan.LegacyID, nil
}

func (c *CF) AccountID(ctx context.Context, domain string) (string, error) {
	zid, err := c.ZoneID(ctx, domain)
	if err != nil {
		return "", err
	}
	r, err := c.do(ctx, "GET", "/zones/"+zid, nil)
	if err != nil {
		return "", err
	}
	var z struct {
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	_ = json.Unmarshal(r.Result, &z)
	if z.Account.ID == "" {
		return "", errors.New("존의 계정 ID를 알 수 없습니다")
	}
	return z.Account.ID, nil
}

type CFList struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	NumItems int    `json:"num_items"`
}

func (c *CF) FindList(ctx context.Context, acct, name string) (*CFList, error) {
	r, err := c.do(ctx, "GET", "/accounts/"+acct+"/rules/lists", nil)
	if err != nil {
		return nil, permHint(err, permLists)
	}
	var ls []CFList
	_ = json.Unmarshal(r.Result, &ls)
	for _, l := range ls {
		if l.Name == name {
			l := l
			return &l, nil
		}
	}
	return nil, nil
}

func (c *CF) CreateList(ctx context.Context, acct, name, desc string) (*CFList, error) {
	r, err := c.do(ctx, "POST", "/accounts/"+acct+"/rules/lists", map[string]any{"name": name, "kind": "ip", "description": desc})
	if err != nil {
		return nil, permHint(err, permLists)
	}
	var l CFList
	_ = json.Unmarshal(r.Result, &l)
	return &l, nil
}

// ReplaceListItems replaces every item of the list (Cloudflare applies it asynchronously).
func (c *CF) ReplaceListItems(ctx context.Context, acct, listID string, items []string, comment string) error {
	body := make([]map[string]string, 0, len(items))
	for _, ip := range items {
		body = append(body, map[string]string{"ip": ip, "comment": comment})
	}
	_, err := c.do(ctx, "PUT", "/accounts/"+acct+"/rules/lists/"+listID+"/items", body)
	return permHint(err, permLists)
}

// ---------------------------------------------------------------- desired state / plan

// reASN matches a rule that is only an ASN condition, optionally negated and parenthesised:
// "not ip.src.asnum in {4766 9318}", "(ip.src.asnum in {12345})". Rules with any other condition
// are not adoptable (rewriting them would silently drop those conditions).
var reASN = regexp.MustCompile(`^\s*\(?\s*(not\s+)?\(?\s*ip\.src\.asnum\s+in\s+\{([0-9\s]+)\}\s*\)?\s*\)?\s*$`)

func parseASNs(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(f), "AS"))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("ASN %q 가 올바르지 않습니다", f)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func asnExpression(asns []int) string {
	parts := make([]string, len(asns))
	for i, n := range asns {
		parts[i] = strconv.Itoa(n)
	}
	return "not ip.src.asnum in {" + strings.Join(parts, " ") + "}"
}

func cfAction(a, def string) string {
	if _, ok := cfAsnActions[a]; ok {
		return a
	}
	return def
}

// ruleSpec: one rule Gilmok manages.
type ruleSpec struct {
	Key, Name, Phase string
	want             CFRule
	err              error   // the settings cannot produce a rule (only matters when enabled)
	id               *string // in CFWAFState
	adopted          bool    // turning off disables instead of deleting
}

func desiredSpecs(d Data, ids *CFWAFState) []ruleSpec {
	st := d.Settings
	var specs []ruleSpec
	add := func(key, name, phase string, id *string, enabled bool, mk func() (CFRule, error)) {
		sp := ruleSpec{Key: key, Name: name, Phase: phase, id: id}
		if enabled {
			sp.want, sp.err = mk()
		}
		sp.want.Enabled = enabled && sp.err == nil
		if sp.want.Ref == "" {
			sp.want.Ref = "gilmok_" + key
		}
		specs = append(specs, sp)
	}
	add("allow", "신뢰 IP 허용", cfPhase, &ids.AllowRuleID, st.CfAllowRule, func() (CFRule, error) {
		ips, err := parseIPList(st.CfAllowIPs)
		if err == nil && len(ips) == 0 {
			err = errors.New("허용할 IP를 하나 이상 입력하세요")
		}
		return CFRule{Ref: refAllow, Action: "skip", ActionParameters: map[string]any{"ruleset": "current"},
			Expression: "ip.src in {" + strings.Join(ips, " ") + "}", Description: descAllow}, err
	})
	add("crowdsec", "CrowdSec 차단 목록", cfPhase, &ids.CsRuleID, st.UseCrowdSec && st.CrowdSecEnabled && st.CrowdSecSync, func() (CFRule, error) {
		return CFRule{Ref: refCrowdSec, Action: "block", Expression: "ip.src in $" + csListName, Description: descCrowdSec}, nil
	})
	add("threat", "위협 차단", cfPhase, &ids.ThreatRuleID, st.CfThreatRule, func() (CFRule, error) {
		expr, err := threatExpression(d)
		return CFRule{Ref: refThreat, Action: cfAction(st.CfThreatAction, "block"), Expression: expr, Description: descThreat}, err
	})
	add("asn", "국가·통신사 제한", cfPhase, &ids.AsnRuleID, st.CfAsnRule, func() (CFRule, error) {
		expr, err := geoExpression(d)
		return CFRule{Ref: refASN, Action: cfAction(st.CfAsnAction, "managed_challenge"), Expression: expr, Description: descASN}, err
	})
	add("custom", "사용자 규칙", cfPhase, &ids.CustomRuleID, st.CfCustomRule, func() (CFRule, error) {
		expr := strings.TrimSpace(st.CfCustomExpr)
		name := strings.TrimSpace(st.CfCustomName)
		if name == "" {
			name = "사용자 규칙"
		}
		var err error
		switch {
		case expr == "":
			err = errors.New("사용자 규칙의 조건식을 입력하세요")
		case len(expr) > cfExprMax:
			err = fmt.Errorf("사용자 규칙 식이 너무 깁니다 (%d자, 한도 %d자)", len(expr), cfExprMax)
		}
		return CFRule{Ref: refCustom, Action: cfAction(st.CfCustomAction, "managed_challenge"), Expression: expr, Description: name + " (길목 관리)"}, err
	})
	add("rate", "요청 속도 제한", cfRatePhase, &ids.RateRuleID, st.CfRateRule, func() (CFRule, error) {
		var conds []string
		for _, p := range splitEntries(st.CfRatePaths) {
			if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\" \\") {
				return CFRule{}, fmt.Errorf("속도 제한 경로 %q 는 / 로 시작하고 공백·따옴표가 없어야 합니다", p)
			}
			conds = append(conds, "http.request.uri.path contains "+cfStr(p))
		}
		expr := `http.request.uri.path contains "/"`
		if len(conds) > 0 {
			expr = orJoin(conds)
		}
		n, per, to := st.CfRateRequests, st.CfRatePeriod, st.CfRateTimeout
		if n < 1 {
			return CFRule{}, errors.New("허용 요청 수는 1 이상이어야 합니다")
		}
		if per <= 0 {
			per = 10
		}
		if to <= 0 {
			to = 10
		}
		return CFRule{Ref: refRate, Action: cfAction(st.CfRateAction, "block"), Expression: expr, Description: descRate,
			Ratelimit: &CFRatelimit{Characteristics: []string{"cf.colo.id", "ip.src"}, Period: per, RequestsPerPeriod: n, MitigationTimeout: to}}, nil
	})
	for i := range specs {
		if specs[i].Key == "asn" {
			specs[i].adopted = ids.AsnAdopted
		}
	}
	return specs
}

type WAFPlanItem struct {
	Key     string  `json:"key"` // allow | crowdsec | threat | asn | custom | rate | list
	Name    string  `json:"name"`
	Phase   string  `json:"phase,omitempty"`
	Action  string  `json:"action"` // create | update | disable | delete | ok | skip | error
	Current *CFRule `json:"current,omitempty"`
	Desired *CFRule `json:"desired,omitempty"`
	Reason  string  `json:"reason,omitempty"`
	ruleID  string
}

func findRule(rs cfRuleset, id, ref string) *CFRule {
	for i, r := range rs.Rules {
		if (id != "" && r.ID == id) || (ref != "" && r.Ref == ref) {
			return &rs.Rules[i]
		}
	}
	return nil
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func sameRule(a, b CFRule) bool {
	if a.Action != b.Action || strings.TrimSpace(a.Expression) != strings.TrimSpace(b.Expression) || a.Enabled != b.Enabled || a.Description != b.Description {
		return false
	}
	if len(b.ActionParameters) > 0 && !jsonEq(a.ActionParameters, b.ActionParameters) {
		return false
	}
	if b.Ratelimit != nil && (a.Ratelimit == nil || a.Ratelimit.Period != b.Ratelimit.Period ||
		a.Ratelimit.RequestsPerPeriod != b.Ratelimit.RequestsPerPeriod || a.Ratelimit.MitigationTimeout != b.Ratelimit.MitigationTimeout) {
		return false
	}
	return true
}

func planRule(sp ruleSpec, rs cfRuleset) WAFPlanItem {
	want := sp.want
	it := WAFPlanItem{Key: sp.Key, Name: sp.Name, Phase: sp.Phase}
	cur := findRule(rs, *sp.id, want.Ref)
	w := want
	switch {
	case sp.err != nil:
		it.Action, it.Reason = "error", sp.err.Error()
		if cur != nil {
			it.Current, it.ruleID = cur, cur.ID
		}
		return it
	case cur == nil && !want.Enabled:
		it.Action, it.Reason = "skip", "사용 안 함"
	case cur == nil:
		it.Action, it.Desired = "create", &w
	case !want.Enabled && !sp.adopted:
		it.Action, it.Current, it.ruleID, it.Reason = "delete", cur, cur.ID, "길목이 만든 규칙 — 끄면 지웁니다 (규칙 수 한도 절약)"
	case !want.Enabled && !cur.Enabled:
		it.Action, it.Current, it.ruleID, it.Reason = "ok", cur, cur.ID, "꺼져 있음"
	case !want.Enabled:
		c := *cur
		c.Enabled = false
		it.Action, it.Current, it.Desired, it.ruleID, it.Reason = "disable", cur, &c, cur.ID, "직접 만든 규칙을 가져온 것이라 지우지 않고 끕니다"
	case sameRule(*cur, want):
		it.Action, it.Current, it.ruleID = "ok", cur, cur.ID
	default:
		it.Action, it.Current, it.Desired, it.ruleID = "update", cur, &w, cur.ID
	}
	if it.Desired != nil && cur != nil && cur.Ref != "" && cur.Ref != want.Ref {
		it.Desired.Ref = "" // adopted rule keeps its own ref
	}
	return it
}

type CFWAFView struct {
	Configured bool          `json:"configured"`
	Error      string        `json:"error,omitempty"`
	Perms      []string      `json:"perms,omitempty"` // missing token permissions (waf | lists)
	Plan       string        `json:"plan"`            // free | pro | business | enterprise | ""
	Limit      int           `json:"limit"`           // custom rules allowed by the plan (0 = unknown)
	RateLimit  int           `json:"rateLimit"`
	Used       int           `json:"used"`  // custom rules in the zone now
	After      int           `json:"after"` // … after applying the plan
	RateUsed   int           `json:"rateUsed"`
	RateAfter  int           `json:"rateAfter"`
	OverLimit  string        `json:"overLimit,omitempty"`
	Rules      []CFRuleView  `json:"rules"`
	RateRules  []CFRuleView  `json:"rateRules"`
	RateError  string        `json:"rateError,omitempty"`
	Items      []WAFPlanItem `json:"items"`
	List       *CFList       `json:"list,omitempty"`
	ListError  string        `json:"listError,omitempty"`
	Adoptable  []CFRule      `json:"adoptable"`
}

type CFRuleView struct {
	CFRule
	Managed string `json:"managed,omitempty"` // allow | crowdsec | threat | asn | custom | rate
}

type cfState struct {
	rs, rrs   cfRuleset
	rateErr   error
	specs     []ruleSpec
	items     []WAFPlanItem
	plan      string
	limits    [2]int
	after     [2]int
	overLimit string
}

// cfLoad reads both phases and builds the plan.
func (a *App) cfLoad(ctx context.Context, d Data, ids *CFWAFState) (*cfState, error) {
	st := d.Settings
	rs, err := a.cf.CustomRules(ctx, st.Domain)
	if err != nil {
		return nil, err
	}
	s := &cfState{rs: rs}
	s.rrs, s.rateErr = a.cf.PhaseRules(ctx, st.Domain, cfRatePhase)
	if plan, err := a.cf.ZonePlan(ctx, st.Domain); err == nil {
		s.plan = plan
		s.limits = cfPlanLimits[plan]
	}
	s.specs = desiredSpecs(d, ids)
	s.after = [2]int{len(rs.Rules), len(s.rrs.Rules)}
	for _, sp := range s.specs {
		set := s.rs
		if sp.Phase == cfRatePhase {
			if s.rateErr != nil {
				if sp.want.Enabled {
					s.items = append(s.items, WAFPlanItem{Key: sp.Key, Name: sp.Name, Phase: sp.Phase, Action: "error", Reason: s.rateErr.Error()})
				}
				continue
			}
			set = s.rrs
		}
		it := planRule(sp, set)
		s.items = append(s.items, it)
		i := 0
		if sp.Phase == cfRatePhase {
			i = 1
		}
		switch it.Action {
		case "create":
			s.after[i]++
		case "delete":
			s.after[i]--
		}
	}
	if s.limits[0] > 0 && s.after[0] > s.limits[0] {
		s.overLimit = fmt.Sprintf("적용하면 사용자 지정 규칙이 %d개가 되어 %s 플랜 한도(%d개)를 넘습니다 — 규칙을 몇 개 끄거나 합치세요", s.after[0], s.plan, s.limits[0])
	} else if s.limits[1] > 0 && s.after[1] > s.limits[1] {
		s.overLimit = fmt.Sprintf("적용하면 속도 제한 규칙이 %d개가 되어 %s 플랜 한도(%d개)를 넘습니다 — 직접 만든 속도 제한 규칙이 있다면 그쪽을 지우거나 이 규칙을 끄세요", s.after[1], s.plan, s.limits[1])
	}
	return s, nil
}

func (a *App) cfwafView(ctx context.Context) CFWAFView {
	d := a.store.Snapshot()
	v := CFWAFView{Configured: a.cf.Configured(), Rules: []CFRuleView{}, RateRules: []CFRuleView{}, Items: []WAFPlanItem{}, Adoptable: []CFRule{}}
	if !v.Configured {
		return v
	}
	ids := d.CFWAF
	s, err := a.cfLoad(ctx, d, &ids)
	if err != nil {
		v.Error = err.Error()
		if p := permOf(err); p != "" {
			v.Perms = append(v.Perms, p)
		}
		return v
	}
	v.Plan, v.Limit, v.RateLimit = s.plan, s.limits[0], s.limits[1]
	v.Used, v.RateUsed, v.After, v.RateAfter, v.OverLimit = len(s.rs.Rules), len(s.rrs.Rules), s.after[0], s.after[1], s.overLimit
	if s.rateErr != nil {
		v.RateError = s.rateErr.Error()
		if p := permOf(s.rateErr); p != "" {
			v.Perms = append(v.Perms, p)
		}
	}
	owner := map[string]string{}
	for _, it := range s.items {
		if it.Current != nil {
			owner[it.Current.ID] = it.Key
		}
	}
	asnOwned := owner != nil && func() bool {
		for _, k := range owner {
			if k == "asn" {
				return true
			}
		}
		return false
	}()
	for _, r := range s.rs.Rules {
		rv := CFRuleView{CFRule: r, Managed: owner[r.ID]}
		if rv.Managed == "" && !asnOwned && reASN.MatchString(r.Expression) {
			v.Adoptable = append(v.Adoptable, r)
		}
		v.Rules = append(v.Rules, rv)
	}
	for _, r := range s.rrs.Rules {
		v.RateRules = append(v.RateRules, CFRuleView{CFRule: r, Managed: owner[r.ID]})
	}
	for _, sp := range s.specs {
		if sp.Key == "crowdsec" && sp.want.Enabled {
			if acct, err := a.cf.AccountID(ctx, d.Settings.Domain); err != nil {
				v.ListError = err.Error()
			} else if l, err := a.cf.FindList(ctx, acct, csListName); err != nil {
				v.ListError = err.Error()
				if p := permOf(err); p != "" {
					v.Perms = append(v.Perms, p)
				}
			} else {
				v.List = l
				if l == nil {
					v.Items = append(v.Items, WAFPlanItem{Key: "list", Name: "IP 목록 $" + csListName, Action: "create", Reason: "CrowdSec 차단 IP를 담을 계정 IP 목록"})
				}
			}
		}
	}
	v.Items = append(v.Items, s.items...)
	return v
}

func (a *App) getCFWAF(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, 200, a.cfwafView(ctx))
}

func (a *App) applyCFWAF(ctx context.Context, L *logger) error {
	a.cfwafMu.Lock() // two applies at once would both create the same rules
	defer a.cfwafMu.Unlock()
	d := a.store.Snapshot()
	st := d.Settings
	ids := d.CFWAF
	save := func() {
		_ = a.store.Update(func(dd *Data) error { dd.CFWAF = ids; return nil })
	}
	defer save()
	s, err := a.cfLoad(ctx, d, &ids)
	if err != nil {
		return err
	}
	for _, it := range s.items { // refuse before writing anything
		if it.Action == "error" {
			return fmt.Errorf("%s: %s", it.Name, it.Reason)
		}
	}
	if s.overLimit != "" {
		return errors.New(s.overLimit)
	}
	for _, sp := range s.specs {
		if sp.Key == "crowdsec" && sp.want.Enabled {
			// the rule references $gilmok_crowdsec, so the list must exist first
			acct, err := a.cf.AccountID(ctx, st.Domain)
			if err != nil {
				return err
			}
			l, err := a.cf.FindList(ctx, acct, csListName)
			if err != nil {
				return err
			}
			if l == nil {
				if l, err = a.cf.CreateList(ctx, acct, csListName, "CrowdSec bans synced by Gilmok"); err != nil {
					return err
				}
				L.f("✓ IP 목록 $%s 만듦", csListName)
			}
			ids.ListID = l.ID
		}
	}
	rs, rrs := s.rs, s.rrs
	for _, sp := range s.specs {
		if sp.Phase == cfRatePhase && s.rateErr != nil {
			if sp.want.Enabled {
				return s.rateErr
			}
			continue
		}
		set := &rs
		if sp.Phase == cfRatePhase {
			set = &rrs
		}
		p := planRule(sp, *set)
		switch p.Action {
		case "ok", "skip":
			if p.ruleID != "" {
				*sp.id = p.ruleID
			}
			L.f("· %s: 변경 없음", sp.Name)
			continue
		case "delete":
			if err := a.cf.DeleteRule(ctx, st.Domain, set.ID, p.ruleID); err != nil {
				L.f("✗ %s: %v", sp.Name, err)
				return err
			}
			*sp.id = ""
			L.f("✓ %s: 지움 (꺼짐)", sp.Name)
		default:
			var pos map[string]any
			switch sp.Key {
			case "allow":
				pos = map[string]any{"index": 1}
			case "crowdsec":
				if ids.AllowRuleID != "" && findRule(*set, ids.AllowRuleID, "") != nil {
					pos = map[string]any{"after": ids.AllowRuleID}
				} else {
					pos = map[string]any{"index": 1}
				}
			}
			id, err := a.cf.UpsertRule(ctx, st.Domain, sp.Phase, *set, p.ruleID, *p.Desired, pos)
			if err != nil {
				L.f("✗ %s: %v", sp.Name, err)
				return err
			}
			*sp.id = id
			L.f("✓ %s: %s", sp.Name, map[string]string{"create": "만듦", "update": "수정", "disable": "끔"}[p.Action])
		}
		fresh, err := a.cf.PhaseRules(ctx, st.Domain, sp.Phase) // ids/positions changed
		if err != nil {
			return err
		}
		*set = fresh
	}
	return nil
}

func (a *App) postCFWAFApply(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	L := &logger{}
	err := a.applyCFWAF(ctx, L)
	if err == nil {
		go a.crowdsecSyncNow()
	}
	res := map[string]any{"ok": err == nil, "log": L.lines}
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, 200, res)
}

// postCFWAFAdopt makes an existing ASN rule (e.g. a hand-made "KR ISP only") Gilmok-managed.
func (a *App) postCFWAFAdopt(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	if err := readJSON(r, &in); err != nil || in.ID == "" {
		fail(w, 400, errors.New("규칙 id가 필요합니다"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d := a.store.Snapshot()
	rs, err := a.cf.CustomRules(ctx, d.Settings.Domain)
	if err != nil {
		fail(w, 400, err)
		return
	}
	cur := findRule(rs, in.ID, "")
	if cur == nil {
		fail(w, 404, errors.New("규칙을 찾을 수 없습니다"))
		return
	}
	m := reASN.FindStringSubmatch(cur.Expression)
	if m == nil {
		fail(w, 400, errors.New("통신사(ASN) 조건 하나로만 된 규칙만 가져올 수 있습니다 — 다른 조건이 섞인 규칙은 길목이 바꾸면 그 조건이 사라집니다"))
		return
	}
	// "not … in {…}" = only these ASNs pass (allow list); without "not" = these ASNs get the action (block list)
	mode := "block"
	if strings.TrimSpace(m[1]) != "" {
		mode = "allow"
	}
	asns, _ := parseASNs(m[2])
	_ = a.store.Update(func(dd *Data) error {
		dd.CFWAF.AsnRuleID, dd.CFWAF.AsnAdopted = cur.ID, true
		dd.Settings.CfAsnRule = cur.Enabled
		parts := make([]string, len(asns))
		for i, n := range asns {
			parts[i] = strconv.Itoa(n)
		}
		dd.Settings.CfAsnList = strings.Join(parts, " ")
		dd.Settings.CfGeoMode, dd.Settings.CfGeoCountries, dd.Settings.CfGeoHosts, dd.Settings.CfGeoBots = mode, "", nil, false
		if _, ok := cfAsnActions[cur.Action]; ok {
			dd.Settings.CfAsnAction = cur.Action
		}
		return nil
	})
	writeJSON(w, 200, map[string]any{"ok": true, "asns": asns, "action": cur.Action, "mode": mode})
}

// ---------------------------------------------------------------- CrowdSec → Cloudflare list

// banItems turns CrowdSec decisions into Cloudflare list items (public IPv4/IPv6 or CIDR only).
func banItems(ds []Decision) []string {
	items, _ := banItemsN(ds)
	return items
}

// banItemsN: Cloudflare list entries from ban decisions, newest decisions first when the list
// limit is reached; dropped = how many did not fit.
func banItemsN(ds []Decision) (items []string, dropped int) {
	ds = append([]Decision(nil), ds...)
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].ID > ds[j].ID }) // newest first
	set := map[string]bool{}
	var order []string
	add := func(v string) {
		if !set[v] {
			set[v] = true
			order = append(order, v)
		}
	}
	for _, d := range ds {
		if !strings.EqualFold(d.Type, "ban") {
			continue
		}
		v := strings.TrimSpace(d.Value)
		switch strings.ToLower(d.Scope) {
		case "ip":
			ip := net.ParseIP(v)
			if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.To4() == nil {
				// Cloudflare lists take IPv6 as /64 or wider
				_, n, _ := net.ParseCIDR(v + "/64")
				v = n.String()
			}
			add(v)
		case "range":
			ip, n, err := net.ParseCIDR(v)
			if err != nil || ip.IsPrivate() || ip.IsLoopback() {
				continue
			}
			ones, bits := n.Mask.Size()
			if bits == 32 && ones < 8 || bits == 128 && ones < 12 { // refuse absurdly wide ranges
				continue
			}
			add(n.String())
		}
	}
	if len(order) > csListMax {
		dropped = len(order) - csListMax
		order = order[:csListMax]
	}
	sort.Strings(order)
	return order, dropped
}
