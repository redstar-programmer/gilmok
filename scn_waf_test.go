package main

// WAF / AUTHELIA config / GRP (no docker) / BULK / UP scenarios

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScnWAFGenerate(t *testing.T) {
	// WAF-03: body inspection switch
	st := Settings{WafParanoia: 1, WafInbound: 5, WafOutbound: 4}
	if out := wafSnippet("x", WAFBlock, st, nil); !strings.Contains(out, "SecRequestBodyAccess Off") {
		t.Fatal("WAF-03 off")
	}
	st.WafBodyAccess = true
	if out := wafSnippet("x", WAFBlock, st, nil); !strings.Contains(out, "SecRequestBodyAccess On") {
		t.Fatal("WAF-03 on")
	}
	// WAF-08: a-b and a.b never share a snippet
	a := &Service{ID: "aaaaaa111", Subdomain: "a-b", WAF: WAFBlock, WAFParanoia: 2}
	b := &Service{ID: "bbbbbb222", Subdomain: "a.b", WAF: WAFBlock, WAFParanoia: 3}
	if wafSnippetFor(a) == wafSnippetFor(b) {
		t.Fatalf("WAF-08: %s", wafSnippetFor(a))
	}
	// WAF-09 / WAF-19: exclusions
	for _, bad := range []WafExclusion{{ID: "abc"}, {ID: "94210"}, {ID: "942100\nSecRuleEngine Off"}, {ID: `942100 "x"`}, {ID: "942100", Note: "a`b"}, {ID: "942100", Note: "a\nb"}, {ID: "942100", Note: strings.Repeat("x", 201)}} {
		if _, err := validateWafExclusions([]WafExclusion{bad}); err == nil {
			t.Errorf("WAF-09/19: %+v accepted", bad)
		}
	}
	if x, err := validateWafExclusions([]WafExclusion{{ID: "942100"}, {ID: "920100-920199", Note: "ok"}}); err != nil || len(x) != 2 {
		t.Fatalf("WAF-09 good: %v %v", x, err)
	}
	// WAF-10 (R8): common 2 + service 3 in the service's own snippet; another site gets the common 2
	st.WafExclude = []WafExclusion{{ID: "911100"}, {ID: "912100"}}
	svc := &Service{ID: "cccccc", Subdomain: "c", WAF: WAFBlock, WAFExclude: []WafExclusion{{ID: "913100"}, {ID: "914100"}, {ID: "915100"}}}
	own := wafSnippet(wafSnippetFor(svc), WAFBlock, st, svc)
	base := wafSnippet(wafSnippetName(WAFBlock), WAFBlock, st, nil)
	if strings.Count(own, "SecRuleRemoveById 91") != 5 || strings.Count(base, "SecRuleRemoveById 91") != 2 {
		t.Fatalf("WAF-10: own=%d base=%d", strings.Count(own, "SecRuleRemoveById 91"), strings.Count(base, "SecRuleRemoveById 91"))
	}
	// WAF-14: custom UA / paths are escaped, odd characters refused
	if err := validateGuardLists(Settings{GuardUA: `evil"bot`}); err == nil {
		t.Fatal("WAF-14: quote accepted")
	}
	if err := validateGuardLists(Settings{GuardPathList: "no-slash"}); err == nil {
		t.Fatal("WAF-14: path without /")
	}
	re := uaRegexp([]string{"a.b(c)+"})
	if !strings.Contains(re, `a\.b\(c\)\+`) {
		t.Fatalf("WAF-14: %s", re)
	}
	if _, err := regexp.Compile(re); err != nil {
		t.Fatal(err)
	}
	// WAF-06: a broken directive in the WAF settings is caught by caddy validate (never applied)
	installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		if strings.Contains(string(stdin), "BROKEN_SECLANG") {
			return "Error: provisioning: invalid directive", fmt.Errorf("exit 1")
		}
		return "", nil
	})
	d := Data{Settings: Settings{Domain: "example.com", CaddyMode: "docker", CaddyContainer: "cad", WafDirectives: "BROKEN_SECLANG"}, Services: []*Service{{ID: "1", Subdomain: "a", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true, WAF: WAFBlock}}}
	if err := validateCaddy(d.Settings, GenerateCaddyfile(d)); err == nil {
		t.Fatal("WAF-06")
	}
}

func TestScnWAFEventsAndTest(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	ts := float64(time.Now().Unix())
	wafLine := `{"level":"warn","ts":` + strconv.FormatFloat(ts, 'f', 3, 64) + `,"logger":"http.handlers.waf","msg":"[client \"1.2.3.4\"] Coraza: Access denied (phase 2). x [id \"942100\"] [msg \"SQL Injection\"] [data \"\"] [uri \"/q?id=1\"] [unique_id \"abc\"]"}`
	accLine := `{"level":"info","ts":` + strconv.FormatFloat(ts+0.5, 'f', 3, 64) + `,"logger":"http.log.access.log1","msg":"handled request","request":{"remote_ip":"1.2.3.4","method":"GET","host":"shop.example.com","uri":"/q?id=1","headers":{}},"duration":0.01,"size":0,"status":403}`
	installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		if args[0] == "logs" {
			return wafLine + "\n" + accLine + "\n", nil
		}
		return "", fmt.Errorf("no")
	})
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCaddy, d.Settings.CaddyContainer = "example.com", true, "cad"
	})
	// WAF-16: host found from the access line with the same path
	m := boss.must(200, "GET", "/api/waf/events?since=1h", "")
	evs := m["events"].([]any)
	if len(evs) == 0 || evs[0].(map[string]any)["host"] != "shop.example.com" {
		t.Fatalf("WAF-16: %v", m)
	}
	// WAF-17: test requests against a fake Caddy (TLS)
	blockAll := true
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if blockAll && r.URL.RawQuery != "" {
			w.WriteHeader(403)
			return
		}
		if strings.Contains(strings.ToLower(r.UserAgent()), "sqlmap") || strings.Contains(r.URL.Path, ".env") {
			w.Header().Set(guardHeader, "bot")
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	f.set(func(d *Data) {
		d.Settings.CaddyContainer, d.Settings.CaddyBase = "127.0.0.1", "{\n\thttps_port "+port+"\n}\n"
		d.Settings.GuardBots, d.Settings.GuardPaths = true, true
		d.Services = []*Service{
			{ID: "w", Subdomain: "shop", Upstream: "s:1", Exposure: ExposurePublic, Enabled: true, WAF: WAFBlock, Guard: true},
			{ID: "m", Subdomain: "secure", Upstream: "s:1", Exposure: ExposurePublic, Enabled: true, Proxied: true, MTLS: true},
		}
	})
	m = boss.must(200, "POST", "/api/waf/test", `{"id":"w"}`)
	res := m["results"].([]any)
	okN, failN := 0, 0
	for _, r := range res {
		switch r.(map[string]any)["verdict"] {
		case "ok":
			okN++
		case "fail":
			failN++
		}
	}
	if len(res) == 0 || okN == 0 || failN != 0 {
		t.Fatalf("WAF-17: ok=%d fail=%d %v", okN, failN, res)
	}
	// the same test against a Caddy that blocks nothing → the attack cases are reported as failures
	blockAll = false
	m = boss.must(200, "POST", "/api/waf/test", `{"id":"w"}`)
	failN = 0
	for _, r := range m["results"].([]any) {
		if r.(map[string]any)["verdict"] == "fail" {
			failN++
		}
	}
	if failN < 3 {
		t.Fatalf("WAF-17: a WAF that blocks nothing must fail the attack cases (%d)", failN)
	}
	// WAF-18: mTLS site cannot be tested from Gilmok
	f.set(func(d *Data) { d.Settings.UseCloudflare = true })
	if code, m := boss.do("POST", "/api/waf/test", `{"id":"m"}`); code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "mTLS") {
		t.Fatalf("WAF-18: %d %v", code, m)
	}
}

func TestScnAutheliaConfig(t *testing.T) {
	// AUTHELIA-03: deny + no rules → a valid block (default two_factor)
	out := GenerateAccessControl(Data{Settings: Settings{Domain: "example.com", DefaultPolicy: "deny"}})
	if !strings.Contains(out, "default_policy: 'two_factor'") || strings.Contains(out, "rules:") {
		t.Fatalf("AUTHELIA-03: %s", out)
	}
	// AUTHELIA-05: no access_control block → appended, the rest unchanged
	cfg := "server:\n  address: x\nnotifier:\n  filesystem: {}\n"
	got := ReplaceAccessControl(cfg, "access_control:\n  default_policy: 'deny'\n")
	if !strings.HasPrefix(got, strings.TrimRight(cfg, "\n")) || !strings.Contains(got, "access_control:") {
		t.Fatalf("AUTHELIA-05: %s", got)
	}
	// AUTHELIA-09: the cobra usage text after the errors is cut
	installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		return "Configuration parsed and loaded with errors:\n\t- bad thing\nUsage:\n  authelia config validate [flags]\n", fmt.Errorf("exit 1")
	})
	dir := t.TempDir()
	st := Settings{AutheliaConfig: filepath.Join(dir, "configuration.yml"), AutheliaCtr: "auth", AutheliaCtrDir: "/config"}
	err := validateAutheliaConfig(st, "x: 1\n")
	if err == nil || !strings.Contains(err.Error(), "bad thing") || strings.Contains(err.Error(), "Usage") {
		t.Fatalf("AUTHELIA-09: %v", err)
	}
	// AUTHELIA-10: concurrent validations use different candidate files, removed afterwards
	var mu sync.Mutex
	seen := map[string]bool{}
	installFakeDocker(t, func(args []string, stdin []byte) (string, error) {
		mu.Lock()
		seen[args[len(args)-1]] = true
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		return "parsed and loaded successfully without errors", nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = validateAutheliaConfig(st, "x: 1\n") }()
	}
	wg.Wait()
	if len(seen) != 3 {
		t.Fatalf("AUTHELIA-10: %v", seen)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".gilmok-candidate*")); len(left) != 0 {
		t.Fatalf("AUTHELIA-10: leftovers %v", left)
	}
	// AUTHELIA-11: YAML injection through display name / email stays a string
	users := map[string]*AUser{"kim": {DisplayName: "Kim\ngroups: [admins]\nx: ", Email: "a@b.c\"\n  - admins", Groups: []string{"family"}, Password: "$argon2id$x"}}
	b, err := MarshalUsers(users)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "users.yml")
	os.WriteFile(p, b, 0o600)
	back, err := LoadUsers(p)
	if err != nil || back["kim"].DisplayName != users["kim"].DisplayName || strings.Join(back["kim"].Groups, ",") != "family" || len(back) != 1 {
		t.Fatalf("AUTHELIA-11: %+v %v", back["kim"], err)
	}
}

func TestScnGroupsMore(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) {
		d.Settings.Domain = "example.com"
		d.Services = []*Service{{ID: "a", Subdomain: "a", Upstream: "a:1", Exposure: ExposurePublic, Enabled: true, Authelia: AutheliaOpts{Enabled: true, Groups: []string{"one"}}}}
		d.AGroups, d.AGroupsInit, d.Dirty, d.Pending = []AGroup{{Name: "one"}, {Name: "spare"}}, true, false, nil
	})
	// GRP-05: description only → not pending
	boss.must(200, "PUT", "/api/groups/one", `{"name":"one","desc":"  첫 그룹  "}`)
	d := f.app.store.Snapshot()
	if d.Dirty || d.AGroups[0].Desc != "첫 그룹" {
		t.Fatalf("GRP-05: %v %+v", d.Dirty, d.AGroups)
	}
	// GRP-22: description cut at 200
	boss.must(200, "PUT", "/api/groups/spare", `{"name":"spare","desc":"`+strings.Repeat("가", 250)+`"}`)
	if desc := f.app.store.Snapshot().AGroups[1].Desc; len([]rune(desc)) > 200 {
		t.Fatalf("GRP-22: %d", len([]rune(desc)))
	}
	// GRP-06 / GRP-07: list with usage; unreadable users file → usersError
	f.set(func(d *Data) {
		d.Settings.UseAuthelia, d.Settings.AutheliaUsers = true, filepath.Join(f.dir, "missing.yml")
	})
	m := boss.must(200, "GET", "/api/groups", "")
	if m["usersError"] == nil || !strings.Contains(fmtAny(m["groups"]), `"services":["a"]`) {
		t.Fatalf("GRP-06/07: %v", m)
	}
	// GRP-20: rename while the users file cannot be read → refused, nothing changed
	if code, _ := boss.do("PUT", "/api/groups/one", `{"name":"uno"}`); code != 400 || f.app.store.Snapshot().Services[0].Authelia.Groups[0] != "one" {
		t.Fatalf("GRP-20: %d", code)
	}
	f.set(func(d *Data) { d.Settings.UseAuthelia = false })
	// GRP-08: rename of an unused group → no pending
	f.set(func(d *Data) { d.Dirty, d.Pending = false, nil })
	boss.must(200, "PUT", "/api/groups/spare", `{"name":"spare2"}`)
	if f.app.store.Snapshot().Dirty {
		t.Fatal("GRP-08: pending without users of the group")
	}
	// GRP-09: one service
	m = boss.must(200, "PUT", "/api/groups/one", `{"name":"uno"}`)
	d = f.app.store.Snapshot()
	if m["services"] != float64(1) || d.Services[0].Authelia.Groups[0] != "uno" || !d.Dirty {
		t.Fatalf("GRP-09: %v", m)
	}
}

// ---------------------------------------------------------------- BULK

func xlsxFrom(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

const sheetNS = `xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"`

func TestScnBulkFiles(t *testing.T) {
	svcs, st := bulkTestData()
	// BULK-04: shared strings, booleans, skipped empty cells (r attribute), inline strings
	b := xlsxFrom(t, map[string]string{
		"xl/workbook.xml":            `<workbook ` + sheetNS + `><sheets><sheet name="s" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="worksheets/data.xml"/></Relationships>`,
		"xl/sharedStrings.xml":       `<sst ` + sheetNS + `><si><t>서브도메인</t></si><si><t>대상</t></si><si><r><t>사</t></r><r><t>용</t></r></si><si><t>neo</t></si></sst>`,
		"xl/worksheets/data.xml": `<worksheet ` + sheetNS + `><sheetData>` +
			`<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="D1" t="s"><v>2</v></c></row>` +
			`<row r="3"><c r="A3" t="s"><v>3</v></c><c r="B3" t="inlineStr"><is><t>neo:80</t></is></c><c r="D3" t="b"><v>0</v></c></row>` +
			`</sheetData></worksheet>`,
	})
	rows, err := readSheet("x.xlsx", b)
	if err != nil {
		t.Fatal(err)
	}
	plan, work, _, err := planBulk(rows, svcs, st, nil)
	if err != nil || plan.Counts["create"] != 1 {
		t.Fatalf("BULK-04/05: %v %+v", err, plan)
	}
	for _, s := range work {
		if s.Subdomain == "neo" && (s.Upstream != "neo:80" || s.Enabled) {
			t.Fatalf("BULK-04: %+v", s)
		}
	}
	if plan.Rows[0].Row != 3 {
		t.Fatalf("BULK-04 row numbers: %d", plan.Rows[0].Row)
	}
	// BULK-06: broken zip / not a sheet
	if _, err := readSheet("x.xlsx", []byte("PK\x03\x04garbage")); err == nil {
		t.Fatal("BULK-06")
	}
	// BULK-08: CP949 csv refused with a hint
	if _, err := readSheet("x.csv", []byte{0xbc, 0xad, 0xba, 0xea, ',', 'a'}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("BULK-08: %v", err)
	}
	// BULK-09: ; and tab separators
	for _, sep := range []string{";", "\t"} {
		rows, err := readSheet("x.csv", []byte("서브도메인"+sep+"대상\nzz"+sep+"z:1\n"))
		if err != nil || len(rows[1]) != 2 || rows[1][1] != "z:1" {
			t.Fatalf("BULK-09 %q: %v %v", sep, rows, err)
		}
	}
	// BULK-26: column aliases
	rows = [][]string{{"subdomain", "upstream(host:port)", "Proxied"}, {"al", "al:1", "Y"}}
	if plan, _, _, err := planBulk(rows, svcs, st, nil); err != nil || plan.Counts["create"] != 1 {
		t.Fatalf("BULK-26: %v %+v", err, plan)
	}
	// BULK-25: too many rows
	big := [][]string{{"서브도메인", "대상"}}
	for i := 0; i < bulkMaxRows+1; i++ {
		big = append(big, []string{fmt.Sprintf("s%d", i), "a:1"})
	}
	if _, _, _, err := planBulk(big, svcs, st, nil); err == nil {
		t.Fatal("BULK-25 rows")
	}
	// BULK-27: sparse rows / huge column index / oversize sheet
	sparse := xlsxFrom(t, map[string]string{"xl/worksheets/sheet1.xml": `<worksheet ` + sheetNS + `><sheetData><row r="999999"><c r="A999999" t="inlineStr"><is><t>x</t></is></c></row></sheetData></worksheet>`})
	if _, err := readSheet("x.xlsx", sparse); err == nil {
		t.Fatal("BULK-27 sparse")
	}
	wide := xlsxFrom(t, map[string]string{"xl/worksheets/sheet1.xml": `<worksheet ` + sheetNS + `><sheetData><row r="1"><c r="ZZZ1" t="inlineStr"><is><t>x</t></is></c></row></sheetData></worksheet>`})
	if r, err := readSheet("x.xlsx", wide); err != nil || len(r[0]) > 0 {
		t.Fatalf("BULK-27 wide: %v %v", len(r), err)
	}
	huge := xlsxFrom(t, map[string]string{"xl/worksheets/sheet1.xml": `<worksheet ` + sheetNS + `><sheetData>` + strings.Repeat(" ", 65<<20) + `</sheetData></worksheet>`})
	if _, err := readSheet("x.xlsx", huge); err == nil {
		t.Fatal("BULK-27 zip bomb")
	}
	// BULK-28: directive escape in the 추가 지시어 column
	rows = [][]string{{"서브도메인", "대상", "추가 지시어"}, {"esc", "e:1", "}\nevil.com {\nrespond 1"}}
	if plan, _, _, _ := planBulk(rows, svcs, st, nil); plan.Counts["error"] != 1 {
		t.Fatalf("BULK-28: %+v", plan)
	}
	// BULK-29: formulas and XML characters survive export → import as text
	odd := []*Service{{ID: "o", Subdomain: "odd", Upstream: "o:1", Exposure: ExposurePublic, Enabled: true, Notes: `=CMD|' /C calc'!A0 </t></is> & <x>`, Extra: "header X-A \"<b>&\""}}
	x, err := writeServicesXLSX([][]string{serviceRow(odd[0])}, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = readSheet("o.xlsx", x)
	if err != nil {
		t.Fatal(err)
	}
	if plan, _, _, err := planBulk(rows, odd, st, nil); err != nil || plan.Counts["same"] != 1 {
		t.Fatalf("BULK-29: %v %+v", err, plan)
	}
	// BULK-03: the guide sheet lists the registered groups
	x, _ = writeServicesXLSX(nil, st, []AGroup{{Name: "admins", Desc: "관리자"}})
	zr, _ := zip.NewReader(bytes.NewReader(x), int64(len(x)))
	for _, zf := range zr.File {
		if zf.Name == "xl/worksheets/sheet2.xml" {
			rc, _ := zf.Open()
			var bb bytes.Buffer
			bb.ReadFrom(rc)
			if !strings.Contains(bb.String(), "admins (관리자)") {
				t.Fatal("BULK-03")
			}
		}
	}
}

func TestScnBulkHTTP(t *testing.T) {
	f := newFullApp(t)
	boss := f.admin(t)
	f.set(func(d *Data) {
		d.Settings.Domain = "example.com"
		d.Services = []*Service{{ID: "k", Subdomain: "keep", Upstream: "k:1", Exposure: ExposurePublic, Enabled: true}}
		d.Dirty, d.Pending = false, nil
	})
	csv := "서브도메인,대상,삭제\nnew1,n:1,\nkeep,k:2,\nbad one,x:1,\nghost,,Y\n"
	body := `{"name":"t.csv","data":"` + base64.StdEncoding.EncodeToString([]byte(csv)) + `","dry":%s}`
	// BULK-22: preview changes nothing
	m := boss.must(200, "POST", "/api/services/bulk", fmt.Sprintf(body, "true"))
	if len(f.app.store.Snapshot().Services) != 1 || m["counts"].(map[string]any)["error"] != float64(2) {
		t.Fatalf("BULK-22: %v", m)
	}
	// BULK-21 (R6): apply skips the error rows, one save, pending 2, one audit entry
	boss.must(200, "POST", "/api/services/bulk", fmt.Sprintf(body, "false"))
	d := f.app.store.Snapshot()
	if len(d.Services) != 2 || len(d.Pending) != 2 {
		t.Fatalf("BULK-21: %d services, pending %v", len(d.Services), d.Pending)
	}
	n := 0
	for _, e := range f.events(t, "audit") {
		if e.Action == "서비스 일괄 등록 (엑셀)" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("BULK-21/AUD-04: %d audit entries", n)
	}
	// BULK-25: oversize upload
	if code, _ := boss.do("POST", "/api/services/bulk", `{"name":"x.csv","data":"`+strings.Repeat("A", 2<<20)+`","dry":true}`); code != 400 {
		t.Fatalf("BULK-25 size: %d", code)
	}
}

// ---------------------------------------------------------------- UP

func TestScnUpstreamsMore(t *testing.T) {
	mk := func(name, state string, nets []string, svc string) inspectCtr {
		var c inspectCtr
		c.Name = "/" + name
		c.State.Status = state
		c.Config.Labels = map[string]string{"com.docker.compose.service": svc}
		c.Config.ExposedPorts = map[string]struct{}{"80/tcp": {}}
		c.NetworkSettings.Networks = map[string]struct{}{}
		for _, n := range nets {
			c.NetworkSettings.Networks[n] = struct{}{}
		}
		return c
	}
	raw := []inspectCtr{
		mk("caddy", "running", []string{"front", "back"}, ""),
		mk("only-back", "running", []string{"back"}, "web"),
		mk("stopped", "exited", []string{"front"}, ""),
		mk("lonely", "running", []string{"x"}, ""),
	}
	var empty inspectCtr
	empty.Name, empty.State.Status = "/bare", "running"
	raw = append(raw, empty)
	svcs := []*Service{{Subdomain: "s1", Upstream: "only-back:80"}, {Subdomain: "s2", Upstream: "http://only-back:80/x"}, {Subdomain: "s3", Upstream: "web:80"}}
	list := buildUpstreams(raw, Settings{CaddyContainer: "caddy"}, svcs, "")
	by := map[string]UpCtr{}
	for _, c := range list {
		by[c.Name] = c
	}
	// UP-02: matched through the second network
	if c := by["only-back"]; c.Reach != "network" || strings.Join(c.Shared, ",") != "back" {
		t.Fatalf("UP-02: %+v", c)
	}
	// UP-06 / UP-07: n services, by container or compose service name
	if c := by["only-back"]; len(c.UsedBy) != 3 {
		t.Fatalf("UP-06/07: %v", c.UsedBy)
	}
	// UP-10: running before stopped, network before none
	order := []string{}
	for _, c := range list {
		order = append(order, c.Name)
	}
	if !(indexOf(order, "only-back") < indexOf(order, "lonely") && indexOf(order, "lonely") < indexOf(order, "stopped")) {
		t.Fatalf("UP-10: %v", order)
	}
	// UP-11: empty slices, not null
	if b := fmtAny(by["bare"]); !strings.Contains(b, `"ports":[]`) || !strings.Contains(b, `"networks":[]`) {
		t.Fatalf("UP-11: %s", b)
	}
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}
