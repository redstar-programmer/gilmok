package main

import (
	"strings"
	"testing"
)

func bulkTestData() ([]*Service, Settings) {
	st := Settings{Domain: "example.com", UseCloudflare: true, UseCaddy: true}
	svcs := []*Service{
		{ID: "a1", Subdomain: "photos", Upstream: "immich:2283", Exposure: ExposurePublic, Enabled: true, ManageDNS: true, WAF: WAFDetect, Authelia: AutheliaOpts{Policy: "two_factor", Groups: []string{}}},
		{ID: "b2", Subdomain: "admin", Upstream: "dock:3000", Exposure: ExposureTailscale, Enabled: true, Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor", Groups: []string{"admins"}}, Notes: "관리", Extra: "header X-A 1\nheader X-B 2"},
	}
	return svcs, st
}

func TestBulkXLSXRoundTrip(t *testing.T) {
	svcs, st := bulkTestData()
	var rows [][]string
	for _, s := range svcs {
		rows = append(rows, serviceRow(s))
	}
	b, err := writeServicesXLSX(rows, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readSheet("x.xlsx", b)
	if err != nil {
		t.Fatal(err)
	}
	plan, _, dirty, err := planBulk(got, svcs, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Counts["same"] != 2 || len(dirty) != 0 {
		t.Fatalf("round trip should change nothing: %+v", plan)
	}
	tpl, _ := writeServicesXLSX(nil, st, []AGroup{{Name: "admins"}})
	if r, err := readSheet("t.xlsx", tpl); err != nil || len(r) != 1 {
		t.Fatalf("template = %v rows, %v", len(r), err)
	}
}

func TestBulkPlanCSV(t *testing.T) {
	svcs, st := bulkTestData()
	csv := "\xef\xbb\xbf서브도메인,대상,노출,Authelia,허용 그룹,WAF,메모,삭제,모르는 열\n" +
		"new,app:80,,1단계,\"a, b\",차단,,,x\n" + // create
		"photos.example.com,immich:2284,,,,,-,,\n" + // update (FQDN accepted, notes cleared)
		"admin,,,,,,,Y,\n" + // delete
		"#comment,,,,,,,,\n" +
		"bad,x y,,,,,,,\n" + // invalid upstream
		"new,app:81,,,,,,,\n" + // duplicate in file
		"gone,,,,,,,Y,\n" + // delete of unknown
		"w,a:1,,,,이상함,,,\n" // bad choice
	rows, err := readSheet("s.csv", []byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	plan, work, dirty, err := planBulk(rows, svcs, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := plan.Counts
	if c["create"] != 1 || c["update"] != 1 || c["delete"] != 1 || c["error"] != 4 {
		t.Fatalf("counts = %v %+v", c, plan.Rows)
	}
	if len(dirty) != 3 || len(work) != 2 || len(plan.Ignored) != 1 {
		t.Fatalf("dirty=%v work=%d ignored=%v", dirty, len(work), plan.Ignored)
	}
	var nw *Service
	for _, s := range work {
		if s.Subdomain == "new" {
			nw = s
		}
		if s.Subdomain == "photos" && (s.Upstream != "immich:2284" || s.WAF != WAFDetect) {
			t.Fatalf("update kept other fields? %+v", s)
		}
	}
	if nw == nil || !nw.Enabled || nw.Exposure != ExposurePublic || !nw.ManageDNS || nw.WAF != WAFBlock ||
		!nw.Authelia.Enabled || nw.Authelia.Policy != "one_factor" || strings.Join(nw.Authelia.Groups, ",") != "a,b" || nw.ID == "" {
		t.Fatalf("new service = %+v", nw)
	}
	if svcs[0].Upstream != "immich:2283" {
		t.Fatal("planBulk must not modify the live list")
	}
	if _, err := readSheet("a.xls", []byte{0xD0, 0xCF}); err == nil {
		t.Fatal(".xls should be refused")
	}
	if _, _, _, err := planBulk([][]string{{"이름없음", "대상"}}, svcs, st, nil); err == nil {
		t.Fatal("missing subdomain column should fail")
	}
}

func TestBulkUnknownGroups(t *testing.T) {
	svcs, st := bulkTestData()
	rows := [][]string{{"서브도메인", "대상", "허용 그룹"}, {"new", "app:80", "admins, ghost"}, {"admin", "", "admins"}, {"new2", "app:81", "admins"}}
	plan, _, _, err := planBulk(rows, svcs, st, map[string]bool{"admins": true})
	if err != nil {
		t.Fatal(err)
	}
	c := plan.Counts
	if c["error"] != 1 || c["create"] != 1 || c["same"] != 1 || !strings.Contains(plan.Rows[0].Error, "ghost") {
		t.Fatalf("plan = %+v", plan)
	}
	if checkNewGroups(map[string]bool{}, []string{"old"}, []string{"old"}) != nil {
		t.Fatal("groups already on the service must stay allowed")
	}
}
