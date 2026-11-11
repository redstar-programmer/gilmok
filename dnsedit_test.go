package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDNSRowsAndEdit(t *testing.T) {
	recs := []DNSRecord{
		{ID: "1", Type: "A", Name: "pub.example.com", Content: "1.1.1.1", Proxied: true},   // service, differs (IP)
		{ID: "2", Type: "A", Name: "same.example.com", Content: "2.2.2.2", Proxied: false}, // service, same
		{ID: "3", Type: "A", Name: "gone.example.com", Content: "2.2.2.2"},                 // managed, no service → orphan
		{ID: "4", Type: "A", Name: "rdp.example.com", Content: "9.9.9.9"},                  // manual
		{ID: "5", Type: "CNAME", Name: "www.example.com", Content: "pub.example.com"},      // manual
		{ID: "6", Type: "A", Name: "hand.example.com", Content: "8.8.8.8"},                 // service with DNS 관리 off
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[{"id":"z1"}]}`)
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == "GET":
			b, _ := json.Marshal(recs)
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":%s,"result_info":{"page":1,"total_pages":1}}`, b)
		default:
			fmt.Fprint(w, `{"success":true,"errors":[],"result":{}}`)
		}
	}))
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()
	t.Setenv("GM_CF_TOKEN", "test-token-not-real-0000000000")
	t.Setenv("GM_CF_TOKEN_FILE", "")

	st := defaultSettings()
	st.Domain, st.UseCloudflare = "example.com", true
	d := Data{Settings: st, LastPublicIP: "2.2.2.2", ManagedDNS: []string{"pub.example.com", "same.example.com", "gone.example.com"},
		Services: []*Service{
			{ID: "p", Subdomain: "pub", Exposure: ExposurePublic, Proxied: true, Enabled: true, ManageDNS: true},
			{ID: "s", Subdomain: "same", Exposure: ExposurePublic, Enabled: true, ManageDNS: true},
			{ID: "n", Subdomain: "new", Exposure: ExposurePublic, Enabled: true, ManageDNS: true},
			{ID: "h", Subdomain: "hand", Exposure: ExposurePublic, Enabled: true, ManageDNS: false},
		}}
	a := &App{cf: NewCF()}
	rows, err := a.dnsRows(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]dnsRow{}
	for _, r := range rows {
		by[r.Type+" "+r.Name] = r
	}
	check := func(key, status string, editable bool) {
		t.Helper()
		r, ok := by[key]
		if !ok || r.Status != status || r.Editable != editable {
			t.Fatalf("%s: %+v", key, r)
		}
	}
	check("A pub.example.com", "diff", false)
	if !by["A pub.example.com"].IPChange || !strings.Contains(by["A pub.example.com"].Reason, "공인 IP 변경 반영") {
		t.Fatalf("IP change must mention the confirmation: %q", by["A pub.example.com"].Reason)
	}
	check("A same.example.com", "ok", false)
	check("A gone.example.com", "orphan", false)
	check("A rdp.example.com", "", true)
	check("CNAME www.example.com", "", true)
	check("A new.example.com", "missing", false)
	if r := by["A hand.example.com"]; r.ServiceID != "h" || r.SvcManage || !r.Editable || r.Status != "" {
		t.Fatalf("service without DNS management: %+v", r)
	}

	// editing rules
	in := dnsEdit{Type: "a", Name: "Mail", Content: "203.0.113.5", Proxied: true, TTL: 300}
	if err := normalizeDNSEdit(d, &in); err != nil || in.Name != "mail.example.com" || in.Type != "A" || in.TTL != 1 {
		t.Fatalf("normalize: %v %+v", err, in)
	}
	for _, bad := range []dnsEdit{
		{Type: "A", Name: "x", Content: "::1"},
		{Type: "AAAA", Name: "x", Content: "1.2.3.4"},
		{Type: "CNAME", Name: "x", Content: "not a host"},
		{Type: "SRV", Name: "x", Content: "a"},
		{Type: "TXT", Name: "x", Content: "a\nb"},
		{Type: "A", Name: "pub", Content: "1.2.3.4"}, // a DNS-managed service owns this name
	} {
		b := bad
		if err := normalizeDNSEdit(d, &b); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	mx := dnsEdit{Type: "MX", Name: "@", Content: "Mail.Example.com.", Priority: 10, Proxied: true}
	if err := normalizeDNSEdit(d, &mx); err != nil || mx.Name != "example.com" || mx.Content != "mail.example.com" || mx.Proxied {
		t.Fatalf("mx: %v %+v", err, mx)
	}
	if editableRecord(d, recs[0]) || !editableRecord(d, recs[3]) {
		t.Fatal("editableRecord")
	}
}
