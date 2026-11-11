package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func ddnsTestData(v6 bool) Data {
	st := defaultSettings()
	st.Domain = "example.com"
	st.TailscaleIP = "100.64.0.1"
	st.UseCloudflare = true
	st.DDNSIPv6 = v6
	return Data{Settings: st, Services: []*Service{
		{ID: "1", Subdomain: "pub", Exposure: ExposurePublic, Enabled: true, ManageDNS: true, Proxied: true},
		{ID: "2", Subdomain: "priv", Exposure: ExposureTailscale, Enabled: true, ManageDNS: true},
		{ID: "3", Subdomain: "manual", Exposure: ExposurePublic, Enabled: true, ManageDNS: false},
	}}
}

func findAct(acts []DNSAction, typ, name string) *DNSAction {
	for i := range acts {
		if acts[i].Type == typ && acts[i].Name == name {
			return &acts[i]
		}
	}
	return nil
}

func TestPlanDNSIPv6(t *testing.T) {
	recs := []DNSRecord{
		{ID: "a1", Type: "A", Name: "pub.example.com", Content: "1.1.1.1", Proxied: true},
		{ID: "a2", Type: "AAAA", Name: "manual.example.com", Content: "2001:db8::9"},
	}
	// IPv6 on: AAAA wanted only for the public managed service
	d := ddnsTestData(true)
	acts := PlanDNS(d, recs, "2.2.2.2", "2001:db8::1", nil, nil)
	if a := findAct(acts, "A", "pub.example.com"); a == nil || a.Action != "update" {
		t.Fatalf("A pub: %+v", a)
	}
	if a := findAct(acts, "AAAA", "pub.example.com"); a == nil || a.Action != "create" || a.content != "2001:db8::1" || !a.proxied {
		t.Fatalf("AAAA pub: %+v", a)
	}
	if findAct(acts, "AAAA", "priv.example.com") != nil || findAct(acts, "AAAA", "manual.example.com") != nil {
		t.Fatal("AAAA must be only for public managed services")
	}
	want := desiredDNS(d, "2.2.2.2", "2001:db8::1")
	if got := managedNames(want, "AAAA"); len(got) != 1 || got[0] != "pub.example.com" {
		t.Fatalf("managed6: %v", got)
	}

	// IPv6 detection failed: skip, never delete the existing AAAA
	recs2 := append(recs, DNSRecord{ID: "a3", Type: "AAAA", Name: "pub.example.com", Content: "2001:db8::1", Proxied: true})
	acts = PlanDNS(d, recs2, "2.2.2.2", "", nil, []string{"pub.example.com"})
	if a := findAct(acts, "AAAA", "pub.example.com"); a == nil || a.Action != "skip" {
		t.Fatalf("AAAA skip: %+v", a)
	}

	// IPv6 turned off: delete only the AAAA this app owns
	d = ddnsTestData(false)
	acts = PlanDNS(d, recs2, "2.2.2.2", "", []string{"pub.example.com"}, []string{"pub.example.com"})
	if a := findAct(acts, "AAAA", "pub.example.com"); a == nil || a.Action != "delete" || a.recordID != "a3" {
		t.Fatalf("AAAA delete: %+v", a)
	}
	if findAct(acts, "AAAA", "manual.example.com") != nil {
		t.Fatal("must not touch AAAA it does not own")
	}
	if a := findAct(acts, "A", "pub.example.com"); a == nil || a.Action == "delete" {
		t.Fatalf("A pub must stay: %+v", a)
	}
}

type fakeDDNSCF struct {
	recs    []DNSRecord
	failIDs map[string]bool
	patched map[string]string
}

func (f *fakeDDNSCF) Records(context.Context, string) ([]DNSRecord, error) { return f.recs, nil }
func (f *fakeDDNSCF) Patch(_ context.Context, _, id string, fields map[string]any) error {
	if f.failIDs[id] {
		return errors.New("boom")
	}
	f.patched[id] = fields["content"].(string)
	if len(fields) != 1 {
		return errors.New("DDNS must change content only")
	}
	return nil
}

func TestDDNSReconcile(t *testing.T) {
	d := ddnsTestData(true)
	cf := &fakeDDNSCF{recs: []DNSRecord{
		{ID: "a", Type: "A", Name: "pub.example.com", Content: "1.1.1.1"},
		{ID: "aaaa", Type: "AAAA", Name: "pub.example.com", Content: "2001:db8::old"},
		{ID: "p", Type: "A", Name: "priv.example.com", Content: "100.64.0.1"},
		{ID: "m", Type: "A", Name: "manual.example.com", Content: "1.1.1.1"},
	}, failIDs: map[string]bool{"aaaa": true}, patched: map[string]string{}}
	up, failed, err := ddnsReconcile(context.Background(), cf, d, ddnsAddrs{ip4: "2.2.2.2", ip6: "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if cf.patched["a"] != "2.2.2.2" || len(up) != 1 {
		t.Fatalf("A update: %v %v", cf.patched, up)
	}
	if len(failed) != 1 || !strings.Contains(failed[0], "AAAA pub.example.com") {
		t.Fatalf("failed: %v", failed)
	}
	if _, ok := cf.patched["p"]; ok {
		t.Fatal("private record must not change")
	}
	if _, ok := cf.patched["m"]; ok {
		t.Fatal("unmanaged record must not change")
	}

	// IPv6 not detected: AAAA untouched, A still handled
	cf.failIDs = map[string]bool{}
	cf.patched = map[string]string{}
	cf.recs[0].Content = "2.2.2.2"
	up, failed, _ = ddnsReconcile(context.Background(), cf, d, ddnsAddrs{ip4: "2.2.2.2"})
	if len(up) != 0 || len(failed) != 0 || len(cf.patched) != 0 {
		t.Fatalf("no-op expected: %v %v %v", up, failed, cf.patched)
	}
}

func TestHoldIPChanges(t *testing.T) {
	d := ddnsTestData(false)
	recs := []DNSRecord{
		{ID: "a1", Type: "A", Name: "pub.example.com", Content: "211.250.185.159", Proxied: true},
		{ID: "p1", Type: "A", Name: "priv.example.com", Content: "100.64.0.9"},
	}
	acts := PlanDNS(d, recs, "211.234.196.10", "", nil, nil)
	pub := findAct(acts, "A", "pub.example.com")
	if pub == nil || !pub.IPChange || pub.Action != "update" {
		t.Fatalf("public address change must be flagged: %+v", pub)
	}
	if p := findAct(acts, "A", "priv.example.com"); p == nil || p.IPChange || p.Action != "update" {
		t.Fatalf("private (Tailscale IP from settings) is not a WAN change: %+v", p)
	}
	held, list := holdIPChanges(acts)
	if len(list) != 1 {
		t.Fatalf("held: %v", list)
	}
	if a := findAct(held, "A", "pub.example.com"); a.Action != "ok" || a.content != "211.250.185.159" {
		t.Fatalf("address must stay: %+v", a)
	}
	// proxied also changed → still an update, but with the old address
	d.Services[0].Proxied = false
	held, _ = holdIPChanges(PlanDNS(d, recs, "211.234.196.10", "", nil, nil))
	if a := findAct(held, "A", "pub.example.com"); a.Action != "update" || a.content != "211.250.185.159" || a.proxied {
		t.Fatalf("proxied-only update: %+v", a)
	}
}
