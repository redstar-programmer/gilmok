package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGroupsLifecycle(t *testing.T) {
	app, _ := newAuthTestApp(t)
	_ = app.store.Update(func(d *Data) error {
		d.Settings.Domain = "example.com"
		d.Services = []*Service{
			{ID: "a", Subdomain: "photos", Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor", Groups: []string{"family", "admins"}}},
			{ID: "b", Subdomain: "admin", Authelia: AutheliaOpts{Enabled: true, Policy: "two_factor", Groups: []string{"admins"}}},
		}
		return nil
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/groups", app.getGroups)
	mux.HandleFunc("POST /api/groups", app.postGroup)
	mux.HandleFunc("PUT /api/groups/{name}", app.putGroup)
	mux.HandleFunc("DELETE /api/groups/{name}", app.deleteGroup)
	do := func(method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do("GET", "/api/groups", ""); c != 200 {
		t.Fatal(c)
	}
	d := app.store.Snapshot()
	if !d.AGroupsInit || len(d.AGroups) != 2 {
		t.Fatalf("seed = %+v", d.AGroups)
	}
	if c := do("POST", "/api/groups", `{"name":"guests","desc":"손님"}`); c != 200 {
		t.Fatal("create", c)
	}
	if c := do("POST", "/api/groups", `{"name":"guests"}`); c != 409 {
		t.Fatal("duplicate should fail", c)
	}
	if c := do("POST", "/api/groups", `{"name":"bad name"}`); c != 400 {
		t.Fatal("bad name should fail", c)
	}
	// rename admins → ops everywhere (services → pending)
	if c := do("PUT", "/api/groups/admins", `{"name":"ops","desc":"운영"}`); c != 200 {
		t.Fatal("rename", c)
	}
	d = app.store.Snapshot()
	for _, s := range d.Services {
		if strings.Contains(strings.Join(s.Authelia.Groups, ","), "admins") {
			t.Fatalf("admins left in %s", s.Subdomain)
		}
	}
	if !d.Dirty || d.Services[1].Authelia.Groups[0] != "ops" {
		t.Fatalf("rename not applied: %+v", d.Services[1].Authelia)
	}
	// rename onto an existing name is refused
	if c := do("PUT", "/api/groups/ops", `{"name":"family"}`); c != 409 {
		t.Fatal("merge rename should fail", c)
	}
	// delete in use → 409, purge → removed from services
	if c := do("DELETE", "/api/groups/family", ""); c != 409 {
		t.Fatal("in-use delete should ask", c)
	}
	if c := do("DELETE", "/api/groups/family?purge=1", ""); c != 200 {
		t.Fatal("purge", c)
	}
	d = app.store.Snapshot()
	if strings.Join(d.Services[0].Authelia.Groups, ",") != "ops" {
		t.Fatalf("purge left %v", d.Services[0].Authelia.Groups)
	}
	if c := do("DELETE", "/api/groups/guests", ""); c != 200 {
		t.Fatal("unused delete", c)
	}
	var names []string
	for _, g := range app.store.Snapshot().AGroups {
		names = append(names, g.Name+"="+g.Desc)
	}
	if strings.Join(names, ",") != "ops=운영" {
		t.Fatalf("groups = %v", names)
	}
	if g, ch := replaceGroup([]string{"a", "b"}, "a", "b"); !ch || strings.Join(g, ",") != "b" {
		t.Fatalf("replaceGroup merge = %v", g)
	}
}

func TestServiceRejectsUnknownGroup(t *testing.T) {
	app, _ := newAuthTestApp(t)
	_ = app.store.Update(func(d *Data) error {
		d.Settings.Domain = "example.com"
		d.AGroups = []AGroup{{Name: "admins"}}
		d.AGroupsInit = true
		return nil
	})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/services", app.saveService)
	post := func(body string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/services", strings.NewReader(body)))
		return rec.Code
	}
	if c := post(`{"subdomain":"a","upstream":"a:1","exposure":"public","authelia":{"enabled":true,"groups":["ghost"]}}`); c != 400 {
		t.Fatal("unknown group should be refused", c)
	}
	if c := post(`{"subdomain":"b","upstream":"b:1","exposure":"public","authelia":{"enabled":true,"groups":["admins"]}}`); c != 200 {
		t.Fatal("registered group should pass", c)
	}
}
