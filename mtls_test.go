package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func parsePEMCert(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGenMTLS(t *testing.T) {
	caPEM, certPEM, keyPEM, err := genMTLS("example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if checkCAPEM(caPEM) != nil || !strings.Contains(keyPEM, "PRIVATE KEY") {
		t.Fatal("bad PEM output")
	}
	ca, cert := parsePEMCert(t, caPEM), parsePEMCert(t, certPEM)
	if !ca.IsCA {
		t.Fatal("CA flag missing")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client certificate does not chain to the CA as a client cert: %v", err)
	}
}

// generate → upload to the zone → switch AOP on → CA into the managed Caddy; a second run replaces
// (and deletes) the previous certificate.
func TestCaddyMTLSGenerate(t *testing.T) {
	f := newFullApp(t)
	c := f.admin(t)
	var mu sync.Mutex
	var calls []string
	uploads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		ok := func(v any) {
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":%s}`, b)
		}
		switch {
		case r.URL.Path == "/zones":
			ok([]map[string]string{{"id": "z1"}})
		case r.URL.Path == "/zones/z1/origin_tls_client_auth" && r.Method == "POST":
			var in map[string]string
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &in)
			if !strings.Contains(in["certificate"], "BEGIN CERTIFICATE") || !strings.Contains(in["private_key"], "PRIVATE KEY") {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"success":false,"errors":[{"code":1,"message":"bad"}]}`)
				return
			}
			uploads++
			ok(map[string]string{"id": fmt.Sprintf("cert%d", uploads), "status": "pending_deployment", "expires_on": "2031-11-11T00:00:00Z"})
		case r.URL.Path == "/zones/z1/origin_tls_client_auth/settings" && r.Method == "PUT":
			ok(map[string]bool{"enabled": true})
		case strings.HasPrefix(r.URL.Path, "/zones/z1/origin_tls_client_auth/") && r.Method == "DELETE":
			ok(map[string]string{"id": "x"})
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":7003,"message":"no route"}]}`)
		}
	}))
	defer srv.Close()
	old := cfAPI
	cfAPI = srv.URL
	defer func() { cfAPI = old }()
	t.Setenv("GM_CF_TOKEN", "test-token-value-1234567890abcdefghij")
	stackDir := filepath.Join(f.dir, "stacks", "caddy")
	f.set(func(d *Data) {
		d.Settings.Domain, d.Settings.UseCloudflare = "example.com", true
		d.Stacks = map[string]*ManagedStack{"caddy": {Name: "caddy", Container: "gilmok-caddy", Dir: stackDir}}
	})

	m := c.must(200, "POST", "/api/stacks/caddy/mtls", `{}`)
	if m["status"] != "pending_deployment" {
		t.Fatalf("response: %v", m)
	}
	ca, err := os.ReadFile(filepath.Join(stackDir, "conf", "certs", "cf-origin-pull-ca.pem"))
	if err != nil || checkCAPEM(string(ca)) != nil {
		t.Fatalf("CA not written: %v", err)
	}
	if st := f.app.store.Snapshot().MTLS; st.CertID != "cert1" || st.Zone != "z1" {
		t.Fatalf("state: %+v", st)
	}
	c.must(200, "POST", "/api/stacks/caddy/mtls", `{}`)
	mu.Lock()
	joined := strings.Join(calls, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "PUT /zones/z1/origin_tls_client_auth/settings") || !strings.Contains(joined, "DELETE /zones/z1/origin_tls_client_auth/cert1") {
		t.Fatalf("calls:\n%s", joined)
	}
	// no private key is kept anywhere in Gilmok's data
	raw, _ := os.ReadFile(filepath.Join(f.dir, "gilmok.json"))
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("a private key ended up in gilmok.json")
	}
}
