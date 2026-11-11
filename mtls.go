package main

// mTLS between Cloudflare and a Caddy Gilmok installed, made by Gilmok:
//
//  1. a private CA and a client certificate signed by it (RSA 2048) are generated here
//  2. the client certificate + key go to Cloudflare as the zone's Authenticated Origin Pulls
//     certificate (POST /zones/{id}/origin_tls_client_auth) and the setting is switched on
//  3. the CA goes into the Caddy's conf/certs/cf-origin-pull-ca.pem — the cf_only snippet trusts it
//
// Only this zone's Cloudflare edge holds the client key, so only requests through this zone reach
// the mTLS sites. Neither private key is kept by Gilmok. Needs the token permission
// Zone · SSL and Certificates · Edit.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MTLSState: the zone-level client certificate Gilmok uploaded (so a new one can replace it).
type MTLSState struct {
	CertID  string    `json:"certId,omitempty"`
	Zone    string    `json:"zone,omitempty"`
	Created time.Time `json:"created,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
}

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// genMTLS makes a CA and a client certificate signed by it. The CA key is thrown away afterwards.
func genMTLS(domain string, now time.Time) (caPEM, certPEM, keyPEM string, err error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "Gilmok origin-pull CA · " + domain, Organization: []string{"Gilmok"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: "Cloudflare origin pull · " + domain, Organization: []string{"Gilmok"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return caPEM, certPEM, keyPEM, nil
}

func cfPermHint(err error) error {
	if err != nil && (strings.Contains(err.Error(), "10000") || strings.Contains(err.Error(), "uthentication") || strings.Contains(err.Error(), "403")) {
		return fmt.Errorf("%v — 토큰에 「영역 · SSL 및 인증서 · 편집 (Zone · SSL and Certificates · Edit)」 권한이 필요합니다", err)
	}
	return err
}

// POST /api/stacks/caddy/mtls — generate, upload to Cloudflare, put the CA into the managed Caddy.
func (a *App) postCaddyMTLS(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	caFile := a.caddyCAFile()
	switch {
	case caFile == "":
		fail(w, 404, errors.New("길목이 설치한 Caddy가 없습니다 — 직접 운영하는 Caddy는 그 컨테이너에 CA 파일을 마운트하세요"))
		return
	case !d.Settings.UseCloudflare || !a.cf.Configured():
		fail(w, 400, errors.New("Cloudflare API 토큰이 필요합니다 — Cloudflare 탭에서 먼저 넣으세요"))
		return
	case strings.TrimSpace(d.Settings.Domain) == "":
		fail(w, 400, errors.New("도메인이 정해져 있지 않습니다"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	zone, err := a.cf.ZoneID(ctx, d.Settings.Domain)
	if err != nil {
		fail(w, 502, err)
		return
	}
	caPEM, certPEM, keyPEM, err := genMTLS(d.Settings.Domain, time.Now())
	if err != nil {
		fail(w, 500, err)
		return
	}
	res, err := a.cf.do(ctx, "POST", "/zones/"+zone+"/origin_tls_client_auth", map[string]string{"certificate": certPEM, "private_key": keyPEM})
	if err != nil {
		fail(w, 502, cfPermHint(err))
		return
	}
	var up struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		ExpiresOn string `json:"expires_on"`
	}
	_ = json.Unmarshal(res.Result, &up)
	if _, err := a.cf.do(ctx, "PUT", "/zones/"+zone+"/origin_tls_client_auth/settings", map[string]bool{"enabled": true}); err != nil {
		fail(w, 502, cfPermHint(fmt.Errorf("인증서는 올렸지만 인증된 원본 풀을 켜지 못했습니다: %w", err)))
		return
	}
	if err := os.MkdirAll(filepath.Dir(caFile), 0o755); err != nil {
		fail(w, 500, err)
		return
	}
	if err := os.WriteFile(caFile, []byte(caPEM), 0o644); err != nil {
		fail(w, 500, err)
		return
	}
	// the previous certificate Gilmok made is no longer trusted by this Caddy: remove it from the zone
	prev := d.MTLS
	if prev.CertID != "" && prev.CertID != up.ID && prev.Zone == zone {
		if _, err := a.cf.do(ctx, "DELETE", "/zones/"+zone+"/origin_tls_client_auth/"+prev.CertID, nil); err != nil {
			a.logEvent("system", "warn", "mtls.cleanup", "cloudflare", fmt.Sprintf("예전 mTLS 클라이언트 인증서를 지우지 못했습니다: %s", oneLine(err.Error())), nil)
		}
	}
	exp, _ := time.Parse(time.RFC3339, up.ExpiresOn)
	_ = a.store.Update(func(x *Data) error {
		x.MTLS = MTLSState{CertID: up.ID, Zone: zone, Created: time.Now(), Expires: exp}
		return nil
	})
	a.auth.audit(r, "audit", "warn", "mTLS 새로 만들기", d.Settings.Domain, "길목이 mTLS CA·클라이언트 인증서를 만들어 Cloudflare(인증된 원본 풀)와 Caddy에 넣었습니다", map[string]any{"certId": up.ID})
	writeJSON(w, 200, map[string]any{"ok": true, "status": up.Status, "expires": up.ExpiresOn})
}
