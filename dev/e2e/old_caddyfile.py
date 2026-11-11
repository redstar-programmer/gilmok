"""E2E part 2 — the production path of 2026-11-11: an old Caddyfile (another Caddy's CA path, the old
Authelia name, mTLS sites) imported from the PC into the Gilmok-installed stack, applied without a CA
(mTLS sites held, the rest applied), then a CA added and applied again (mTLS enforced for real).
Runs on the environment e2e.py set up."""
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile

import fresh_install as e2e

api, check, https = e2e.api, e2e.check, e2e.https
DOMAIN = e2e.DOMAIN


def mtls_refused(host):
    """True when the site will not talk to a client without a certificate (the mTLS check works)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection(("127.0.0.1", 19443), timeout=10)
        t = ctx.wrap_socket(s, server_hostname=host)
        t.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = t.recv(200)
        t.close()
        return not data
    except (ssl.SSLError, ConnectionResetError, OSError):
        return True


def make_ca():
    d = tempfile.mkdtemp()
    key, crt = os.path.join(d, "ca.key"), os.path.join(d, "ca.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                    "-days", "30", "-subj", "/CN=e2e-ca"], capture_output=True, check=True)
    pem = open(crt).read()
    os.remove(key)
    os.remove(crt)
    os.rmdir(d)
    return pem


def main():
    pw = open(e2e.PW_FILE).read().strip()
    api("POST", "/api/auth/login", {"name": "tester", "password": pw})
    s = api("GET", "/api/state")["settings"]
    s["useCloudflare"] = True  # mTLS sites are generated only with Cloudflare in use (no token here)
    api("PUT", "/api/settings", s)
    old = """{
\temail old@example.com
}

(cf_only) {
\ttls {
\t\tclient_auth {
\t\t\tmode require_and_verify
\t\t\ttrust_pool file /etc/caddy/cf-origin-pull-ca.pem
\t\t}
\t}
}

(authelia) {
\tforward_auth authelia:9091 {
\t\turi /api/authz/forward-auth
\t\tcopy_headers Remote-User Remote-Groups Remote-Name Remote-Email
\t}
}

auth.%(d)s {
\timport cf_only
\treverse_proxy authelia:9091
}

notes.%(d)s {
\timport cf_only
\treverse_proxy gm-e2e:8080
}

open.%(d)s {
\treverse_proxy gm-e2e:8080
}

secret.%(d)s:8443 {
\timport authelia
\treverse_proxy gm-e2e:8080
}
""" % {"d": DOMAIN}
    r = api("POST", "/api/import", {"name": "Caddyfile", "content": old})
    warns = " / ".join(r.get("warnings") or [])
    check("P2-01 PC 파일 가져오기 (관리형 골격 유지)", r.get("imported", 0) >= 4 and "기본 골격" in warns, warns[:300])
    st = api("GET", "/api/state")
    base = st["settings"]["caddyBase"]
    check("P2-02 골격: 예전 CA 경로·Authelia 이름이 들어오지 않음",
          "trust_pool file /etc/caddy/certs/cf-origin-pull-ca.pem" in base and "trust_pool file /etc/caddy/cf-origin-pull-ca.pem" not in base and "forward_auth authelia:9091" not in base, "")
    ups = {x["subdomain"]: x["upstream"] for x in st["services"]}
    check("P2-03 예전 Authelia 대상 → 새 Authelia", ups.get("auth") == "e2e-authelia:9091", json.dumps(ups))

    r = api("POST", "/api/apply", {})
    log = r.get("log") or []
    check("P2-04 CA 없이 적용: 성공 + mTLS 사이트만 보류", r.get("ok") and any("보류" in l and "notes" in l for l in log), (r.get("error") or "")[:300] + " | " + " / ".join(log[-3:])[:300])
    code, _ = https("open." + DOMAIN)
    check("P2-05 보류와 무관한 사이트 정상", code in (200, 403), f"HTTP {code}")
    st = api("GET", "/api/state")
    check("P2-06 보류 사이트는 적용 대기에 남음", any("보류" in p for p in st.get("pending") or []), json.dumps(st.get("pending"), ensure_ascii=False)[:200])
    r = api("GET", "/api/check/caddy")
    ca = [c for c in r["checks"] if c["id"] == "ca"]
    check("P2-07 점검: mTLS CA 보류 중(주의)", ca and ca[0]["status"] == "warn", json.dumps(ca, ensure_ascii=False)[:200])

    bad = api("POST", "/api/stacks/caddy/ca", {"pem": "not a pem"}, ok=(400,))
    check("P2-08 잘못된 PEM 거부", "error" in bad, str(bad)[:200])
    api("POST", "/api/stacks/caddy/ca", {"pem": make_ca()})
    r = api("POST", "/api/apply", {})
    check("P2-09 CA 넣고 적용: 보류 없이 성공", r.get("ok") and not any("보류" in l for l in r.get("log") or []), (r.get("error") or "")[:300])
    st = api("GET", "/api/state")
    check("P2-10 적용 대기 비워짐", not st.get("pending"), json.dumps(st.get("pending"), ensure_ascii=False)[:200])
    check("P2-11 mTLS 사이트는 클라이언트 인증서 없이 거부", mtls_refused("notes." + DOMAIN))
    code, _ = https("open." + DOMAIN)
    check("P2-12 일반 사이트는 계속 정상", code in (200, 403), f"HTTP {code}")
    r = api("GET", "/api/check/caddy")
    bad = [f"{c['label']}: {c.get('detail', '')}" for c in r["checks"] if c["status"] == "fail"]
    check("P2-13 Caddy 점검 실패 없음", not bad, " / ".join(bad)[:300])
    r = api("GET", "/api/check/authelia")
    bad = [f"{c['label']}: {c.get('detail', '')}" for c in r["checks"] if c["status"] == "fail"]
    check("P2-14 Authelia 점검 실패 없음 (네트워크 포함)", not bad, " / ".join(bad)[:300])


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        check("P2 예외", False, str(ex)[:400])
    sys.exit(e2e.report())
