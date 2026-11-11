"""Fresh-install end-to-end test against a real Docker (isolated names / ports).

Gilmok (gm-e2e, 127.0.0.1:18095) installs Caddy (e2e-caddy, https 19443, internal certs, network
gm-e2e-net chosen explicitly), Authelia (e2e-authelia, network left empty → must follow Caddy) and
CrowdSec (e2e-crowdsec), adds services, applies, and the sites are reached for real.
No Cloudflare (no token in tests). Prints a result table; exit code 1 on any failure.
"""
import http.cookiejar
import json
import os
import tempfile
import secrets
import ssl
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:18095"
PW_FILE = os.path.join(tempfile.gettempdir(), "gilmok-e2e-pw.txt")
DOMAIN = "e2e.test"
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
results = []


def api(method, path, body=None, ok=(200, 202)):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json", "X-GM": "1"})
    try:
        with opener.open(req, timeout=120) as r:
            code, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read()
    try:
        js = json.loads(raw or b"{}")
    except Exception:
        js = {"raw": raw[:300].decode("utf-8", "replace")}
    if code not in ok:
        raise RuntimeError(f"{method} {path} → {code} {js}")
    return js


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail else ""), flush=True)
    return cond


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()


def wait_job(name, limit=900):
    t0 = time.time()
    while time.time() - t0 < limit:
        j = api("GET", "/api/stacks")["stacks"][name].get("job") or {}
        if j.get("state") and j["state"] != "running":
            return j
        time.sleep(3)
    return {"state": "timeout"}


def https(host, path="/"):
    """GET https://host:19443 through 127.0.0.1 with SNI = host (internal CA → no verify)."""
    import socket
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.create_connection(("127.0.0.1", 19443), timeout=15)
    t = ctx.wrap_socket(s, server_hostname=host)
    t.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    buf = b""
    while True:
        try:
            chunk = t.recv(65536)
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    t.close()
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    code = int(head.split(" ")[1]) if head.startswith("HTTP/") else 0
    loc = ""
    for line in head.split("\r\n"):
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
    return code, loc


def main():
    pw = "e2e-" + secrets.token_urlsafe(12)
    open(PW_FILE, "w").write(pw)  # throwaway test value for part 2 (outside the repo)
    # 1. first visit: language, admin/admin → own administrator
    st = api("GET", "/api/auth/state")
    check("01 첫 접속: 언어 미선택", st.get("lang", "") == "", str(st.get("lang")))
    api("POST", "/api/auth/lang", {"lang": "ko"})
    api("POST", "/api/auth/login", {"name": "admin", "password": "admin"})
    api("POST", "/api/auth/bootstrap", {"name": "tester", "display": "tester", "password": pw})
    me = api("GET", "/api/state")
    check("02 관리자 생성 후 상태 조회", "settings" in me)

    # 2. settings like the wizard: components + domain
    s = me["settings"]
    s.update({"domain": DOMAIN, "useCaddy": True, "useAuthelia": True, "useCrowdSec": True, "useCloudflare": False, "useTailscale": False})
    api("PUT", "/api/settings", s)

    # 3. Caddy: explicit network (like choosing "reverseproxy"), internal certs, own port
    pre = api("POST", "/api/stacks/caddy/preflight", {"container": "e2e-caddy", "network": "gm-e2e-net", "httpsPort": "19443", "tls": "internal"})
    fails = [c for c in pre.get("checks", []) if c.get("status") == "fail"]
    check("03 Caddy 사전 점검 통과", not fails, json.dumps(fails, ensure_ascii=False)[:300])
    api("POST", "/api/stacks/caddy/install", {"container": "e2e-caddy", "network": "gm-e2e-net", "httpsPort": "19443", "tls": "internal"})
    j = wait_job("caddy")
    check("04 Caddy 설치", j.get("state") == "ok", (j.get("error") or "")[:300])
    log = "\n".join(j.get("log") or [])
    check("05 설치 로그에 진행 출력", len(j.get("log") or []) > 5 and j.get("updated"), f"{len(j.get('log') or [])}줄")

    # 4. Authelia: network LEFT EMPTY → must land on Caddy's network
    api("POST", "/api/stacks/authelia/install", {"container": "e2e-authelia", "adminUser": "admin", "secretPassword": pw, "portal": "auth", "addPortal": "1"})
    j = wait_job("authelia")
    check("06 Authelia 설치", j.get("state") == "ok", (j.get("error") or "")[:300])
    nets = sh("docker", "inspect", "-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", "e2e-authelia")
    check("07 Authelia가 Caddy 네트워크(gm-e2e-net)에", "gm-e2e-net" in nets, nets)

    # 5. CrowdSec
    api("POST", "/api/stacks/crowdsec/install", {"container": "e2e-crowdsec"})
    j = wait_job("crowdsec")
    check("08 CrowdSec 설치", j.get("state") == "ok", (j.get("error") or "")[:300])

    # 6. services: the portal was added by the Authelia install; add a gated site and an open one
    st = api("GET", "/api/state")
    subs = {x["subdomain"]: x for x in st["services"]}
    check("09 로그인 포털 서비스 자동 추가", "auth" in subs and subs["auth"]["upstream"] == "e2e-authelia:9091", json.dumps(list(subs)))
    api("POST", "/api/services", {"subdomain": "open", "upstream": "gm-e2e:8080", "exposure": "public", "enabled": True, "authelia": {"policy": "two_factor"}})
    api("POST", "/api/services", {"subdomain": "gated", "upstream": "gm-e2e:8080", "exposure": "public", "enabled": True, "authelia": {"enabled": True, "policy": "one_factor", "groups": ["admins"]}})

    # 7. checks before applying
    for tgt in ("caddy", "authelia", "crowdsec"):
        r = api("GET", f"/api/check/{tgt}?force=1")
        bad = [f"{c['label']}: {c.get('detail','')}" for c in r.get("checks", []) if c.get("status") == "fail"]
        check(f"10 점검 {tgt}: 실패 없음", not bad, " / ".join(bad)[:400])

    # 8. apply
    plan = api("GET", "/api/plan?dns=0")
    check("11 미리보기에 사이트 3개", all(h in plan.get("caddyNext", "") for h in ("auth." + DOMAIN, "open." + DOMAIN, "gated." + DOMAIN)))
    r = api("POST", "/api/apply", {})
    check("12 적용 성공", r.get("ok"), (r.get("error") or "")[:400] + " | " + " / ".join((r.get("log") or [])[-4:])[:400])
    st = api("GET", "/api/state")
    check("13 적용 후 대기 없음", not st.get("pending"), json.dumps(st.get("pending"), ensure_ascii=False)[:200])

    # 9. real requests through the installed Caddy
    time.sleep(3)
    code, _ = https("open." + DOMAIN, "/healthz")
    check("14 공개 사이트 응답 (Caddy → 길목)", code in (200, 403, 404), f"HTTP {code}")
    code, _ = https("auth." + DOMAIN)
    check("15 로그인 포털 응답 (Caddy → Authelia)", code == 200, f"HTTP {code}")
    code, loc = https("gated." + DOMAIN)
    check("16 관문 사이트는 로그인으로 넘김", code in (302, 303, 401) and ("auth." + DOMAIN in loc or code == 401), f"HTTP {code} {loc}")

    # 10. CrowdSec LAPI from Gilmok (bouncer key matches)
    r = api("GET", "/api/check/crowdsec?force=1")
    lapi = [c for c in r.get("checks", []) if c["id"] == "lapi"]
    check("17 CrowdSec LAPI 연결 (바운서 키)", lapi and lapi[0]["status"] in ("ok", "warn"), json.dumps(lapi, ensure_ascii=False)[:300])

    # 11. restart keeps working (bouncer re-registered, Authelia still reachable)
    api("POST", "/api/stacks/crowdsec/restart", {})
    j = wait_job("crowdsec")
    check("18 CrowdSec 재시작 후 준비됨", j.get("state") == "ok", (j.get("error") or "")[:300])
    r = api("GET", "/api/check/crowdsec?force=1")
    lapi = [c for c in r.get("checks", []) if c["id"] == "lapi"]
    check("19 재시작 뒤 LAPI 키 유효", lapi and lapi[0]["status"] == "ok", json.dumps(lapi, ensure_ascii=False)[:300])

    # 12. local links / topology networks
    loc = api("GET", "/api/services/local")
    nets = {k: v.get("network") for k, v in loc.items()}
    check("20 서비스 네트워크 감지", any(v == "gm-e2e-net" for v in nets.values()), json.dumps(nets))

    # 13. hold: an imported site needing a snippet the base does not have
    api("POST", "/api/services", {"subdomain": "snip", "upstream": "gm-e2e:8080", "exposure": "public", "enabled": True, "extra": "import not_there", "authelia": {"policy": "two_factor"}})
    r = api("POST", "/api/apply", {})
    check("21 없는 스니펫 사이트만 보류, 적용은 성공", r.get("ok") and any("보류" in l for l in r.get("log") or []), (r.get("error") or "")[:300])
    code, _ = https("auth." + DOMAIN)
    check("22 보류 뒤에도 다른 사이트 정상", code == 200, f"HTTP {code}")


def report():
    fails = [r for r in results if not r[1]]
    print(f"\n== {len(results) - len(fails)}/{len(results)} 통과 ==")
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        check("예외", False, str(e)[:500])
    sys.exit(report())
