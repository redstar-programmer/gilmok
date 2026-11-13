"""Integration test over the whole feature set, on the environment fresh_install.py set up
(real Caddy / Authelia / CrowdSec containers, no Cloudflare). Each case is INT-<area>-<n>;
results are printed as a table and the exit code is 1 when anything failed.

    python fresh_install.py && python integration.py
"""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import socket
import ssl
import struct
import sys
import time
import urllib.request

import fresh_install as fi

BASE, DOMAIN = fi.BASE, fi.DOMAIN
results = fi.results
check = fi.check


class Client:
    """One browser session against Gilmok (own cookie jar)."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def do(self, method, path, body=None, raw=False):
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json", "X-GM": "1"})
        try:
            with self.op.open(req, timeout=180) as r:
                code, out = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, out = e.code, e.read()
        if raw:
            return code, out
        try:
            return code, json.loads(out or b"{}")
        except Exception:
            return code, {"raw": out[:300].decode("utf-8", "replace")}


def site(host, path="/", method="GET", headers=None, body=b"", port=19443):
    """A real HTTPS request through the installed Caddy (SNI = host, internal CA)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    t = ctx.wrap_socket(s, server_hostname=host)
    hdr = {"Host": host, "Connection": "close", "User-Agent": "Mozilla/5.0 gilmok-it", "Accept": "text/html"}
    hdr.update(headers or {})
    if body:
        hdr["Content-Length"] = str(len(body))
    t.sendall((f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdr.items()) + "\r\n").encode() + body)
    buf = b""
    while True:
        try:
            c = t.recv(65536)
        except Exception:
            break
        if not c:
            break
        buf += c
    t.close()
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    code = int(lines[0].split(" ")[1]) if lines and lines[0].startswith("HTTP/") else 0
    hs = {}
    cookies = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hs[k.strip().lower()] = v.strip()
            if k.strip().lower() == "set-cookie":
                cookies.append(v.strip().split(";", 1)[0])
    return code, hs, rest, cookies


def totp(secret, t=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", int((t or time.time()) // 30))
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def ok(code, m, codes=(200,)):
    return code in codes


def main():
    S = {}
    pw = open(fi.PW_FILE).read().strip()
    a = Client()
    code, _ = a.do("POST", "/api/auth/login", {"name": "tester", "password": pw})
    if not check("INT-0 로그인", code == 200, f"HTTP {code}"):
        return
    st = a.do("GET", "/api/state")[1]
    svc = {x["subdomain"]: x for x in st.get("services") or []}
    # the held "snip" site of fresh_install is not needed here
    if "snip" in svc:
        a.do("DELETE", "/api/services/" + svc["snip"]["id"])
    S.update(locals())
    for name, fn in SECTIONS:
        try:
            fn(S)
        except Exception as ex:
            import traceback
            traceback.print_exc()
            check(f"INT {name} 예외", False, str(ex)[:300])


SECTIONS = []


def wait_job(c, name, limit=900):
    t0 = time.time()
    while time.time() - t0 < limit:
        j = (c.do("GET", "/api/stacks")[1]["stacks"][name].get("job") or {})
        if j.get("state") and j["state"] != "running":
            return j
        time.sleep(3)
    return {"state": "timeout"}


def sec_svc(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    code, m = a.do("POST", "/api/services", {"subdomain": "bad one", "upstream": "x:1", "exposure": "public"})
    check("INT-SVC-1 잘못된 서브도메인 거부", code == 400, str(m)[:120])
    code, m = a.do("POST", "/api/services", {"subdomain": "badup", "upstream": "x 1", "exposure": "public"})
    check("INT-SVC-2 공백 든 대상 거부", code == 400, str(m)[:120])
    code, m = a.do("POST", "/api/services", {"subdomain": "temp", "upstream": "gm-e2e:8080", "exposure": "public", "enabled": True, "authelia": {"policy": "two_factor"}})
    check("INT-SVC-3 서비스 추가", code == 200, str(m)[:120])
    tmp = m.get("id") or m.get("service", {}).get("id")
    if not tmp:
        tmp = {x["subdomain"]: x for x in a.do("GET", "/api/state")[1]["services"]}["temp"]["id"]
    code, m = a.do("POST", "/api/services", {"subdomain": "temp", "upstream": "gm-e2e:8080", "exposure": "public"})
    check("INT-SVC-4 같은 서브도메인 중복 거부", code in (400, 409), f"HTTP {code}")
    code, m = a.do("PUT", "/api/services/" + tmp, {"subdomain": "temp", "upstream": "gm-e2e:8080", "exposure": "public", "enabled": False, "authelia": {"policy": "two_factor"}})
    check("INT-SVC-5 서비스 수정(끄기)", code == 200, str(m)[:120])
    st = a.do("GET", "/api/state")[1]
    check("INT-SVC-6 변경이 적용 대기로", bool(st.get("pending")), json.dumps(st.get("pending"), ensure_ascii=False)[:150])
    plan = a.do("GET", "/api/plan?dns=0")[1]
    check("INT-SVC-7 꺼진 서비스는 미리보기에 없음", "temp." + DOMAIN not in plan.get("caddyNext", ""))
    code, _ = a.do("DELETE", "/api/services/" + tmp)
    check("INT-SVC-8 서비스 삭제", code == 200, f"HTTP {code}")


SECTIONS.append(("SVC", sec_svc))


def sec_apply(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    code, m = a.do("POST", "/api/services", {"subdomain": "broken", "upstream": "gm-e2e:8080", "exposure": "public", "enabled": True, "extra": "not_a_directive here", "authelia": {"policy": "two_factor"}})
    bid = (m.get("id") or "") if code == 200 else ""
    if not bid:
        bid = {x["subdomain"]: x for x in a.do("GET", "/api/state")[1]["services"]}.get("broken", {}).get("id", "")
    before = site("auth." + DOMAIN)[0]
    code, r = a.do("POST", "/api/apply", {})
    check("INT-APPLY-1 깨진 지시어는 검증에서 막힘", code == 200 and not r.get("ok") and "검증" in (r.get("error") or "") + " ".join(r.get("log") or []), (r.get("error") or "")[:200])
    check("INT-APPLY-2 막힌 뒤 기존 사이트 그대로", site("auth." + DOMAIN)[0] == before == 200, f"{before}")
    code, m = a.do("POST", "/api/validate", {"target": "caddy"})
    check("INT-APPLY-3 검증 API가 실패를 알려 줌", code == 200 and not m.get("ok", True), str(m)[:150])
    a.do("DELETE", "/api/services/" + bid)
    code, r = a.do("POST", "/api/apply", {})
    check("INT-APPLY-4 고친 뒤 적용 성공", r.get("ok"), (r.get("error") or "")[:200])
    code, b = a.do("GET", "/api/backups")
    blist = b if isinstance(b, list) else (b.get("backups") or [])
    check("INT-APPLY-5 적용 전 백업이 남음", code == 200 and len(blist) > 0, f"{len(blist)}개")


SECTIONS.append(("APPLY", sec_apply))


def sec_auth(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    code, _ = a.do("POST", "/api/groups", {"name": "family", "desc": "가족"})
    check("INT-AUTH-1 그룹 등록", code == 200, f"HTTP {code}")
    code, m = a.do("POST", "/api/users", {"username": "kim", "displayname": "Kim", "email": "kim@" + DOMAIN, "password": "kim-pass-1234567", "groups": ["family"]})
    check("INT-AUTH-2 Authelia 사용자 추가(바로 반영)", code == 200, str(m)[:150])
    code, m = a.do("POST", "/api/users", {"username": "x2", "password": "long enough pw", "groups": ["nogroup"]})
    check("INT-AUTH-3 등록 안 된 그룹 거부", code == 400, str(m)[:120])
    users = a.do("GET", "/api/users")[1]
    check("INT-AUTH-4 사용자 목록에 비밀번호 없음", "kim" in json.dumps(users) and "argon2" not in json.dumps(users))
    time.sleep(8)  # Authelia restarts after a user change
    # real first-factor login on the portal
    def authelia_login(user, pwd):
        body = json.dumps({"username": user, "password": pwd, "keepMeLoggedIn": False}).encode()
        code, hs, rest, cookies = site("auth." + DOMAIN, "/api/firstfactor", "POST", {"Content-Type": "application/json", "Accept": "application/json"}, body)
        return code, cookies
    code, ck = authelia_login("admin", pw)
    check("INT-AUTH-5 Authelia 관리자 실제 로그인", code == 200 and ck, f"HTTP {code}")
    if ck:
        c2, hs, _, _ = site("gated." + DOMAIN, "/", headers={"Cookie": "; ".join(ck)})
        check("INT-AUTH-6 로그인 후 관문 사이트 통과(admins)", c2 not in (401, 302, 303), f"HTTP {c2}")
    code, ck2 = authelia_login("kim", "kim-pass-1234567")
    check("INT-AUTH-7 일반 사용자 실제 로그인", code == 200 and ck2, f"HTTP {code}")
    if ck2:
        c3, _, _, _ = site("gated." + DOMAIN, "/", headers={"Cookie": "; ".join(ck2)})
        check("INT-AUTH-8 그룹이 다르면 관문에서 거부", c3 == 403, f"HTTP {c3}")
    code, _ = authelia_login("kim", "wrong-password")
    check("INT-AUTH-9 틀린 비밀번호는 Authelia가 거부", code in (401, 403), f"HTTP {code}")
    code, _ = a.do("DELETE", "/api/users/kim")
    check("INT-AUTH-10 사용자 삭제", code == 200, f"HTTP {code}")


SECTIONS.append(("AUTH", sec_auth))


def sec_waf(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    st = a.do("GET", "/api/state")[1]
    op = {x["subdomain"]: x for x in st["services"]}["open"]
    op2 = dict(op, waf="block", guard=True)
    code, m = a.do("PUT", "/api/services/" + op["id"], op2)
    check("INT-WAF-1 WAF 차단·기본 차단 켜기", code == 200, str(m)[:150])
    code, r = a.do("POST", "/api/apply", {})
    check("INT-WAF-2 적용", r.get("ok"), (r.get("error") or "")[:200])
    time.sleep(2)
    c, hs, _, _ = site("open." + DOMAIN, "/?id=1%27%20OR%20%271%27=%271")
    check("INT-WAF-3 SQL 인젝션 요청 403", c == 403, f"HTTP {c}")
    c, hs, _, _ = site("open." + DOMAIN, "/", headers={"User-Agent": "sqlmap/1.7"})
    check("INT-WAF-4 공격 도구 UA 기본 차단 403 + 분류 헤더", c == 403 and "x-gilmok-block" in hs, f"HTTP {c} {hs.get('x-gilmok-block')}")
    c, hs, _, _ = site("open." + DOMAIN, "/.env")
    check("INT-WAF-5 탐색 경로(/.env) 차단", c == 403, f"HTTP {c}")
    c, hs, _, _ = site("open." + DOMAIN, "/")
    # the upstream (Gilmok) itself answers 403 to non-local callers, so "passed" = not blocked by Caddy
    check("INT-WAF-6 정상 요청은 기본 차단·WAF에 안 걸림", "x-gilmok-block" not in hs and c != 0, f"HTTP {c}")
    code, m = a.do("POST", "/api/waf/test", {"id": op["id"]})
    rows = m.get("results") or m.get("tests") or []
    check("INT-WAF-7 WAF 시험(길목 → Caddy) 실행", code == 200 and rows, str(m)[:200])
    time.sleep(3)
    code, ev = a.do("GET", "/api/waf/events?since=1h")
    check("INT-WAF-8 차단 기록 조회", code == 200 and len(ev.get("events") or []) > 0, f"{len(ev.get('events') or [])}건")


SECTIONS.append(("WAF", sec_waf))


def sec_cs(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    code, m = a.do("POST", "/api/crowdsec/decisions", {"ip": "203.0.113.77", "duration": "1h", "reason": "integration"})
    check("INT-CS-1 수동 차단 추가", code == 200, str(m)[:150])
    code, m = a.do("POST", "/api/crowdsec/decisions", {"ip": "--scope Range", "duration": "1h"})
    check("INT-CS-2 이상한 입력 거부", code == 400, f"HTTP {code}")
    time.sleep(2)
    code, cs = a.do("GET", "/api/crowdsec")
    ds = [d for d in (cs.get("decisions") or []) if d.get("value") == "203.0.113.77" or d.get("ip") == "203.0.113.77"]
    check("INT-CS-3 차단 목록에 보임", code == 200 and ds, json.dumps(cs)[:200])
    if ds:
        code, _ = a.do("DELETE", "/api/crowdsec/decisions/" + str(ds[0].get("id")))
        check("INT-CS-4 차단 해제", code == 200, f"HTTP {code}")


SECTIONS.append(("CS", sec_cs))


def sec_dash(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    for _ in range(5):
        site("auth." + DOMAIN)
    time.sleep(4)
    code, dash = a.do("GET", "/api/dashboard")
    widgets = dash.get("widgets") or []
    check("INT-DASH-1 대시보드 위젯", code == 200 and len(widgets) >= 5, f"{len(widgets)}개")
    code, data = a.do("POST", "/api/dash/data", {"widgets": widgets})
    check("INT-DASH-2 위젯 데이터", code == 200 and data, str(list(data)[:3]))
    code, rq = a.do("GET", "/api/logs/requests?since=1h")
    n = len(rq.get("requests") or rq.get("rows") or [])
    check("INT-LOG-1 접근 로그가 DB에 쌓임", code == 200 and n > 0, f"{n}건")
    code, evs = a.do("GET", "/api/logs/events?cat=audit")
    check("INT-LOG-2 감사 로그(누가 무엇을)", code == 200 and len(evs.get("events") or []) > 0, f"{len(evs.get('events') or [])}건")
    code, csv = a.do("GET", "/api/logs/export?cat=audit", raw=True)
    check("INT-LOG-3 감사 로그 CSV 내보내기", code == 200 and b"," in csv[:200], f"{len(csv)}바이트")
    code, ls = a.do("GET", "/api/logs/status")
    check("INT-LOG-4 로그 DB 상태", code == 200, str(ls)[:120])


SECTIONS.append(("DASH", sec_dash))


def sec_acc(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    code, m = a.do("POST", "/api/accounts", {"name": "opr", "display": "운영자", "role": "operator"})
    temp = m.get("tempPassword", "")
    check("INT-ACC-1 운영자 계정 추가(임시 비밀번호)", code == 200 and temp, str({k: v for k, v in m.items() if k != 'tempPassword'})[:120])
    o = Client()
    code, _ = o.do("POST", "/api/auth/login", {"name": "opr", "password": temp})
    code2, g = o.do("GET", "/api/state")
    check("INT-ACC-2 임시 비밀번호는 바꾸기 전엔 막힘(게이트)", code == 200 and code2 == 403 and g.get("gate") == "password", f"{code2} {g.get('gate')}")
    newpw = "nine-river-stone-42"  # must not contain the account name (that is refused, INT-ACC-3b)
    code, _ = o.do("POST", "/api/auth/password", {"current": temp, "new": newpw})
    check("INT-ACC-3 비밀번호 변경 후 사용 가능", code == 200 and o.do("GET", "/api/state")[0] == 200, f"HTTP {code}")
    code, m = Client().do("POST", "/api/auth/login", {"name": "opr", "password": "opr-is-in-this-pw"})
    check("INT-ACC-3b 틀린 비밀번호 로그인 거부", code in (400, 401), f"HTTP {code}")
    code, _ = o.do("DELETE", "/api/accounts/tester")
    check("INT-ACC-4 운영자는 계정 관리 불가(403)", code == 403, f"HTTP {code}")
    code, m = o.do("POST", "/api/auth/totp/begin")
    sec = m.get("secret", "")
    code, _ = o.do("POST", "/api/auth/totp/enable", {"code": totp(sec)}) if sec else (0, None)
    check("INT-ACC-5 2단계 인증 켜기", code == 200, f"HTTP {code}")
    o2 = Client()
    code, m = o2.do("POST", "/api/auth/login", {"name": "opr", "password": newpw})
    check("INT-ACC-6 2단계 인증 계정은 코드 없이 로그인 안 됨", code != 200 or m.get("need2fa") or m.get("totp"), f"HTTP {code} {str(m)[:80]}")
    time.sleep(31)  # a new TOTP window (the same code may not be used twice)
    code, _ = o2.do("POST", "/api/auth/login", {"name": "opr", "password": newpw, "code": totp(sec)})
    check("INT-ACC-7 코드로 로그인", code == 200, f"HTTP {code}")
    code, ss = a.do("GET", "/api/auth/sessions")
    check("INT-ACC-8 세션 목록", code == 200 and len(ss.get("sessions") or []) >= 1, f"{len(ss.get('sessions') or [])}개")
    code, m = a.do("POST", "/api/roles", {"name": "보기+로그", "perms": ["logs"]})
    check("INT-ACC-9 역할 만들기", code == 200, str(m)[:120])
    code, _ = a.do("DELETE", "/api/accounts/opr")
    check("INT-ACC-10 계정 삭제 → 그 세션도 끊김", code == 200 and o2.do("GET", "/api/state")[0] == 401, f"HTTP {code}")
    code, _ = a.do("DELETE", "/api/accounts/tester")
    check("INT-ACC-11 자기 자신 삭제 거부", code in (400, 403, 409), f"HTTP {code}")


SECTIONS.append(("ACC", sec_acc))


def sec_bulk(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    csv = "서브도메인,대상,노출\nbulk1,gm-e2e:8080,공개\nbulk2,gm-e2e:8080,사설\nbad name,x,공개\n".encode("utf-8")
    body = {"name": "s.csv", "data": base64.b64encode(csv).decode(), "dry": True}
    code, p = a.do("POST", "/api/services/bulk", body)
    cnt = p.get("counts") or {}
    check("INT-BULK-1 CSV 미리보기 (추가 2, 오류 1)", code == 200 and cnt.get("create") == 2 and cnt.get("error") == 1, str(cnt))
    body["dry"] = False
    code, p = a.do("POST", "/api/services/bulk", body)
    check("INT-BULK-2 CSV 반영(오류 행만 빼고)", code == 200 and (p.get("counts") or {}).get("create") == 2, str(p.get("counts")))
    code, x = a.do("GET", "/api/services/export.xlsx", raw=True)
    check("INT-BULK-3 엑셀 내보내기", code == 200 and x[:2] == b"PK", f"{len(x)}바이트")
    ngx = "server { server_name nx." + DOMAIN + "; location / { proxy_pass http://gm-e2e:8080; } }"
    code, m = a.do("POST", "/api/import/sites", {"format": "nginx", "files": [{"name": "a.conf", "content": ngx}]})
    check("INT-IMP-1 nginx 불러오기 미리보기", code == 200 and any(s["sub"] == "nx" for s in m.get("sites") or []), str(m)[:150])
    code, m = a.do("POST", "/api/import/sites/apply", {"format": "nginx", "files": [{"name": "a.conf", "content": ngx}], "pick": ["nx"]})
    check("INT-IMP-2 고른 사이트 추가", code == 200 and "nx" in (m.get("added") or []), str(m)[:150])
    code, r = a.do("POST", "/api/apply", {})
    check("INT-IMP-3 일괄·불러온 사이트 적용", r.get("ok"), (r.get("error") or "")[:200])
    c, _, _, _ = site("nx." + DOMAIN)
    check("INT-IMP-4 불러온 사이트 실제 응답", c in (200, 403), f"HTTP {c}")


SECTIONS.append(("BULK", sec_bulk))


def sec_stack(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    code, m = a.do("POST", "/api/stacks/authelia/compose-check", {"content": "services: [broken"})
    check("INT-STK-1 compose 검사: 깨진 YAML", code == 200 and not m.get("ok"), str(m)[:120])
    code, cur = a.do("GET", "/api/stacks/authelia/compose")
    code, m = a.do("POST", "/api/stacks/authelia/compose-check", {"content": cur.get("content", "")})
    check("INT-STK-2 compose 검사: 지금 파일 정상", code == 200 and m.get("ok"), str(m)[:150])
    bad = cur.get("content", "").replace("container_name: e2e-authelia", "container_name: other")
    code, m = a.do("POST", "/api/stacks/authelia/compose-check", {"content": bad})
    check("INT-STK-3 compose 검사: container_name 바꾸면 거부", not m.get("ok"), str(m)[:150])
    code, _ = a.do("POST", "/api/stacks/crowdsec/stop", {})
    j = wait_job(a, "crowdsec")
    st = a.do("GET", "/api/stacks")[1]["stacks"]["crowdsec"]
    check("INT-STK-4 CrowdSec 정지", j.get("state") == "ok" and st.get("state") != "running", st.get("state"))
    code, _ = a.do("POST", "/api/stacks/crowdsec/start", {})
    j = wait_job(a, "crowdsec")
    st = a.do("GET", "/api/stacks")[1]["stacks"]["crowdsec"]
    check("INT-STK-5 CrowdSec 시작(준비될 때까지)", j.get("state") == "ok" and st.get("state") == "running", (j.get("error") or "")[:150])
    code, _ = a.do("POST", "/api/stacks/authelia/restart", {})
    j = wait_job(a, "authelia")
    check("INT-STK-6 Authelia 재시작 후 포털 정상", j.get("state") == "ok" and site("auth." + DOMAIN)[0] == 200, (j.get("error") or "")[:150])


SECTIONS.append(("STACK", sec_stack))


def sec_cfg(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    code, exp = a.do("GET", "/api/config/export", raw=True)
    blob = exp.decode("utf-8", "replace")
    check("INT-CFG-1 설정 내보내기(비밀값 없음)", code == 200 and "services" in blob and "proxySecret" not in blob and "argon2" not in blob, f"{len(blob)}바이트")
    code, m = a.do("POST", "/api/config/import", {"name": "c.json", "data": base64.b64encode(exp).decode(), "dry": True})
    check("INT-CFG-2 같은 설정 복원 미리보기", code == 200, str(m)[:150])
    for path in ("/api/topology", "/api/health", "/api/system", "/api/updates", "/api/setup/detect", "/api/docker/containers",
                 "/api/docker/upstreams", "/api/docker/networks", "/api/fs/browse", "/api/tailscale/detect", "/api/waf/meta",
                 "/api/groups", "/api/accounts", "/api/services/local", "/api/reset/plan", "/api/stacks"):
        code, m = a.do("GET", path)
        check(f"INT-VIEW {path}", code == 200, f"HTTP {code} {str(m)[:100] if code != 200 else ''}")
    code, m = a.do("POST", "/api/updates/check", {})
    check("INT-UPD-1 업데이트 확인", code == 200, str(m)[:150])
    code, m = a.do("GET", "/api/dns")
    check("INT-CF-1 Cloudflare 없이 DNS 화면은 안내", code in (200, 400, 409, 502), f"HTTP {code}")


SECTIONS.append(("CFG", sec_cfg))


def sec_reset(S):
    a, pw = S["a"], S["pw"]
    for k, v in S.items():
        globals().setdefault(k, v)
    caddyfile_before = fi.sh("docker", "exec", "e2e-caddy", "cat", "/etc/caddy/Caddyfile")
    code, m = a.do("POST", "/api/reset", {"confirm": "초기화", "accounts": False})
    check("INT-RST-1 초기화", code == 200, str(m)[:150])
    st = a.do("GET", "/api/state")
    check("INT-RST-2 초기화 뒤 서비스 0개·로그인 유지", st[0] == 200 and not st[1].get("services"), f"HTTP {st[0]}")
    check("INT-RST-3 Caddy 설정은 그대로(길목 밖은 안 건드림)", fi.sh("docker", "exec", "e2e-caddy", "cat", "/etc/caddy/Caddyfile") == caddyfile_before)
    check("INT-RST-4 사이트는 계속 동작", site("auth." + DOMAIN)[0] == 200)


SECTIONS.append(("RESET", sec_reset))


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        import traceback
        traceback.print_exc()
        check("INT 예외", False, str(ex)[:300])
    sys.exit(fi.report())
