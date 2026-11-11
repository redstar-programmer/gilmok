# 길목 (Gilmok)

홈랩·소규모 서버의 리버스 프록시 구성 — **Caddy + Authelia + Cloudflare + CrowdSec + Tailscale** — 을 웹 화면 하나에서 관리하는 도구입니다.
Go 단일 바이너리(Docker 이미지)와 빌드 도구 없는 HTML/CSS/JS 화면으로 되어 있습니다. 화면은 한국어입니다.

> 길목: 넓은 길에서 좁은 길로 들어서는 어귀. 모든 요청이 지나가는 그 자리를 관리한다는 뜻입니다.

## 할 수 있는 일

- **서비스 관리** — 서브도메인마다 공개 / 사설(Tailscale 등) 노출, Cloudflare Proxied / DNS only, mTLS(인증된 원본 풀), Authelia 정책·그룹, WAF를 정하고, 엑셀·CSV로 일괄 등록
- **안전한 적용** — Caddyfile과 Authelia `access_control` 생성 → 컨테이너 안에서 검증 → 백업 → 무중단 반영 → 상태 확인 → 실패하면 **자동 롤백**
- **Cloudflare** — DNS 레코드 동기화, DDNS(IPv4/IPv6), WAF 사용자 지정 규칙·속도 제한, 엣지 이벤트
- **보안** — Caddy 기본 차단·Coraza WAF(OWASP CRS), CrowdSec 판정 → Cloudflare 엣지 차단 연동
- **Authelia** — 사용자(argon2id)·그룹 관리
- **관찰** — 대시보드(요청·응답시간·상태코드·인증서·컨테이너), 구성도, 감사·보안·시스템 로그(SQLite)
- **운영** — 이미지 업데이트 알림·앱 안 업데이트(compose), 설정 백업·복원, 첫 설정 마법사
- **관리형 스택** — Caddy·Authelia·CrowdSec이 없으면 길목이 옆 컨테이너로 설치·관리
- 여러 관리자 계정·역할 권한, 2단계 인증(TOTP), 중요 작업 재인증, 시스템 / 다크 / 화이트 테마

이미 쓰고 있는 Caddyfile·Authelia 설정을 **가져와서** 시작할 수 있고, 쓰지 않는 구성요소(예: Cloudflare 없이 Caddy만)는 끌 수 있습니다.

## 설치

[deploy/README.md](deploy/README.md)를 보세요. 요약:

```bash
# 리눅스 예시 — 값은 deploy/.env.example 참고
mkdir -p ~/gilmok/{data,secrets} && cd ~/gilmok
git clone https://github.com/redstar-programmer/gilmok.git src
cp src/deploy/docker-compose.yml . && cp src/deploy/.env.example .env
touch secrets/cf_token secrets/crowdsec_key
docker compose up -d --build
```

Windows(Docker Desktop)는 `deploy\install.ps1`을 씁니다. 설치 뒤 서버에서 `http://127.0.0.1:8088`에 접속해 `admin` / `admin`으로 로그인하면 바로 본인 관리자 계정을 만들게 되고, 초기 계정은 비활성화됩니다.

## 보안 주의

- 관리 화면은 **인터넷에 직접 공개하지 마세요.** 기본으로 `127.0.0.1`에만 열리고, 원격 접속은 사설망(Tailscale 등) + Authelia 사이트로만 하도록 설계되어 있습니다.
- 길목은 Docker 소켓에 접근합니다(컨테이너 검증·재시작·업데이트). 길목 계정이 곧 서버 관리 권한이라고 생각하세요.
- Docker Desktop(Windows·macOS)은 외부 접속자 IP를 게이트웨이 IP로 바꿉니다. 그래서 IP 기반 차단은 Cloudflare 엣지에서 하도록 되어 있습니다.

## 개발

```bash
go test ./...                                         # 단위·시나리오·침투 테스트
bash dev/reset.sh                                     # 테스트 스택 데이터 생성 (dev/run, git 제외)
docker compose -f dev/docker-compose.yml up -d --build   # http://127.0.0.1:18088
```

테스트 스택은 실제 Caddy·Authelia·CrowdSec 컨테이너를 다른 이름으로 띄웁니다(`local_certs`라 외부 호출 없음). 테스트 목록은 [docs/TEST_SCENARIOS.md](docs/TEST_SCENARIOS.md)에 있습니다.

## 라이선스

[MIT](LICENSE)
