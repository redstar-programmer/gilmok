<div align="center">

# 길목 (Gilmok)

### 집 서버로 들어오는 길을 한곳에서 관리합니다

[English](README.en.md) | **한국어**

[![Release](https://img.shields.io/github/v/release/redstar-programmer/gilmok?label=release)](https://github.com/redstar-programmer/gilmok/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker Hub](https://img.shields.io/docker/v/vitive/gilmok?label=docker&sort=semver)](https://hub.docker.com/r/vitive/gilmok)

**Caddy, Authelia, Cloudflare, CrowdSec, Tailscale로 꾸린 리버스 프록시를 웹 화면 하나에서 설정하고 적용하는 도구입니다.**

</div>

---

## 만든 이유

집 서버에 서비스가 열 개를 넘어가면서, 하나를 추가할 때마다 Caddyfile을 고치고, Authelia 규칙을 넣고, Cloudflare에 DNS 레코드를 만들고, reload한 다음 잘 되는지 확인하는 일이 반복됐습니다. 이 중 하나만 빠뜨려도 사이트가 열리지 않거나, 더 나쁘게는 로그인 없이 열립니다.

길목은 이 과정을 「서비스 하나 = 설정 한 줄」로 묶습니다. 저장한 내용은 바로 반영되지 않고, 무엇이 바뀌는지 먼저 보여 준 다음 검증을 통과한 것만 적용합니다. 적용하다 실패하면 이전 상태로 되돌립니다.

이름의 「길목」은 넓은 길에서 좁은 길로 들어서는 어귀를 뜻합니다. 서버로 들어오는 모든 요청이 지나가는 자리를 관리한다는 의미로 붙였습니다.

## 주요 기능

### 서비스 관리
서브도메인마다 공개(:443) 또는 사설(Tailscale·VPN 전용), Cloudflare Proxied 또는 DNS only, mTLS, Authelia 로그인 정책과 허용 그룹, WAF 모드를 정합니다. 엑셀(.xlsx)이나 CSV로 여러 개를 한 번에 등록할 수 있고, 대상 주소는 실행 중인 Docker 컨테이너 목록에서 고를 수 있습니다.

### 안전한 적용
「적용」을 누르면 Caddyfile과 Authelia 규칙을 만들고, 실제 컨테이너 안에서 `caddy validate`와 `authelia config validate`로 먼저 검사합니다. 통과하면 백업한 뒤 Authelia 재시작, Caddy 무중단 reload, DNS 동기화 순서로 반영하고, 중간에 실패하면 바꾼 파일을 모두 원래대로 돌립니다.

> 공개 레코드의 IP 주소가 바뀌는 DNS 변경은 기본으로 보류합니다. 길목을 테스트 PC 같은 다른 네트워크에서 돌리다가 운영 레코드를 엉뚱한 IP로 바꾸는 사고를 막기 위해서입니다.

### 기존 설정 가져오기
지금 쓰는 Caddyfile을 읽어 전역 옵션과 스니펫은 「기본 골격」으로, 사이트 블록은 서비스로 옮깁니다. Authelia는 `configuration.yml`에서 `access_control` 블록만 바꾸고, 주석이나 `{{ secret }}` 템플릿, OIDC, notifier 설정은 건드리지 않습니다.

### Cloudflare
DNS 레코드 생성·수정·삭제, Proxied 전환, DDNS(IPv4·IPv6)를 처리합니다. 엣지 WAF 규칙으로 신뢰 IP 허용, 스캐너·AI 크롤러 차단, 국가·통신사(ASN) 제한, 요청 속도 제한을 만들 수 있고, 무료 플랜의 규칙 수 한도를 넘지 않는지 미리 확인합니다.

### WAF와 CrowdSec
Caddy 앞단에서 알려진 스캐너, 공격 도구, `/.env` 같은 탐색 경로를 403으로 막습니다. 여기에 Coraza WAF(OWASP CRS)를 서비스별로 「탐지만」 또는 「차단」으로 켤 수 있습니다. CrowdSec은 Cloudflare를 거쳐 들어온 요청의 실제 IP로 공격을 판정하고, 차단은 Cloudflare 엣지에서 합니다.

### 대시보드와 로그
분당 요청 수, 5xx 비율, 응답시간 p95, 상태코드별 추이, 서비스 응답 여부, 컨테이너 자원, 인증서 만료일을 위젯으로 봅니다. 누가 무엇을 바꿨는지 남는 감사 로그와 보안·시스템 로그는 SQLite에 저장되고, 디스크 여유가 줄면 기록을 줄입니다.

### 없는 구성요소 설치
Caddy, Authelia, CrowdSec이 아직 없다면 길목이 옆 컨테이너로 설치하고 연결 설정까지 맞춥니다. 설치한 뒤에도 compose 파일을 화면에서 고칠 수 있습니다.

### 구성도
인터넷에서 Cloudflare, 공유기, Caddy를 거쳐 각 서비스까지 이어지는 경로를 그림으로 그립니다. 응답하지 않는 서비스로 가는 선은 멈춘 점선으로 표시됩니다.

### 계정과 접근 보안
사람마다 계정을 만들고 관리자, 운영자, 보기 전용 같은 역할을 줍니다. 2단계 인증(TOTP), 중요한 작업 전 비밀번호 재확인, 로그인 잠금이 들어 있고, 관리 화면은 서버 자신이나 Caddy를 거친 지정된 경로로만 열립니다.

### 화면 언어
한국어와 영어를 지원합니다. 처음 접속할 때 고른 언어가 그 설치의 언어가 되고, 나중에 설정 탭에서 바꿀 수 있습니다.

## 기술 스택

| 구분 | 내용 |
|---|---|
| 백엔드 | **Go 1.26** 단일 바이너리, 표준 `net/http` |
| 화면 | 빌드 도구 없는 HTML / CSS / JavaScript, 바이너리에 내장 |
| 저장 | 설정은 JSON 파일, 로그는 **SQLite** (cgo 없음) |
| 연동 | Docker CLI, Caddy, Authelia, Cloudflare API, CrowdSec LAPI |
| 이미지 | `vitive/gilmok` — linux/amd64, linux/arm64 |

## 빠른 시작

### 요구 사항
- Docker 20.10 이상, Docker Compose v2
- amd64 또는 arm64 (라즈베리 파이 포함)
- Cloudflare를 쓴다면 API 토큰 (설치 후 화면에서 넣어도 됩니다)

### 설치

```bash
# 1. 폴더 만들기
mkdir gilmok && cd gilmok

# 2. compose 파일 받기 (.env는 필요 없습니다)
curl -fsSLO https://github.com/redstar-programmer/gilmok/releases/latest/download/docker-compose.yml

# 3. 실행
docker compose up -d
```

이미 쓰고 있는 Caddy나 Authelia에 붙이려면 받은 `docker-compose.yml` 안의 주석 처리된 줄(폴더, 컨테이너 이름, 네트워크)을 풀면 됩니다. 폴더와 이름을 `.env`로 따로 관리하고 싶다면 [deploy/docker-compose.yml](deploy/docker-compose.yml)과 [.env.example](deploy/.env.example)을 쓰세요. Windows에서는 설치 스크립트([deploy/README.md](deploy/README.md))도 있습니다.

### 접속

| 항목 | 주소 |
|---|---|
| 관리 화면 | `http://127.0.0.1:8088` (서버 자신에서만 열립니다) |

처음 접속하면 언어를 고르고, **admin / admin**으로 로그인합니다. 로그인하자마자 본인 관리자 계정을 만드는 화면이 나오고, 그 순간 admin 계정은 비활성화됩니다. 그다음 「빠른 설정」이 컨테이너와 설정 파일을 찾아 연결을 도와줍니다.

> 관리 화면을 인터넷에 직접 열지 마세요. 휴대폰 같은 다른 기기에서 쓰려면 설정 탭의 「길목 사이트 만들기」로 Tailscale 전용 + Authelia 2단계 인증 사이트를 만드는 것을 권장합니다.
> 길목은 Docker 소켓을 사용하므로, 길목 관리자 계정은 사실상 서버 관리 권한과 같습니다.

### 업데이트

```bash
docker compose pull
docker compose up -d
```

설정과 로그는 `./data`에 남아 있습니다. 버전을 고정하려면 compose 파일의 이미지를 `vitive/gilmok:0.1.4`처럼 바꾸세요.

## 환경변수

처음 시작할 때만 쓰는 기본값입니다. 그 뒤로는 화면에서 바꾼 설정이 우선합니다.

| 변수 | 설명 | 기본값 |
|---|---|---|
| `GM_LANG` | 화면 언어 `ko` 또는 `en`. 비우면 첫 접속 때 묻습니다 | (없음) |
| `GM_DOMAIN` | 서비스 주소의 기준 도메인 | (없음) |
| `GM_TAILSCALE_IP` | 사설 서비스 DNS가 가리킬 주소 | (없음) |
| `GM_CADDY_CONTAINER` | Caddy 컨테이너 이름 | `caddy` |
| `GM_AUTHELIA_CONTAINER` | Authelia 컨테이너 이름 | `authelia` |
| `GM_CROWDSEC_CONTAINER` | CrowdSec 컨테이너 이름 | `crowdsec` |
| `GM_CADDYFILE` | 길목이 읽고 쓰는 Caddyfile 경로 | (없음) |
| `GM_AUTHELIA_CONFIG` | Authelia `configuration.yml` 경로 | (없음) |
| `GM_AUTHELIA_USERS` | Authelia `users_database.yml` 경로 | (없음) |
| `GM_CROWDSEC_LAPI` | CrowdSec LAPI 주소 | (없음) |
| `GM_CF_TOKEN_FILE` | Cloudflare API 토큰 파일. 없으면 화면에서 입력 | (없음) |
| `GM_CROWDSEC_KEY_FILE` | CrowdSec 바운서 키 파일. 없으면 화면에서 생성 | (없음) |
| `GM_DATA` | 데이터 폴더 | `/data` |
| `TZ` | 시간대 | `UTC` |

Cloudflare 토큰에는 `Zone · Zone · Read`와 `Zone · DNS · Edit` 권한이 필요합니다. WAF 규칙을 쓰려면 `Zone · Zone WAF · Edit`, 엣지 이벤트를 보려면 `Zone · Analytics · Read`, CrowdSec 차단 목록을 쓰려면 `Account · Account Filter Lists · Edit`를 더 넣으세요. 토큰은 저장하기 전에 실제로 조회해서 확인합니다.

## 알아 둘 점

> **Docker Desktop(Windows, macOS)에서는 접속자 IP가 전부 게이트웨이 IP로 보입니다.** 그래서 서버 안에서 IP로 판단하는 기능(GeoIP, fail2ban 등)은 쓸 수 없고, 길목은 IP 기반 차단을 Cloudflare 엣지에서 합니다. CrowdSec도 Cloudflare만 접속할 수 있는 mTLS 사이트의 로그에서만 실제 IP를 믿습니다.

> 지금은 **Caddy만** 지원합니다. nginx는 다음 계획에 있습니다.

> 길목이 만드는 파일(Caddyfile 주석 등)은 화면 언어와 상관없이 한국어로 적힙니다.

> 리눅스에서 동작은 확인했지만, SELinux 환경(`:z` 라벨)은 아직 확인하지 못했습니다.

## 개발

```bash
go test ./...                                             # 단위·시나리오·침투 테스트
bash dev/reset.sh                                         # 테스트 스택 데이터 만들기
docker compose -f dev/docker-compose.yml up -d --build    # http://127.0.0.1:18088
```

테스트 스택은 실제 Caddy(Coraza 포함), Authelia, CrowdSec 컨테이너를 다른 이름으로 띄우고, 외부로는 요청을 보내지 않습니다. 화면 문구를 바꿨다면 `go run ./tools/i18n`으로 원문 목록을 다시 만들고 영어 번역(`web/i18n/en.json`)을 채워 주세요. 테스트 목록은 [docs/TEST_SCENARIOS.md](docs/TEST_SCENARIOS.md)에 있습니다.

새 버전은 `v0.1.2` 같은 태그를 올리면 GitHub Actions가 테스트를 돌리고, Docker Hub 이미지와 릴리스를 만듭니다.

## 라이선스

MIT 라이선스입니다. 자세한 내용은 [LICENSE](LICENSE)를 보세요.

## 문의

- [Issues](https://github.com/redstar-programmer/gilmok/issues) — 버그 제보, 기능 제안
- [Releases](https://github.com/redstar-programmer/gilmok/releases) — 버전별 변경 내용
- [Docker Hub](https://hub.docker.com/r/vitive/gilmok) — 이미지

<div align="center">
<sub>길목 — 집 서버로 들어오는 길을 한곳에서</sub>
</div>
