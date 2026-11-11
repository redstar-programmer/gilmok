# 설계: 길목이 직접 설치·관리하는 구성요소 (관리형 스택)

> 상태: **1차 구현 완료** (2026-11-10) — 10장 1~5단계 끝, 6단계(연결형 → 관리형 이전)는 2차.
> 결정된 것: 같은 컨테이너가 아니라 **옆 컨테이너로 설치**, nginx 지원은 **이번 범위 밖**(나중 단계).
> 「6. 정할 것」은 모두 추천안으로 확정.

## 1. 목표

길목 하나만 설치한 사람도 화면에서 Caddy·Authelia·CrowdSec을 **설치 → 연결 → 운영**까지 끝낼 수 있게 한다.

- 「설치」 버튼 하나로 길목이 compose 파일·설정·비밀값을 만들고 컨테이너를 띄운 뒤, 길목 설정(컨테이너 이름·파일 경로·키)을 자동으로 맞춘다
- 이미 띄워 둔 컨테이너에 **연결**하는 지금 방식은 그대로 둔다 — 구성요소마다 「연결(기존)」 / 「관리형(길목이 설치)」 중 하나
- 관리형도 지금과 같은 원칙: 생성 → 검증 → 백업 → 적용 → 실패 시 복원

### 하지 않는 것
- 길목 컨테이너 안에서 다른 프로세스를 띄우기 (사용자 결정 — 장애·업데이트가 한 덩어리가 되고 관리 UI와 인터넷 443이 섞임)
- nginx / Nginx Proxy Manager (다음 단계. 다만 「7. nginx를 위한 자리」는 남긴다)
- Tailscale 설치 (호스트 설치형이 정석, 컨테이너 Tailscale은 별개 주제)
- 기존(연결) 구성요소를 관리형으로 **자동 이전** — 이전은 사용자가 명시적으로 할 때만 (「5.6」)

## 2. 사용자 흐름

```
첫 접속 → 빠른 설정 / 설정 마법사
   구성요소 카드마다:  ○ 이미 있는 컨테이너에 연결   ● 길목이 설치
                                                   └ 미리보기: 만들 컨테이너·포트·폴더·이미지
   [설치] → 진행 로그(이미지 받기 → 설정 생성 → 시작 → 상태 확인) → 연결 점검 결과
```

- 각 구성요소 탭의 ① 연결 단계에도 같은 선택이 있다 (나중에 설치·제거 가능)
- 설치 전 **사전 점검**: 포트(80/443/8443) 사용 중인지, 같은 이름 컨테이너가 있는지, 디스크 여유, Docker 연결
- 설치 중 실패하면 이번에 만든 컨테이너만 지우고(데이터 폴더는 남김) 원인을 보여 준다

## 3. 파일·컨테이너 배치

길목 데이터 폴더(`/data`) 아래에 둔다 — 길목 백업·이동 단위와 같아지고, 호스트 경로 문제가 하나로 모인다.

```
/data/stacks/
  caddy/      compose.yml  Caddyfile  data/(인증서)  config/  cf-origin-pull-ca.pem
  authelia/   compose.yml  config/configuration.yml  config/users_database.yml  secrets/*  data/db.sqlite3
  crowdsec/   compose.yml  acquis.yaml  gilmok-caddy-logs.yaml  config/  data/
```

- compose 프로젝트 이름 `gilmok-<구성요소>`, 컨테이너 이름 `gilmok-caddy` 등 (사용자가 바꿀 수 있음)
- 공용 네트워크: 길목이 붙어 있는 **사용자 정의** 네트워크를 쓴다. `bridge`·`host`·`none`은 제외 — 기본 `bridge`는
  컨테이너 이름 DNS(`gilmok-authelia:9091`)가 안 된다. 쓸 만한 네트워크가 없으면 `gilmok-net`을 만들고
  `docker network connect`로 **길목 자신부터** 연결한 뒤 스택을 띄운다
- 라벨 `gilmok.managed=<구성요소>` — 관리형 판별·업데이트·제거에 사용

### 호스트 경로 (Docker Desktop의 함정)
compose의 bind 경로는 **Docker 데몬이 아는 경로**여야 한다. 이미 `compose.go`가 같은 문제를 풀었다:
길목 자신의 마운트(`selfMounts`)에서 `/data`의 호스트 경로를 찾고 → Docker Desktop이면
`/run/desktop/mnt/host/<드라이브>/…`(`daemonPath`)로 바꾸고 → 그 경로를 `--project-directory`로 `docker compose`.
관리형 스택은 이 흐름을 그대로 재사용한다. `/data`가 **이름 있는 볼륨**이어도 따로 분기하지 않는다 —
`docker inspect`의 그 마운트 `Source`(`/var/lib/docker/volumes/<이름>/_data`)가 데몬이 아는 호스트 경로이므로
그 아래 `stacks/<구성요소>`를 bind로 넘기면 bind 마운트와 같은 코드로 동작한다(`docker cp` 분기 없음 — 생성·검증·백업·롤백이
모두 로컬 파일 그대로).

## 4. 구성요소별 설계

### 4.1 Caddy
- **이미지**: Cloudflare DNS + Coraza가 든 Caddy가 필요(`deploy/caddy/Dockerfile`). 「6. 정할 것 ①」
- **포트**: 공개 `443`(`80`은 기본 닫음, 체크하면 열기 — HTTP→HTTPS 리다이렉트·HTTP-01용).
  사설 `:8443`의 게시 주소는 **사설 경로 종류(`topoPrivKind`)에 맞춘다**:
  - `ts_serve`(tailscale serve가 호스트에서 넘겨줌) → `127.0.0.1:8443` — 지금 운영 구성. 외부에 안 열림
  - `ts_direct`(기기가 Tailscale IP로 직접) → `<Tailscale IP>:8443` (모르면 `0.0.0.0:8443` + 경고)
  - `vpn` → `0.0.0.0:8443` + 경고
  - 어느 경우든 Caddy 사이트에는 원래대로 출발지 제한(사설 대역 `remote_ip`)이 붙는다
- **Caddyfile**: 길목이 만든다(지금과 같음). 처음엔 기본 골격(전역 옵션 + 스니펫 `cf_only`·`authelia`)만, 사이트는 서비스 탭에서
- **인증서**: `data/` 볼륨에 보관 → 컨테이너를 다시 만들어도 재발급 없음
- **Cloudflare 토큰(DNS-01)**: 스택 폴더의 `.env`(0600)에 `CLOUDFLARE_API_TOKEN=…`을 길목이 쓴다. compose는 `${CLOUDFLARE_API_TOKEN}`.
  실행 때마다 env를 넘기는 방식은 누군가 호스트에서 `docker compose up -d`를 하면 빈 값으로 재생성되어 인증서 갱신이 깨진다.
  토큰을 바꾸면(`POST /api/cloudflare/token`) `.env`를 고치고 Caddy를 `up -d`로 재생성. (컨테이너 env는 `docker inspect`로 보이는 건
  어느 방식이든 같음 — docker.sock 접근이 곧 관리자 권한)
- **관리 API(:2019)는 열지 않는다**: Docker 모드는 검증·적용을 `docker exec … caddy validate/reload`로 하고 관리 API는
  `CaddyMode=api`(PC 설치 Caddy)에서만 쓴다. 0.0.0.0:2019를 열면 같은 네트워크의 아무 컨테이너나 Caddy 설정을 바꿀 수 있다
- **mTLS**: Cloudflare 「인증된 원본 풀」 CA 파일(`cf-origin-pull-ca.pem`) — 공개 CA라 길목이 내장해서 넣는다
- 설치 뒤 자동 설정: `CaddyMode=docker`, `CaddyContainer`, `CaddyfilePath`, `CaddyfileInCtr`, `CaddyStackDir`

### 4.2 Authelia
- **설정 생성** (`configuration.yml`, **v4.38+ 문법**): 길목이 아는 값으로 최소 구성 — 구버전 키는 `level=fatal`
  ```yaml
  theme: dark
  server: { address: 'tcp://:9091' }
  log: { level: info }
  totp: { issuer: '<도메인>' }
  authentication_backend: { file: { path: /config/users_database.yml, password: { algorithm: argon2 } } }
  session:
    cookies:
      - domain: '<도메인>'
        authelia_url: 'https://auth.<도메인>'
  storage: { local: { path: /data/db.sqlite3 } }
  notifier: { filesystem: { filename: /data/notification.txt } }   # 함정 3: smtp와 동시 사용 금지
  access_control: { default_policy: deny, rules: [...] }           # 길목이 생성하는 블록
  ```
  처음 rules: 포털 자신(`auth.<도메인>`)은 bypass. 비밀값은 파일에 넣지 않는다(아래 env)
- **비밀값**: 길목이 무작위 생성 → `secrets/*` 0600 → `_FILE` 환경변수
  - `AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE` (구 `AUTHELIA_JWT_SECRET_FILE` 아님)
  - `AUTHELIA_SESSION_SECRET_FILE`, `AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE`
  - 화면·로그·감사 로그에 값이 나오지 않음. 생성한 설정은 설치 전에 `authelia config validate`로 검증(지금의 검증 경로 재사용)
- **포털 서비스**: 설치 화면에서 「`auth.<도메인>` 서비스 추가」 체크(기본 켬) → 공개·Proxied·mTLS(Cloudflare 사용 시),
  upstream `<authelia 컨테이너>:9091`, **Authelia 관문 없음**(자기 자신을 forward_auth하면 무한 리다이렉트)
- **첫 사용자**: 설치 화면에서 Authelia 관리자 계정(이름·비밀번호) 입력 → argon2id로 `users_database.yml`, 그룹 `admins` (함정 4: groups는 리스트)
- 시작 확인: 지금의 `Startup complete` / `level=fatal` 판정 재사용 (함정 6)
- 설치 뒤 자동 설정: `AutheliaCtr`, `AutheliaConfig`, `AutheliaUsers`, `AutheliaCtrDir`, `AutheliaStackDir`

### 4.3 CrowdSec
- 이미지 `crowdsecurity/crowdsec`, 컬렉션 `crowdsecurity/caddy crowdsecurity/http-cve`
- `acquis.yaml`: `source: docker`, `container_name: [<관리형 또는 연결된 Caddy 컨테이너>]`, `type: gmcaddy` — Caddy 컨테이너 이름이 바뀌면 길목이 다시 쓰고 재시작
- 파서 `gilmok-caddy-logs.yaml` 내장 (`deploy/crowdsec`의 것)
- 바운서 키: `BOUNCER_KEY_gilmok` env에 길목이 만든 키 → `<data>/secrets/crowdsec_key` (지금 「바운서 키 만들기」와 같은 파일)
- docker.sock 읽기 전용 마운트 필요 (Caddy 로그를 읽음) — 화면에 이유와 함께 표시
- 설치 뒤 자동 설정: `CrowdSecContainer`, `CrowdSecLAPI=http://<컨테이너>:8080`, `UseCrowdSec`

## 5. 수명 주기

| 동작 | 내용 |
|---|---|
| 설치 | 사전 점검 → 파일 생성 → `compose pull` → `up -d` → 상태 확인 → 길목 설정 반영 → 연결 점검 |
| 시작·정지·재시작 | 구성요소 탭 ① 연결 단계 버튼 (`compose start/stop/restart`) |
| 업데이트 | 지금의 이미지 업데이트 그대로 (`compose.go`) — 관리형은 compose 위치를 이미 알아서 자동 감지 실패가 없음 |
| 설정 다시 만들기 | Authelia `configuration.yml`의 길목 관리 부분(세션 도메인 등) — 도메인이 바뀌면 「적용」 때 함께 |
| 제거 | 컨테이너·네트워크 정리, **데이터 폴더는 남김**(체크하면 삭제 — 인증서·사용자 DB가 사라짐을 경고) |
| 이전(연결 → 관리형) | 기존 Caddyfile·Authelia 설정/사용자/DB를 관리형 폴더로 **복사**하고 새 컨테이너를 띄운 뒤, 기존 컨테이너는 사용자가 직접 정지 (포트 충돌 안내). 자동 삭제 없음 |

- 모든 동작은 감사 로그, 실패는 시스템 이벤트
- 권한: 설치·제거·이전은 「연결·시스템」 + step-up(재인증)
- 초기화(`/api/reset`)는 관리형 컨테이너를 **건드리지 않는다** — 길목 밖이므로. 초기화 화면에 「관리형 컨테이너는 남습니다(구성요소 탭에서 제거)」 안내

## 6. 결정 (2026-11-10 확정)

1. **Caddy 이미지**: 설치 때 길목이 내장 Dockerfile(`deploy/caddy/Dockerfile`과 같은 것)로 **직접 빌드**. 레지스트리 운영 없음,
   업데이트는 기존 「직접 빌드 + 베이스 이미지 비교」. 빌드는 2~5분이라 **백그라운드 작업 + 진행 로그 폴링**(동기 HTTP 금지 —
   브라우저·리버스 프록시 타임아웃)
2. **포트 80**: 기본 닫음, 체크하면 열기
3. **Authelia 포털 서비스**: 설치하며 자동 추가 제안(체크 기본 켬) — 4.2
4. **관리형 컨테이너 이름**: 기본 `gilmok-caddy`·`gilmok-authelia`·`gilmok-crowdsec`, 바꿀 수 있음(컨테이너 이름 규칙 검증 — 기존 설정 검증과 같은 규칙)
5. **연결형 → 관리형 이전**: 2차로 미룸

## 7. nginx를 위한 자리 (지금은 구현하지 않음)

나중에 nginx를 붙일 때 다시 뜯지 않도록, Caddy 전용 부분을 **프록시 엔진** 경계 뒤로 모으는 작업은 관리형 Caddy를 만들면서 같이 한다:
- 생성(`GenerateCaddyfile`) · 검증 · 적용(reload) · 가져오기 · 접근 로그 파서 · 관리형 설치 템플릿
- 서비스 모델(`Service`)은 엔진 중립 유지 — `Extra`(Caddy 지시어)만 엔진 전용으로 표시
- 엔진별 기능 표(WAF·mTLS·forward_auth·인증서)를 두고, 지원하지 않는 기능은 화면에서 숨김

## 8. 위험과 대응

| 위험 | 대응 |
|---|---|
| 포트 443 충돌(기존 프록시가 이미 사용) | 사전 점검에서 차단, 어떤 컨테이너가 쓰는지 표시 |
| Docker Desktop 경로 변환 실패 | 기존 `compose.go` 경로 로직 + 설치 전 `compose config -q`로 검증 |
| 비밀값 노출 | 생성 즉시 0600 파일, `_FILE` 방식, 응답·로그·감사 로그에 값 없음(기존 원칙) |
| docker.sock 권한 | 길목은 이미 가지고 있음. CrowdSec에는 읽기 전용으로만 |
| 설치 중간 실패 | 이번에 만든 컨테이너만 제거, 파일은 남겨 원인 확인 가능 |
| 길목 데이터 폴더가 커짐(인증서·DB·CrowdSec 데이터) | 디스크 가드에 관리형 폴더 크기 포함, 로그 정리 대상에서는 제외 |
| 운영 NAS 실수 | 기존 연결형은 사용자가 「이전」을 고르기 전엔 절대 건드리지 않음 |

## 9. 테스트 계획

- 단위: 가짜 Docker(`dockerRun`)로 설치·실패 정리·이름/포트 충돌·경로 변환·비밀값 미노출 검사, 생성 파일 골든 테스트(compose.yml·configuration.yml·acquis.yaml)
- 통합(dev 스택): 길목만 띄운 빈 환경 → 화면에서 Caddy·Authelia·CrowdSec 설치 → 서비스 추가 → 적용 → 로그인·mTLS·CrowdSec 판정까지 (기존 dev 스택과 이름이 겹치지 않게 `gm-test-` 접두사)
- 문서: `docs/TEST_SCENARIOS.md`에 MSTK-xx 표 추가

## 10. 구현 순서 (승인 후)

1. 공통: 관리형 스택 엔진(파일 생성·compose 실행·상태·제거), 사전 점검, 네트워크 선택/생성, 마운트 경로(bind·이름 있는 볼륨 공통),
   **백그라운드 작업**(한 번에 하나, 진행 로그 링 버퍼) — API `GET /api/stacks`(상태+작업 로그), `POST /api/stacks/{name}/{install|start|stop|restart|remove}`(즉시 202 + 작업 id)
2. Caddy 관리형 + 프록시 엔진 경계 정리
3. Authelia 관리형 (비밀값·첫 사용자·포털 서비스)
4. CrowdSec 관리형 (acquis 자동 갱신·바운서 키)
5. 빠른 설정·마법사에 「길목이 설치」 선택 연결
6. (2차) 연결형 → 관리형 이전

## 11. 검토 반영 기록 (2026-11-10, 1차 외부 검토)

| 지적 | 판단 | 반영 |
|---|---|---|
| Caddy 빌드는 수 분 — 동기 요청이면 타임아웃 | 맞음 | 6-① 백그라운드 작업 + 폴링 |
| 포털 서비스는 Authelia 관문 없이, upstream `:9091` | 맞음 | 4.2 포털 서비스 |
| 관리형 Caddy의 관리 API(:2019)를 네트워크에 열어야 한다 | **맞지 않음** — Docker 모드는 `docker exec`로 검증·적용하고 관리 API는 `api` 모드 전용(`caddyctl.go`). 열면 같은 네트워크의 컨테이너가 Caddy 설정을 바꿀 수 있음 | 4.1에 「열지 않는다」 명시 |
| 실행 시 env로 넘긴 Cloudflare 토큰은 호스트에서 `compose up` 하면 사라짐 | 맞음 | 4.1 스택 `.env`(0600) + 토큰 변경 시 재생성 |
| Authelia v4.38+ 문법(`session.cookies`, 새 비밀값 env 이름) | 맞음 | 4.2 템플릿·env 이름, 설치 전 `config validate` |
| 이름 있는 볼륨이면 `docker cp` 분기 대신 마운트 `Source` 경로를 bind로 | 맞음 — 분기 제거 | 3 |
| 사설 포트는 `127.0.0.1`이면 다른 Tailscale 기기가 못 들어옴 | **부분적으로** — `tailscale serve`(지금 운영)는 호스트가 127.0.0.1로 넘겨주므로 그게 맞음. 기기가 Tailscale IP로 직접 오는 구성에서만 문제 | 4.1 사설 경로 종류별 게시 주소 |
| 기본 `bridge` 네트워크는 컨테이너 이름 DNS가 안 됨 | 맞음 | 3 사용자 정의 네트워크만, 없으면 `gilmok-net` 생성 + 길목 먼저 연결 |
