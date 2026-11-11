# 길목 설치 (Docker)

Docker가 있는 서버(Windows + Docker Desktop, 또는 리눅스)에 길목을 설치하는 순서입니다. 아래의 폴더·컨테이너 이름·도메인·IP는 모두 **예시**이니 자기 환경에 맞게 바꾸세요.
설치만으로는 Caddy·Authelia·DNS가 **바뀌지 않습니다**. 실제 변경은 화면에서 「적용」을 누를 때만 일어납니다.

## 0. 준비물

- 이 저장소를 서버에 받습니다 (예: `git clone`). Go를 설치할 필요는 없습니다. 빌드는 컨테이너 안에서 합니다.
- 이미 운영 중인 Caddy·Authelia에 길목을 붙이는 경우 다음을 확인합니다.
  - Caddyfile과 Caddy의 compose 파일이 있는 폴더 (예: `D:\Docker\caddy`)
  - Authelia의 compose 폴더와 설정 폴더 (예: `D:\Docker\authelia`, `D:\Docker\authelia\config`)
  - Caddy가 연결된 Docker 네트워크 이름 (예: `reverseproxy`)
- Caddy·Authelia·CrowdSec이 아직 없다면 길목이 옆 컨테이너로 **새로 설치**할 수도 있습니다 (첫 접속 후 「빠른 설정」). 이때 Caddyfile·Authelia 폴더는 비어 있어도 됩니다 — 리눅스는 아래 「직접 compose로 설치」를 쓰세요.

## 1. 설치

### Windows (PowerShell)

```powershell
cd D:\src\gilmok
powershell -ExecutionPolicy Bypass -File .\deploy\install.ps1 -Target D:\Docker\gilmok `
    -CaddyDir D:\Docker\caddy -AutheliaDir D:\Docker\authelia -AutheliaConfigDir D:\Docker\authelia\config `
    -CaddyContainer caddy -AutheliaContainer authelia -Network reverseproxy `
    -Domain example.com -TailscaleIP 100.64.0.10 -TimeZone Asia/Seoul
```

- 넘긴 옵션은 `<Target>\.env`에 저장됩니다. **다시 실행할 때(= 길목 업데이트)는 옵션 없이** `install.ps1 -Target D:\Docker\gilmok`만 하면 저장된 값을 씁니다.
- `-Domain`·`-TailscaleIP`는 처음 시작할 때의 기본값입니다. 빼면 웹 화면(설정 탭 › 도메인)에서 정하거나, 「기존 설정 가져오기」 때 Caddyfile의 사이트 주소에서 자동으로 알아냅니다.
- 그 밖의 옵션: `-Container`(길목 컨테이너 이름, 기본 `gilmok`), `-Port`(127.0.0.1에 여는 포트, 기본 `8088`), `-CrowdSecContainer`, `-Lang ko|en`(화면 언어 — 빼면 첫 접속에서 고름), `-Image`(기본 `vitive/gilmok:latest`, 예: `vitive/gilmok:0.2.0`으로 고정), `-Build`(Docker Hub 이미지 대신 이 저장소에서 빌드, `.env`에 기억 — `-Build:$false`로 되돌림).

스크립트가 하는 일은 다음과 같습니다. 다시 실행해도 안전합니다.

1. `<Target>\{data,secrets}`를 만듭니다.
2. `docker-compose.yml`을 놓습니다 (`-Build`면 소스도 `src`에 복사).
3. **Cloudflare 토큰**을 실행 중인 Caddy 컨테이너의 환경변수(`CLOUDFLARE_API_TOKEN`)에서 읽어 `secrets\cf_token`에 저장합니다. 화면에는 출력하지 않습니다.
   - 토큰을 바꿨다면 `-RenewToken` 옵션으로 다시 읽습니다.
   - 찾지 못해도 설치는 계속됩니다. 설치 뒤 웹 화면의 **Cloudflare 탭 › API 토큰 · 존**에서 붙여넣으면 됩니다(만드는 방법도 그 화면에 있음). 저장 전에 Cloudflare에 실제로 조회해 확인합니다.
4. Docker Hub 이미지(`vitive/gilmok`)를 받아 `docker compose up -d`로 띄웁니다. `-Build`면 `docker compose ... up -d --build`로 빌드하고, 빌드 과정에서 `go test`가 함께 돌아 테스트가 실패하면 설치도 멈춥니다.

`secrets\cf_token`은 평문 파일입니다. 필요하면 읽기 권한을 본인 계정으로 좁히세요(Docker가 읽을 수 있는지 꼭 확인).

### 직접 compose로 설치 (리눅스 등)

```bash
mkdir -p ~/gilmok/secrets && cd ~/gilmok
curl -fsSLO https://raw.githubusercontent.com/redstar-programmer/gilmok/main/deploy/docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/redstar-programmer/gilmok/main/deploy/.env.example -o .env
touch secrets/cf_token secrets/crowdsec_key     # 파일이 없으면 Docker가 폴더로 만들어 버림
$EDITOR .env                                    # 폴더·컨테이너 이름·네트워크·언어(GM_LANG)
docker network create reverseproxy 2>/dev/null || true
docker compose up -d
```

업데이트: `docker compose pull && docker compose up -d`. 소스에서 빌드하려면 저장소를 `src`에 받고 `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`.

## 2. 첫 접속

서버에서(직접 또는 원격 데스크톱·SSH 터널로) **http://127.0.0.1:8088**에 접속합니다 (`-Port`를 바꿨다면 그 포트).

0. **화면 언어**(한국어 / English)를 고릅니다. 이 설치의 모든 화면이 그 언어로 나오고, 나중에 설정 탭 › 화면 언어에서 바꿉니다 (`GM_LANG`/`-Lang`으로 정했으면 이 화면은 건너뜀).
1. 아이디 **`admin`**, 비밀번호 **`admin`**으로 로그인합니다(새로 설치했을 때만 있는 초기 계정).
2. 바로 **새 관리자 계정 만들기** 화면이 나옵니다. 본인 아이디(`admin` 말고)와 비밀번호(12자 이상)를 정하면, 그 계정으로 이어서 들어가고 **admin/admin은 그 즉시 비활성화**됩니다(비밀번호도 무작위로 바뀌어 다시 켤 수 없음). Authelia 사용자와는 별개입니다.
   - 새로 설치한 뒤 이 단계를 마치기 전까지는 누구나 아는 비밀번호이므로, 설치하자마자 바로 진행하세요(접속은 서버의 127.0.0.1:8088에서만 됩니다).
   - 예전 버전에서 업그레이드했다면 기존 관리자 비밀번호가 아이디 `admin` 계정으로 옮겨지고(초기 계정 아님), 예전에 켠 2단계 인증도 그대로 옮겨집니다.
3. (선택, 권장) **설정 탭 › 내 계정**에서 **2단계 인증(TOTP)**을 켭니다. 휴대폰 인증 앱으로 QR을 찍고 6자리 코드를 넣은 뒤, **복구 코드 10개**를 따로 보관합니다(휴대폰을 잃어버렸을 때 6자리 코드 대신 하나씩 씀).
4. 처음 로그인하면 **「빠른 설정」 또는 「설정 마법사」**를 고르는 창이 뜹니다. 빠른 설정은 찾은 컨테이너·파일·도메인을 한 화면에서 확인하고 시작하고, 마법사는 단계별로 진행합니다 (나중에 설정 탭 머리의 「설정 마법사 열기」로 다시 열 수 있음).
   - **Caddy 연결 / Authelia 연결**: 모든 항목이 ✓여야 합니다.
     - 「마운트 일치」는 길목이 고치는 파일과 컨테이너가 실제로 읽는 파일이 같은지 확인하는 항목입니다.
     - 「업데이트 준비 (compose)」가 ✓이면 앱 안에서 이미지 업데이트가 가능합니다.
     - 「Cloudflare 토큰 (업데이트용)」은 「실행 중인 Caddy와 같은 토큰」이어야 합니다.
   - **Cloudflare 연결**: 토큰, 존, DNS 읽기가 모두 ✓여야 합니다.
   - **기존 설정 가져오기**: 운영 Caddyfile, access_control, DNS를 읽어 서비스 목록을 만듭니다. 파일은 바꾸지 않습니다.
   - **서비스 확인**: 공개/Tailscale 구분, 구름 색, mTLS, Authelia 정책이 「서비스 분류」와 맞는지 확인합니다.
   - **미리보기 → 적용**: 처음에는 주석·구역 제목 차이가 diff로 보이는 게 정상입니다. 내용을 꼭 읽어보고 적용하세요.

## 3. 원격 접속 등록 (길목 자신)

서비스 탭에서 **서비스 추가**를 누르고 아래 값을 넣습니다.

| 항목 | 값 |
|---|---|
| 서브도메인 | `gilmok` (원하는 이름) |
| 노출 방식 | Tailscale 전용 (:8443) |
| 대상 (upstream) | `gilmok:8080` |
| Authelia | 사용 · 2단계 · 그룹 `admins` |
| DNS 자동 관리 | 사용 (→ `100.64.0.10`) |

적용한 뒤 Tailscale에 연결된 기기에서 `https://gilmok.example.com`에 접속합니다. 로그인은 Authelia(2단계)와 길목 계정(아이디·비밀번호·2단계 코드), 두 번입니다.

> Authelia가 고장 나면 원격 화면도 열리지 않습니다. 그럴 때는 서버에서 `http://127.0.0.1:8088`로 들어가세요. 이 비상 통로는 항상 열려 있습니다.

## 4. 이미지 업데이트 (Caddy / Authelia)

Caddy 탭이나 Authelia 탭의 「이미지 업데이트」 단계를 씁니다.

- compose 프로젝트와 폴더는 컨테이너 라벨에서 자동으로 감지합니다.
- 길목은 `D:\Docker\caddy`(`/stacks/caddy`)와 `D:\Docker\authelia`(`/stacks/authelia`, 읽기 전용)를 마운트하고 있습니다. 이 폴더를 Docker Desktop 경로(`/run/desktop/mnt/host/d/...`)로 연결해서 `docker compose`를 실행합니다.
- Caddy 업데이트에는 길목의 Cloudflare 토큰을 넘깁니다. 길목에 토큰이 없으면 업데이트를 거부합니다. `.env`의 잘못된 값으로 재생성되는 것을 막기 위해서입니다.
- 앱 안에서 업데이트가 안 되면 단계 안의 「고급 → 수동 명령」을 서버에서 직접 실행합니다.

한 번이라도 앱 안에서 업데이트하면 컨테이너 라벨의 작업 폴더가 `/run/desktop/mnt/host/d/...` 형식으로 바뀝니다. 길목은 이 형식도 인식합니다. 나중에 NAS에서 직접 `docker compose up`을 해도 문제는 없지만, 설정 해시가 달라서 컨테이너가 한 번 더 재생성될 수 있습니다.

## 5. 길목 자체 업데이트

- compose: `docker compose pull && docker compose up -d` (`.env`의 `GM_IMAGE`로 버전 고정 가능)
- Windows 스크립트: `install.ps1 -Target <폴더>`를 다시 실행 (Docker Hub 이미지를 다시 받음, `-Build`로 설치했다면 저장소를 새 버전으로 바꾼 뒤 실행)

`data`(설정 DB, 백업)와 `secrets`는 그대로 유지됩니다.

## 5-0. 구성요소 (설정 탭 › 구성요소)

길목은 Caddy·Authelia·Cloudflare·CrowdSec을 **필요한 것만 골라서** 쓸 수 있습니다. 예를 들면 Caddy만, Caddy+Authelia, Cloudflare DNS만, 또는 전부를 쓸 수 있습니다.

- 고르지 않은 구성요소는 탭과 설정이 숨겨지고, 적용·점검·업데이트 확인·로그 수집에서도 빠집니다. 그 구성요소의 파일이나 컨테이너는 건드리지 않습니다.
- 처음 시작할 때는 마운트된 파일, 컨테이너, 토큰, 서비스 설정을 보고 자동으로 추정합니다. Proxied이나 mTLS 서비스가 있으면 Cloudflare를, Authelia를 쓰는 서비스가 있으면 Authelia를 「사용」으로 봅니다.
- 쓰던 보호 기능이 빠지는 전환은 빨간 경고를 띄우고 한 번 더 확인합니다. 예를 들어 mTLS 서비스가 있는데 Cloudflare를 끄거나, 로그인 관문이 있는데 Authelia를 끄는 경우입니다.
- CrowdSec의 자동 차단은 Cloudflare 엣지에서 하므로, CrowdSec만 쓰면 판정과 기록까지만 합니다.

## 5-1. 대시보드 (첫 화면)

로그인하면 **대시보드**가 먼저 열립니다. 위젯은 「위젯 편집」 버튼으로 추가·수정·삭제하고, 끌어서 순서를 바꿀 수 있습니다. 배치는 길목 DB에 저장됩니다.

| 위젯 | 내용 |
|---|---|
| 숫자 카드 | 분당 요청, 5xx 비율, 응답시간 평균/p95, 전송량, WAF 차단, CrowdSec 차단 IP, 정상 서비스 수, 인증서 최단 남은 일수. 경고 기준값을 정할 수 있음 |
| 추이 차트 | 요청 수, 상태코드별(누적 막대), 응답시간(평균·p95), 전송량, WAF 차단. 기간 5분~24시간 |
| 응답시간 분포 | 요청 하나를 점 하나로 표시. **드래그로 영역을 고르면** 해당 요청 목록(사이트·URI·상태·응답시간·실제 IP)이 열림 |
| 상위 목록 | 사이트 / 경로 / 상태코드 / 클라이언트 IP(mTLS 사이트만) / 느린 요청 |
| 서비스 상태 맵 | 각 서비스의 upstream TCP 연결 여부·지연(30초마다), 최근 기록 띠. 누르면 서비스 편집 |
| 컨테이너 리소스 | CPU·메모리와 추이(15초마다, `docker stats`) |
| 인증서 만료 | Caddy가 실제로 내보내는 인증서의 남은 기간 |
| 최근 이벤트 | WAF 차단, 5xx 오류 |

- **데이터 출처**: 길목이 만드는 모든 사이트에 `log # gilmok`을 붙여 Caddy 접근 로그를 켜고, `docker logs -f`로 실시간 집계합니다.
  - 이전 버전에서 업그레이드했다면 대시보드 위의 「접근 로그 켜기」를 누르고 적용하세요.
  - 지표는 1시간분은 10초 단위, 24시간분은 1분 단위로 `/data/metrics.json`에 저장되므로 재시작해도 남습니다.
- **로그 크기 제한 (권장)**: 접근 로그가 Caddy 컨테이너 로그로 쌓입니다. Docker Desktop은 기본적으로 로그를 자르지 않으므로 `D:\Docker\caddy\docker-compose.yml`의 caddy 서비스에 다음을 추가하세요. 길목과 CrowdSec 컨테이너에는 이미 들어 있습니다.
  ```yaml
      logging:
        options: { max-size: "10m", max-file: "3" }
  ```
- 컨테이너·상태·인증서 수집은 대시보드를 보고 있을 때(마지막 조회 후 10분)만 돌아갑니다. 요청 집계는 항상 돕니다.

## 5-2. 로그 (로그 탭)

모든 기록은 `D:\Docker\gilmok\data\gilmok-logs.db`(SQLite)에 저장됩니다.

| 종류 | 내용 | 기본 보존 |
|---|---|---|
| 감사 | 모든 설정·서비스·사용자 변경(변경 전/후 값), 적용, 이미지 업데이트, 로그인·로그아웃, 2단계 인증, 세션 종료, 로그 삭제. 비밀번호·코드·토큰은 `***`로 가림 | 365일 |
| 보안·침입탐지 | WAF 차단, CrowdSec 차단/해제, Authelia 로그인 실패·차단, 관리자 로그인 실패·잠금, 허용되지 않은 경로로의 접속 시도 | 180일 |
| 시스템 | 시작·종료, 서비스 다운/복구, 디스크 단계 변화, 새 이미지 발견, 보존 정리 | 30일 |
| 요청 | Caddy가 받은 모든 요청 (대시보드 과거 보기의 원본) | 7일 |
| 지표 | 사이트별 1분 단위 통계 | 90일 |

- **보기**: 종류별 검색·기간·수준·사이트·상태코드 필터, 행을 누르면 상세(JSON), CSV 내보내기(최대 10만 건)
- **디스크 보호** (설정에서 바꿀 수 있음):
  - 여유 20% 이하 → 경고
  - 10% 이하 → 강력 경고, 첫 화면 알림
  - 5% 이하 → 요청 로그·지표 기록 중단 (감사·보안·시스템 로그는 계속, 여유 1% 미만이면 모두 중단)
  - DB 최대 크기(기본 2 GB)를 넘으면 가장 오래된 요청 로그부터 지움
- **I/O·교착 방지**:
  - 쓰기는 한 곳(단일 쓰기 스레드)에서 1초마다 묶어서 한 번에 기록 (WAL 모드)
  - 대기열이 차면 기다리지 않고 버리며, 버린 건수는 「기록 상태」에 표시
  - 삭제·보존 정리는 5천 건씩 나눠서 진행

## 5-3. 접근 보안 (설정 탭 › 접근 보안)

길목은 전체 네트워크(프록시·SSO·DNS·WAF)를 바꿀 수 있으므로 여러 겹으로 막습니다.

1. **접근 경로 제한**: 다음 두 경로만 받고, 같은 Docker 네트워크의 다른 컨테이너가 `gilmok:8080`으로 직접 오는 요청은 거부하고 보안 로그에 남깁니다.
   - 서버의 `127.0.0.1:8088` (호스트 포트)
   - Caddy가 「길목 사이트」에만 붙이는 비밀 헤더(`X-Gilmok-Proxy`)가 있는 요청
2. **Caddy 경유 시 Authelia 필수**: Authelia가 넘긴 `Remote-User`가 없으면 거부합니다. 허용 그룹을 지정할 수 있습니다(예: `admins`).
3. **계정과 권한** (설정 탭 › 계정 관리): 사람마다 계정을 따로 만들고 역할을 줍니다. 모든 작업은 누가 했는지 감사 로그에 남습니다.
   - 기본 역할: **관리자**(모든 권한, 바꿀 수 없음) · **운영자**(구성 변경, 적용, Authelia 사용자, 차단 관리) · **보기 전용**. 권한을 골라 역할을 새로 만들 수 있습니다.
   - 권한: 구성 변경 / 적용·외부 반영 / Authelia 사용자 / 차단 관리 / 로그 관리 / 계정·접근 보안. 권한이 없는 작업은 서버가 거부합니다(화면은 모두 볼 수 있음).
   - 새 계정은 **임시 비밀번호**로 시작합니다. 처음 로그인하면 본인 비밀번호로 바꾸게 됩니다. 관리자는 임시 비밀번호 재발급, 2단계 인증 초기화(휴대폰 분실), 사용 중지, 삭제를 할 수 있습니다.
   - 「계정·접근 보안」 권한이 있는 사용 중 계정은 항상 하나 이상 남습니다(마지막 관리자는 지우거나 내릴 수 없음).
4. **2단계 인증 (TOTP)**: 기본은 **계정마다 선택**입니다. 각자 설정 탭 › 내 계정에서 켜고 끄고, 기기를 바꾸거나 복구 코드를 새로 만듭니다. 관리자는 계정 관리에서 **계정별 「2단계 요구」 스위치**로, 또는 여러 계정을 골라 **일괄**로 요구할 수 있습니다 — 요구받은 계정은 설정을 마쳐야 쓸 수 있고 본인이 끌 수 없습니다.
5. **세션**: 유휴 30분, 최대 12시간이면 만료됩니다. 세션 목록(계정별)을 보고 강제 종료할 수 있습니다. 계정을 사용 중지·삭제하거나 비밀번호를 재설정하면 그 계정의 세션이 바로 끊깁니다.
6. **중요 작업 재인증**: 적용, 사용자·계정 변경, 로그 삭제, 보안·로그 설정 변경, 이미지 업데이트, Cloudflare 규칙 적용은 10분 안에 비밀번호(+코드)를 다시 확인해야 합니다.
7. **잠금**: 5회 실패마다 5분 → 10분 → … 최대 1시간 잠깁니다 (계정·IP별 + 전체).
8. **그 밖**: Origin 확인, CSP·보안 헤더 강화, 비밀번호 12자 이상(아이디 포함 금지), 없는 아이디와 틀린 비밀번호를 구별할 수 없게 처리.

> 업그레이드한 뒤에는 **한 번 「적용」**을 해야 길목 사이트에 비밀 헤더가 붙습니다. 그 전까지 Caddy를 거친 원격 접속은 거부되고, 서버의 127.0.0.1:8088은 계속 열려 있습니다. 길목 사이트에는 Authelia를 켜 두세요(3장).

## 5-4. 이미지 업데이트 알림

길목은 12시간마다 Caddy·Authelia·CrowdSec 이미지를 레지스트리 최신본과 비교합니다. 이 비교는 manifest HEAD 요청이라 Docker Hub 받기 한도에 걸리지 않습니다.

- 새 이미지가 있으면 위쪽에 「↑ 업데이트 N건」이 뜨고, 로그인할 때 알림이 나옵니다.
- 각 탭의 「이미지 업데이트」 카드에도 표시됩니다.
- 직접 빌드하는 Caddy는 Dockerfile의 `FROM` 베이스 이미지(예: `caddy:builder`, `caddy:latest`)를 비교합니다. 처음 확인할 때 기준값을 기록하고, 앱 안에서 업데이트하면 기준값을 갱신합니다.

## 5-5. Caddy 연결 방식 (Caddy 탭 › Caddy 연결)

| 방식 | 언제 | 비고 |
|---|---|---|
| Docker 컨테이너 | 지금 구성 (caddy) | 목록에서 컨테이너를 고를 수 있음 |
| Caddy 관리 API | Windows에 직접 설치한 Caddy 등 | Caddyfile 전역 옵션에 `admin 0.0.0.0:2019 { origins host.docker.internal:2019 }`를 넣고, **Windows 방화벽에서 2019 포트는 Docker(WSL) 대역만 허용**합니다. Caddyfile 폴더를 길목에 마운트해야 합니다 |
| 같은 PC의 caddy 실행 파일 | 길목도 Docker 없이 직접 실행할 때 | `caddy validate`와 `caddy reload`를 직접 호출 |

Docker가 아닌 방식에서는 대시보드 요청 통계와 앱 안 이미지 업데이트를 지원하지 않습니다. 둘 다 Docker 로그와 compose가 필요하기 때문입니다.

## 6. 보안 강화 (선택): WAF · Cloudflare 규칙 · CrowdSec

Docker Desktop(Windows·macOS)은 외부 접속자 IP를 브리지 게이트웨이(예: `172.18.0.1`)로 바꿉니다. 그래서 IP로 판단하는 기능은 서버 안에서 쓰지 않고, 아래처럼 나눠서 씁니다.

| 층 | 판단 근거 | 적용 범위 | 길목 화면 |
|---|---|---|---|
| Caddy 기본 차단 | User-Agent·경로 (스캐너, AI 크롤러, `/.env` 같은 탐색) | 켠 사이트 모두 (Coraza 없이도 동작) | Caddy 탭 › 기본 차단, 서비스별 보호 |
| Caddy WAF (Coraza + OWASP CRS) | 요청 **내용** (SQL 인젝션, XSS, 경로 탐색, 명령 실행 등) | Proxied·DNS only·Tailscale 사이트 모두 | Caddy 탭 › WAF 엔진, 서비스별 보호, WAF 이벤트, WAF 시험 |
| Cloudflare WAF 규칙 | Cloudflare 엣지가 보는 **실제 IP**·국가·ASN·User-Agent·경로, 요청 속도 | Proxied 사이트 | Cloudflare 탭 › WAF 규칙, 엣지 이벤트 |
| CrowdSec | mTLS 사이트 로그의 실제 IP (`Cf-Connecting-Ip`) | 판정은 CrowdSec, 차단은 Cloudflare 엣지 | CrowdSec 탭 |

### 6-1. Caddy WAF · 기본 차단

1. `D:\Docker\caddy\Dockerfile`을 [caddy/Dockerfile](caddy/Dockerfile) 내용으로 바꿉니다. Cloudflare DNS 플러그인과 Coraza를 함께 빌드합니다.
   - 예전 Dockerfile에 다른 플러그인이 있었다면 `--with` 줄로 추가합니다.
2. Caddy 탭 › 이미지 업데이트로 다시 빌드합니다. 「WAF 엔진」 단계에 「✓ Coraza WAF 모듈 있음」이 보이는지 확인합니다.
3. **기본 차단**: 「기본 차단」에서 막을 항목(스캐너·공격 도구, 공격 경로는 기본으로 켜짐, AI 크롤러·User-Agent 없음·PHP는 선택)을 고르고, 「서비스별 보호」에서 사이트마다 켭니다. 앱과 관계없이 공격인 요청이라 오탐이 거의 없습니다.
4. **WAF**: 「서비스별 보호」에서 사이트마다 **「탐지만」**으로 켜고 적용합니다.
5. 며칠 쓴 뒤 「WAF 이벤트」를 봅니다. 항목별·서비스별로 모여 보입니다. 정상 사용인데 걸린 규칙이 있으면 「예외…」를 눌러 **그 서비스만** 또는 공통 예외로 넣습니다.
6. 오탐이 없으면 「차단」으로 바꾸고 적용한 뒤, 「WAF 시험」으로 SQL 인젝션·XSS·스캐너 요청 등이 실제로 막히는지 확인합니다.

「WAF 엔진」에서 차단 민감도(paranoia), 기록만 하는 민감도, 차단 점수, 본문 검사, 허용 메서드, 검사할 OWASP 규칙 그룹을 정합니다. 서비스마다 민감도·예외를 따로 둘 수 있습니다(「세부…」).

- 기본값은 요청 본문 검사 **꺼짐**입니다. Immich 같은 대용량 업로드가 느려지거나 막히지 않게 하기 위해서입니다.
- 허용 메서드 기본값은 `GET HEAD POST OPTIONS PUT PATCH DELETE`입니다(OWASP 기본값은 PUT·DELETE를 막음). WebDAV는 `PROPFIND MKCOL COPY MOVE LOCK UNLOCK`을 더합니다.
- WAF를 켠 사이트 수만큼 Caddy 메모리가 늘어납니다(테스트 기준 사이트 8개에 약 60MB).
- Caddy에서는 인증(Authelia)이 WAF보다 먼저 실행됩니다. 로그인하지 않은 요청은 Authelia가 먼저 막습니다.
- 예전 버전에서 「추가 규칙」에 넣은 `SecRuleRemoveById` 줄은 처음 시작할 때 「공통 규칙 예외」 목록으로 옮겨집니다.

### 6-2. Cloudflare WAF 규칙

Cloudflare API 토큰에 다음 권한을 추가합니다. 대시보드 › 내 프로필 › API 토큰에서 기존 토큰을 편집합니다.

- 영역 · 영역 WAF · 편집 (사용자 지정 규칙, 속도 제한 규칙)
- 영역 · 분석 · 읽기 (엣지 이벤트)
- 계정 · 계정 필터 목록 · 편집 (CrowdSec 차단 IP 목록, CrowdSec을 쓸 때만)

그다음 Cloudflare 탭 › WAF 규칙으로 갑니다. 카드마다 켜고 설정한 뒤 「저장」 → 「Cloudflare에 적용」 순서입니다.

| 카드 | 하는 일 |
|---|---|
| 신뢰 IP 허용 | 목록의 IP는 다른 길목 규칙을 건너뜀 (맨 앞) |
| CrowdSec 차단 목록 | CrowdSec 판정 IP 차단 (CrowdSec 탭에서 켬) |
| 위협 차단 | 차단 IP · 스캐너 · AI 크롤러 · 공격 경로 · User-Agent 없음 · PHP를 **규칙 하나**로 묶어 차단 |
| 국가·통신사 제한 | 허용 목록/차단 목록 방식, 국가 코드와 ASN, 확인된 검색엔진 봇 통과, 대상 서비스 선택 |
| 사용자 규칙 | Cloudflare 규칙 식을 직접 작성 |
| 요청 속도 제한 | 경로별로 IP당 요청 수 제한 (로그인 무차별 대입 방지) |

- **규칙 수 한도**: Free 플랜은 사용자 지정 규칙 5개, 속도 제한 규칙 1개(기간·차단 시간 10초 고정)입니다. 화면에 「지금 → 적용 후 / 한도」가 보이고, 넘으면 적용하지 않습니다. 길목이 만든 규칙은 끄면 **지웁니다**(자리 확보). 직접 만든 규칙을 가져온 것은 지우지 않고 끕니다.
- 직접 만든 국가·통신사(ASN) 규칙이 보이면 **「길목이 관리하도록 가져오기」**를 누릅니다. 새 규칙을 만들지 않고 그 규칙을 수정합니다.
- 길목이 관리하지 않는 다른 규칙은 건드리지 않습니다.
- **엣지 이벤트**: Cloudflare가 막거나 챌린지한 요청을 규칙·국가·IP·경로·서비스별로 봅니다. 의심 IP는 「차단」으로 위협 차단 규칙의 차단 IP에 넣을 수 있습니다.

### 6-3. CrowdSec (Cloudflare 연동형)

```powershell
cd D:\src\gilmok
powershell -ExecutionPolicy Bypass -File .\deploy\install.ps1 -CrowdSec
```

- 컨테이너 `crowdsec`를 추가하고 바운서 키를 `secrets\crowdsec_key`에 만듭니다. 키는 화면에 출력하지 않습니다.
- 이 선택은 `D:\Docker\gilmok\.env`(`COMPOSE_PROFILES=crowdsec`)에 기억되므로, 이후에는 `-CrowdSec` 없이 다시 실행해도 유지됩니다.

설치한 다음 CrowdSec 탭에서 위에서부터 진행합니다.

1. **연결 확인**: 컨테이너, LAPI(바운서 키), 길목 파서가 모두 ✓여야 합니다.
2. **로그 수집**: 켜고 적용합니다. Proxied + mTLS 사이트에만 접근 로그와 실제 IP 필드가 붙습니다.
   - DNS only 사이트는 `Cf-Connecting-Ip` 헤더를 위조할 수 있으므로 일부러 제외합니다.
3. **Cloudflare 동기화**: 켠 뒤, Cloudflare 탭 › WAF 규칙에서 「CrowdSec 차단 목록」 규칙을 적용합니다. 이때 IP 목록 `$gilmok_crowdsec`와 차단 규칙이 함께 만들어집니다.
4. **차단 목록**: CrowdSec이 판정한 IP를 확인하고, 직접 차단하거나 해제할 수 있습니다.

Cloudflare로 보내는 것은 이 서버에서 판정한 IP뿐입니다. 커뮤니티 차단 목록은 보내지 않습니다(Cloudflare 목록 한도 10,000개).

### 구성도

서비스 탭에서 「구성도」를 고르면 전체 구성을 트리 그림으로 볼 수 있습니다.

- 인터넷 → Cloudflare → 공유기 → Caddy → (Proxied·mTLS / DNS only / Tailscale) → 서비스 순서로 그려집니다.
- Authelia 관문, WAF, CrowdSec 흐름도 함께 표시됩니다.
- 서비스에 마우스를 올리면 그 경로가 강조되고, 누르면 편집 화면이 열립니다.
- **자동으로 읽는 것**: Caddy 컨테이너의 호스트 게시 포트(`docker inspect`), Docker 환경(Docker Desktop 여부), 공인 IP, 서비스 설정 전부.
- **물어보는 것**: 인터넷과 이 서버 사이(공유기 포트포워딩 / 공인 IP 직접 / Cloudflare Tunnel / 다른 프록시), 사설 접속 경로(tailscale serve / Tailscale IP 직접 / 다른 VPN), 호스트 이름.
  - 입력하기 전에는 그 자리에 「?」 노드와 예시가 그려집니다. 노드를 누르거나 「앞단·호스트 정보…」 버튼으로 입력합니다. 이 값은 그림에만 쓰이고 설정 파일은 바꾸지 않습니다.
- 입력한 값과 감지한 값이 맞지 않으면 그림 위에 「구성 확인」으로 알려 줍니다. 예를 들면 다음과 같은 경우입니다.
  - 공유기가 넘기는 포트와 Caddy의 게시 포트가 다르다
  - 공개 포트가 127.0.0.1에만 열려 있다
  - Tailscale 전용 포트가 모든 인터페이스에 열려 있다
  - Cloudflare Tunnel인데 DNS only 서비스가 있다

## 하지 말 것

- `GM_DEV_FAULTS`를 운영 compose에 넣지 마세요. 장애 주입은 테스트 스택 전용입니다.
- 8088 포트를 `127.0.0.1` 밖으로 열지 마세요.
- Caddyfile을 직접 고치지 마세요. 다음 적용 때 덮어써집니다. 전역 옵션과 스니펫은 Caddy 탭의 「기본 골격」에서 고칩니다.
  `(gm_waf_block)`·`(gm_waf_detect)` 스니펫은 길목이 만들므로 기본 골격에 넣지 않습니다.
- CrowdSec이나 fail2ban을 Caddy의 접속 IP(`remote_ip`)로 동작하게 바꾸지 마세요. Docker Desktop에서는 그 값이 모든 사용자에게 같은 게이트웨이 IP라서, 한 번 차단하면 전원이 막힙니다.
