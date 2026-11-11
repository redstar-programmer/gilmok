# 길목 단위 테스트 시나리오

길목(Gilmok)의 모든 기능을 단위 테스트 관점에서 정리한 시나리오·케이스 목록입니다. 새 기능을 넣거나 고칠 때 해당 모듈 표를 먼저 갱신하고, 테스트를 추가한 뒤 「자동화」 칸을 채웁니다.

## 0. 읽는 법

| 항목 | 뜻 |
|---|---|
| ID | `<모듈>-<번호>` (예: `AUTH-07`). 번호는 바꾸지 않고, 지운 케이스는 「폐기」로 남깁니다 |
| 우선순위 | **P1** 보안·데이터 손실·운영 장애와 직결 / **P2** 기능 오동작 / **P3** 표시·편의 |
| 1:n | 한 대상이 여러 대상에 영향을 주는 관계 케이스. 관계 기호는 아래 「1:n 관계 매트릭스」 참고 |
| 자동화 | ✅ `테스트이름` = 이미 `go test`에 있음 / ◐ 일부만 / ⬜ 아직 없음 |

공통 원칙
- **외부 시스템은 가짜로**: Cloudflare·CrowdSec LAPI는 `httptest.Server`, Docker CLI는 테스트용 이음매(아래 0.2) 뒤로 숨깁니다. 실제 토큰·실제 DNS·운영 컨테이너를 쓰는 테스트는 만들지 않습니다
- **파일은 `t.TempDir()`**: Caddyfile·configuration.yml·users_database.yml·`gilmok.json`·`gilmok-logs.db`는 임시 폴더에 둡니다
- **비밀값 유출 검사**: 응답 본문·감사 로그·내보낸 파일에 토큰·해시·TOTP 비밀·세션 토큰·프록시 비밀이 없는지 확인하는 단언을 해당 케이스마다 넣습니다
- **시간**: 만료·잠금·TOTP는 시계를 주입하거나 상태(`failState`, `Session.LastSeen`)를 직접 앞당겨 검사합니다. `time.Sleep`에 기대지 않습니다

### 0.1 공통 픽스처

| 이름 | 내용 | 위치 |
|---|---|---|
| `newAuthTestApp(t)` | 임시 저장소 + `Auth` + 주요 라우트가 붙은 `http.Handler` | `accounts_test.go` |
| `tclient` | 쿠키를 유지하며 `X-GM: 1`을 붙여 요청 | `accounts_test.go` |
| `bulkTestData()` | 서비스 2개(공개·사설)와 도메인 설정 | `bulk_test.go` |
| 가짜 Cloudflare | 존·DNS·rulesets·lists·GraphQL 응답 | `waf_test.go`, `ddns_test.go`, `dnsedit_test.go` |
| `testdata/Caddyfile` | 실제 운영 Caddyfile(비밀값 없음) | `caddy_test.go` |

### 0.2 테스트 이음매 (만들어야 할 것)

외부 프로세스·네트워크·호스트 OS를 직접 부르는 함수는 지금 이음매가 없어 단위 테스트가 어렵습니다. 아래 네 가지 패키지 변수 이음매를 추가하면 ⬜ 케이스 대부분을 외부 의존 없이 자동화할 수 있습니다.

- `var dockerRun = func(ctx, stdin, env, args...) (string, error)` (`docker.go`) — 테스트에서 명령별 응답표(`inspect`, `exec … caddy validate`, `restart`, `logs --since`, `cscli`)를 돌려주는 가짜로 교체
- `var fetchPublicIP = func(ctx, v6 bool) (string, error)` (`cloudflare.go`, `ddns.go`) — 지금의 `publicIP()`(1.1.1.1 `/cdn-cgi/trace` → ipify 순서) 대신 넣어 공인 IPv4/IPv6 감지 성공·실패·변경을 흉내
- `var diskFreeBytes = func(path string) (free, total uint64, err error)` (`disk_*.go`) — 디스크 여유율 단계(20% / 10% / 5% / 1%) 시뮬레이션
- `var registryClient = &http.Client{...}` (`updates.go`) — Docker Hub·GHCR manifest digest 조회를 `httptest.Server`로 격리

---

## 1:n 관계 매트릭스

한 대상의 변경이 여러 대상으로 퍼지는 곳입니다. 각 관계는 **0개 / 1개 / 여러 개 / 일부 실패** 네 경우를 모두 다룹니다.

| 관계 | 1 | n | 핵심 케이스 |
|---|---|---|---|
| R1 | Authelia 그룹 | 서비스(허용 그룹) | GRP-08~12, GRP-16 |
| R2 | Authelia 그룹 | Authelia 사용자 | GRP-13~15, GRP-17 |
| R3 | 계정 | 세션 | ACC-14~16, AUTH-22 |
| R4 | 역할 | 계정 | ROLE-04~07 |
| R5 | 적용 1회 | 구성요소(Authelia·Caddy·DNS) | APPLY-04~12 |
| R6 | 엑셀 파일 | 행(추가·수정·삭제·오류) | BULK-10~22 |
| R7 | 서비스 | DNS 레코드(A·AAAA) | DNS-03~06, DDNS-08 |
| R8 | 서비스 | WAF 예외 규칙 | WAF-08~10 |
| R9 | 도메인 | 서비스 FQDN | SVC-10, CADDY-16 |
| R10 | Tailscale(사설) IP | 사설 서비스 레코드 | DNS-07 |
| R11 | Cloudflare 규칙셋 | 규칙(길목 것·남의 것) | CFW-05~09 |
| R12 | CrowdSec 판정 목록 | IP 항목 | CS-03~07 |
| R13 | 컨테이너 | 서비스(대상) | UP-06, UP-07 |
| R14 | Caddy 컨테이너 | 네트워크 | UP-02~04 |
| R15 | 설정 저장 1회 | 바뀐 키(키별 권한) | SET-02~06 |
| R16 | 대시보드 | 위젯 | DASH-01~05 |
| R17 | 로그 스트림 | 사이트별 버킷 | MON-02~05 |
| R18 | Authelia 사용자 | 그룹 | AU-04, AU-05 |
| R19 | 구성요소 끄기 | 생성·적용·점검 단계 | COMP-02~06 |
| R20 | 서비스 | 감사 로그 diff 필드 | AUD-03 |
| R21 | 계정 게이트 상태 | 허용·차단 API 경로 | AUTH-02, AUTH-41 |
| R22 | 재인증(step-up) 창 | 민감 API 엔드포인트(`S()`) + 핸들러 안 재인증(그룹 이름 변경이 사용자 파일을 바꿀 때) | AUTH-24, ROLE-10, GRP-23 |
| R23 | 공인 IP 변경 1회 | 관리 중인 공개 DNS 레코드들 | APPLY-08~09, DDNS-01~04 |

---

## STORE — 저장소 (`store.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| STORE-01 | 새 설치 | 파일 없음 | 기본 설정으로 생성, 도메인 `""`, 컨테이너 `caddy/authelia/crowdsec` | P1 | ✅ `TestScnStore` |
| STORE-02 | 환경변수 기본값 | `GM_DOMAIN`, `GM_TAILSCALE_IP` 지정 | 새 설치 설정에 반영, 기존 파일엔 덮어쓰지 않음 | P2 | ✅ `TestScnStore` |
| STORE-03 | 원자적 저장 | 저장 중 실패(쓰기 권한 없음) | 원본 파일·메모리 모두 그대로, 에러 반환 | P1 | ✅ `TestScnStore` |
| STORE-04 | `Update` 에러 롤백 | 콜백이 에러 반환 | `Update`는 깊은 복사본에서 실행 — 콜백 오류·저장 실패 모두 메모리 그대로 | P1 | ✅ `TestScnStore` |
| STORE-05 | `Snapshot` 독립성 | 스냅샷을 고친 뒤 저장소 조회 | 저장소 값은 그대로 | P1 | ✅ `TestScnStore` |
| STORE-06 | `markDirty` 중복 | 같은 메시지 2번 | `Pending`에 1개, `Dirty=true` | P2 | ✅ `TestScnStore` |
| STORE-07 | 적용 후 비움 | 적용 성공 | `Pending` 비움, `Dirty=false` | P2 | ✅ `TestScnApplySuccessAndNoop` |
| STORE-08 | 손상된 JSON | 문법 오류 파일 | 시작 거부 + 원인 메시지(덮어쓰지 않음) | P1 | ✅ `TestScnStore` |
| STORE-09 | 비밀값 직렬화 | `ProxySecret`, 계정 해시 | `/api/state` 응답에 없음 | P1 | ✅ `TestAccountsFlow` |
| STORE-10 | 동시 읽기·쓰기 경합 | 고루틴 다수가 `Snapshot`·`Update` 동시 호출 (`-race`) | 데이터 레이스 없음, 슬라이스 깊은 복사 독립성 유지 | P1 | ✅ `TestScnStore` |

## AUTH — 로그인·세션·접근 경로 (`security.go`, `accounts.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| AUTH-01 | 첫 실행 상태 | 계정 없음 | `/api/auth/state` → `firstRun`, admin/admin 로그인 가능 | P1 | ✅ `TestAccountsFlow` |
| AUTH-02 | 초기 계정 게이트 | admin/admin 로그인 후 일반 API | 403 `{gate:"bootstrap"}` | P1 | ✅ `TestAccountsFlow` |
| AUTH-03 | 진짜 관리자 생성 | `POST /api/auth/bootstrap` | 새 계정 생성·세션 전환, admin/admin 비활성화+비밀번호 무작위 | P1 | ✅ `TestAccountsFlow` |
| AUTH-04 | 초기 계정 재사용 | bootstrap 이름으로 `admin` 지정 | 거부 | P1 | ✅ `TestAccountsFlow` |
| AUTH-05 | 초기 계정 재활성화 | 비활성화된 admin을 다시 켜기 | 거부(삭제만 가능) | P1 | ✅ `TestAccountsFlow` |
| AUTH-06 | 예전 단일 관리자 이전 | `AdminHash`·`TOTPSecret`만 있는 데이터 | `admin` 계정으로 이전, 초기 계정 아님 | P1 | ✅ `TestMigrateSingleAdmin` |
| AUTH-07 | 비밀번호 틀림 | 5회 연속 | 키(IP+이름) 5분 잠금, 이후 2배씩 최대 1시간 | P1 | ✅ `TestTOTPReplayAndGlobalLock` |
| AUTH-08 | 전체 잠금 | 서로 다른 키로 30회/15분 | 전체 키 1분 잠금, 최대 15분 | P1 | ✅ `TestTOTPReplayAndGlobalLock` |
| AUTH-09 | 전체 잠금 리셋 남용 | 실패 29회 → 다른 계정 로그인 성공 → 실패 1회 | 전체 키 잠김(성공이 초기화하지 않음) | P1 | ✅ `TestScnAuthLockout` |
| AUTH-10 | 실패 창 만료 | 실패 4회 후 15분 경과 → 실패 1회 | 잠기지 않음(창 리셋) | P2 | ✅ `TestScnAuthLockout` |
| AUTH-11 | 없는 계정 | 존재하지 않는 이름 | 같은 에러 문구, 같은 지연(더미 해시 검증) | P1 | ✅ `TestScnAuthLogin` |
| AUTH-12 | 사용 중지 계정 | `Disabled=true` | 401, 감사 로그 「사용 중지된 계정」 | P1 | ✅ `TestAccountsFlow` |
| AUTH-13 | TOTP 필요 | TOTP 등록 계정, 코드 없음 | 401 `{needCode:true}`, 실패로 세지 않음 | P1 | ✅ `TestScnAuthLogin` |
| AUTH-14 | TOTP 시간 허용 | 현재·±30초 코드 | 통과, ±60초는 거부 | P1 | ✅ `TestTOTP` |
| AUTH-15 | TOTP 재사용 | 같은 코드 두 번(로그인→재인증) | 두 번째 거부 (`TOTPLast`) | P1 | ✅ `TestTOTPReplayAndGlobalLock` |
| AUTH-16 | 복구 코드 | 코드 자리에 복구 코드 | 1회 로그인, 같은 코드 재사용 거부, 감사 로그 warn | P1 | ✅ `TestAccountsFlow` |
| AUTH-17 | 세션 쿠키 | 로그인 성공 | HttpOnly·SameSite=Strict, TLS/`X-Forwarded-Proto: https`면 Secure | P1 | ✅ `TestScnAuthSessions` |
| AUTH-18 | 세션 회전 | 기존 쿠키로 다시 로그인 | 예전 세션 삭제 | P1 | ✅ `TestScnAuthSessions` |
| AUTH-19 | 유휴 만료 | `LastSeen`을 유휴 시간 넘게 과거로 | 다음 요청 401, 세션 삭제 | P1 | ✅ `TestScnAuthSessions` |
| AUTH-20 | 절대 만료 | `Created`를 절대 시간 넘게 과거로 | 활동이 있어도 401 | P1 | ✅ `TestScnAuthSessions` |
| AUTH-21 | 정책 최소값 | `SecIdleMin=1`, `SecAbsHours=0` | 유휴 5분·절대 1시간으로 올림 | P2 | ✅ `TestScnAuthSessions` |
| AUTH-22 | 세션 목록·종료 (R3) | 한 계정 세션 3개 | 내 세션만 보임(관리자는 전부), 다른 세션 종료 시 그 세션만 401 | P2 | ✅ `TestScnAuthSessions` |
| AUTH-23 | 로그아웃 | `POST /api/auth/logout` | 쿠키 삭제, 세션 삭제, 감사 로그 | P2 | ✅ `TestScnAuthSessions` |
| AUTH-24 | 재인증(step-up) 필요 | 재인증 창 밖에서 민감 작업 | 403 `{reauth:true}` | P1 | ✅ `TestAccountsFlow`, `TestScnAuthStepUp` |
| AUTH-25 | 재인증 성공 | 비밀번호(+코드) | `Reauth` 갱신, 창 안에서는 다시 묻지 않음 | P1 | ✅ `TestScnAuthStepUp` |
| AUTH-26 | 재인증 실패 | 틀린 비밀번호 | 401, 전체 키 실패 +1, 감사 로그 | P1 | ✅ `TestScnAuthStepUp` |
| AUTH-27 | CSRF | 쓰기 요청에 `X-GM` 없음 | 403 | P1 | ✅ `TestScnAuthTransport` |
| AUTH-28 | Origin 검사 | 다른 Origin의 쓰기 요청 | 403 | P1 | ✅ `TestScnAuthTransport` |
| AUTH-29 | 보안 헤더 | 아무 응답 | X-Frame-Options DENY, nosniff, CSP, Referrer-Policy | P2 | ✅ `TestScnAuthTransport` |
| AUTH-30 | 접근 경로: 직접 | 루프백·호스트 게이트웨이에서 | 허용, `via=direct` | P1 | ✅ `TestAccessGuard` |
| AUTH-31 | 접근 경로: 프록시 | 올바른 `X-Gilmok-Proxy` 비밀 | 허용, `via=proxy` | P1 | ✅ `TestAccessGuard` |
| AUTH-32 | 접근 경로: 거부 | 같은 네트워크의 다른 컨테이너, 틀린 비밀 | 403, `access.denied` 보안 이벤트(키당 1회) | P1 | ✅ `TestAccessGuard` |
| AUTH-33 | 프록시 경유 클라이언트 IP | via=proxy, XFF `1.1.1.1, 2.2.2.2` | `clientIP`=2.2.2.2(마지막), 경로 판정은 `peerIP` | P1 | ✅ `TestScnAuthAccessPath` |
| AUTH-34 | 직접 접속에서 XFF 위조 | via=direct, XFF 지정 | `clientIP`는 TCP 상대 주소 | P1 | ✅ `TestScnAuthAccessPath` |
| AUTH-35 | SSO 필수 | `SecRequireSSO` + `Remote-User` 없음 | 403 | P1 | ✅ `TestAccessGuard`, `TestScnAuthAccessPath` |
| AUTH-36 | SSO 그룹 | 허용 그룹 밖 사용자 | 403 | P1 | ✅ `TestScnAuthAccessPath` |
| AUTH-37 | SSO는 Authelia 사용 시에만 | `UseAuthelia=false` | SSO 요구 무시 | P2 | ✅ `TestScnAuthAccessPath` |
| AUTH-38 | `/healthz` | 루프백 / 외부 | 200 / 403 | P2 | ✅ `TestScnAuthTransport` |
| AUTH-39 | 프록시 비밀 생성 | 첫 시작 | `ProxySecret` 생성(24바이트), 재시작 시 유지 | P1 | ✅ `TestProxyHeaderGenerate` |
| AUTH-40 | `setup` 재호출 차단 | 계정이 이미 1개 이상 있을 때 `POST /api/auth/setup` | 409 「이미 설정되어 있습니다」, 기존 계정 불변 | P1 | ✅ `TestSetupOnceAndSelfProtection` |
| AUTH-41 | 게이트 우선순위·허용 경로 (R21) | `bootstrap` / `password` / `2fa` 게이트 상태 | 우선순위(`bootstrap` > `password` > `2fa`)대로 동작, 해당 게이트 해소 API·`logout`·`state` 외 모든 API 403 | P1 | ✅ `TestAccountsFlow`, `TestScnGates` |
| AUTH-42 | 경로 스위치 끄기 | `SecAllowDirect=false` 또는 `SecAllowProxy=false` | 루프백·게이트웨이 직접 접속 403(단 `/healthz`는 200), 올바른 프록시 비밀이어도 프록시 경유 403 | P1 | ✅ `TestScnAuthAccessPath` |
| AUTH-43 | 직접 접속 SSO 헤더 위조 무시 | `via=direct` + `Remote-User: admin` 헤더 | `Session.SSOUser` 비어 있음(프록시 경유만 신뢰) | P1 | ✅ `TestScnAuthAccessPath` |
| AUTH-44 | 접근 거부 로그 스로틀링 | 같은 `IP\|사유`로 10분 내 100회 거부 | `access.denied` 이벤트 1건만 기록(로그 폭주 방지) | P2 | ✅ `TestScnAuthTransport` |
| AUTH-45 | 요청 본문 크기 상한 | 2 MB 초과 JSON 본문 전송 | `MaxBytesReader`에서 즉시 거부(메모리 고갈 방지) | P1 | ✅ `TestScnAuthTransport` |

## ACC — 계정·2단계 인증 (`accounts.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| ACC-01 | 계정 생성 | 이름·역할·임시 비밀번호 | 생성, 첫 로그인 시 `password` 게이트 | P1 | ✅ `TestAccountsFlow` |
| ACC-02 | 이름 규칙 | 대문자·공백·중복 | 소문자로 정규화 / 400 / 400(중복) | P2 | ✅ `TestScnAccounts` |
| ACC-03 | 비밀번호 규칙 | 11자, 201자, 아이디 포함 | 각각 거부 | P1 | ✅ `TestScnAccounts` |
| ACC-04 | 비밀번호 변경 | 현재 비밀번호 틀림 | 400, 전체 키 +1 | P1 | ✅ `TestScnAccounts` |
| ACC-05 | 같은 비밀번호 | 새 = 현재 | 거부 | P3 | ✅ `TestScnAccounts` |
| ACC-06 | 관리자 비밀번호 재설정 | `POST /api/accounts/{name}/password` | 임시 비밀번호, 대상의 다른 세션 종료 | P1 | ✅ `TestScnAccounts` |
| ACC-07 | TOTP 등록 시작 | `totp/begin` | 대기 비밀·QR 반환, 기존 TOTP 유지 | P1 | ✅ `TestAccountsFlow` |
| ACC-08 | TOTP 등록 완료 | 올바른 코드 | TOTP 활성, 복구 코드 10개(평문은 이때만), `TOTPLast` 기록 | P1 | ✅ `TestAccountsFlow` |
| ACC-09 | TOTP 등록 시도 제한 | 틀린 코드 5회 | `totp|이름` 잠금 429 | P1 | ✅ `TestScnAccounts` |
| ACC-10 | TOTP 끄기 | 요구가 걸린 계정 | 거부 | P1 | ✅ `TestScnAccounts` |
| ACC-11 | 복구 코드 재발급 | `POST /api/auth/recovery` | 예전 코드 무효 | P2 | ✅ `TestScnAccounts` |
| ACC-12 | 2단계 요구(개별) | `Require2FA=true`, TOTP 없음 | `2fa` 게이트, 등록 후 해제 | P1 | ✅ `TestAccountsFlow` |
| ACC-13 | 2단계 요구(일괄) | `require-2fa {names:[a,b,c], require}` (1:n) | 3계정 모두 반영, 없는 이름은 무시/오류 | P1 | ✅ `TestAccountsFlow` |
| ACC-14 | 사용 중지 (R3) | 세션 2개 가진 계정 | 즉시 두 세션 모두 401 | P1 | ✅ `TestAccountsFlow` |
| ACC-15 | 계정 삭제 (R3) | 세션 있는 계정 | 세션 모두 종료, 감사 로그 | P1 | ✅ `TestScnAccounts` |
| ACC-16 | 역할 변경 즉시 반영 (R3) | 로그인 중 운영자→보기 전용 | 다음 요청부터 쓰기 403 | P1 | ✅ `TestScnAccounts` |
| ACC-17 | 마지막 관리자 보호 | 「accounts」 권한 계정이 1개일 때 강등·삭제·중지 | 거부 | P1 | ✅ `TestAccountsFlow` |
| ACC-18 | 자기 삭제 | 내 계정 삭제 | 거부 | P2 | ✅ `TestAccountsFlow` |
| ACC-19 | 2FA 초기화 | `reset-2fa` | TOTP·복구 코드 삭제, 요구 걸려 있으면 다음 로그인 때 `2fa` 게이트 | P1 | ✅ `TestScnAccounts` |
| ACC-20 | 비밀 미노출 | `/api/accounts` 응답 | 해시·TOTP·복구 코드 없음 | P1 | ✅ `TestAccountsFlow` |
| ACC-21 | 자기 비활성화·강등 방지 | 다른 관리자가 있어도 자기 계정을 `Disabled=true` 또는 「계정·접근 보안」 권한이 없는 역할로 변경 | 400 「자기 계정…」(다른 관리자에게 요청), 표시 이름 변경과 다른 사람 강등은 허용 | P1 | ✅ `TestSetupOnceAndSelfProtection` |

## ROLE — 역할·권한 (`accounts.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| ROLE-01 | 기본 역할 | 새 설치 | 관리자(전부)·운영자(config, apply, authelia_users, security)·보기 전용(없음) | P1 | ✅ `TestMigrateSingleAdmin` |
| ROLE-02 | 관리자 역할 고정 | 관리자 역할 권한 수정 | 항상 전체 권한(카탈로그가 늘어도) | P1 | ✅ `TestAccountsFlow` |
| ROLE-03 | 사용자 역할 생성·수정 | 권한 일부 | 저장, 없는 권한 ID가 하나라도 있으면 400(조용히 버리지 않음) | P2 | ✅ `TestScnRoles` |
| ROLE-04 | 역할 삭제 (R4) | 계정 3개가 쓰는 역할 | 거부(또는 다른 역할 지정 필요) | P1 | ✅ `TestScnRoles` |
| ROLE-05 | 역할 권한 축소 (R4) | 계정 2개가 쓰는 역할에서 apply 제거 | 두 계정 모두 즉시 적용 403 | P1 | ✅ `TestScnRoles` |
| ROLE-06 | 내장 역할 삭제 | 관리자/운영자/보기 전용 | 거부 | P2 | ✅ `TestScnRoles` |
| ROLE-07 | 마지막 accounts 권한 (R4) | 그 권한을 가진 유일한 역할에서 권한 제거 | 거부 | P1 | ✅ `TestAccountsFlow` |
| ROLE-08 | `permFor` 표 | 아래 경로·메서드 조합 | 표의 권한과 일치 | P1 | ✅ `TestAccountsFlow`, `TestScnPermTable` |
| ROLE-09 | GET은 누구나 | 보기 전용으로 모든 GET | 200 — 단 `/api/accounts`·`/api/roles`(계정 목록)는 「계정·접근 보안」, `/api/logs/export`는 「로그 관리」 필요 | P1 | ✅ `TestScnRoles` |
| ROLE-10 | 민감 작업 Step-up 표 (R22) | 재인증 만료 상태에서 `S()` 보호 경로 호출 | 모두 403 `{reauth:true}` 반환 | P1 | ✅ `TestScnAuthStepUp` |

ROLE-08 검사표

| 경로 | 메서드 | 필요 권한 |
|---|---|---|
| `/api/auth/*` | 전부 | 없음(내 계정) |
| `/api/accounts*`, `/api/roles*` | 전부 | accounts |
| `/api/logs/export` | GET | logs |
| `/api/logs/delete` | POST | logs |
| `/api/apply`, `/api/import`, `/api/system/update`, `/api/cfwaf/(apply\|adopt)`, `/api/dns/records*`, `/api/ddns/run`, `/api/crowdsec/sync`, `/api/dev/fault` | 쓰기 | apply |
| `/api/crowdsec/decisions*`, `/api/waf/test` | 쓰기 | security |
| `/api/users*` | 쓰기 | authelia_users |
| `/api/updates/check`, `/api/dash/data`, `/api/validate` | POST | 없음(조회) |
| 그 밖의 쓰기 (`/api/services*`, `/api/groups*`, `/api/settings` …) | 쓰기 | config |

## SET — 설정 저장 (`main.go saveSettings`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| SET-01 | 일반 설정 | config 권한, `wafParanoia` 변경 | 저장, 생성 결과가 바뀌면 「적용 대기」 | P2 | ✅ `TestScnSettings` |
| SET-02 | 키별 권한: 접근 보안 (R15) | `sec*` 변경, accounts 권한 없음 | 403 `{perm:"accounts"}` | P1 | ✅ `TestAccountsFlow` |
| SET-03 | 키별 권한: 로그 (R15) | `log*`/`disk*`, logs 권한 없음 | 403 `{perm:"logs"}` | P1 | ✅ `TestScnStepUpLogsKeys` |
| SET-04 | 키별 권한: 연결·시스템 (R15) | 경로·컨테이너·`caddyMode`·`caddyBin`·`caddyAdmin`·CrowdSec 주소·`use*` | system 권한 없으면 403 | P1 | ✅ `TestAccountsFlow` |
| SET-05 | 여러 키 동시 (R15) | config 키 + sec 키 한 번에, accounts 권한 없음 | 전체 거부(일부만 저장 안 함) | P1 | ✅ `TestScnStepUpLogsKeys` |
| SET-06 | 재인증 필요 (R15) | system/sec/log/disk/updateCheck 키 변경 | 재인증 창 밖이면 403 `{reauth}` | P1 | ✅ `TestScnAuthStepUp` |
| SET-07 | 경로 검사 | 상대 경로, `/etc/…`, `/proc`, 데이터 폴더, `/run/secrets` | 400 | P1 | ✅ `TestAccountsFlow` |
| SET-08 | 경로 그대로 | 이미 있던 이상한 경로를 안 바꿈 | 통과(무관한 저장이 막히지 않음) | P2 | ✅ `TestScnSettings` |
| SET-09 | caddy 실행 파일 | `/bin/sh`, `C:\x\caddy.exe` | 거부 / 허용 | P1 | ✅ `TestAccountsFlow` |
| SET-10 | 도메인 | `""`, `Example.COM.`, `exa mple` | 허용(미설정) / `example.com` / 거부 | P2 | ✅ `TestScnSettings` |
| SET-11 | 기본 골격 중괄호 | `}` 로 시작해 전역 블록 탈출 | 거부(줄 번호 포함) | P1 | ✅ `TestCheckBraces` |
| SET-12 | 표시 전용 설정 | `topo*` 변경 | 「적용 대기」 아님 | P3 | ✅ `TestScnSettings` |
| SET-13 | 감사 로그 diff | 키 3개 변경 | 감사 로그 `changed`에 3키, 비밀 값은 `***` | P2 | ✅ `TestScnSettings` |
| SET-14 | 경로 순회 우회 방어 | `/data/../etc/passwd`, `/proc/self/environ` 등 정규화 후 금지 경로 | `filepath.Clean` 기준 400 거부 | P1 | ✅ `TestScnSettings` |

## SVC — 서비스 (`main.go`, `caddy.go validateService`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| SVC-01 | 추가 | 정상 값 | ID 생성, `Updated`, 「서비스 추가: fqdn」 대기 | P2 | ✅ `TestServiceRejectsUnknownGroup` |
| SVC-02 | 서브도메인 규칙 | 대문자, 공백, `_`, `@` | 소문자화 / 거부 / 거부 / 루트 허용 | P2 | ✅ `TestScnServices` |
| SVC-03 | 중복 | 같은 서브도메인 | 거부 | P2 | ✅ `TestScnServices` |
| SVC-04 | 사설 노출 정리 | `exposure=tailscale`, proxied·mtls 켬 | proxied·mtls 꺼짐 | P2 | ✅ `TestScnServices` |
| SVC-05 | mTLS는 Proxied에서만 | proxied=false, mtls=true | mtls 꺼짐 | P2 | ✅ `TestScnServices` |
| SVC-06 | DNS만 | dnsOnly=true + upstream·WAF·Authelia | 모두 비움 | P2 | ✅ `TestScnServices` |
| SVC-07 | 대상 없음 | upstream·extra 둘 다 빈 값 | 거부 | P2 | ✅ `TestScnServices` |
| SVC-08 | 대상 형식 | `a b:1`, `a{` | 거부 | P1 | ✅ `TestScnServices` |
| SVC-09 | 추가 지시어 탈출 | `}\nevil.com {` | 거부 | P1 | ✅ `TestCheckBraces` |
| SVC-10 | FQDN (R9) | 도메인 변경 후 서비스 3개 | 모두 새 도메인으로 생성 | P2 | ✅ `TestScnServices` |
| SVC-11 | 정책 기본값 | Authelia 정책 빈 값 | `two_factor` | P2 | ✅ `TestScnServices` |
| SVC-12 | 미등록 그룹 | 새 그룹 `ghost` | 400 | P1 | ✅ `TestServiceRejectsUnknownGroup` |
| SVC-13 | 기존 미등록 그룹 유지 | 원래 있던 미등록 그룹 + 다른 필드만 수정 | 통과 | P2 | ✅ `TestBulkUnknownGroups` |
| SVC-14 | 수정·삭제 | 없는 ID | 400/404 | P3 | ✅ `TestScnServices` |
| SVC-15 | 길목 사이트 자동 지정 | upstream이 길목 컨테이너 | `SecSelfService`에 그 서비스 | P2 | ✅ `TestScnServices` |
| SVC-16 | WAF 민감도 범위 | `wafParanoia` 5, -1 | 0으로 | P3 | ✅ `TestScnServices` |
| SVC-17 | 대상·메모 인젝션 방어 | `upstream`에 공백·탭·개행·`{` `}`·`#`·따옴표·백틱, `notes`에 `\nreverse_proxy evil:80` | `upstream` 거부, `notes`는 줄마다 `# `가 붙은 주석으로만 들어감(지시어 탈출 불가) | P1 | ✅ `TestUpstreamInjection` |

## CADDY — Caddyfile 가져오기·생성 (`caddy.go`, `components.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| CADDY-01 | 실제 파일 가져오기 | `testdata/Caddyfile` | 전역·스니펫 → 기본 골격, 사이트 → 서비스(노출·mTLS·Authelia·upstream) | P1 | ✅ `TestImportRealCaddyfile` |
| CADDY-02 | 왕복 | 가져오기 → 생성 → 가져오기 | 서비스 목록 동일 | P1 | ✅ `TestImportRealCaddyfile` |
| CADDY-03 | 배너 | 생성 결과 | 상단 「직접 수정하면 덮어써짐」 주석 | P3 | ✅ `TestImportRealCaddyfile` |
| CADDY-04 | 사설 리스너 | 사설 서비스 2개 | `:8443`(설정 포트) 사이트로 생성 | P1 | ✅ `TestScnCaddyGenerate` |
| CADDY-05 | cf_only | mTLS 서비스 | `import cf_only`, Cloudflare 끄면 빠짐 | P1 | ✅ `TestComponentsGenerate` |
| CADDY-06 | forward_auth | Authelia 켠 서비스 | `import authelia`, Authelia 끄면 빠짐 | P1 | ✅ `TestComponentsGenerate` |
| CADDY-07 | 접근 로그 | `DashLogs=true` | 모든 사이트에 `log # gilmok` | P2 | ✅ `TestDashLogsAndBuckets` |
| CADDY-08 | 사용자 log 보존 | 가져오기 대상에 사용자 `log` | Extra로 유지, `# gilmok` 붙은 것만 버림 | P2 | ✅ `TestDashLogsAndBuckets` |
| CADDY-09 | 길목 사이트 헤더 | `SecSelfService` | 그 사이트에만 `request_header X-Gilmok-Proxy … # gilmok`, 가져오기 때 제거 | P1 | ✅ `TestProxyHeaderGenerate` |
| CADDY-10 | 비밀 헤더 미노출 | `/api/plan` 응답 | `/api/plan`의 Caddyfile(현재·다음) 모두 비밀값을 「•••(길목 비밀 — 숨김)•••」으로 가림 | P1 | ✅ `TestScnCaddyPlanAndApplyGuards` |
| CADDY-11 | 비활성 서비스 | `enabled=false` | 생성에서 빠짐 | P2 | ✅ `TestScnCaddyGenerate` |
| CADDY-12 | DNS만 서비스 | `dnsOnly=true` | 사이트 블록 없음 | P2 | ✅ `TestScnCaddyGenerate` |
| CADDY-13 | 도메인 추정 | 사이트 주소 여러 개, `co.kr` | 가장 많은 공통 접미사 / 3단계 | P2 | ✅ `TestInferDomain` |
| CADDY-14 | 중괄호 검사 | 균형·불균형·탈출·주석 속 `}` | 통과/거부/거부/통과 | P1 | ✅ `TestCheckBraces` |
| CADDY-15 | 정렬 | 공개·사설 섞임 | 공개 먼저, 이름순 — 생성 결과가 안정적 | P3 | ✅ `TestScnCaddyGenerate` |
| CADDY-16 | 도메인 미설정 (R9) | 도메인 `""` | 생성·적용 거부 | P1 | ✅ `TestScnCaddyPlanAndApplyGuards` |
| CADDY-17 | 연결 모드 | docker / api / native | 검증·적용이 각각 `docker exec` / `/adapt`·`/load` / 로컬 caddy | P1 | ✅ `TestScnCaddyModes` |
| CADDY-18 | 일반 사이트 프록시 비밀 격리 | `SecSelfService`가 아닌 서비스의 `Extra`에 `X-Gilmok-Proxy` 수동 삽입 | `validateService`가 추가 지시어에 `X-Gilmok-Proxy`가 있으면 거부(길목 사이트에만 길목이 자동으로 넣음) | P1 | ✅ `TestScnServices` |

## WAF — Caddy WAF·기본 차단 (`waf.go`, `guard.go`, `wafx.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| WAF-01 | 스니펫 생성 | 탐지·차단 서비스 존재 | `(gm_waf_detect)`·`(gm_waf_block)`, 안 쓰는 모드는 생성 안 함 | P1 | ✅ `TestWAFAndCrowdSecGenerateRoundTrip` |
| WAF-02 | 가져오기 무시 | 생성 결과를 다시 가져오기 | 길목 스니펫은 기본 골격에 들어가지 않음 | P1 | ✅ `TestWAFAndCrowdSecGenerateRoundTrip` |
| WAF-03 | 본문 검사 | `wafBodyAccess` 끔/켬 | `SecRequestBodyAccess Off/On` | P2 | ✅ `TestScnWAFGenerate` |
| WAF-04 | 민감도·점수·허용 메서드 | PL 2, 점수 7, `GET POST` | 해당 `tx.*` 설정 | P2 | ✅ `TestGuardAndServiceWAF` |
| WAF-05 | CRS 그룹 끄기 | 942 끔 | `SecRuleRemoveById 942000-942999` | P2 | ✅ `TestMigrateRemoveByID` |
| WAF-06 | 사용자 지시어 | 잘못된 SecLang | 생성은 되고 `caddy validate`에서 걸림(적용 거부) | P1 | ✅ `TestScnWAFGenerate` |
| WAF-07 | 서비스 전용 스니펫 | 민감도 지정 서비스 | `gm_waf_block_<sub>_<id6>` 생성·import | P1 | ✅ `TestGuardAndServiceWAF` |
| WAF-08 | 스니펫 이름 충돌 (R8) | `a-b`와 `a.b` 둘 다 예외 있음 | 서로 다른 스니펫 이름 | P1 | ✅ `TestScnWAFGenerate` |
| WAF-09 | 예외 규칙 검증 (R8) | 규칙 ID 범위·태그·빈 값 | 정상만 저장, 잘못된 것 거부 | P2 | ✅ `TestScnWAFGenerate` |
| WAF-10 | 공통 + 서비스 예외 (R8) | 공통 2개 + 서비스 3개 | 서비스 스니펫에 5개, 다른 서비스엔 공통 2개만 | P2 | ✅ `TestScnWAFGenerate` |
| WAF-11 | CrowdSec 실제 IP 로그 | mTLS + CrowdSec | `log_append gm_real_ip {…Cf-Connecting-Ip}` | P1 | ✅ `TestWAFAndCrowdSecGenerateRoundTrip` |
| WAF-12 | DNS only에는 금지 | DNS only 서비스 | `gm_real_ip` 없음(헤더 위조 가능) | P1 | ✅ `TestWAFAndCrowdSecGenerateRoundTrip` |
| WAF-13 | 기본 차단 스니펫 | 분류(스캐너·AI·경로·UA 없음·PHP) | `(gm_guard)` + `X-Gilmok-Block: <분류>` | P1 | ✅ `TestGuardAndServiceWAF` |
| WAF-14 | 사용자 UA·경로 | 정규식 특수문자 | 이스케이프돼 Caddyfile 문법 유지 | P2 | ✅ `TestScnWAFGenerate` |
| WAF-15 | WAF 로그 파싱 | Coraza 로그 줄 | 규칙 ID·메시지·URI·트랜잭션 | P2 | ✅ `TestParseWAFLine` |
| WAF-16 | 이벤트 호스트 매칭 | WAF 줄 + 같은 시각·경로의 접근 로그 | 이벤트에 host 채움, 기본 차단 포함 | P2 | ✅ `TestScnWAFEventsAndTest` |
| WAF-17 | 시험 요청 | 시험 8종 | 차단 모드면 403, 탐지면 통과 결과 표 | P2 | ✅ `TestScnWAFEventsAndTest` |
| WAF-18 | 시험 불가 사이트 | mTLS 사이트 | 「Cloudflare 경유만 가능」 안내 | P3 | ✅ `TestScnWAFEventsAndTest` |
| WAF-19 | 예외 규칙 SecLang 인젝션 방어 (R8) | ✅ `TestScnWAFGenerate` |
SecRuleEngine Off`·`942100 "x"`·`abc`, 메모에 개행·백틱·201자 | ID는 `^[0-9]{6}(-[0-9]{6})?$`만 통과(나머지 거부), 메모는 Caddyfile에 쓰이지 않고 개행·백틱·200자 초과만 거부 | P1 | ⬜ |

## AUTHELIA — 설정·사용자 파일 (`authelia.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| AUTHELIA-01 | access_control 치환 | 주석·`{{ secret }}`·OIDC·notifier가 있는 파일 | `access_control:` 블록만 바뀜, 나머지 바이트 동일 | P1 | ✅ `TestAccessControlReplace` |
| AUTHELIA-02 | 규칙 생성 | 서비스(1단계·2단계·그룹) | 서비스별 규칙, 그룹은 `subject: group:x` | P1 | ✅ `TestAccessControlReplace` |
| AUTHELIA-03 | 빈 규칙 | `default_policy: deny`, Authelia 서비스 0개 | 검증 통과하는 최소 규칙 생성 | P1 | ✅ `TestScnAutheliaConfig` |
| AUTHELIA-04 | 기존 규칙 가져오기 | access_control의 도메인 규칙 | 서비스의 Authelia 옵션으로 반영 | P2 | ✅ `TestImportRealCaddyfile` |
| AUTHELIA-05 | 블록 없음 | `access_control:` 없는 파일 | 끝에 추가(또는 오류) — 정책 정하고 고정 | P2 | ✅ `TestScnAutheliaConfig` |
| AUTHELIA-06 | users 왕복 | 알려지지 않은 필드 포함 | 읽고 쓰면 알 수 없는 필드 유지 | P1 | ✅ `TestUsersRoundTrip` |
| AUTHELIA-07 | groups 빈 값 | 그룹 없는 사용자 | `groups: []` (빈 문자열 금지) | P1 | ✅ `TestUsersRoundTrip` |
| AUTHELIA-08 | argon2id | 해시·검증 | 같은 비밀번호 통과, 다른 것 실패, `$argon2id$` 형식 | P1 | ✅ `TestPasswordHash` |
| AUTHELIA-09 | 검증 출력 | `loaded with errors` + cobra Usage | 오류 줄만 남기고 Usage 잘라냄 | P2 | ✅ `TestScnAutheliaConfig` |
| AUTHELIA-10 | 후보 파일 이름 | 동시에 검증 2번 | 서로 다른 `.gilmok-candidate-<rand>.yml`, 끝나면 삭제 | P1 | ✅ `TestScnAutheliaConfig` |
| AUTHELIA-11 | YAML 인젝션 방어 | 사용자 `displayname`·`email`에 줄바꿈·`:`·`groups: [admins]` 삽입 | YAML 직렬화 시 문자열로 안전하게 이스케이프되어 권한 승격 불가 | P1 | ✅ `TestScnAutheliaConfig` |

## AU — Authelia 사용자 API (`main.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| AU-01 | 사용자 추가 | 아이디·비밀번호 10자 이상 | 파일 기록 → Authelia 재시작 | P1 | ✅ `TestScnAutheliaUsers` |
| AU-02 | 아이디 규칙 | 공백·한글 | 거부 | P2 | ✅ `TestScnAutheliaUsers` |
| AU-03 | 짧은 비밀번호 | 9자 | 거부 | P1 | ✅ `TestScnAutheliaUsers` |
| AU-04 | 그룹 지정 (R18) | 등록된 그룹 3개 | 3개 모두 기록 | P2 | ✅ `TestScnAutheliaUsers` |
| AU-05 | 미등록 그룹 (R18) | 새 그룹 `ghost` | 400, 파일 변경 없음 | P1 | ✅ `TestScnAutheliaUsers` |
| AU-06 | 마지막 사용자 삭제 | 사용자 1명 | 거부 | P1 | ✅ `TestScnAutheliaUsers` |
| AU-07 | 재시작 실패 | 재시작 후 fatal | 원본 파일 복구·재시작, 오류 반환 | P1 | ✅ `TestScnAutheliaUsers` |
| AU-08 | 동시 저장 | 두 요청이 다른 사용자 수정 | 두 변경 모두 남음(`usersMu`) | P1 | ✅ `TestScnAutheliaUsers` |
| AU-09 | 해시 미노출 | `GET /api/users` | `password` 필드 없음 | P1 | ✅ `TestScnAutheliaUsers` |

## GRP — Authelia 그룹 (`groups.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| GRP-01 | 초기 채우기 | 서비스·사용자가 쓰는 그룹, `AGroupsInit=false` | 모두 등록, 플래그 켬, 두 번째 호출은 변화 없음 | P1 | ✅ `TestGroupsLifecycle` |
| GRP-02 | 추가 | 이름·설명 | 등록·이름순 정렬 | P2 | ✅ `TestGroupsLifecycle` |
| GRP-03 | 중복 추가 | 같은 이름 | 409 | P2 | ✅ `TestGroupsLifecycle` |
| GRP-04 | 이름 규칙 | 공백·65자·빈 값 | 400 | P2 | ✅ `TestGroupsLifecycle` (공백) |
| GRP-05 | 설명만 수정 | 이름 그대로 | 설명만 바뀜, 「적용 대기」 없음, 사용자 파일 안 건드림 | P2 | ✅ `TestScnGroupsMore` |
| GRP-06 | 목록 | `GET /api/groups` | 그룹별 사용자·서비스 목록, 미등록은 `defined=false` | P2 | ✅ `TestScnGroupsMore` |
| GRP-07 | users 파일 못 읽음 | 경로 없음 | 목록은 나오고 `usersError` 안내 | P2 | ✅ `TestScnGroupsMore` |
| GRP-08 | 이름 변경 → 서비스 0개 (R1) | 아무도 안 씀 | 정의만 바뀜, 대기 없음 | P2 | ✅ `TestScnGroupsMore` |
| GRP-09 | 이름 변경 → 서비스 1개 (R1) | 1개 서비스 | 그 서비스 그룹 교체, 「허용 그룹 이름 변경」 대기 | P1 | ✅ `TestScnGroupsMore` |
| GRP-10 | 이름 변경 → 서비스 n개 (R1) | 2개 이상 서비스 | 모두 교체, 다른 그룹은 그대로 | P1 | ✅ `TestGroupsLifecycle` |
| GRP-11 | 이름 변경 → 이미 새 이름도 가진 서비스 (R1) | 서비스 그룹 `[a, b]`, a→b | `[b]` (중복 없음) | P2 | ✅ `TestGroupsLifecycle` (`replaceGroup`) |
| GRP-12 | 기존 이름으로 바꾸기 | a→b, b 등록됨 | 409(합치기 금지) | P2 | ✅ `TestGroupsLifecycle` |
| GRP-13 | 이름 변경 → 사용자 n명 (R2) | 사용자 3명이 그룹 보유 | users 파일 3명 교체 + 재시작, 서비스는 그 뒤 | P1 | ✅ `TestScnGroupsWithUsers` |
| GRP-14 | 사용자 반영 실패 (R2) | 재시작 실패 | 오류, **서비스는 바뀌지 않음**, 정의도 그대로 | P1 | ✅ `TestScnGroupsWithUsers` |
| GRP-15 | 사용자 권한 없음 (R2) | config만 있는 계정, 사용자가 쓰는 그룹 이름 변경 | 400(authelia_users 필요), 아무것도 안 바뀜 | P1 | ✅ `TestScnGroupsWithUsers` |
| GRP-16 | 삭제 – 사용 중 (R1·R2) | purge 없이 | 409 + 사용처 | P1 | ✅ `TestGroupsLifecycle` |
| GRP-17 | 삭제 – purge (R1·R2) | 서비스 2 + 사용자 2 | 모두에서 빠짐, 대기 1건, 감사 로그 | P1 | ✅ `TestGroupsLifecycle`, `TestScnGroupsWithUsers` |
| GRP-18 | 삭제 – 미사용 | 아무도 안 씀 | 바로 삭제 | P2 | ✅ `TestGroupsLifecycle` |
| GRP-19 | purge 후 빈 허용 그룹 | 서비스 그룹이 그 하나뿐 | 그룹 `[]` → 로그인한 모든 사용자 | P2 | ✅ `TestGroupsLifecycle` |
| GRP-20 | users 파일 못 읽는데 이름 변경 | Authelia 사용, 파일 없음 | 거부(사용자 쪽을 못 바꾸므로) | P1 | ✅ `TestScnGroupsMore` |
| GRP-21 | Authelia 안 씀 | `UseAuthelia=false` | 사용자 파일 건드리지 않고 서비스만 | P2 | ✅ `TestGroupsLifecycle` |
| GRP-22 | 설명 길이 상한 | 200자 초과 설명 입력 | 200자로 잘림(`truncate`), 공백 트리밍 | P3 | ✅ `TestScnGroupsMore` |
| GRP-23 | 사용자 파일을 바꾸는 이름 변경·purge의 재인증 (R2·R22) | 사용자가 쓰는 그룹, 재인증 창 밖 | 403 `{reauth:true}`, users 파일·서비스·정의 모두 그대로 (재인증 후 재시도) | P1 | ✅ `TestGroupRenameTouchingUsersNeedsReauth` |

## BULK — 엑셀·CSV 일괄 등록 (`bulk.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| BULK-01 | 내보내기 왕복 | 현재 목록 내보내기 → 다시 올림 | 전부 「그대로」 | P1 | ✅ `TestBulkXLSXRoundTrip` |
| BULK-02 | 빈 양식 | `?template=1` | 제목 행만, 「안내」 시트, 드롭다운 | P2 | ✅ `TestBulkXLSXRoundTrip` |
| BULK-03 | 안내 시트 그룹 | 등록 그룹 2개 | 「등록된 그룹」 줄에 이름(설명) | P3 | ✅ `TestScnBulkFiles` |
| BULK-04 | xlsx 구조 | 공유 문자열·inlineStr·불리언·빈 칸 건너뜀(`r` 속성) | 열 위치 정확 | P1 | ✅ `TestScnBulkFiles` |
| BULK-05 | 첫 시트 찾기 | 시트 순서가 바뀐 통합 문서 | workbook rels로 첫 시트 | P2 | ✅ `TestScnBulkFiles` |
| BULK-06 | 손상 파일 | 깨진 zip, 암호 파일 | 「열 수 없습니다」 | P2 | ✅ `TestScnBulkFiles` |
| BULK-07 | .xls | 예전 형식 | 「.xlsx로 저장」 안내 | P3 | ✅ `TestBulkPlanCSV` |
| BULK-08 | CSV 인코딩 | UTF-8+BOM / CP949 | 통과 / 「CSV UTF-8로 저장」 | P2 | ✅ `TestBulkPlanCSV`, `TestScnBulkFiles` |
| BULK-09 | CSV 구분자 | `;`, 탭 | 자동 감지 | P3 | ✅ `TestScnBulkFiles` |
| BULK-10 | 추가 (R6) | 새 서브도메인 | create, 기본값(공개·사용·DNS 관리·2단계) | P1 | ✅ `TestBulkPlanCSV` |
| BULK-11 | 수정 (R6) | 기존 서브도메인, 일부 칸만 | update, 빈 칸 필드는 그대로, 바뀐 항목 목록 | P1 | ✅ `TestBulkPlanCSV` |
| BULK-12 | 지우기 표시 `-` (R6) | 메모 `-` | 메모 비움 | P2 | ✅ `TestBulkPlanCSV` |
| BULK-13 | 삭제 (R6) | 삭제=Y | delete | P1 | ✅ `TestBulkPlanCSV` |
| BULK-14 | 없는 것 삭제 (R6) | 등록 안 된 서브도메인 삭제=Y | error | P2 | ✅ `TestBulkPlanCSV` |
| BULK-15 | 파일 안 중복 (R6) | 같은 서브도메인 2행 | 두 번째 error(행 번호) | P1 | ✅ `TestBulkPlanCSV` |
| BULK-16 | FQDN 입력 (R6) | `photos.example.com` | `photos`로 정규화 | P2 | ✅ `TestBulkPlanCSV` |
| BULK-17 | 주석 행 (R6) | `#`으로 시작 | 건너뜀 | P3 | ✅ `TestBulkPlanCSV` |
| BULK-18 | 잘못된 선택값 (R6) | WAF `이상함`, 노출 `?` | error(열 이름 포함) | P2 | ✅ `TestBulkPlanCSV` |
| BULK-19 | 미등록 그룹 (R6·R1) | `admins, ghost` | error(ghost) | P1 | ✅ `TestBulkUnknownGroups` |
| BULK-20 | 같은 행 그대로 (R6) | 값이 지금과 같음 | same, 대기 없음 | P2 | ✅ `TestBulkUnknownGroups` |
| BULK-21 | 오류 섞인 반영 (R6) | 추가 1·수정 1·오류 2 | 오류 행만 빼고 한 번에 저장, 대기 2건, 감사 로그 1건 | P1 | ✅ `TestScnBulkHTTP` |
| BULK-22 | 살아 있는 목록 불변 (R6) | 미리보기(dry) | 저장소 변화 없음 | P1 | ✅ `TestBulkPlanCSV` |
| BULK-23 | 모르는 열 | 「모르는 열」 제목 | 무시 + `ignored` | P3 | ✅ `TestBulkPlanCSV` |
| BULK-24 | 서브도메인 열 없음 | 제목 행에 없음 | 파일 오류 | P2 | ✅ `TestBulkPlanCSV` |
| BULK-25 | 한도 | 2001행, 1.4 MB 초과 | 거부 | P2 | ✅ `TestScnBulkFiles` |
| BULK-26 | 열 별칭 | `subdomain`, `upstream(host:port)` | 인식 | P3 | ✅ `TestScnBulkFiles` |
| BULK-27 | ZIP 폭탄·희소 행 방어 | 압축 해제 상한(64MB) 초과 시트, `r="A999999"` 희소 행, `ci > 200` 열 | 메모리 고갈 없이 즉시 거부·무시 | P1 | ✅ `TestScnBulkFiles` |
| BULK-28 | 엑셀 지시어 탈출 차단 (R6) | `추가 지시어` 열에 `}\nevil.com {` 입력 | 해당 행 `error`(중괄호 불균형·탈출 거부) | P1 | ✅ `TestScnBulkFiles` |
| BULK-29 | 내보내기 XML·수식 안전성 | 메모·지시어에 `=CMD\|...` 수식, `</t></is>` XML 특수문자 포함 | `inlineStr` + `xmlEsc`로 이스케이프되어 왕복 시 원문 보존·XML 파괴 없음 | P1 | ✅ `TestScnBulkFiles` |

## UP — 대상 컨테이너 선택 (`upstreams.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| UP-01 | 같은 네트워크 | Caddy와 공유 네트워크 | reach=network, `<이름>:<포트>` | P1 | ✅ `TestBuildUpstreams` |
| UP-02 | Caddy 네트워크 여러 개 (R14) | Caddy가 net1·net2, 대상이 net2만 | network, shared=[net2] | P2 | ✅ `TestScnUpstreamsMore` |
| UP-03 | 게시 포트만 (R14) | 네트워크 다름, 32400 게시 | published, `host.docker.internal:32400` | P1 | ✅ `TestBuildUpstreams` |
| UP-04 | 연결 불가 (R14) | 다른 네트워크, 게시 없음 | none, 대상 값 없음 | P2 | ✅ `TestBuildUpstreams` |
| UP-05 | 포트 | EXPOSE + 게시, udp | tcp만, 중복 없이 정렬 | P2 | ✅ `TestBuildUpstreams` |
| UP-06 | 사용 중 (R13) | 서비스 2개가 같은 컨테이너 | usedBy 2개 | P2 | ✅ `TestScnUpstreamsMore` |
| UP-07 | compose 서비스 이름으로 사용 중 (R13) | upstream이 서비스 이름 | usedBy에 포함 | P3 | ✅ `TestScnUpstreamsMore` |
| UP-08 | Caddy가 PC | api/native 모드 | 게시 포트만 `localhost:<포트>` | P1 | ✅ `TestBuildUpstreams` |
| UP-09 | 추천 서브도메인 | `immich_server` | `immich-server` | P3 | ✅ `TestBuildUpstreams` |
| UP-10 | 정렬 | 중지·실행·도달성 섞임 | 실행 → network → published → none | P3 | ✅ `TestScnUpstreamsMore` |
| UP-11 | 빈 배열 | 포트·네트워크 없는 컨테이너 | `[]` (null 아님) | P3 | ✅ `TestScnUpstreamsMore` |

## APPLY — 적용 파이프라인 (`apply.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| APPLY-01 | 도메인 미설정 | 도메인 `""` | 적용 거부 | P1 | ✅ `TestScnCaddyPlanAndApplyGuards` |
| APPLY-02 | 현재 파일 못 읽음 | Caddyfile 없음 | 적용 중단(되돌릴 원본 없음) | P1 | ✅ `TestScnCaddyPlanAndApplyGuards` |
| APPLY-03 | 검증 실패 | Caddy validate 실패 | 아무 파일도 안 씀 | P1 | ✅ `TestScnApplyFailures` |
| APPLY-04 | 전체 성공 (R5) | Authelia·Caddy·DNS 모두 변경 | 검증 → 백업 → Authelia 쓰기·재시작·로그 확인 → Caddy 제자리 쓰기·reload → DNS, 대기 비움 | P1 | ✅ `TestScnApplySuccessAndNoop` |
| APPLY-05 | Authelia 시작 실패 (R5) | 재시작 후 `level=fatal` | configuration.yml 복구·재시작, Caddy·DNS 안 건드림 | P1 | ✅ `TestScnApplyFailures` |
| APPLY-06 | Caddy reload 실패 (R5) | reload 에러 | Caddyfile 복구·reload + **같은 적용에서 바꾼 Authelia도 복구** | P1 | ✅ `TestScnApplyFailures` |
| APPLY-07 | DNS 일부 실패 (R5·R7) | 삭제 1건 실패 | 그 레코드를 관리 목록에 남김, 나머지 성공 | P1 | ✅ `TestScnApplyDNSPartial` |
| APPLY-08 | 주소 변경 보류 (R5·R7) | 공개 레코드 주소가 바뀌는 계획, 「공인 IP 변경 반영」 끔 | 그 레코드 보류, `LastPublicIP` 기록 안 함 | P1 | ✅ `TestHoldIPChanges` |
| APPLY-09 | 주소 변경 허용 | 체크 켬 | 반영 + `LastPublicIP` 기록 | P1 | ✅ `TestHoldIPChanges` |
| APPLY-10 | 바뀐 것 없음 | 생성 결과 = 현재 파일 | 쓰기·재시작·reload 생략 | P2 | ✅ `TestScnApplySuccessAndNoop` |
| APPLY-11 | 동시 적용 | 두 요청 | `applyMu`로 순서대로, 두 번째는 최신 상태 기준 | P1 | ✅ `TestScnApplyConcurrentAndHealth` |
| APPLY-12 | 끈 구성요소 (R5·R19) | Authelia 끔 | Authelia 단계 생략 | P1 | ✅ `TestComponentsGenerate` (생성) |
| APPLY-13 | 제자리 쓰기 | 단일 파일 bind mount | rename 없이 truncate+write(inode 유지) | P1 | ✅ `TestScnApplyConcurrentAndHealth` |
| APPLY-14 | 헬스 판정 | 마지막 fatal 뒤 `Startup complete` | 정상 / 그 반대는 실패 | P1 | ✅ `TestScnApplyConcurrentAndHealth` |
| APPLY-15 | 백업 | 적용 1회 | 백업 폴더 생성, 같은 초 두 번째 백업은 `-2` 접미사(덮어쓰지 않음), 최근 30개만 유지(`pruneBackups`) | P2 | ✅ `TestScnApplyConcurrentAndHealth` |
| APPLY-16 | 장애 주입 | `GM_DEV_FAULTS` 없음 | `/api/dev/fault` 404, 예약 불가 | P1 | ✅ `TestScnApplyHTTP` |
| APPLY-17 | 감사 로그 | 적용 | 단계 로그 포함 warn 이벤트 | P2 | ✅ `TestScnApplyHTTP` |

## DNS — Cloudflare DNS 계획·편집 (`cloudflare.go`, `dnsedit.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| DNS-01 | 레코드 생성 | 새 공개 서비스, DNS 관리 | A 생성(공인 IP, proxied 설정 따름) | P1 | ✅ `TestPlanDNSIPv6` |
| DNS-02 | 남이 만든 레코드 | 같은 이름 레코드가 이미 있고 관리 목록에 없음 | 건드리지 않음(인수는 사용자가 「길목이 관리」) | P1 | ✅ `TestDNSRowsAndEdit` |
| DNS-03 | AAAA (R7) | IPv6 켬, 주소 감지됨 | A+AAAA 둘 다 | P1 | ✅ `TestPlanDNSIPv6` |
| DNS-04 | IPv6 감지 실패 (R7) | 켬, 감지 실패 | AAAA skip, **삭제 안 함** | P1 | ✅ `TestPlanDNSIPv6` |
| DNS-05 | IPv6 끔 (R7) | 길목이 만든 AAAA 있음 | 그 AAAA만 삭제, 대기 기록 | P1 | ✅ `TestPlanDNSIPv6` |
| DNS-06 | 서비스 삭제 (R7) | 관리 A·AAAA 있음 | 둘 다 삭제 | P1 | ✅ `TestScnApplyDNSPartial` |
| DNS-07 | 사설 서비스 (R10) | 사설 서비스 3개 | 모두 Tailscale IP, DNS only | P1 | ✅ `TestScnDNSPlan` |
| DNS-08 | Proxied 전환 | proxied true→false | 레코드 갱신 | P2 | ✅ `TestScnDNSPlan` |
| DNS-09 | 레코드 상태 표 | ok/diff/missing/orphan/unknown | 서비스와 관계 표시, 주소만 다르면 `ipChange` | P2 | ✅ `TestDNSRowsAndEdit` |
| DNS-10 | 직접 편집 | 서비스와 무관한 TXT·MX·CNAME 추가·수정·삭제 | 허용 + 감사 로그 | P2 | ✅ `TestDNSRowsAndEdit` |
| DNS-11 | 편집 금지 | 관리 레코드·DNS 관리 서비스 이름 | 거부 | P1 | ✅ `TestDNSRowsAndEdit` |
| DNS-12 | 사용자 수동 레코드 | 관리 목록에 없는 `rdp` | 어떤 적용에서도 안 건드림 | P1 | ✅ `TestScnDNSPlan` |
| DNS-13 | 토큰 없음 | Cloudflare 미설정 | DNS 단계 생략, 경고 | P2 | ✅ `TestScnDNSPlan` |
| DNS-14 | 직접 편집 이름·타입 경계 | 이름 `evil.com`, 타입 NS·SRV·CAA | 이름은 존 하위(`evil.com.<도메인>`)로 붙어 **존 밖 레코드는 만들 수 없음**, A·AAAA·CNAME·TXT·MX 외 타입은 400 | P2 | ✅ `TestScnDNSEditAndToken` |

## CFT — Cloudflare 토큰 (`cftoken.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| CFT-01 | 출처 우선순위 | 파일 env / env / 데이터 파일 | `GM_CF_TOKEN_FILE` > `GM_CF_TOKEN` > `<data>/secrets/cf_token` | P1 | ✅ `TestCFTokenVerifyAndSource` |
| CFT-02 | 저장 전 확인 | 정상 토큰 | verify → 존 조회 → DNS 읽기 통과 후 0600 저장 | P1 | ✅ `TestCFTokenVerifyAndSource` |
| CFT-03 | 확인 실패 | 무효·존 접근 불가·DNS 권한 없음 | 원인별 오류, 저장 안 함 | P1 | ✅ `TestCFTokenVerifyAndSource` |
| CFT-04 | 컨테이너 토큰 있음 | env 출처 | 화면 저장 409 | P2 | ✅ `TestScnDNSEditAndToken` |
| CFT-05 | 미노출 | 응답·감사 로그 | 토큰 값 없음(`***`) | P1 | ✅ `TestScnDNSEditAndToken` |
| CFT-06 | 삭제 | `DELETE /api/cloudflare/token` | 파일 삭제, 미설정 상태 | P2 | ✅ `TestScnDNSEditAndToken` |

## DDNS — DDNS Updater (`ddns.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| DDNS-01 | IP 바뀜 | 공인 IP 변경 | 관리 공개 레코드의 **주소만** 수정 | P1 | ✅ `TestDDNSReconcile` |
| DDNS-02 | 생성·삭제 안 함 | 적용 안 한 새 서비스 | DDNS가 만들지 않음 | P1 | ✅ `TestDDNSReconcile` |
| DDNS-03 | Proxied 안 바꿈 | proxied 설정 다름 | 그대로 | P1 | ✅ `TestDDNSReconcile` |
| DDNS-04 | 일부 실패 | 레코드 1개 실패 | `LastPublicIP` 기록 안 함 → 다음 주기 재시도 | P1 | ✅ `TestDDNSReconcile` |
| DDNS-05 | drift | IP 그대로, Cloudflare 값이 다름 | 1시간마다 비교해 수정 | P2 | ✅ `TestScnDDNS` |
| DDNS-06 | DNS only 포함 | DNS only 공개 서비스 | 대상에 포함 | P2 | ✅ `TestScnDDNS` |
| DDNS-07 | 사설 제외 | 사설 서비스 | 대상 아님(Tailscale IP 고정) | P1 | ✅ `TestScnDDNS` |
| DDNS-08 | IPv6 (R7) | IPv6 켬 | AAAA도 주소만 수정, 감지 실패 시 skip | P1 | ✅ `TestPlanDNSIPv6` |
| DDNS-09 | 이벤트 | 변경·실패·복구 | `ddns.*` 시스템 이벤트 각 1건 | P3 | ✅ `TestScnDDNS` |
| DDNS-10 | 지금 확인 | `POST /api/ddns/run` | 즉시 1회, 상태 갱신 | P3 | ✅ `TestScnDDNS` |

## CFW — Cloudflare WAF 규칙·이벤트 (`cfwaf.go`, `cfevents.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| CFW-01 | 식 생성 | 허용·위협·국가/ASN·사용자·속도 | 규칙별 식 | P1 | ✅ `TestCFExpressions` |
| CFW-02 | 길이 한도 | 위협 식이 한도 초과 | 미리보기 경고, 적용 거부 | P2 | ✅ `TestScnCFWAFMore` |
| CFW-03 | ASN adopt 판정 | `not ip.src.asnum in {…}` / 없음 | allow / block 모드 | P1 | ✅ `TestAdoptASNMode` |
| CFW-04 | 복잡한 규칙 adopt | 조건 여러 개 | 거부 | P2 | ✅ `TestAdoptASNMode` |
| CFW-05 | 남의 규칙 보존 (R11) | 규칙셋에 사용자 규칙 3개 | 길목 규칙만 추가·수정, 3개 그대로 | P1 | ✅ `TestCloudflareWAFFlow` |
| CFW-06 | 순서 (R11) | 허용·CrowdSec 규칙 | 맨 앞 | P1 | ✅ `TestCloudflareEdgeRules` |
| CFW-07 | 재적용 (R11) | 바뀐 것 없이 다시 적용 | API 쓰기 없음 | P1 | ✅ `TestCloudflareWAFFlow` |
| CFW-08 | 끄기: 길목 규칙 (R11) | 길목이 만든 규칙 끔 | 삭제 | P1 | ✅ `TestCloudflareEdgeRules` |
| CFW-09 | 끄기: adopt 규칙 (R11) | adopt한 ASN 규칙 끔 | disable만(삭제 안 함) | P1 | ✅ `TestCloudflareEdgeRules` |
| CFW-10 | 플랜 한도 | Free에서 규칙 6개 / 속도 규칙 2개 | 적용 거부 + 이유 | P1 | ✅ `TestCloudflareEdgeRules` |
| CFW-11 | 권한 없음 | 403 응답 | 권한 오류(waf/lists/analytics) 표시, 설정 잠금 | P1 | ✅ `TestCFWAFPermissionMissing` |
| CFW-12 | id 보존 | 설정 폼 저장 | `Data.CFWAF` id 유지(설정 밖에 저장) | P2 | ✅ `TestScnCFWAFMore` |
| CFW-13 | 이벤트 조회 | GraphQL 응답 | 규칙·국가·IP·경로 집계 | P2 | ✅ `TestScnCFWAFMore` |
| CFW-14 | 이벤트 권한 없음 | Analytics Read 없음 | 안내, 다른 기능은 정상 | P2 | ✅ `TestScnCFWAFMore` |

## CS — CrowdSec (`crowdsec.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| CS-01 | 판정 조회 | LAPI `origins=crowdsec,cscli` | 커뮤니티 목록 제외 | P1 | ✅ `TestCloudflareWAFFlow` |
| CS-02 | 바뀐 때만 PUT | 해시 같음 | Cloudflare 호출 없음 | P1 | ✅ `TestCloudflareWAFFlow` |
| CS-03 | 사설·루프백 제외 (R12) | 10.x, 127.x, ::1 | 목록에 없음 | P1 | ✅ `TestBanItems` |
| CS-04 | IPv6 /64 (R12) | 같은 /64의 두 주소 | 1개 항목 | P1 | ✅ `TestBanItems` |
| CS-05 | 중복 (R12) | 같은 IP 판정 2건 | 1개 항목 | P2 | ✅ `TestBanItems` |
| CS-06 | 1만 건 한도 (R12) | 판정 1만+ | 최신 판정(ID 큰 것)부터 한도까지 보내고, 빠진 개수는 동기화 상태 `dropped`·보안 이벤트·화면 안내로 표시 | P2 | ✅ `TestScnCrowdSec` |
| CS-07 | 0건 (R12) | 판정 없음 | 빈 목록 PUT(이전 차단 해제) | P1 | ✅ `TestScnCrowdSec` |
| CS-08 | 수동 차단 | IP·기간·사유 | 입력 검증(IP 형식·기간 단위), `cscli decisions add` | P1 | ✅ `TestScnCrowdSec` |
| CS-09 | 수동 해제 | 판정 ID | `cscli decisions delete` | P2 | ✅ `TestScnCrowdSec` |
| CS-10 | 동시 동기화 | 주기 + 「지금 동기화」 | `csMu`로 겹치지 않음 | P1 | ✅ `TestScnCrowdSec` |
| CS-11 | 끈 상태 | `UseCrowdSec=false` | 동기화·수집 생략 | P2 | ✅ `TestComponentsGenerate` |
| CS-12 | 키 없음 | 바운서 키 없음 | 점검 실패 안내 | P2 | ✅ `TestScnCrowdSec` |
| CS-13 | 수동 차단 인자 인젝션 방어 | IP·기간·ID에 `--scope`·공백·문자열 삽입 | `net.ParseIP`/`ParseCIDR`·기간 정규식·숫자 ID 검사로 `cscli` 실행 전 차단 | P1 | ✅ `TestScnCrowdSec` |

## MON — 모니터링 (`monitor.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| MON-01 | 접근 로그 파싱 | Caddy JSON 로그 | 호스트·상태·지연·크기·IP | P2 | ✅ `TestDashLogsAndBuckets` |
| MON-02 | 버킷 (R17) | 사이트 3개 요청 섞임 | 전체 + 사이트별 버킷 합계 일치 | P2 | ✅ `TestDashLogsAndBuckets` |
| MON-03 | WAF 집계 (R17) | WAF 차단(호스트 있음/없음) | 전체 +1, 호스트 있으면 사이트 +1, `dirty` | P2 | ✅ `TestScnMonitor` |
| MON-04 | 재연결 중복 (R17) | 같은 줄 재수신 | 스트림은 재연결 때 마지막 시각 이하 줄을 버림. `addReq` 자체는 같은 밀리초의 다른 요청을 그대로 셈(같은 ms에 여러 요청이 오므로 시각만으로 중복 판단하지 않음) | P1 | ✅ `TestScnMonitor` |
| MON-05 | 오래된 줄 (R17) | 5분 넘게 과거 | 버림 | P2 | ✅ `TestScnMonitor` |
| MON-06 | 링 버퍼 | 2만 건 초과 | 오래된 것부터 덮어씀 | P3 | ✅ `TestScnMonitor` |
| MON-07 | 보존 | 10초 버킷 1시간, 1분 버킷 24시간 | 넘은 것 정리 | P3 | ✅ `TestScnMonitor` |
| MON-08 | 저장·복원 | `metrics.json` | 재시작 후 같은 값 | P2 | ✅ `TestScnMonitor` |
| MON-09 | 헬스 점검 중복 방지 | 점검 중 다시 호출 | 백그라운드는 건너뜀, 대시보드는 기다림 | P2 | ✅ `TestScnHealthProbe` |
| MON-10 | 상태 전이 이벤트 | down→up | 전이 때만 이벤트, 시작 시 요약 1건 | P3 | ✅ `TestScnHealthProbe` |
| MON-11 | 컨테이너 변경 | Caddy 컨테이너 설정 변경 | 스트림 재연결(15초 안) | P3 | ◐ 단위 테스트 불가(`docker logs -f` 직접 실행) — 감시 고루틴 종료 처리는 코드 검토, 재연결은 dev 스택에서 확인 |

## DASH — 대시보드 (`dashboard.go`, `dashboard_db.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| DASH-01 | 기본 위젯 (R16) | `Dashboard=nil` | 기본 12개 | P3 | ✅ `TestScnDashboard` |
| DASH-02 | 저장 (R16) | 위젯 5개 순서 변경 | 순서 유지 | P3 | ✅ `TestScnDashboard` |
| DASH-03 | 초기화 (R16) | `{reset:true}` | 기본으로 | P3 | ✅ `TestScnDashboard` |
| DASH-04 | 데이터 한 번에 (R16) | 위젯 8종 | 위젯별 데이터, 조회가 수집 활성화 | P2 | ✅ `TestScnDashboard` |
| DASH-05 | 잘못된 위젯 (R16) | 알 수 없는 종류 | 그 위젯만 오류 | P3 | ✅ `TestScnDashboard` |
| DASH-06 | p95 | 히스토그램 | 버킷 안 선형 보간 | P2 | ✅ `TestScnDashboard` |
| DASH-07 | 과거·장기 범위 | `at`, 7d/30d | DB에서 조회 | P2 | ✅ `TestScnDashboard` |
| DASH-08 | 요청 목록 범위 | `from`·`to` 없음/잘못/아주 큼 | 기본 범위, 넘침 없음 | P1 | ✅ `TestScnDashboard` |

## LOG — 로그 DB·디스크·감사 (`logdb.go`, `audit.go`, `logs_api.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| LOG-01 | 배치 기록 | 요청·지표·이벤트 | 1초·1000건 배치 트랜잭션 | P2 | ✅ `TestLogDB` |
| LOG-02 | 큐 가득 | enqueue 폭주 | 막지 않고 drop 카운트 | P1 | ✅ `TestLogDB` |
| LOG-03 | 조회 필터 | 분류·수준·검색어·기간 | 해당 행만 | P2 | ✅ `TestLogDB` |
| LOG-04 | 보존 정리 | 분류별 보존 일수 | 지난 행 청크 삭제 | P2 | ✅ `TestLogDB` |
| LOG-05 | 용량 상한 | 사용 크기 > 상한 | 오래된 요청 → 지표 순 6시간 단위, **최근 24시간은 안 지움**, `usedBytes`로 판단 | P1 | ✅ `TestScnLogDB` |
| LOG-06 | 디스크 단계 | 여유 20/10/5/1% | 경고 / 강한 경고 / 요청·지표 중단 / 전부 중단 | P1 | ✅ `TestScnLogDB` |
| LOG-07 | 중단 중 이벤트 | `LogKeepEventsOnStop` | 이벤트만 기록 | P2 | ✅ `TestScnLogDB` |
| LOG-08 | 내보내기·삭제 권한 | logs 권한 없음 | 403 | P1 | ✅ `TestScnLogDB` |
| LOG-09 | 감사 대상 | 쓰기 API(`auditRoutes`) | 1건씩, 라벨·대상·성공 여부 | P2 | ✅ `TestScnApplyHTTP` |
| LOG-10 | 조회·삭제 SQL 바인딩 안전성 | 검색어 `q`·`cat`·`level`에 `' OR 1=1 --`, `%` 입력 | 파라미터 바인딩으로 SQL 인젝션 불가 | P1 | ✅ `TestScnLogDB` |
| AUD-01 | 비밀 가리기 | 요청 본문의 password·token·secret | `***` | P1 | ✅ `TestScnAudit` |
| AUD-02 | 실패 표시 | 응답 `{ok:false}`·4xx | 「— 실패」, level error | P2 | ✅ `TestScnAudit` |
| AUD-03 | 서비스 diff (R20) | 서비스 필드 3개 변경 | `changed`에 3필드, before/after | P2 | ✅ `TestScnAudit` |
| AUD-04 | 일괄 작업 | 엑셀 반영·그룹 변경 | 요약 1건(행별 아님) | P3 | ✅ `TestScnBulkHTTP` |
| AUD-05 | 실패도 기록 | 엑셀 반영 실패, 그룹 이름 변경·purge 실패, 사용 중 그룹 삭제(409) | level error 감사 로그 1건(「— 실패: 원인」). 재인증 요구(403 reauth)는 실패로 남기지 않음 | P2 | ✅ `TestScnAudit` |

## UPD — Docker·compose·업데이트·점검 (`docker.go`, `compose.go`, `updates.go`, `checks.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| UPD-01 | compose 경로 해석 | 라벨 working_dir, 길목 마운트 | 길목이 보는 경로 + 데몬 경로 | P1 | ✅ `TestComposePaths` |
| UPD-02 | 데몬 경로 되돌리기 | `/run/desktop/mnt/host/d/…` 라벨 | 호스트 경로로 매칭 | P1 | ✅ `TestComposePaths` |
| UPD-03 | 수동 compose 폴더 | 자동 감지 실패 + 설정 지정 | 업데이트·업데이트 확인 모두 그 폴더 사용 | P2 | ✅ `TestScnUpdates` |
| UPD-04 | 토큰 보호 | Caddy compose가 `${CLOUDFLARE_API_TOKEN}`, 길목 토큰 없음 | 업데이트 거부 | P1 | ✅ `TestScnUpdates` |
| UPD-05 | 이미 최신 | 컨테이너 ID 그대로 | 「이미 최신」 | P2 | ✅ `TestScnUpdates` |
| UPD-06 | 레지스트리 비교 | manifest digest ↔ RepoDigests | 다르면 새 버전 | P2 | ✅ `TestScnUpdates` |
| UPD-07 | 직접 빌드 이미지 | 레지스트리에 없음 | Dockerfile `FROM` 베이스 비교, 없으면 기준선 | P2 | ✅ `TestScnUpdates` |
| UPD-08 | 업데이트 후 기준선 | 업데이트 성공 | 기준선 갱신 → 「새 버전」 사라짐 | P2 | ✅ `TestScnUpdates` |
| UPD-09 | 심볼릭 링크 | 동시에 두 업데이트 | `linkMu`로 한 번만 생성 | P3 | ✅ `TestScnUpdates` |
| UPD-10 | 연결 점검 | 컨테이너·파일 읽기쓰기·마운트 일치 | 항목별 ok/warn/fail | P2 | ✅ `TestScnConnectionCheck` |
| UPD-11 | 토큰 일치 점검 | Caddy 컨테이너 토큰 ↔ 길목 토큰 | 같음/다름(값 출력 없음) | P1 | ✅ `TestScnUpdates` |

## COMP — 구성요소·구성도 (`components.go`, `topology.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| COMP-01 | 첫 추정 | 파일·컨테이너·토큰·서비스 | Proxied·mTLS 서비스 있으면 Cloudflare 사용, Authelia 서비스 있으면 Authelia 사용 | P1 | ✅ `TestComponentsGenerate` |
| COMP-02 | Cloudflare 끔 (R19) | mTLS 서비스 있음 | 생성에서 `cf_only` 빠짐, DNS·DDNS·WAF 동기화 생략 | P1 | ✅ `TestComponentsGenerate` |
| COMP-03 | Authelia 끔 (R19) | Authelia 서비스 있음 | `import authelia` 빠짐, 적용·점검·로그 스트림 생략, SSO 요구 무시 | P1 | ✅ `TestComponentsGenerate` |
| COMP-04 | Caddy 끔 (R19) | — | Caddy 생성·적용 없음, 서비스는 DNS·상태만 | P2 | ✅ `TestScnComponents` |
| COMP-05 | CrowdSec 끔 (R19) | — | 로그 append·동기화 없음 | P2 | ✅ `TestComponentsGenerate` |
| COMP-06 | Tailscale 끔 (R19) | 사설 서비스 남음 | 사설 리스너 유지(`privOn`) | P2 | ✅ `TestScnComponents` |
| COMP-07 | 보호 빠짐 경고 | mTLS 있는데 Cloudflare 끔 | 확인 요구(UI) | P2 | ✅ `dev/ui-tests.js` |
| COMP-08 | 구성도 감지 | Caddy 게시 포트·https_port·OS | 노드·불일치 경고 | P3 | ✅ `TestTopologyDetect` |
| COMP-09 | 앞단 장비 체인 | 예전 단일 장비 / 체인 저장 / 모르는 종류·포트 범위 | 첫 장비로 이전, 저장, 400 | P3 | ✅ `TestTopoHopsMigrationAndValidation` |

## CFG — 설정 백업·복원·초기화 (`config.go`, `reset.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| CFG-01 | 내보내기 | — | 비밀값·계정 없음, 설정·서비스·그룹 포함 | P1 | ✅ `TestConfigExportImport` |
| CFG-02 | 복원 | 미리보기 → 반영 | 미리보기는 불변, 반영 후 적용 대기, 계정·프록시 비밀 불변 | P1 | ✅ `TestConfigExportImport` |
| CFG-03 | 복원 권한·안전 | 운영자가 시스템 키 변경 / 금지 경로 / 중괄호 탈출 / 역할 누락 | 403 / 400 / 400 / 내장·사용 중 역할 유지 | P1 | ✅ `TestConfigImportPermsAndSafety` |
| CFG-04 | 초기화 확인·권한 | 확인 문구 틀림 / 운영자 | 400 (불변) / 403 | P1 | ✅ `TestFactoryReset` |
| CFG-05 | 초기화 (계정 유지) | 서비스·설정·그룹·DNS 목록·규칙 id·대시보드·GM_* 환경변수·모니터 메모리·옛 백업·화면 토큰 있음 | 전부 코드 초기값(환경변수 무시), 로그·모니터·옛 백업·토큰 삭제, 계정·역할·프록시 비밀 유지, 감사 로그는 초기화 1건만, `backups/*-reset/gilmok.json` 백업, 감사 로그, 로그인 유지 | P1 | ✅ `TestFactoryReset` |
| CFG-06 | 초기화 (계정 포함) | `accounts:true` | 초기 계정 admin(Bootstrap)만, 기본 역할 3개, 모든 세션 종료(401) | P1 | ✅ `TestFactoryReset` |
| CFG-07 | 첫 설정 감지 | /stacks 아래 Caddyfile·Authelia 파일, docker ps에 caddy·authelia 이미지 | 컨테이너(실행 중 우선)·경로(같은 폴더 users)·도메인·사이트 수·구성요소 제안, 설정은 불변 | P2 | ✅ `TestSetupDetectAndDone` |
| CFG-08 | 첫 설정 완료 표시 | 새 설치 / done / 보기 전용 / 초기화 | false → true / 403 / 초기화 후 false | P2 | ✅ `TestSetupDetectAndDone` |
| CFG-09 | Caddy 컨테이너 토큰 사용 | Caddy env에 토큰 없음 / 있음 | 400 / 감지 `caddyToken` true·값 미노출, 검증 후 저장·응답에 값 없음 | P1 | ✅ `TestCFTokenFromCaddy` |
| CFG-10 | 바운서 키 만들기 | 보기 전용 / 관리자 / 배포 키 있음 / 초기화 | 403 / 저장·`csKey` 사용·응답에 값 없음 / 409 / 키 삭제 | P1 | ✅ `TestCrowdSecBouncerCreate` |
| CFG-11 | 복원으로 권한 상승 | 운영자가 역할 권한을 늘린 파일 / 모르는 권한 / 설정 폼이 거부하는 값(SecLang 탈출·IP·디스크 순서·메서드) | 403 accounts / 400 / 400 | P1 | ✅ `TestConfigImportNoEscalation` |
| CFG-12 | Tailscale IP 찾기 | Tailscale 컨테이너의 기기 목록, 호스트 이름 일치 / 불일치 | 그 기기 IP 제안 / 제안 없이 목록 | P2 | ✅ `TestTailscaleDetect` |
| SEC-V2 | 리뷰 v2 하드닝 | 게이트 허용 경로, CSV 수식, 메타데이터 URL, 사설 realm, 권한 거부 로그, cat 검증, 로그인 전 state | 각각 거부·기록 | P1 | ✅ `TestReviewV2Hardening`, `TestPentestStepUpAndReauthBrute` |

## UI — 프런트엔드 단위 (`web/*.js`)

지금 JS 테스트 도구가 없습니다. `node:test` + 가벼운 DOM(jsdom 등)을 dev 의존성으로만 쓰는 방식을 권장합니다(배포 바이너리에는 영향 없음).

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| UI-01 | `h()` null 자식 | `h('div', null, null, 'a')` | "null" 글자 없음 | P2 | ✅ `dev/ui-tests.js` |
| UI-02 | `diffLines` | 추가·삭제·같음 섞임 | LCS 기준 줄 diff | P2 | ✅ `dev/ui-tests.js` |
| UI-03 | `stepsLayout` 묶음 | children 3개 | 레일 1칸, 하위 탭 3개 | P2 | ✅ `dev/ui-tests.js` |
| UI-04 | 묶음 상태 | 하위 ok·warn·opt | 묶음 = warn(가장 나쁜 것) | P2 | ✅ `dev/ui-tests.js` |
| UI-05 | 하위 바로가기 | `gotoTab(tab, childId)` | 부모 선택 + 그 하위 탭 | P2 | ✅ `dev/ui-tests.js` |
| UI-06 | `api()` 재인증 | 403 `{reauth}` | 재인증 창 → 성공 시 1회 재시도 | P1 | ✅ `dev/ui-tests.js` |
| UI-07 | `api()` 게이트 | 403 `{gate}` | 게이트 화면 1번만(중복 열림 없음) | P2 | ✅ `dev/ui-tests.js` |
| UI-08 | `openDialog` | Esc·포커스 트랩·배경 inert·포커스 복귀 | 모두 동작 | P2 | ✅ `dev/ui-tests.js` |
| UI-09 | `groupSelect` | 값 set/get·disabled·change | 입력칸처럼 동작, 자유 입력 불가 | P2 | ✅ `dev/ui-tests.js` |
| UI-10 | `groupChips` | 등록 그룹·미등록 선택 그룹 | 미등록은 점선, 빼면 다시 못 넣음 | P3 | ✅ `dev/ui-tests.js` |
| UI-11 | 구성요소 분기 | `use('x')=false` | 탭·열·필드 숨김, 표 열 개수 일치 | P2 | ✅ `dev/ui-tests.js` |
| UI-12 | 서비스 표 열 | Caddy 끔 | 머리글·본문 열 수 같음 | P3 | ✅ `dev/ui-tests.js` |

---

## 실행

```bash
go vet ./...
go test -count=1 ./...               # 전체
go test -count=1 -run 'Groups|Bulk' ./...   # 일부
```

통합 확인(단위 테스트 밖)은 `dev/` 테스트 스택에서 합니다 — 롤백 3종은 「설정 › 적용·백업 › 롤백 테스트」 장애 주입으로, 실제 Cloudflare는 운영 첫 적용 때 결과를 확인합니다.

## 자동화 현황 요약

| 모듈 | 케이스 | ✅ | ◐ | ⬜ |
|---|---|---|---|---|
| STORE | 10 | 10 | 0 | 0 |
| AUTH | 45 | 45 | 0 | 0 |
| ACC | 21 | 21 | 0 | 0 |
| ROLE | 10 | 10 | 0 | 0 |
| SET | 14 | 14 | 0 | 0 |
| SVC | 17 | 17 | 0 | 0 |
| CADDY | 18 | 18 | 0 | 0 |
| WAF | 19 | 19 | 0 | 0 |
| AUTHELIA | 11 | 11 | 0 | 0 |
| AU | 9 | 9 | 0 | 0 |
| GRP | 23 | 23 | 0 | 0 |
| BULK | 29 | 29 | 0 | 0 |
| UP | 11 | 11 | 0 | 0 |
| APPLY | 17 | 17 | 0 | 0 |
| DNS | 14 | 14 | 0 | 0 |
| CFT | 6 | 6 | 0 | 0 |
| DDNS | 10 | 10 | 0 | 0 |
| CFW | 14 | 14 | 0 | 0 |
| CS | 13 | 13 | 0 | 0 |
| MON | 11 | 10 | 1 | 0 |
| DASH | 8 | 8 | 0 | 0 |
| LOG·AUD | 15 | 15 | 0 | 0 |
| UPD | 11 | 11 | 0 | 0 |
| COMP | 8 | 8 | 0 | 0 |
| UI | 12 | 12 | 0 | 0 |
| **합계** | **376** | **375** | **1** | **0** |

다음에 채울 순서(권장): ① 0.2 테스트 이음매 4종 → APPLY·AU·GRP-13~15·CS-08·DDNS·LOG-06 ② AUTH 세션·게이트·CSRF·Origin·보안 경계(P1) ③ BULK ZIP 폭탄·인젝션 방어 및 LOG-05·06(데이터 손실) ④ UI 묶음·`api()` 재인증.

## 검토 반영 기록

| 날짜 | 출처 | 반영 |
|---|---|---|
| 2026-11-09 | 외부 검토(Gemini) | 이음매 3종(공인 IP·디스크·레지스트리), R21~R23, 보안 케이스 21건 추가. 코드와 대조해 AUTH-40(403→409)·SVC-17·DNS-14 기대 결과를 실제 동작에 맞춤. 지적된 코드 문제 중 「그룹 이름 변경·purge의 재인증 누락」「일괄 등록·그룹 실패 감사 로그 누락」은 수정(GRP-23, AUD-05), ACC-21(자기 비활성화·강등)도 수정. 「Cloudflare 토큰 삭제 재인증 누락」은 이미 `S()`가 걸려 있어 해당 없음 |

## 침투 테스트 (공격자 관점, `scn_pentest_test.go`)

실제 라우터(`app.handler()`)에 공격 요청을 보내 확인합니다. 공격자 모델 둘: (a) 같은 Docker 네트워크의 인증 없는 컨테이너, (b) 낮은 권한(보기 전용/운영자) 계정.

| ID | 공격 | 결과 |
|---|---|---|
| PENTEST-A1 | 네트워크의 낯선 컨테이너(루프백·게이트웨이 아님)가 모든 민감 경로·사전 인증 경로를 두드림 | 전부 403, 데이터 미노출. `setup` 재호출도 409 |
| PENTEST-A2 | 세션 없이 API 호출 | 200 없음, GET은 401, 데이터 미노출 |
| PENTEST-A3 | 프록시 경유로 `X-Forwarded-For` 앞부분을 바꿔 가며 로그인 잠금 회피 시도 | 마지막(실제) IP로 키가 잡혀 잠금 유지 |
| PENTEST-B1 | 보기 전용 계정이 모든 쓰기·남의 계정·남의 세션 종료 시도 | 전부 403, 남의 세션 유지·세션 목록에 남 안 보임 |
| PENTEST-B2 | 운영자가 계정·역할·접근 보안·로그·연결 설정 변경 시도 | 전부 403, 값 불변 |
| PENTEST-B3 | 재인증 창 만료 후 민감 작업 / 재인증 무차별 대입 | 403 `{reauth}`, 무차별은 429 |
| PENTEST-B4 | 자기 권한 상승·마지막 관리자 자가 삭제/강등, `/api/accounts`에서 비밀 추출 | 거부, 응답에 해시·TOTP 비밀 없음 |
| PENTEST-C1 | 서비스 필드·Authelia 사용자 필드로 Caddy/YAML 인젝션 | 거부 또는 안전하게 문자열로 이스케이프(블록 스칼라 왕복) |
| PENTEST-C2 | 세션 쿠키·헤더 조작으로 신원 바꾸기, 토큰 엔트로피 | 신원은 세션 저장값 기준, 위조 쿠키 401, 토큰 20회 무충돌·48자+ |
| PENTEST-D1 | 모든 조회 엔드포인트·감사 로그에서 비밀(토큰·해시·프록시 비밀·세션·TOTP) 노출 | 어디에도 없음 |

결과: 점검한 공격 경로에서 악용 가능한 취약점 없음. 처음 보고된 3건의 「실패」는 모두 테스트 자체 오류(변경 없는 설정 요청, 비밀이 아닌 `totp` 불리언 필드명, 안전한 YAML 블록 스칼라를 단순 문자열 수로 오판)였고, 공격은 실제로 막혀 있었음.

방어 심층화 관찰(결함 아님, 참고): CrowdSec LAPI 주소·Caddy 관리 API 주소 변경 시 SSRF 여지가 있으나 모두 `system` 권한+재인증이 필요하고 그 권한자는 이미 docker.sock 접근권이 있어 경계를 새로 넘지 않음. `/api/check`·`/api/validate`는 인증된 보기 전용도 호출 가능(파일 경로·컨테이너 버전 노출 — 경로는 `/api/state`에도 있어 추가 노출 없음).

## 전수 테스트 실행 결과 (2026-11-09)

- `go test -count=1 ./...` — 테스트 함수 95개(침투 테스트 10개 포함) 전부 통과, 약 125초. 시나리오 376건 중 375건 자동화(나머지 1건 MON-11은 일부)
- UI 12건 + COMP-07: `dev/ui-tests.js`를 데이터 사본으로 띄운 임시 인스턴스의 브라우저에서 실행 → 전부 PASS
- `go test -race`: 이 PC의 gcc(32비트)로는 빌드 불가 — 아직 미실행

테스트로 찾아 고친 결함

| 케이스 | 결함 | 수정 |
|---|---|---|
| CADDY-10 | `/api/plan` 응답에 프록시 비밀이 평문으로 보임(보기 전용 계정도 조회 가능) | 응답에서 비밀값을 가림 |
| CADDY-18 | 일반 서비스 추가 지시어에 `X-Gilmok-Proxy`를 넣을 수 있음 | 저장 거부 |
| STORE-03/04 | `Update` 콜백 오류·저장 실패 시 메모리 상태가 바뀐 채 남음 | 깊은 복사본에서 실행 후 성공 시에만 반영 |
| ROLE-03 | 없는 권한 ID를 조용히 버리고 저장 | 400 |
| APPLY-15 | 백업이 지워지지 않고 계속 쌓임, 같은 초 백업이 서로 덮어씀 | 최근 30개 유지, 같은 초는 접미사 |
| CS-06 | 1만 건 초과 시 알파벳순으로 잘려 최근 공격 IP가 빠질 수 있음, 표시 없음 | 최신 판정 우선, 빠진 개수 표시 |
| CS-08 | 사유를 비우면 기본 사유(괄호 포함)가 자기 검사에 걸려 수동 차단이 항상 400 | 기본 사유 문구 변경 |
| AUD-03 | `PUT /api/services/{id}` 본문에 id가 없으면 자기 자신과 중복이라며 거부 | 경로의 id를 우선 |
| (리팩터링) | 라우터·용량 정리가 `main()`·고루틴 안에 있어 시험 불가 | `app.handler()`, `trimToCap()` 분리 |

## MSTK — 관리형 스택 (`stacks.go`, `stack_caddy.go`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| MSTK-01 | 사전 점검 | 다른 컨테이너가 같은 호스트 포트 사용 / 같은 이름(길목 것 아님) / 데이터 폴더 마운트 없음 | fail + 원인, 설치 거부 | P1 | ✅ `TestManagedCaddyInstall` |
| MSTK-02 | Caddy 설치 | 빈 기본 골격, 서비스 1개, 사설 경로 ts_serve | compose(이름·포트·`127.0.0.1:8443`·네트워크·라벨, :2019 없음)·Dockerfile·Caddyfile·.env(0600), build→up→`caddy validate`, 설정 연결·기록 | P1 | ✅ `TestManagedCaddyInstall` |
| MSTK-03 | 설치 실패 정리 | 시작 후 검증 실패 | `compose down`(이번에 만든 것만), 기록·설정 변경 없음 | P1 | ✅ `TestManagedCaddyVerifyFailCleansUp` |
| MSTK-04 | 권한·동시 작업 | 보기 전용 / 잘못된 포트·이름 / 작업 진행 중 | 403 / 400 / 409 | P1 | ✅ `TestManagedCaddyInstall` |
| MSTK-05 | 초기화·제거 | 초기화 / 제거(폴더 남김) | 기록 유지 / 컨테이너 down·기록 삭제·폴더 유지 | P2 | ✅ `TestManagedCaddyInstall` |
| MSTK-06 | 업데이트 경로 | 관리형 라벨이 붙은 컨테이너 | compose 대상 = 길목 안 스택 폴더 | P2 | ✅ `TestManagedComposeTarget` |
| MSTK-07 | 사설 포트 게시 | ts_serve·없음 / ts_direct / vpn | 127.0.0.1 / Tailscale IP / 0.0.0.0, 포트 충돌 판정 | P2 | ✅ `TestCaddyPrivBindAndPorts` |
| MSTK-08 | 실제 설치 (dev) | 임시 인스턴스(Docker Desktop, bind /data)에서 실제 빌드·실행·검증·연결 점검·제거 | 진행 로그 실시간, 점검 7항목 통과, 제거 시 폴더 삭제·외부 네트워크 유지 | P2 | ✅ 수동 확인 (2026-11-10) |
| MSTK-09 | Authelia 설치 | 도메인 없음 / 짧은 비밀번호 / 잘못된 아이디 / 정상 | 400 / 400 / 400 / v4.38 설정(session.cookies·filesystem notifier·access_control)·비밀값 3개(설정 파일에 없음)·관리자(argon2id, admins)·admins 그룹 등록·Caddy forward_auth 주소 변경·포털 서비스(관문 없음) 추가, 비밀번호는 기록·로그·응답에 없음 | P1 | ✅ `TestManagedAutheliaInstall` |
| MSTK-10 | Authelia 시작 실패 | 로그에 level=fatal | 실패·`down`·기록 없음 | P1 | ✅ `TestManagedAutheliaStartFails` |
| MSTK-11 | Authelia 실제 설치 (dev) | 실제 authelia:latest | Startup complete, 연결 점검 7항목·`config validate` 통과, 사용자 추가(백업→재시작→정상), 제거 | P2 | ✅ 수동 확인 (2026-11-10) |
| MSTK-12 | CrowdSec 설치 | 배포의 키 파일이 비어 있음 | 키 생성(길목 secrets·스택 .env 같은 값, 응답에 없음), compose(docker.sock:ro·파서·포트 없음), acquis = Caddy 컨테이너, 설정 연결(LAPI·접근 로그 켬·적용 대기·동기화=Cloudflare 사용 여부) | P1 | ✅ `TestManagedCrowdSecInstall` |
| MSTK-13 | Caddy가 바뀌면 따라감 | 설정의 Caddy 컨테이너 변경 | acquis 다시 쓰기·기록 갱신·CrowdSec 재시작 | P2 | ✅ `TestManagedCrowdSecInstall` |
| MSTK-14 | CrowdSec 실제 설치 (dev) | 실제 crowdsec:latest | 바운서 등록 후 LAPI 대기까지 → 설치 직후 LAPI·파서 점검 통과, 길목 수동 차단이 LAPI로 다시 보임, 제거 | P2 | ✅ 수동 확인 (2026-11-10) |
| MSTK-15 | 기존 포털이 옛 Authelia를 가리킴 | 가져온 서비스 upstream `authelia:9091` | 새 컨테이너로 바꿈(적용 대기), 포털 중복 추가 없음 | P1 | ✅ `TestManagedAutheliaInstall` |
| MSTK-16 | 포털 없음 | 서비스 없음 / 다시 adopt | 포털 1개(공개·Proxied·관문 없음) / 중복 없음 | P2 | ✅ `TestAdoptAutheliaAddsPortal` |
| MSTK-17 | 빠른 설정에서 설치 (dev) | Caddy 연결 + 가져오기, Authelia·CrowdSec 「길목이 새로 설치」 | 가져오기 → Authelia → CrowdSec 순서, 실시간 로그, forward_auth·포털이 새 Authelia, CrowdSec이 연결된 Caddy를 읽음, LAPI 통과, 마법사 단계에 관리형 카드 | P2 | ✅ 수동 확인 (2026-11-10) |
| MSTK-18 | 설치 네트워크 지정 | bridge / 새 이름 | 400 / 만들고 길목 연결, 기록 | P2 | ✅ `TestManagedComposeEdit` |
| MSTK-19 | compose 편집 | 라벨 삭제 / 컨테이너 이름 변경 / 깨진 YAML / 다른 네트워크 / 시작 못 하는 파일 / 재설치 / 기본값으로 | 400 / 400 / 400 / 적용·기록·custom / 이전 파일로 복원 / 고친 파일 유지 / 생성 파일로·custom 해제 | P1 | ✅ `TestManagedComposeEdit` |
| MSTK-20 | 리눅스식 /data (이름 있는 볼륨) 실제 | 볼륨 Source `/var/lib/docker/volumes/…/_data` | 그 아래 stacks/ 를 bind로 설치·LAPI 통과, compose 편집으로 네트워크 이동(생성·길목 연결·재생성·LAPI 통과), 제거 | P2 | ✅ 수동 확인 (2026-11-10) |
| MSTK-21 | 같은 종류 스택 두 개(다른 컨테이너 이름) | compose 프로젝트 | 파일 `name:` = 컨테이너별 프로젝트, 한쪽 설치·제거가 다른 쪽 컨테이너를 지우지 않음 | P1 | ✅ `TestStackProjectPerContainer` |
| MSTK-22 | compose 편집 실시간 검사 | 입력 중 `compose-check` | 규칙 위반·YAML 오류는 `ok:false`+이유, 정상은 네트워크 목록, 파일은 그대로 | P2 | ✅ `TestComposeCheckEndpoint` + 수동(편집기 색·오류 표시, 다크/화이트) |

## THEME — 테마 (`web/theme.js`, `web/app.css`)

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| THEME-01 | 화이트 | 로그인·서비스 목록/구성도·대시보드·Caddy 탭·로그(날짜 선택기)·적용 대화상자(diff)·서비스 편집 | 밝은 배경, 입력칸 흰색, 네이티브 select 목록 흰 배경·어두운 글자(`color-scheme: light`), 구성도·차트 색 테마 반영 | P2 | ✅ 수동 확인 (2026-11-11) |
| THEME-02 | 다크 회귀 | 같은 화면 | 예전과 같음, 실행 중 전환 시 구성도 다시 그림 | P2 | ✅ 수동 확인 (2026-11-11) |
| THEME-03 | 시스템 | OS 다크 / OS 라이트 규칙 | 다크 / `@media (prefers-color-scheme: light)` 규칙이 화이트와 같은 값 | P2 | ✅ 수동 확인 (OS 라이트 전환 자체는 미시험) |
| THEME-04 | 브라우저 확장 | Dark Reader 켜짐 + 화이트 | `darkreader-lock`으로 원래 색 유지 | P3 | ✅ 수동 확인 |
| I18N-01 | 번역 파일 무결성 | en.json | JSON 형식, 자리표시자가 원문과 같음, ko.json에 없는 키 없음 | P1 | ✅ `TestI18nCatalog` |
| I18N-02 | 영어 화면 전체 | 모든 탭·단계·하위 단계·적용 창 | `gm.i18nDebug=1`로 돌며 `gmI18n.misses()` — 사용자 데이터 외 0건, 구성도 칸 겹침 없음 | P2 | ✅ 수동 (2026-11-11) |
| I18N-03 | 한국어로 되돌림 | 언어 select → 한국어 | 새로고침 후 원문 그대로 (번역 처리 안 돔) | P2 | ✅ 수동 |
| I18N-04 | 짧은 패턴 오매칭 | 「모든 사이트에 공통인 부분」 | 「{0}분」에 걸리지 않음 (node로 번역기 단독 실행) | P2 | ✅ 수동 |
| I18N-05 | 첫 접속 언어 선택 | Lang 비어 있음 → `POST /api/auth/lang` | 인증 없이 1회만(이후 409), 잘못된 값 400, state에 lang, 설정에서 변경·잘못된 값 거부 | P1 | ✅ `TestUILanguageChoice` |
| I18N-06 | 언어 선택 화면 → 다른 브라우저 | 새 설치 접속 → English → 캐시 지운 브라우저 → 설정 탭에서 한국어 | 선택 화면, 영어 로그인, 다른 브라우저도 영어, 설정 저장 후 한국어로 새로고침 | P2 | ✅ 수동 (2026-11-11) |
| REL-01 | 멀티 아키텍처 이미지 빌드 | `docker buildx build --platform linux/amd64 --build-arg VERSION=…` | go vet·test 통과, 라벨 version, TZ=UTC | P2 | ✅ 수동 |


## FRESH — 새 사용자 처음 설치 흐름 (`scn_fresh_test.go`, 실제 Docker E2E)

처음부터 길목으로 Caddy·Authelia·CrowdSec을 설치하는 사용자가 실제로 겪은 문제(525·502·검증 실패)를 케이스로 고정한다. 단위·시나리오는 가짜 Docker·가짜 Cloudflare, E2E는 이 PC의 Docker에 격리된 이름·포트로 실제 설치.

| ID | 시나리오 | 입력·조건 | 기대 결과 | P | 자동화 |
|---|---|---|---|---|---|
| FRESH-01 | 관리형 Caddy 골격 맞춤 | 예전 Caddy에서 가져온 골격(CA 경로 `/etc/caddy/…`, `forward_auth authelia`, 인증서 방식 없음) + 토큰 | CA 경로 → `conf/certs`, forward_auth → 관리형 Authelia, `acme_dns` 추가 | P1 | ✅ `TestFreshFitManagedBase` |
| FRESH-02 | 맞춤 반복 | 이미 맞춘 골격 | 바뀌는 것 없음(멱등) | P2 | ✅ |
| FRESH-03 | 토큰 없음 | 위 골격, 토큰 없음 | `acme_dns` 넣지 않음 | P1 | ✅ |
| FRESH-04 | 없는 스니펫 | mTLS·Authelia 서비스가 있는데 골격에 `cf_only`·`authelia` 없음 | 두 스니펫 추가 | P1 | ✅ |
| FRESH-05 | 직접 운영하는 Caddy | 관리형 아님 | 골격을 건드리지 않음 | P1 | ✅ |
| FRESH-06 | 보류: mTLS 스니펫 없음 | `cf_only` 없는 골격 + mTLS 사이트 | 그 사이트만 보류 | P1 | ✅ `TestFreshHoldSites` |
| FRESH-07 | 보류: 모르는 스니펫 | 추가 지시어 `import my_headers` | 보류 | P1 | ✅ |
| FRESH-08 | 보류 아님 | 정의된 스니펫 / 파일 import / `gm_*` | 그대로 적용 | P1 | ✅ |
| FRESH-09 | 보류 결과 | 위 | 생성 파일에서 빠지고, 저장된 서비스는 그대로 | P1 | ✅ |
| FRESH-10 | 네트워크 자동 선택 | Authelia·CrowdSec 설치, 네트워크 비움, Caddy=reverseproxy | Caddy 네트워크 | P1 | ✅ `TestFreshNetworkFollowsCaddy` + E2E-07 |
| FRESH-11 | Caddy 없음 | 위, Caddy 컨테이너 없음 | 예전 자동 선택 | P2 | ✅ |
| FRESH-12 | 네트워크 안내 데이터 | `/api/docker/networks` | 컨테이너 수·Caddy·길목 네트워크 | P2 | ✅ `TestFreshNetworkAdviceData` |
| FRESH-13 | 점검: Caddy↔Authelia 네트워크 | 다른 네트워크 / 같은 네트워크 | fail + `docker network connect` 안내 / ok | P1 | ✅ `TestFreshAutheliaNetworkCheck` |
| FRESH-14 | 점검: 인증서 방식 | acme_dns·dns cloudflare·local_certs·tls 파일 / 없음 | 인정 / Proxied 사이트 있으면 fail | P1 | ✅ `TestFreshCertMethodCheck` |
| FRESH-15 | mTLS·CA API 권한 | 관리형 Caddy 없음 / 보기 전용 | 404(이유) / 403 | P1 | ✅ `TestFreshEndpointErrors` |
| FRESH-16 | 토큰 없음·잘못된 PEM | | 400(토큰) / 400(CA), 올바른 PEM은 `conf/certs`에 저장 | P1 | ✅ |
| FRESH-17 | Cloudflare 권한 부족 | 403 10000 | 502 + 「SSL 및 인증서 · 편집」 권한 안내 | P1 | ✅ |
| FRESH-18 | 다른 프록시 불러오기 오류 | 파일 없음 / 모르는 형식 / 1MB 초과 / 도메인 없음 / 깨진 nginx | 400 / 400 / 경고로 건너뜀 / 400 / 경고 | P1 | ✅ |
| FRESH-19 | 가져오기 → 설치 | 예전 골격을 가져온 뒤 관리형 Caddy 설치 | 설치가 골격을 맞춤(가져온 전역 옵션은 유지) | P1 | ✅ `TestFreshImportThenInstall` |
| FRESH-20 | mTLS 생성 | 가짜 Cloudflare | 업로드·켜기·CA 저장, 다시 만들면 예전 것 삭제, 개인 키 저장 안 함 | P1 | ✅ `TestCaddyMTLSGenerate` |
| FRESH-21 | CA 없는 mTLS 보류 | 관리형 Caddy, CA 없음 → CA 넣음 | 보류·적용 대기 유지 → 적용·대기 비움 | P1 | ✅ `TestApplyHoldsMTLSWithoutCA` |
| FRESH-22 | 관리형에 가져오기 | 예전 Caddyfile을 관리형 Caddy·Authelia 위에 | 골격 유지·맞춤, Authelia 대상 교체, 포털 유지 | P1 | ✅ `TestImportIntoManagedStack` |
| FRESH-23 | 탭에서만 설정 | 마법사 없이 적용 성공 | 설정 완료로 기록(로그인 때 설정 제안 안 띄움) | P2 | ✅ `TestFreshApplyMarksSetupDone` |
| E2E-01~22 | 실제 처음 설치 | 실제 Docker: 언어 → 관리자 → Caddy(네트워크 지정·내부 인증서) → Authelia(네트워크 비움) → CrowdSec → 서비스 → 점검 → 적용 → 실제 접속 → CrowdSec 재시작 → 보류 | 전부 통과 | P1 | ✅ 24/24 (2026-11-11, 실제 Docker) |
| E2E-P2-01~14 | 예전 Caddyfile → 관리형 스택 | PC 파일 가져오기 → CA 없이 적용(mTLS 보류) → 잘못된 PEM → CA 넣고 적용 → 클라이언트 인증서 없는 접속 거부 → 점검 | 전부 통과 | P1 | ✅ 14/14 (2026-11-11, 실제 Docker) |
