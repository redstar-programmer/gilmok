# 처음 설치 E2E (실제 Docker)

새 사용자가 길목으로 Caddy·Authelia·CrowdSec을 처음 설치하는 흐름을 실제 Docker에서 끝까지 돌립니다.
이름·포트를 따로 써서 다른 컨테이너와 겹치지 않습니다 (`gm-e2e`, `e2e-*`, 네트워크 `gm-e2e-net`, 포트 18095·19443).
Cloudflare는 쓰지 않습니다 (실제 토큰을 넣지 말 것).

```bash
docker build -t gilmok:e2e --build-arg VERSION=e2e .
docker run -d --name gm-e2e -p 127.0.0.1:18095:8080 --add-host host.docker.internal:host-gateway   -v gm-e2e-data:/data -v //var/run/docker.sock:/var/run/docker.sock gilmok:e2e
cd dev/e2e
python fresh_install.py      # 1부: 언어 → 관리자 → Caddy(네트워크 지정) → Authelia(네트워크 비움) → CrowdSec → 서비스 → 점검 → 적용 → 실제 접속
python old_caddyfile.py      # 2부: 예전 Caddyfile → CA 없이 적용(mTLS 보류) → CA 넣고 적용 → mTLS 실제 확인
# 또는 1부 다음에 기능 전체 통합 테스트(91건, 마지막에 초기화하므로 2부와는 따로)
python integration.py

# 정리
docker rm -f gm-e2e e2e-caddy e2e-authelia e2e-crowdsec
docker volume rm gm-e2e-data && docker network rm gm-e2e-net
```

결과 기록은 docs/TEST_SCENARIOS.md 「FRESH」 표.
