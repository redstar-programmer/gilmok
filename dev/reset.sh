#!/usr/bin/env bash
# Generates the test-stack fixtures under dev/run/ (git-ignored). Test values only.
#   bash dev/reset.sh          create if missing
#   bash dev/reset.sh --force  wipe dev/run and recreate (stop the stack first)
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
RUN=run
AUTHELIA_IMG=authelia/authelia:latest

if [[ "${1:-}" == "--force" ]]; then rm -rf "$RUN"; fi
if [[ -f "$RUN/.ready" ]]; then echo "dev/run already exists (use --force to recreate)"; exit 0; fi

mkdir -p "$RUN/caddy" "$RUN/authelia/config" "$RUN/authelia/secrets" "$RUN/data"

# ---- Caddy: production Caddyfile + local_certs (no ACME / Cloudflare traffic from the test box)
python - "$ROOT/testdata/Caddyfile" "$RUN/caddy/Caddyfile" <<'EOF'
import sys
src = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n")
assert src.startswith("{\n"), "global options block expected at top"
src = "{\n\tlocal_certs\n" + src[2:]
open(sys.argv[2], "w", encoding="utf-8", newline="\n").write(src)
EOF
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=gmtest origin-pull CA" \
  -keyout "$RUN/caddy/.ca-key.pem" -out "$RUN/caddy/cf-origin-pull-ca.pem" 2>/dev/null

# ---- Authelia secrets (_FILE style, same names as production)
for f in jwt_secret session_secret storage_encryption_key oidc_hmac_secret; do
  openssl rand -hex 32 | tr -d '\n' > "$RUN/authelia/secrets/$f"
done
openssl genrsa -out "$RUN/authelia/secrets/oidc_jwks_rsa.pem" 2048 2>/dev/null

hash() { # $1 = algorithm args...
  MSYS_NO_PATHCONV=1 docker run --rm "$AUTHELIA_IMG" authelia crypto hash generate "$@" | sed -n 's/^Digest: //p'
}
OIDC_SECRET="$(openssl rand -hex 16)"
USER_PW="test-$(openssl rand -hex 6)"
OIDC_DIGEST="$(hash pbkdf2 --variant sha512 --password "$OIDC_SECRET")"
USER_HASH="$(hash argon2 --password "$USER_PW")"
[[ -n "$OIDC_DIGEST" && -n "$USER_HASH" ]] || { echo "hash generation failed"; exit 1; }

# configuration.yml = reference template with a real client_secret digest
python - "$ROOT/dev/authelia.configuration.yml" "$RUN/authelia/config/configuration.yml" "$OIDC_DIGEST" <<'EOF'
import sys, re
src = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n")
src, n = re.subn(r"client_secret: '[^']*'", "client_secret: '" + sys.argv[3] + "'", src)
assert n == 1
open(sys.argv[2], "w", encoding="utf-8", newline="\n").write(src)
EOF

cat > "$RUN/authelia/config/users_database.yml" <<EOF
users:
  tester:
    disabled: false
    displayname: "Test User"
    password: "$USER_HASH"
    email: tester@example.test
    groups:
      - admins
EOF

cat > "$RUN/TEST_CREDENTIALS.txt" <<EOF
# test stack only — not used anywhere else
authelia user   : tester / $USER_PW
oidc client     : immich / $OIDC_SECRET
EOF
touch "$RUN/.ready"
echo "dev/run created"
