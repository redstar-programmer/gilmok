# Caddy + Cloudflare DNS (acme_dns) + Coraza WAF (OWASP CRS) for caddy.
# Replace D:\Docker\caddy\Dockerfile with this file (the compose file already uses `build: .`),
# then run the image update from Gilmok (Caddy tab > image update) or `docker compose up -d --build`.
# If the old Dockerfile added other plugins, add them as more --with lines.
FROM caddy:builder AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/corazawaf/coraza-caddy/v2

FROM caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
