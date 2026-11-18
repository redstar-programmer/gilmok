# Test stack copy of deploy/caddy/Dockerfile (Caddy + Cloudflare DNS + Coraza WAF + GeoIP).
FROM caddy:builder AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/corazawaf/coraza-caddy/v2 \
    --with github.com/porech/caddy-maxmind-geolocation

FROM caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
