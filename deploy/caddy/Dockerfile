# Caddy + Cloudflare DNS (acme_dns) + Coraza WAF (OWASP CRS) + GeoIP country block.
#
# Published as vitive/gilmok-caddy (linux/amd64, linux/arm64) by .github/workflows/caddy.yml —
# a Caddy installed by Gilmok pulls that image, so registry-based update tools (Dockhand,
# Watchtower, Diun, …) can see its updates too.
#
# Using it for your own Caddy: either set `image: vitive/gilmok-caddy:latest` in its compose file,
# or copy this file next to that compose file (with `build: .`) and add more --with lines for other
# plugins, then run the image update from Gilmok (Caddy tab > image update) or
# `docker compose up -d --build`.
ARG CADDY_VERSION=2

# the builder runs on the build machine and cross-compiles (no slow CPU emulation for arm64)
FROM --platform=$BUILDPLATFORM caddy:${CADDY_VERSION}-builder AS builder
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH xcaddy build \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/corazawaf/coraza-caddy/v2 \
    --with github.com/porech/caddy-maxmind-geolocation

FROM caddy:${CADDY_VERSION}
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
LABEL org.opencontainers.image.title="gilmok-caddy" \
      org.opencontainers.image.description="Caddy with Cloudflare DNS, Coraza WAF (OWASP CRS) and GeoIP country matching — the Caddy Gilmok installs" \
      org.opencontainers.image.source="https://github.com/redstar-programmer/gilmok" \
      org.opencontainers.image.licenses="Apache-2.0"
