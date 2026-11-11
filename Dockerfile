# Gilmok — single static Go binary + docker CLI (to exec/restart Caddy/Authelia via the socket)
# Multi-arch: the build stage runs on the builder's own platform (tests run once, natively) and
# cross-compiles for each target (docker buildx --platform linux/amd64,linux/arm64).

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web ./web
COPY testdata ./testdata
RUN go vet ./... && go test ./...
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=""
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w${VERSION:+ -X main.version=$VERSION}" -o /out/gilmok .

FROM alpine:3.22
ARG VERSION=""
LABEL org.opencontainers.image.title="Gilmok" \
      org.opencontainers.image.description="Web UI for a Caddy + Authelia + Cloudflare + CrowdSec + Tailscale reverse proxy" \
      org.opencontainers.image.source="https://github.com/redstar-programmer/gilmok" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION"
RUN apk add --no-cache docker-cli docker-cli-compose ca-certificates tzdata
COPY --from=build /out/gilmok /usr/local/bin/gilmok
ENV GM_DATA=/data GM_LISTEN=:8080 TZ=UTC
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/gilmok"]
