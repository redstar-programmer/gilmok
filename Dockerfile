# Gilmok — single static Go binary + docker CLI (to exec/restart Caddy/Authelia via the socket)

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web ./web
COPY testdata ./testdata
RUN go vet ./... && go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gilmok .

FROM alpine:3.22
RUN apk add --no-cache docker-cli docker-cli-compose ca-certificates tzdata
COPY --from=build /out/gilmok /usr/local/bin/gilmok
ENV GM_DATA=/data GM_LISTEN=:8080 TZ=Asia/Seoul
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/gilmok"]
