<div align="center">

# Gilmok (길목)

### One place to manage every way into your home server

**English** | [한국어](README.md)

[![Release](https://img.shields.io/github/v/release/redstar-programmer/gilmok?label=release)](https://github.com/redstar-programmer/gilmok/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker Hub](https://img.shields.io/docker/v/vitive/gilmok?label=docker&sort=semver)](https://hub.docker.com/r/vitive/gilmok)

**A web UI that configures and applies a reverse proxy built from Caddy, Authelia, Cloudflare, CrowdSec and Tailscale.**

</div>

---

## Why

Once a home server passes ten or so services, adding one more means editing the Caddyfile, adding an Authelia rule, creating a DNS record in Cloudflare, reloading, and checking that it all works. Miss one of those steps and the site either doesn't open or, worse, opens without a login.

Gilmok turns that into "one service, one row of settings". Saving doesn't change anything yet: you first see what will change, only what passes validation is applied, and if applying fails it rolls back to the previous state.

The name means the narrow spot where a wide road turns into an alley in Korean — the place every request to your server passes through.

## Features

### Services
For each subdomain you choose public (:443) or private (Tailscale / VPN only), Cloudflare Proxied or DNS only, mTLS, the Authelia login policy and allowed groups, and the WAF mode. Many services can be imported at once from Excel (.xlsx) or CSV, and the upstream can be picked from your running Docker containers.

### Safe apply
"Apply" generates the Caddyfile and Authelia rules and checks them first inside the real containers with `caddy validate` and `authelia config validate`. If they pass, it backs up, restarts Authelia, reloads Caddy without downtime and syncs DNS, in that order. If anything fails along the way, every changed file goes back to what it was.

> DNS changes that would move a public record to a different IP are held by default. This prevents a copy of Gilmok running elsewhere (say, a test PC) from pointing your production records at the wrong address.

### Import what you have
Your current Caddyfile is read in: global options and snippets become the "base configuration", site blocks become services. In Authelia's `configuration.yml` only the `access_control` block is replaced; comments, `{{ secret }}` templates, OIDC and the notifier are left alone.

### Cloudflare
Creates, updates and deletes DNS records, switches Proxied on and off, and runs DDNS for IPv4 and IPv6. Edge WAF rules cover trusted IPs, scanners and AI crawlers, country and ISP (ASN) limits and rate limiting, and the free plan's rule limits are checked before anything is sent.

### WAF and CrowdSec
Known scanners, attack tools and probe paths like `/.env` get a 403 right at the front of Caddy. On top of that, Coraza WAF (OWASP CRS) can be set to "detect only" or "block" per service. CrowdSec judges attacks by the real IP of requests that came through Cloudflare, and the block happens at the Cloudflare edge.

### Dashboard and logs
Requests per minute, 5xx rate, p95 response time, status codes over time, whether each service responds, container resources and certificate expiry, all as widgets. An audit log of who changed what, plus security and system logs, is kept in SQLite and recording is cut back when disk space runs low.

### Install what's missing
No Caddy, Authelia or CrowdSec yet? Gilmok installs them as sibling containers and wires up the connection settings. You can still edit their compose files from the UI afterwards.

### Diagram
Draws the path from the internet through Cloudflare, your router and Caddy to each service. Lines to services that don't respond turn into still dashed lines.

### Accounts and access
One account per person, with roles such as administrator, operator and view-only. Two-factor authentication (TOTP), a password re-check before sensitive actions and login lockout are built in, and the admin UI only opens from the server itself or through a designated Caddy route.

### Languages
Korean and English. The language picked on the first visit becomes the language of that install and can be changed later in the Settings tab.

## Tech stack

| Part | What |
|---|---|
| Backend | **Go 1.26** single binary, standard `net/http` |
| UI | HTML / CSS / JavaScript with no build step, embedded in the binary |
| Storage | settings in a JSON file, logs in **SQLite** (no cgo) |
| Talks to | Docker CLI, Caddy, Authelia, Cloudflare API, CrowdSec LAPI |
| Image | `vitive/gilmok` — linux/amd64, linux/arm64 |

## Quick start

### Requirements
- Docker 20.10 or newer with Docker Compose v2
- amd64 or arm64 (Raspberry Pi included)
- A Cloudflare API token if you use Cloudflare (can also be added in the UI after installing)

### Install

```bash
# 1. make a folder
mkdir gilmok && cd gilmok

# 2. get the compose file (no .env needed)
curl -fsSLO https://github.com/redstar-programmer/gilmok/releases/latest/download/docker-compose.yml

# 3. start it
docker compose up -d
```

To manage a Caddy or Authelia you already run, uncomment the marked lines (folders, container names, network) in the downloaded `docker-compose.yml`. If you'd rather keep folders and names in a `.env`, use [deploy/docker-compose.yml](deploy/docker-compose.yml) with [.env.example](deploy/.env.example). There's also an install script for Windows ([deploy/README.md](deploy/README.md), in Korean).

### Access

| What | Address |
|---|---|
| Admin UI | `http://127.0.0.1:8088` (opens on the server itself only) |

On the first visit you pick the language and sign in with **admin / admin**. Right after that you create your own administrator account, and the admin account is disabled at that moment. "Quick setup" then finds your containers and config files and helps you connect them.

> Don't expose the admin UI to the internet. To use it from a phone or another device, the "Create Gilmok site" button in the Settings tab sets up a Tailscale-only site behind Authelia two-factor login.
> Gilmok uses the Docker socket, so a Gilmok administrator effectively has admin rights on the server.

### Update

```bash
docker compose pull
docker compose up -d
```

Settings and logs stay in `./data`. To pin a version, change the image in the compose file to something like `vitive/gilmok:0.1.2`.

## Environment variables

These are only first-start defaults; after that, what you change in the UI wins.

| Variable | Description | Default |
|---|---|---|
| `GM_LANG` | UI language, `ko` or `en`. Empty: asked on the first visit | (none) |
| `GM_DOMAIN` | Base domain for service addresses | (none) |
| `GM_TAILSCALE_IP` | Address private services' DNS points to | (none) |
| `GM_CADDY_CONTAINER` | Caddy container name | `caddy` |
| `GM_AUTHELIA_CONTAINER` | Authelia container name | `authelia` |
| `GM_CROWDSEC_CONTAINER` | CrowdSec container name | `crowdsec` |
| `GM_CADDYFILE` | Caddyfile path Gilmok reads and writes | (none) |
| `GM_AUTHELIA_CONFIG` | Authelia `configuration.yml` path | (none) |
| `GM_AUTHELIA_USERS` | Authelia `users_database.yml` path | (none) |
| `GM_CROWDSEC_LAPI` | CrowdSec LAPI address | (none) |
| `GM_CF_TOKEN_FILE` | Cloudflare API token file. Otherwise entered in the UI | (none) |
| `GM_CROWDSEC_KEY_FILE` | CrowdSec bouncer key file. Otherwise created in the UI | (none) |
| `GM_DATA` | Data folder | `/data` |
| `TZ` | Time zone | `UTC` |

The Cloudflare token needs `Zone · Zone · Read` and `Zone · DNS · Edit`. Add `Zone · Zone WAF · Edit` for WAF rules, `Zone · Analytics · Read` for edge events and `Account · Account Filter Lists · Edit` for the CrowdSec block list. The token is checked against Cloudflare before it's saved.

## Good to know

> **On Docker Desktop (Windows, macOS) every visitor shows up with the gateway IP.** IP-based features inside the server (GeoIP, fail2ban and so on) can't work there, so Gilmok does IP-based blocking at the Cloudflare edge. CrowdSec only trusts the real IP in logs of mTLS sites, which nothing but Cloudflare can reach.

> Only **Caddy** is supported for now. nginx is next on the list.

> Files Gilmok generates (Caddyfile comments and the like) are written in Korean regardless of the UI language.

> It runs on Linux, but SELinux setups (`:z` labels) haven't been tested yet.

## Development

```bash
go test ./...                                             # unit, scenario and penetration tests
bash dev/reset.sh                                         # create test-stack data
docker compose -f dev/docker-compose.yml up -d --build    # http://127.0.0.1:18088
```

The test stack runs real Caddy (with Coraza), Authelia and CrowdSec containers under different names and sends nothing to the outside. If you change UI text, rebuild the message catalog with `go run ./tools/i18n` and fill in the English translation (`web/i18n/en.json`). The test list is in [docs/TEST_SCENARIOS.md](docs/TEST_SCENARIOS.md) (Korean).

Pushing a tag like `v0.1.2` makes GitHub Actions run the tests and publish the Docker Hub image and the release.

## License

MIT. See [LICENSE](LICENSE).

## Support

- [Issues](https://github.com/redstar-programmer/gilmok/issues) — bug reports and feature requests
- [Releases](https://github.com/redstar-programmer/gilmok/releases) — what changed in each version
- [Docker Hub](https://hub.docker.com/r/vitive/gilmok) — images

<div align="center">
<sub>Gilmok — one place for every way into your home server</sub>
</div>
